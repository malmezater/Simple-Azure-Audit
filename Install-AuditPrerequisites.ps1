#Requires -Version 7.4

<#
.SYNOPSIS
    Installs everything Invoke-AzureAudit.ps1 needs, without running an audit.

.DESCRIPTION
    Intended for provisioning a dedicated audit workstation (e.g. a PAW built with PAWDeploy).
    Winget apps (PowerShell 7, Azure CLI, Python) are expected to be installed first -
    see PAWDeploy-AzureAudit.xml. This script then installs:

      1. PowerShell modules  (Az, Microsoft.Graph.Authentication, Pester, Maester, PSRule.Rules.Azure,
                              WARA, AzureResourceInventory, ImportExcel, AzAPICall)
      2. Prowler             (Python venv in %ProgramData%\SimpleAzureAudit\prowler, added to PATH)
      3. AzGovViz script     (downloaded to <ToolsPath>\Azure-Governance-Visualizer)
      4. Maester tests       (<ToolsPath>\maester-tests)

    Run it again at any time to update: modules are updated, Prowler is upgraded and
    AzGovViz / Maester tests are refreshed.

.PARAMETER Scope
    AllUsers (default when elevated) or CurrentUser.

.PARAMETER ToolsPath
    Same folder Invoke-AzureAudit.ps1 uses for downloaded tools. Default: .\tools next to this script.

.PARAMETER ProwlerPath
    Folder for the Prowler Python virtual environment. Default: %ProgramData%\SimpleAzureAudit\prowler

.EXAMPLE
    pwsh -ExecutionPolicy Bypass -File .\Install-AuditPrerequisites.ps1

.EXAMPLE
    .\Install-AuditPrerequisites.ps1 -Scope CurrentUser -SkipProwler
#>

[CmdletBinding()]
param(
    [ValidateSet("AllUsers", "CurrentUser")]
    [string]$Scope,
    [string]$ToolsPath   = (Join-Path $PSScriptRoot "tools"),
    [string]$ProwlerPath = (Join-Path $env:ProgramData "SimpleAzureAudit\prowler"),
    [switch]$SkipModules,
    [switch]$SkipProwler,
    [switch]$SkipAzGovViz,
    [switch]$SkipMaesterTests
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $Scope) { $Scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" } }
if ($Scope -eq "AllUsers" -and -not $isAdmin) { throw "-Scope AllUsers requires an elevated PowerShell session." }

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result([string]$Item, [string]$Status, [string]$Detail = "") {
    $results.Add([PSCustomObject]@{ Item = $Item; Status = $Status; Detail = $Detail })
    $color = switch ($Status) { "OK" { "Green" } "Skipped" { "DarkGray" } default { "Red" } }
    Write-Host ("  {0,-28} {1,-8} {2}" -f $Item, $Status, $Detail) -ForegroundColor $color
}

# ─────────────────────────────────────────────────────────────
# 1. POWERSHELL MODULES
# ─────────────────────────────────────────────────────────────

$modules = @(
    "Az"                               # built-in checks, all Az-based tools
    "Az.ResourceGraph"                 # WARA, ARI (listed explicitly in case Az is pinned to an older version)
    "Az.CostManagement"                # ARI
    "Microsoft.Graph.Authentication"   # Maester
    "Pester"                           # Maester (5.x)
    "Maester"
    "PSRule"                           # PSRule engine
    "PSRule.Rules.Azure"               # PSRule for Azure rules + Export-AzRuleData
    "WARA"
    "ImportExcel"                      # ARI
    "AzureResourceInventory"
    "AzAPICall"                        # AzGovViz (it installs its pinned version itself if it differs)
)

Write-Host "`n[PowerShell modules - scope $Scope]" -ForegroundColor Magenta
if ($SkipModules) {
    Add-Result "PowerShell modules" "Skipped"
}
else {
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne "Trusted") {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
    foreach ($name in $modules) {
        try {
            $installed = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
            $params = @{ Name = $name; Scope = $Scope; Force = $true; AllowClobber = $true; ErrorAction = "Stop" }
            # Windows ships a signed Pester 3.x; installing 5.x next to it needs -SkipPublisherCheck.
            if ($name -eq "Pester") { $params.SkipPublisherCheck = $true }
            Install-Module @params
            $now = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
            $detail = if ($installed -and $installed.Version -ne $now.Version) { "$($installed.Version) -> $($now.Version)" } else { "$($now.Version)" }
            Add-Result $name "OK" $detail
        }
        catch {
            Add-Result $name "Failed" $_.Exception.Message
        }
    }
}

# ─────────────────────────────────────────────────────────────
# 2. PROWLER (Python venv)
# ─────────────────────────────────────────────────────────────

Write-Host "`n[Prowler]" -ForegroundColor Magenta
if ($SkipProwler) {
    Add-Result "Prowler" "Skipped"
}
else {
    try {
        # Prowler supports Python 3.10 - 3.13. Prefer the py launcher so the right version is picked.
        $python = $null
        if (Get-Command py -ErrorAction SilentlyContinue) {
            foreach ($v in "3.12", "3.13", "3.11", "3.10") {
                & py "-$v" -c "import sys" 2>$null
                if ($LASTEXITCODE -eq 0) { $python = @("py", "-$v"); break }
            }
        }
        if (-not $python -and (Get-Command python -ErrorAction SilentlyContinue)) {
            $ver = (& python -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null)
            if ($ver -in "3.10", "3.11", "3.12", "3.13") { $python = @("python") }
        }
        if (-not $python) { throw "Python 3.10-3.13 not found. Install it first (winget: Python.Python.3.12)." }

        $venvPython = Join-Path $ProwlerPath "Scripts\python.exe"
        if (-not (Test-Path $venvPython)) {
            New-Item -ItemType Directory -Force -Path (Split-Path $ProwlerPath) | Out-Null
            $exe = $python[0]; $pyArgs = @($python | Select-Object -Skip 1) + @("-m", "venv", $ProwlerPath)
            & $exe @pyArgs
            if ($LASTEXITCODE -ne 0) { throw "Could not create the Python venv in $ProwlerPath." }
        }
        & $venvPython -m pip install --upgrade pip --quiet
        & $venvPython -m pip install --upgrade prowler --quiet
        if ($LASTEXITCODE -ne 0) { throw "pip install prowler failed." }

        # Put prowler.exe on PATH (machine-wide when elevated).
        $scripts = Join-Path $ProwlerPath "Scripts"
        $target  = if ($isAdmin) { "Machine" } else { "User" }
        $path    = [Environment]::GetEnvironmentVariable("Path", $target)
        if (($path -split ';') -notcontains $scripts) {
            [Environment]::SetEnvironmentVariable("Path", ($path.TrimEnd(';') + ";" + $scripts), $target)
        }
        $version = (& (Join-Path $scripts "prowler.exe") --version 2>$null | Select-Object -Last 1)
        Add-Result "Prowler" "OK" "$version ($ProwlerPath)"
    }
    catch {
        Add-Result "Prowler" "Failed" $_.Exception.Message
    }
}

# ─────────────────────────────────────────────────────────────
# 3. AZURE GOVERNANCE VISUALIZER
# ─────────────────────────────────────────────────────────────

Write-Host "`n[Azure Governance Visualizer]" -ForegroundColor Magenta
if ($SkipAzGovViz) {
    Add-Result "AzGovViz" "Skipped"
}
else {
    try {
        New-Item -ItemType Directory -Force -Path $ToolsPath | Out-Null
        $root    = Join-Path $ToolsPath "Azure-Governance-Visualizer"
        $zip     = Join-Path $ToolsPath "azgovviz.zip"
        $extract = Join-Path $ToolsPath "_azgovviz_extract"
        Invoke-WebRequest -Uri "https://github.com/Azure/Azure-Governance-Visualizer/archive/refs/heads/master.zip" -OutFile $zip -UseBasicParsing
        if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
        Expand-Archive -Path $zip -DestinationPath $extract -Force
        if (Test-Path $root) { Remove-Item $root -Recurse -Force }
        Move-Item -Path (Get-ChildItem $extract -Directory | Select-Object -First 1).FullName -Destination $root
        Remove-Item $zip, $extract -Recurse -Force -ErrorAction SilentlyContinue
        $v = (Get-Content (Join-Path $root "version.json") -Raw | ConvertFrom-Json).ProductVersion
        Add-Result "AzGovViz" "OK" "$v ($root)"
    }
    catch {
        Add-Result "AzGovViz" "Failed" $_.Exception.Message
    }
}

# ─────────────────────────────────────────────────────────────
# 4. MAESTER TESTS
# ─────────────────────────────────────────────────────────────

Write-Host "`n[Maester tests]" -ForegroundColor Magenta
if ($SkipMaesterTests) {
    Add-Result "Maester tests" "Skipped"
}
else {
    try {
        Import-Module Maester -ErrorAction Stop
        $tests = Join-Path $ToolsPath "maester-tests"
        if (Test-Path (Join-Path $tests "*")) { Update-MaesterTests -Path $tests }
        else { New-Item -ItemType Directory -Force -Path $tests | Out-Null; Install-MaesterTests -Path $tests }
        Add-Result "Maester tests" "OK" $tests
    }
    catch {
        Add-Result "Maester tests" "Failed" $_.Exception.Message
    }
}

# ─────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────

$failed = @($results | Where-Object Status -eq "Failed")
Write-Host "`n[Summary]" -ForegroundColor Magenta
Write-Host "  $($results.Count - $failed.Count) OK/skipped, $($failed.Count) failed." -ForegroundColor $(if ($failed.Count) { "Yellow" } else { "Green" })
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "  Azure CLI not found - optional, but lets Prowler reuse 'az login' (winget: Microsoft.AzureCLI)." -ForegroundColor DarkYellow
}
Write-Host "  Open a new terminal so PATH changes take effect." -ForegroundColor Gray
if ($failed.Count) { exit 1 }
