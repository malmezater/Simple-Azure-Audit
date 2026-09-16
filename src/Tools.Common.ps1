# ─────────────────────────────────────────────────────────────
# Tools.Common.ps1
# Shared plumbing for the external assessment tools:
# prerequisite checks, child-process execution and file helpers.
#
# External PowerShell tools (Maester, WARA, AzGovViz, ARI) run in a child
# pwsh process. That keeps their module state, StrictMode and preference
# variables away from this script. The Az login is shared through the
# normal Az context autosave, so no extra sign-in is needed for Az-based tools.
# ─────────────────────────────────────────────────────────────

$script:ToolCatalog = [ordered]@{
    Native   = "Built-in checks (NSG, RBAC, cost, encryption, Key Vault, storage, tagging, Azure Advisor)"
    Prowler  = "Prowler - CIS / NIST / ISO security posture checks for Azure and Entra ID"
    Maester  = "Maester - Entra ID, Conditional Access, EIDSCA and CISA identity tests"
    AzGovViz = "Azure Governance Visualizer - RBAC, policy, orphaned resources, Defender plans and PSRule (Well-Architected)"
    WARA     = "Well-Architected Reliability Assessment (Microsoft APRL) - reliability recommendations and retirements"
    ARI      = "Azure Resource Inventory - Excel inventory and network topology diagram (appendix)"
}

function ConvertTo-PSLiteral {
    # Returns a single-quoted PowerShell string literal for embedding values in generated scripts.
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Get-PwshPath {
    $p = (Get-Process -Id $PID).Path
    if ($p -and (Split-Path $p -Leaf) -match '^pwsh') { return $p }
    $cmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $p
}

function Test-ModuleAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)
}

function Get-ModuleVersionString {
    param([Parameter(Mandatory)][string]$Name)
    $m = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($m) { return $m.Version.ToString() }
    return ""
}

function Install-AuditModule {
    # Installs a PowerShell Gallery module for the current user when -InstallMissing is used.
    param([Parameter(Mandatory)][string]$Name, [switch]$InstallMissing)
    if (Test-ModuleAvailable $Name) { return $true }
    if (-not $InstallMissing) { return $false }
    Write-Step "  Installing module $Name (CurrentUser)..." "Yellow"
    try {
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        return (Test-ModuleAvailable $Name)
    } catch {
        Write-Step "  Could not install ${Name}: $($_.Exception.Message)" "DarkYellow"
        return $false
    }
}

function Invoke-ToolProcess {
    <#
      Runs a script block text in a child pwsh process with a transcript.
      The child inherits the console, so interactive sign-ins (browser/device code) work.
      Returns [PSCustomObject]@{ ExitCode; DurationSeconds; LogPath }
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ScriptText,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$LogDirectory
    )

    New-Item -ItemType Directory -Force -Path $WorkingDirectory, $LogDirectory | Out-Null
    $logPath    = Join-Path $LogDirectory "$($Name.ToLower()).log"
    $scriptPath = Join-Path $LogDirectory "$($Name.ToLower())-run.ps1"

    $wrapped = @"
`$ErrorActionPreference = 'Continue'
`$ProgressPreference = 'SilentlyContinue'
Set-Location -LiteralPath $(ConvertTo-PSLiteral $WorkingDirectory)
Start-Transcript -Path $(ConvertTo-PSLiteral $logPath) -Force | Out-Null
`$__exit = 0
try {
$ScriptText
}
catch {
    Write-Host "ERROR: `$(`$_.Exception.Message)" -ForegroundColor Red
    `$__exit = 1
}
finally {
    Stop-Transcript | Out-Null
}
exit `$__exit
"@
    Set-Content -Path $scriptPath -Value $wrapped -Encoding utf8

    # Start-Process -NoNewWindow shares the console (so sign-in prompts are visible)
    # without the child's output leaking into this function's return value.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath (Get-PwshPath) -NoNewWindow -Wait -PassThru `
        -ArgumentList @("-NoProfile", "-NoLogo", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`"")
    $exit = $proc.ExitCode
    $sw.Stop()

    return [PSCustomObject]@{
        ExitCode        = $exit
        DurationSeconds = $sw.Elapsed.TotalSeconds
        LogPath         = $logPath
    }
}

function Get-LatestFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Filter, [switch]$Recurse)
    if (-not (Test-Path $Path)) { return $null }
    Get-ChildItem -Path $Path -Filter $Filter -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function New-ReportLink {
    param([string]$Label, [System.IO.FileInfo]$File, [string]$RunFolder)
    if (-not $File) { return $null }
    return @{ Label = $Label; Path = (Get-RelativeReportPath -BasePath $RunFolder -FullPath $File.FullName) }
}

function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path, [int]$Depth = 50)
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8
    return ($raw | ConvertFrom-Json -Depth $Depth)
}

function Invoke-AuditTools {
    <#
      Runs (unless -ImportOnly) and imports each selected external tool.
      Every tool writes to <RunFolder>/raw/<tool>; logs go to <RunFolder>/logs.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Tools,
        [Parameter(Mandatory)][string]$RunFolder,
        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$ManagementGroupId,
        [string]$ToolsPath,
        [switch]$ImportOnly,
        [switch]$InstallMissing
    )

    $logDir = Join-Path $RunFolder "logs"
    $step = 0
    $external = @($Tools | Where-Object { $_ -ne "Native" })

    foreach ($tool in $external) {
        $step++
        $raw = Join-Path (Join-Path $RunFolder "raw") $tool.ToLower()
        Write-Section "EXTERNAL $step/$($external.Count) - $($tool.ToUpper())"

        $common = @{ RawFolder = $raw; RunFolder = $RunFolder }
        try {
            switch ($tool) {
                "Prowler" {
                    if (-not $ImportOnly) { Invoke-ProwlerScan @common -LogDirectory $logDir -TenantId $TenantId -SubscriptionId $SubscriptionId }
                    Import-ProwlerResults @common
                }
                "Maester" {
                    if (-not $ImportOnly) { Invoke-MaesterScan @common -LogDirectory $logDir -TenantId $TenantId -ToolsPath $ToolsPath -InstallMissing:$InstallMissing }
                    Import-MaesterResults @common
                }
                "AzGovViz" {
                    if (-not $ImportOnly) { Invoke-AzGovVizScan @common -LogDirectory $logDir -TenantId $TenantId -SubscriptionId $SubscriptionId -ManagementGroupId $ManagementGroupId -ToolsPath $ToolsPath -InstallMissing:$InstallMissing }
                    Import-AzGovVizResults @common -SubscriptionId $SubscriptionId
                }
                "WARA" {
                    if (-not $ImportOnly) { Invoke-WARAScan @common -LogDirectory $logDir -TenantId $TenantId -SubscriptionId $SubscriptionId -InstallMissing:$InstallMissing }
                    Import-WARAResults @common
                }
                "ARI" {
                    if (-not $ImportOnly) { Invoke-ARIScan @common -LogDirectory $logDir -TenantId $TenantId -SubscriptionId $SubscriptionId -InstallMissing:$InstallMissing }
                    Import-ARIResults @common
                }
            }
        } catch {
            Write-Step "  $tool failed: $($_.Exception.Message)" "Red"
            Add-ToolRun -Tool $tool -Status "Failed" -Description $script:ToolCatalog[$tool] -Message $_.Exception.Message
        }
    }
}

function Get-ToolRunRecord {
    param([Parameter(Mandatory)][string]$Tool)
    $script:ToolRuns | Where-Object { $_.Tool -eq $Tool } | Select-Object -First 1
}

function Save-ToolRunState {
    # Persists scan metadata (duration, exit code, message) so -ImportFrom can show it later.
    param([Parameter(Mandatory)][string]$RawFolder, [Parameter(Mandatory)][hashtable]$State)
    New-Item -ItemType Directory -Force -Path $RawFolder | Out-Null
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $RawFolder "_run.json") -Encoding utf8
}

function Get-ToolRunState {
    param([Parameter(Mandatory)][string]$RawFolder)
    $p = Join-Path $RawFolder "_run.json"
    if (Test-Path $p) { return (Read-JsonFile $p) }
    return $null
}

function Complete-ToolImport {
    # Registers the tool run after import, combining scan state with import results.
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$RawFolder,
        [int]$FindingCount = 0,
        [int]$Passed = -1,
        [int]$Failed = -1,
        [int]$Total = -1,
        [string]$Scope,
        [string]$Version,
        [object[]]$Reports = @(),
        [switch]$NoResults
    )
    $state = Get-ToolRunState $RawFolder
    $status   = "$(Get-PropValue $state 'Status')"
    $message  = "$(Get-PropValue $state 'Message')"
    $d        = Get-PropValue $state 'DurationSeconds'
    $duration = if ($d) { [double]$d } else { 0 }
    if (-not $Version) { $Version = "$(Get-PropValue $state 'Version')" }

    if ($NoResults) {
        if (-not $status -or $status -in @("Succeeded","PartiallySucceeded")) { $status = "Failed" }
        if (-not $message) { $message = "No results found in raw/$($Tool.ToLower())." }
    }
    elseif (-not $status) {
        $status = "Imported"
    }

    Add-ToolRun -Tool $Tool -Status $status -Description $script:ToolCatalog[$Tool] -Scope $Scope `
        -Message $message -Version $Version -DurationSeconds $duration `
        -Passed $Passed -Failed $Failed -Total $Total -FindingCount $FindingCount -Reports $Reports
}
