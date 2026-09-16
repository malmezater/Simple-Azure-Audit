#Requires -Version 7.0

<#
.SYNOPSIS
    Azure Environment Audit Script - merges built-in checks with Prowler, Maester,
    PSRule for Azure, Azure Governance Visualizer, WARA and Azure Resource Inventory into one report.

.DESCRIPTION
    Runs a review of an Azure subscription (plus its Entra ID tenant) and generates:
      - An interactive, self-contained HTML report (overview, prioritised issues,
        findings grouped per check, affected resources, tool coverage)
      - A CSV file with every finding for Excel / Power BI
      - audit-data.json with the merged, normalised data
      - The raw output of every external tool under raw\<tool>

    Built-in checks (-Tools Native):
      1. Security       - NSG rules, open ports, RBAC/Owner roles, classic admins
      2. Cost           - Unattached disks, stopped VMs, orphaned NICs/PublicIPs, empty RGs
      3. Infrastructure - VM disk encryption, Key Vault certificates, Storage soft-delete
      4. Compliance     - TLS versions, HTTPS enforcement, blob access, tagging, Key Vault protection
      5. Advisor        - All active Azure Advisor recommendations (requires Az.Advisor)

    External tools (all free / open source):
      Prowler   - CIS/NIST/ISO security posture for Azure and Entra ID (pip install prowler)
      Maester   - Entra ID, Conditional Access, EIDSCA, CISA tests (PowerShell module)
      PSRule    - PSRule for Azure, Well-Architected rules for all pillars (PowerShell module)
      AzGovViz  - RBAC, policy, orphaned resources, Defender plan coverage
      WARA      - Microsoft Well-Architected Reliability Assessment collector (PowerShell module)
      ARI       - Azure Resource Inventory Excel + network diagram (appendix, no findings)

    Tools that are not installed are reported as "Not installed" and skipped, unless
    -InstallMissing is used (PowerShell modules and AzGovViz are then installed for
    the current user; Prowler must be installed with pip).

    Source layout:
      - src\AuditCommon.ps1            (helpers, shared findings collection, tool-run register)
      - src\Checks.*.ps1               (built-in checks)
      - src\Tools.Common.ps1           (child-process runner, prerequisites, dispatcher)
      - src\Tools.<Tool>.ps1           (run + import adapter per external tool)
      - src\AuditReport.ps1            (New-AuditReport)
      - src\report-template.html       (HTML/CSS/JS of the report)

.PARAMETER TenantID
    Tenant to sign in to. Omitted = the active context is used.

.PARAMETER SubscriptionId
    One or more subscription IDs to audit (array or comma-separated). Omitted = you are prompted
    when several are available and can answer e.g. 2, 1-3, 1,3,5 or all.

.PARAMETER AllSubscriptions
    Audit every enabled subscription the account can see in the tenant, without prompting.

.PARAMETER OutputPath
    Folder where the run folder is created. Default: current directory.

.PARAMETER RequiredTags
    Comma-separated list of required tags to check for. Default: "Environment,Owner,CostCenter"

.PARAMETER Tools
    Which assessments to run: All, Native, Prowler, Maester, PSRule, AzGovViz, WARA, ARI. Default: All.

.PARAMETER ExcludeTools
    Tools to leave out when -Tools All is used, e.g. -ExcludeTools ARI,AzGovViz

.PARAMETER ManagementGroupId
    Management group AzGovViz starts from. Default: tenant root management group (= tenant ID).

.PARAMETER ToolsPath
    Folder for downloaded tool content (AzGovViz script, Maester tests). Default: .\tools next to this script.

.PARAMETER InstallMissing
    Install missing PowerShell modules (Maester, Pester, PSRule.Rules.Azure, WARA, AzureResourceInventory) and download AzGovViz.

.PARAMETER ImportFrom
    Rebuild the report from an existing run folder without signing in or scanning again.

.PARAMETER CustomerName
    Name shown as the report title. Default: the subscription name.

.PARAMETER PreparedBy
    Optional "prepared by" text shown in the report header (e.g. your company).

.PARAMETER SkipAdvisor
    Skip the Azure Advisor fetch in the built-in checks.

.PARAMETER OpenReport
    Open the HTML report automatically in the browser after the run.

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-..." -SubscriptionId "xxxxxxxx-..." -OutputPath "C:\Temp\AuditReports" -InstallMissing

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -Tools Native,Prowler,Maester -CustomerName "Contoso AB" -PreparedBy "Malmesater Cloud" -OpenReport

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-..." -AllSubscriptions -CustomerName "Contoso AB" -OpenReport

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -SubscriptionId "sub-id-1","sub-id-2" -OpenReport

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -ImportFrom "C:\Temp\AuditReports\AzureAudit_Prod_2026-09-16_08-12" -OpenReport

.NOTES
    All operations are read-only. Requires Reader on the subscription (Security Reader recommended),
    Global Reader in Entra ID for Maester, and Reader on the management group for AzGovViz.
#>

[CmdletBinding()]
param(
    [string]   $TenantID,
    [string[]] $SubscriptionId,
    [switch]   $AllSubscriptions,
    [string]   $OutputPath    = ".",
    [string]   $RequiredTags  = "Environment,Owner,CostCenter",
    [ValidateSet("All","Native","Prowler","Maester","PSRule","AzGovViz","WARA","ARI")]
    [string[]] $Tools         = @("All"),
    [ValidateSet("Native","Prowler","Maester","PSRule","AzGovViz","WARA","ARI")]
    [string[]] $ExcludeTools  = @(),
    [string]   $ManagementGroupId,
    [string]   $ToolsPath     = (Join-Path $PSScriptRoot "tools"),
    [string]   $ImportFrom,
    [string]   $CustomerName,
    [string]   $PreparedBy,
    [switch]   $InstallMissing,
    [switch]   $SkipAdvisor,
    [switch]   $OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"
$ScriptVersion         = "2.0.0"

function Stop-Audit {
    # $ErrorActionPreference is SilentlyContinue for the Az calls, which would also swallow 'throw'.
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "`nERROR: $Message" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────────────────────
# LOAD SUBMODULES
# ─────────────────────────────────────────────────────────────

$srcPath = Join-Path $PSScriptRoot "src"
# Loading must fail loudly: with SilentlyContinue a file that cannot be loaded (blocked by the
# execution policy, missing, or broken) would be skipped and surface later as "Invoke-XScan is not recognized".
$srcFiles = @(
    "AuditCommon.ps1",
    "Checks.Security.ps1", "Checks.Cost.ps1", "Checks.Infrastructure.ps1", "Checks.Compliance.ps1", "Checks.Advisor.ps1",
    "Tools.Common.ps1", "Tools.Prowler.ps1", "Tools.Maester.ps1", "Tools.PSRule.ps1", "Tools.AzGovViz.ps1", "Tools.WARA.ps1", "Tools.ARI.ps1",
    "AuditReport.ps1"
)
foreach ($file in $srcFiles) {
    $srcFile = Join-Path $srcPath $file
    if (-not (Test-Path -LiteralPath $srcFile)) { Stop-Audit "Missing file: $srcFile. Copy the complete src folder." }
    $ErrorActionPreference = "Stop"
    try {
        . $srcFile
    }
    catch {
        $hint = ""
        if ($IsWindows -and (Get-Item -LiteralPath $srcFile -Stream Zone.Identifier -ErrorAction SilentlyContinue)) {
            $hint = "`nThe file is marked as downloaded from the internet and the execution policy blocks it. Unblock the folder once:`n  Get-ChildItem '$PSScriptRoot' -Recurse -File | Unblock-File`nor start the audit with: pwsh -ExecutionPolicy Bypass -File .\Invoke-AzureAudit.ps1 ..."
        }
        Stop-Audit "Could not load src\$file`: $($_.Exception.Message)$hint"
    }
    finally {
        $ErrorActionPreference = "SilentlyContinue"
    }
}
$missingFunctions = @("Invoke-AuditTools", "Invoke-ProwlerScan", "Invoke-MaesterScan", "Invoke-PSRuleScan", "Invoke-AzGovVizScan",
    "Invoke-WARAScan", "Invoke-ARIScan", "New-AuditReport") | Where-Object { -not (Get-Command $_ -CommandType Function -ErrorAction SilentlyContinue) }
if ($missingFunctions) { Stop-Audit "The src files did not load completely (missing: $($missingFunctions -join ', ')). Copy the complete src folder again." }

$allTools = @("Native","Prowler","Maester","PSRule","AzGovViz","WARA","ARI")
$selectedTools = if ($Tools -contains "All") { $allTools } else { $allTools | Where-Object { $_ -in $Tools } }
$selectedTools = @($selectedTools | Where-Object { $_ -notin $ExcludeTools })
if ($selectedTools.Count -eq 0) { Stop-Audit "No tools selected. Check -Tools / -ExcludeTools." }

Write-Host @"

  ╔══════════════════════════════════════════════════════╗
  ║         Azure Environment Audit Script  v$($ScriptVersion.PadRight(12))║
  ║   Security · Identity · Reliability · Cost · Gov     ║
  ╚══════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────
# MODE 1: REBUILD REPORT FROM AN EXISTING RUN FOLDER
# ─────────────────────────────────────────────────────────────

if ($ImportFrom) {
    $runFolder = (Resolve-Path -LiteralPath $ImportFrom -ErrorAction Stop).Path
    $runInfoPath = Join-Path $runFolder "run.json"
    if (-not (Test-Path $runInfoPath)) { Stop-Audit "run.json not found in $runFolder - is this an Invoke-AzureAudit run folder?" }
    $runInfo = Read-JsonFile $runInfoPath

    $tenant   = "$(Get-PropValue $runInfo 'TenantId')"
    $scopeSubs = @(Get-PropValue $runInfo 'Subscriptions' | Where-Object { $_ } | ForEach-Object {
        [PSCustomObject]@{ Id = "$(Get-PropValue $_ 'Id')"; Name = "$(Get-PropValue $_ 'Name')" }
    })
    if ($scopeSubs.Count -eq 0) {   # run folders created before multi-subscription support
        $scopeSubs = @([PSCustomObject]@{ Id = "$(Get-PropValue $runInfo 'SubscriptionId')"; Name = "$(Get-PropValue $runInfo 'SubscriptionName')" })
    }
    $baseName = "$(Get-PropValue $runInfo 'BaseName')"
    if (-not $CustomerName) { $CustomerName = "$(Get-PropValue $runInfo 'CustomerName')" }
    if (-not $PreparedBy)   { $PreparedBy   = "$(Get-PropValue $runInfo 'PreparedBy')" }
    $script:AuditContext.Subscriptions = $scopeSubs
    $script:AuditContext.TenantId = $tenant

    Write-Host "`n  Rebuilding report from: $runFolder" -ForegroundColor White

    $nativeRaw = Join-Path (Join-Path $runFolder "raw") "native"
    $nativeFile = Join-Path $nativeRaw "findings.json"
    if ("Native" -in $selectedTools -and (Test-Path $nativeFile)) {
        $nativeItems = @(Read-JsonFile $nativeFile)
        Import-FindingObjects -Items $nativeItems
        Complete-ToolImport -Tool "Native" -RawFolder $nativeRaw -FindingCount $nativeItems.Count `
            -Scope (Get-ScopeLabel $scopeSubs) -Version $ScriptVersion
    }

    $present = @($selectedTools | Where-Object { $_ -ne "Native" -and (Test-Path (Join-Path (Join-Path $runFolder "raw") $_.ToLower())) })
    if ($present.Count -gt 0) {
        Invoke-AuditTools -Tools $present -RunFolder $runFolder -TenantId $tenant -SubscriptionIds $scopeSubs.Id -ImportOnly
    }
    $generatedAt = "$(Get-PropValue $runInfo 'StartedAt')"
}

# ─────────────────────────────────────────────────────────────
# MODE 2: SCAN
# ─────────────────────────────────────────────────────────────

else {
    $requiredModules = @("Az.Accounts")
    if ("Native" -in $selectedTools) {
        $requiredModules += @("Az.Compute", "Az.Network", "Az.Storage", "Az.KeyVault", "Az.Resources", "Az.Websites")
    }
    $missingModules = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
    if ($missingModules.Count -gt 0) {
        Stop-Audit "Missing required modules: $($missingModules -join ', '). Install with: Install-Module $($missingModules -join ', ') -Scope CurrentUser"
    }

    if (-not (Get-AzContext -ErrorAction SilentlyContinue) -or ($TenantID -and (Get-AzContext).Tenant.Id -ne $TenantID)) {
        Write-Host "`nSigning in to Azure..." -ForegroundColor Yellow
        if ($TenantID) { Connect-AzAccount -TenantId $TenantID | Out-Null }
        else { Connect-AzAccount | Out-Null }
    }

    # ── Subscription scope ───────────────────────────────────
    $subParams = @{ ErrorAction = "SilentlyContinue" }
    if ($TenantID) { $subParams.TenantId = $TenantID }
    $available = @(Get-AzSubscription @subParams | Where-Object { $_.State -eq "Enabled" } | Sort-Object Name)
    if ($available.Count -eq 0) { Stop-Audit "No enabled subscriptions were found for the signed-in account." }

    $requestedIds = @($SubscriptionId | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })
    if ($requestedIds.Count -gt 0) {
        $selected = @(foreach ($id in $requestedIds) {
            $match = $available | Where-Object { $_.Id -eq $id -or $_.Name -eq $id } | Select-Object -First 1
            if (-not $match) { Stop-Audit "Subscription '$id' was not found or is not enabled for this account." }
            $match
        })
    }
    elseif ($AllSubscriptions -or $available.Count -eq 1) {
        $selected = $available
    }
    else {
        Write-Host "`nSubscriptions available:`n" -ForegroundColor Yellow
        for ($i = 0; $i -lt $available.Count; $i++) {
            Write-Host ("  [{0,2}] {1}  ({2})" -f ($i + 1), $available[$i].Name, $available[$i].Id) -ForegroundColor White
        }
        $selected = $null
        while (-not $selected) {
            $answer = Read-Host "`nWhich subscriptions? (e.g. 2, 1-3, 1,3,5 or all)"
            $indexes = Resolve-SubscriptionSelection -Selection $answer -Count $available.Count
            if ($null -eq $indexes -or @($indexes).Count -eq 0) {
                Write-Host "Invalid selection. Use numbers between 1 and $($available.Count), ranges like 1-3, or 'all'." -ForegroundColor Red
            }
            else {
                $selected = @($indexes | ForEach-Object { $available[$_] })
            }
        }
    }

    # De-duplicate while keeping order
    $seenSubs = @{}
    $scopeSubs = @(foreach ($sub in $selected) {
        if ($seenSubs.ContainsKey($sub.Id)) { continue }
        $seenSubs[$sub.Id] = $true
        [PSCustomObject]@{ Id = $sub.Id; Name = $sub.Name }
    })

    Set-AzContext -SubscriptionId $scopeSubs[0].Id | Out-Null
    $ctx     = Get-AzContext
    $tenant  = $ctx.Tenant.Id
    $reqTags = $RequiredTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $script:AuditContext.Subscriptions = $scopeSubs
    $script:AuditContext.TenantId = $tenant

    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $scopeName = if ($scopeSubs.Count -eq 1) { $scopeSubs[0].Name }
                 elseif ($CustomerName) { "$CustomerName`_$($scopeSubs.Count)subs" }
                 else { "$($scopeSubs.Count)subscriptions" }
    $baseName  = "AzureAudit_$($scopeName -replace '[^a-zA-Z0-9]','_')_$timestamp"
    $runFolder = Join-Path (Resolve-Path $OutputPath).Path $baseName
    New-Item -ItemType Directory -Force -Path $runFolder | Out-Null
    $generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm"

    [ordered]@{
        BaseName = $baseName; TenantId = $tenant; Subscriptions = $scopeSubs
        SubscriptionName = $scopeSubs[0].Name; SubscriptionId = $scopeSubs[0].Id
        CustomerName = $CustomerName; PreparedBy = $PreparedBy; StartedAt = $generatedAt
        Tools = $selectedTools; ScriptVersion = $ScriptVersion; Account = "$($ctx.Account.Id)"
    } | ConvertTo-Json | Set-Content -Path (Join-Path $runFolder "run.json") -Encoding utf8

    Write-Host "`n  Tenant       : $tenant" -ForegroundColor Gray
    Write-Host "  Subscriptions: $($scopeSubs.Count)" -ForegroundColor White
    foreach ($sub in $scopeSubs) { Write-Host "    - $($sub.Name)  ($($sub.Id))" -ForegroundColor Gray }
    Write-Host "  Tools        : $($selectedTools -join ', ')" -ForegroundColor Gray
    Write-Host "  Run folder   : $runFolder" -ForegroundColor Gray
    Write-Host "  Start time   : $(Get-Date -Format 'HH:mm:ss')`n" -ForegroundColor Gray

    # ── Built-in checks ──────────────────────────────────────
    if ("Native" -in $selectedTools) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $n = 0
        foreach ($sub in $scopeSubs) {
            $n++
            Write-Host "`n══ Built-in checks $n/$($scopeSubs.Count): $($sub.Name) ══" -ForegroundColor Cyan
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            $script:AuditContext.SubscriptionId   = $sub.Id
            $script:AuditContext.SubscriptionName = $sub.Name

            Invoke-SecurityChecks       -SubscriptionId $sub.Id -SubscriptionName $sub.Name
            Invoke-CostChecks
            Invoke-InfrastructureChecks
            Invoke-ComplianceChecks     -RequiredTags $reqTags
            Invoke-AdvisorChecks        -SkipAdvisor:$SkipAdvisor
        }
        $script:AuditContext.SubscriptionId = ""
        $sw.Stop()

        $nativeRaw = Join-Path (Join-Path $runFolder "raw") "native"
        New-Item -ItemType Directory -Force -Path $nativeRaw | Out-Null
        $nativeFindings = (Get-AuditFindings).ToArray()
        ConvertTo-Json -InputObject $nativeFindings -Depth 4 | Set-Content -Path (Join-Path $nativeRaw "findings.json") -Encoding utf8
        Save-ToolRunState -RawFolder $nativeRaw -State @{ Status = "Succeeded"; DurationSeconds = $sw.Elapsed.TotalSeconds; Version = $ScriptVersion }
        Complete-ToolImport -Tool "Native" -RawFolder $nativeRaw -FindingCount $nativeFindings.Count -Scope (Get-ScopeLabel $scopeSubs) -Version $ScriptVersion
    }

    # ── External tools ───────────────────────────────────────
    $externalTools = @($selectedTools | Where-Object { $_ -ne "Native" })
    if ($externalTools.Count -gt 0) {
        Invoke-AuditTools -Tools $externalTools -RunFolder $runFolder -TenantId $tenant -SubscriptionIds $scopeSubs.Id `
            -ManagementGroupId $ManagementGroupId -ToolsPath $ToolsPath -InstallMissing:$InstallMissing
        # Tool runs may have switched the Az context; restore it for anything that follows.
        Set-AzContext -SubscriptionId $scopeSubs[0].Id -ErrorAction SilentlyContinue | Out-Null
    }
}

# ─────────────────────────────────────────────────────────────
# GENERATE REPORTS
# ─────────────────────────────────────────────────────────────

$htmlPath = Join-Path $runFolder "$baseName.html"
$csvPath  = Join-Path $runFolder "$baseName.csv"
$dataPath = Join-Path $runFolder "audit-data.json"
$findings = Get-AuditFindings
$toolRuns = Get-ToolRuns

$reportParams = @{
    Findings         = $findings
    ToolRuns         = $toolRuns
    Subscriptions    = $scopeSubs
    TenantId         = $tenant
    CsvPath          = $csvPath
    HtmlPath         = $htmlPath
    DataPath         = $dataPath
    CustomerName     = $CustomerName
    PreparedBy       = $PreparedBy
    ScriptVersion    = $ScriptVersion
}
if ($generatedAt) { $reportParams.GeneratedAt = $generatedAt }
New-AuditReport @reportParams

# ─────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────

$sevCount = @{}
foreach ($s in "Critical","High","Medium","Low","Info") {
    $sevCount[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count
}

Write-Host @"

  ╔══════════════════════════════════════════════════╗
  ║              AUDIT COMPLETE                      ║
  ╠══════════════════════════════════════════════════╣
  ║  Total     : $($findings.Count.ToString().PadRight(36))║
  ║  Critical  : $($sevCount.Critical.ToString().PadRight(36))║
  ║  High      : $($sevCount.High.ToString().PadRight(36))║
  ║  Medium    : $($sevCount.Medium.ToString().PadRight(36))║
  ║  Low       : $($sevCount.Low.ToString().PadRight(36))║
  ║  Info      : $($sevCount.Info.ToString().PadRight(36))║
  ╠══════════════════════════════════════════════════╣
"@ -ForegroundColor Cyan

foreach ($t in $toolRuns) {
    $line = "{0,-9} {1,-18} {2,6} findings" -f $t.Tool, $t.Status, $t.FindingCount
    $color = switch ($t.Status) { "Succeeded" { "Green" } "Imported" { "Green" } "PartiallySucceeded" { "Yellow" } "Failed" { "Red" } default { "DarkGray" } }
    Write-Host "  ║  $($line.PadRight(48))║" -ForegroundColor $color
}

Write-Host @"
  ╚══════════════════════════════════════════════════╝
  HTML   : $(Split-Path $htmlPath -Leaf)
  CSV    : $(Split-Path $csvPath -Leaf)
  Folder : $runFolder
"@ -ForegroundColor Cyan

if ($OpenReport) {
    Write-Host "`n  Opening report in the browser..." -ForegroundColor Green
    Start-Process $htmlPath
} elseif (-not $ImportFrom) {
    $open = Read-Host "`n  Open the HTML report in the browser? (y/n)"
    if ($open -eq "y") { Start-Process $htmlPath }
}
