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
    Subscription ID to run against. Omitted = you are prompted when several are available.

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
    .\Invoke-AzureAudit.ps1 -ImportFrom "C:\Temp\AuditReports\AzureAudit_Prod_2026-09-16_08-12" -OpenReport

.NOTES
    All operations are read-only. Requires Reader on the subscription (Security Reader recommended),
    Global Reader in Entra ID for Maester, and Reader on the management group for AzGovViz.
#>

[CmdletBinding()]
param(
    [string]   $TenantID,
    [string]   $SubscriptionId,
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

# ─────────────────────────────────────────────────────────────
# LOAD SUBMODULES
# ─────────────────────────────────────────────────────────────

$srcPath = Join-Path $PSScriptRoot "src"
foreach ($file in @(
    "AuditCommon.ps1",
    "Checks.Security.ps1", "Checks.Cost.ps1", "Checks.Infrastructure.ps1", "Checks.Compliance.ps1", "Checks.Advisor.ps1",
    "Tools.Common.ps1", "Tools.Prowler.ps1", "Tools.Maester.ps1", "Tools.PSRule.ps1", "Tools.AzGovViz.ps1", "Tools.WARA.ps1", "Tools.ARI.ps1",
    "AuditReport.ps1"
)) {
    . (Join-Path $srcPath $file)
}

$allTools = @("Native","Prowler","Maester","PSRule","AzGovViz","WARA","ARI")
$selectedTools = if ($Tools -contains "All") { $allTools } else { $allTools | Where-Object { $_ -in $Tools } }
$selectedTools = @($selectedTools | Where-Object { $_ -notin $ExcludeTools })
if ($selectedTools.Count -eq 0) { throw "No tools selected. Check -Tools / -ExcludeTools." }

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
    if (-not (Test-Path $runInfoPath)) { throw "run.json not found in $runFolder - is this an Invoke-AzureAudit run folder?" }
    $runInfo = Read-JsonFile $runInfoPath

    $subName  = "$(Get-PropValue $runInfo 'SubscriptionName')"
    $subId    = "$(Get-PropValue $runInfo 'SubscriptionId')"
    $tenant   = "$(Get-PropValue $runInfo 'TenantId')"
    $baseName = "$(Get-PropValue $runInfo 'BaseName')"
    if (-not $CustomerName) { $CustomerName = "$(Get-PropValue $runInfo 'CustomerName')" }
    if (-not $PreparedBy)   { $PreparedBy   = "$(Get-PropValue $runInfo 'PreparedBy')" }
    $script:AuditContext.SubscriptionId = $subId
    $script:AuditContext.SubscriptionName = $subName
    $script:AuditContext.TenantId = $tenant

    Write-Host "`n  Rebuilding report from: $runFolder" -ForegroundColor White

    $nativeRaw = Join-Path (Join-Path $runFolder "raw") "native"
    $nativeFile = Join-Path $nativeRaw "findings.json"
    if ("Native" -in $selectedTools -and (Test-Path $nativeFile)) {
        $nativeItems = @(Read-JsonFile $nativeFile)
        Import-FindingObjects -Items $nativeItems
        Complete-ToolImport -Tool "Native" -RawFolder $nativeRaw -FindingCount $nativeItems.Count `
            -Scope "Subscription: $subName" -Version $ScriptVersion
    }

    $present = @($selectedTools | Where-Object { $_ -ne "Native" -and (Test-Path (Join-Path (Join-Path $runFolder "raw") $_.ToLower())) })
    if ($present.Count -gt 0) {
        Invoke-AuditTools -Tools $present -RunFolder $runFolder -TenantId $tenant -SubscriptionId $subId -ImportOnly
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
        throw "Missing required modules: $($missingModules -join ', '). Install with: Install-Module $($missingModules -join ', ') -Scope CurrentUser"
    }

    if (-not (Get-AzContext -ErrorAction SilentlyContinue) -or ($TenantID -and (Get-AzContext).Tenant.Id -ne $TenantID)) {
        Write-Host "`nSigning in to Azure..." -ForegroundColor Yellow
        if ($TenantID) { Connect-AzAccount -TenantId $TenantID | Out-Null }
        else { Connect-AzAccount | Out-Null }
    }

    if ($SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
    else {
        $subParams = @{ ErrorAction = "SilentlyContinue" }
        if ($TenantID) { $subParams.TenantId = $TenantID }
        $subscriptions = @(Get-AzSubscription @subParams | Where-Object { $_.State -eq "Enabled" })

        if ($subscriptions.Count -eq 0) {
            throw "No enabled subscriptions were found for the signed-in account."
        }
        elseif ($subscriptions.Count -eq 1) {
            Set-AzContext -SubscriptionId $subscriptions[0].Id | Out-Null
        }
        else {
            Write-Host "`nMultiple subscriptions found. Please choose one:`n" -ForegroundColor Yellow
            for ($i = 0; $i -lt $subscriptions.Count; $i++) {
                Write-Host ("  [{0}] {1}  ({2})" -f ($i + 1), $subscriptions[$i].Name, $subscriptions[$i].Id) -ForegroundColor White
            }
            $choice = $null
            while (-not $choice) {
                $answer = Read-Host "`nEnter the number of the subscription to audit (1-$($subscriptions.Count))"
                if ($answer -match '^\d+$' -and [int]$answer -ge 1 -and [int]$answer -le $subscriptions.Count) {
                    $choice = $subscriptions[[int]$answer - 1]
                }
                else {
                    Write-Host "Invalid selection. Please enter a number between 1 and $($subscriptions.Count)." -ForegroundColor Red
                }
            }
            Set-AzContext -SubscriptionId $choice.Id | Out-Null
        }
    }

    $ctx     = Get-AzContext
    $subName = $ctx.Subscription.Name
    $subId   = $ctx.Subscription.Id
    $tenant  = $ctx.Tenant.Id
    $reqTags = $RequiredTags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $script:AuditContext.SubscriptionId = $subId
    $script:AuditContext.SubscriptionName = $subName
    $script:AuditContext.TenantId = $tenant

    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $baseName  = "AzureAudit_$($subName -replace '[^a-zA-Z0-9]','_')_$timestamp"
    $runFolder = Join-Path (Resolve-Path $OutputPath).Path $baseName
    New-Item -ItemType Directory -Force -Path $runFolder | Out-Null
    $generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm"

    [ordered]@{
        BaseName = $baseName; SubscriptionName = $subName; SubscriptionId = $subId; TenantId = $tenant
        CustomerName = $CustomerName; PreparedBy = $PreparedBy; StartedAt = $generatedAt
        Tools = $selectedTools; ScriptVersion = $ScriptVersion; Account = "$($ctx.Account.Id)"
    } | ConvertTo-Json | Set-Content -Path (Join-Path $runFolder "run.json") -Encoding utf8

    Write-Host "`n  Subscription : $subName" -ForegroundColor White
    Write-Host "  ID           : $subId"    -ForegroundColor Gray
    Write-Host "  Tenant       : $tenant"   -ForegroundColor Gray
    Write-Host "  Tools        : $($selectedTools -join ', ')" -ForegroundColor Gray
    Write-Host "  Run folder   : $runFolder" -ForegroundColor Gray
    Write-Host "  Start time   : $(Get-Date -Format 'HH:mm:ss')`n" -ForegroundColor Gray

    # ── Built-in checks ──────────────────────────────────────
    if ("Native" -in $selectedTools) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-SecurityChecks       -SubscriptionId $subId -SubscriptionName $subName
        Invoke-CostChecks
        Invoke-InfrastructureChecks
        Invoke-ComplianceChecks     -RequiredTags $reqTags
        Invoke-AdvisorChecks        -SkipAdvisor:$SkipAdvisor
        $sw.Stop()

        $nativeRaw = Join-Path (Join-Path $runFolder "raw") "native"
        New-Item -ItemType Directory -Force -Path $nativeRaw | Out-Null
        $nativeFindings = @(Get-AuditFindings)
        ConvertTo-Json -InputObject $nativeFindings -Depth 4 | Set-Content -Path (Join-Path $nativeRaw "findings.json") -Encoding utf8
        Save-ToolRunState -RawFolder $nativeRaw -State @{ Status = "Succeeded"; DurationSeconds = $sw.Elapsed.TotalSeconds; Version = $ScriptVersion }
        Complete-ToolImport -Tool "Native" -RawFolder $nativeRaw -FindingCount $nativeFindings.Count -Scope "Subscription: $subName" -Version $ScriptVersion
    }

    # ── External tools ───────────────────────────────────────
    $externalTools = @($selectedTools | Where-Object { $_ -ne "Native" })
    if ($externalTools.Count -gt 0) {
        Invoke-AuditTools -Tools $externalTools -RunFolder $runFolder -TenantId $tenant -SubscriptionId $subId `
            -ManagementGroupId $ManagementGroupId -ToolsPath $ToolsPath -InstallMissing:$InstallMissing
        # Tool runs may have switched the Az context; restore it for anything that follows.
        Set-AzContext -SubscriptionId $subId -ErrorAction SilentlyContinue | Out-Null
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
    SubscriptionName = $subName
    SubscriptionId   = $subId
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
