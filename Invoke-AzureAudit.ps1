#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Compute, Az.Network, Az.Storage, Az.KeyVault, Az.Resources, Az.Websites

<#
.SYNOPSIS
    Azure Environment Audit Script - Security, Cost, Infrastructure, Compliance & Advisor

.DESCRIPTION
    Runs a comprehensive review of an Azure subscription and generates:
      - An HTML report with color-coded findings
      - A CSV file for further analysis in Excel

    Checks:
      1. Security       - NSG rules, open ports, RBAC/Owner roles, classic admins
      2. Cost           - Unattached disks, stopped VMs, orphaned NICs/PublicIPs, empty RGs
      3. Infrastructure - VM disk encryption, Key Vault certificates, Storage soft-delete
      4. Compliance     - TLS versions, HTTPS enforcement, blob access, tagging, Key Vault protection
      5. Advisor        - All active Azure Advisor recommendations (requires Az.Advisor)

    The checks themselves are split across the src folder:
      - src\AuditCommon.ps1            (helper functions + shared findings collection)
      - src\Checks.Security.ps1        (Invoke-SecurityChecks)
      - src\Checks.Cost.ps1            (Invoke-CostChecks)
      - src\Checks.Infrastructure.ps1  (Invoke-InfrastructureChecks)
      - src\Checks.Compliance.ps1      (Invoke-ComplianceChecks)
      - src\Checks.Advisor.ps1         (Invoke-AdvisorChecks)
      - src\AuditReport.ps1            (New-AuditReport)

.PARAMETER SubscriptionId
    Subscription ID to run against. Omitted = the active context is used.

.PARAMETER OutputPath
    Folder to save the report and CSV in. Default: current directory.

.PARAMETER RequiredTags
    Comma-separated list of required tags to check for.
    Default: "Environment,Owner,CostCenter"

.PARAMETER SkipAdvisor
    Skip the Azure Advisor fetch (faster run).

.PARAMETER OpenReport
    Open the HTML report automatically in the browser after the run.

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutputPath "C:\AuditReports"

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -RequiredTags "Environment,Owner,Project" -SkipAdvisor -OpenReport

.NOTES
    Requires read access (Reader) at the subscription level.
    Running with Security Reader is recommended for full security checks.
#>

[CmdletBinding()]
param(
    [string]   $SubscriptionId,
    [string]   $OutputPath    = ".",
    [string]   $RequiredTags  = "Environment,Owner,CostCenter",
    [switch]   $SkipAdvisor,
    [switch]   $OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────
# LOAD SUBMODULES
# ─────────────────────────────────────────────────────────────

$srcPath = Join-Path $PSScriptRoot "src"
. (Join-Path $srcPath "AuditCommon.ps1")
. (Join-Path $srcPath "Checks.Security.ps1")
. (Join-Path $srcPath "Checks.Cost.ps1")
. (Join-Path $srcPath "Checks.Infrastructure.ps1")
. (Join-Path $srcPath "Checks.Compliance.ps1")
. (Join-Path $srcPath "Checks.Advisor.ps1")
. (Join-Path $srcPath "AuditReport.ps1")

# ─────────────────────────────────────────────────────────────
# INIT & AUTH
# ─────────────────────────────────────────────────────────────

Write-Host @"

  ╔══════════════════════════════════════════════════════╗
  ║         Azure Environment Audit Script               ║
  ║   Security · Cost · Infrastructure · Compliance      ║
  ╚══════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Write-Host "`nSigning in to Azure..." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
}

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

$ctx     = Get-AzContext
$subName = $ctx.Subscription.Name
$subId   = $ctx.Subscription.Id
$tenant  = $ctx.Tenant.Id
$reqTags = $RequiredTags -split "," | ForEach-Object { $_.Trim() }

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$baseName  = "AzureAudit_$($subName -replace '[^a-zA-Z0-9]','_')_$timestamp"
$htmlPath  = Join-Path $OutputPath "$baseName.html"
$csvPath   = Join-Path $OutputPath "$baseName.csv"

Write-Host "`n  Subscription : $subName" -ForegroundColor White
Write-Host "  ID           : $subId"    -ForegroundColor Gray
Write-Host "  Tenant       : $tenant"   -ForegroundColor Gray
Write-Host "  Start time   : $(Get-Date -Format 'HH:mm:ss')`n" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────
# RUN CHECKS
# ─────────────────────────────────────────────────────────────

Invoke-SecurityChecks       -SubscriptionId $subId -SubscriptionName $subName
Invoke-CostChecks
Invoke-InfrastructureChecks
Invoke-ComplianceChecks     -RequiredTags $reqTags
Invoke-AdvisorChecks        -SkipAdvisor:$SkipAdvisor

# ─────────────────────────────────────────────────────────────
# GENERATE REPORTS
# ─────────────────────────────────────────────────────────────

$findings = Get-AuditFindings

New-AuditReport `
    -Findings $findings `
    -SubscriptionName $subName `
    -SubscriptionId $subId `
    -TenantId $tenant `
    -CsvPath $csvPath `
    -HtmlPath $htmlPath

# ─────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────

$sevCount = @{
    Critical = ($findings | Where-Object Severity -eq "Critical").Count
    High     = ($findings | Where-Object Severity -eq "High").Count
    Medium   = ($findings | Where-Object Severity -eq "Medium").Count
    Low      = ($findings | Where-Object Severity -eq "Low").Count
    Info     = ($findings | Where-Object Severity -eq "Info").Count
}

Write-Host @"

  ╔══════════════════════════════════════════════════╗
  ║              AUDIT COMPLETE                      ║
  ╠══════════════════════════════════════════════════╣
  ║  Total     : $($findings.Count.ToString().PadRight(38))║
  ║  Critical  : $($sevCount.Critical.ToString().PadRight(38))║
  ║  High      : $($sevCount.High.ToString().PadRight(38))║
  ║  Medium    : $($sevCount.Medium.ToString().PadRight(38))║
  ║  Low       : $($sevCount.Low.ToString().PadRight(38))║
  ║  Info      : $($sevCount.Info.ToString().PadRight(38))║
  ╠══════════════════════════════════════════════════╣
  ║  HTML : $($(Split-Path $htmlPath -Leaf).PadRight(38))║
  ║  CSV  : $($(Split-Path $csvPath -Leaf).PadRight(38))║
  ╚══════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if ($OpenReport) {
    Write-Host "`n  Opening report in the browser..." -ForegroundColor Green
    Start-Process $htmlPath
} else {
    $open = Read-Host "`n  Open the HTML report in the browser? (y/n)"
    if ($open -eq "y") { Start-Process $htmlPath }
}
