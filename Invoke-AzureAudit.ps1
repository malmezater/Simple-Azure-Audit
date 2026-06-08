#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Compute, Az.Network, Az.Storage, Az.KeyVault, Az.Resources, Az.Websites

<#
.SYNOPSIS
    Azure Environment Audit Script – Säkerhet, Kostnad, Infrastruktur, Compliance & Advisor

.DESCRIPTION
    Kör en heltäckande kontroll av en Azure-prenumeration och genererar:
      - En HTML-rapport med färgkodade fynd
      - En CSV-fil för vidare analys i Excel

    Kontrollerar:
      1. Säkerhet      – NSG-regler, öppna portar, RBAC/Owner-roller, klassiska admins
      2. Kostnad       – Ohängda diskar, stoppade VMs, lösa NICs/PublicIPs, tomma RGs
      3. Infrastruktur – VM-diskkryptering, Key Vault-certifikat, Storage soft-delete
      4. Compliance    – TLS-versioner, HTTPS-tvång, blob-åtkomst, taggning, Key Vault-skydd
      5. Advisor       – Alla aktiva Azure Advisor-rekommendationer (kräver Az.Advisor)

    Själva kontrollerna ligger uppdelade i src-mappen:
      - src\AuditCommon.ps1            (hjälpfunktioner + delad fyndsamling)
      - src\Checks.Security.ps1        (Invoke-SecurityChecks)
      - src\Checks.Cost.ps1            (Invoke-CostChecks)
      - src\Checks.Infrastructure.ps1  (Invoke-InfrastructureChecks)
      - src\Checks.Compliance.ps1      (Invoke-ComplianceChecks)
      - src\Checks.Advisor.ps1         (Invoke-AdvisorChecks)
      - src\AuditReport.ps1            (New-AuditReport)

.PARAMETER SubscriptionId
    Prenumerations-ID att köra mot. Utelämnas = aktiv kontext används.

.PARAMETER OutputPath
    Mapp att spara rapport och CSV i. Standard: aktuell katalog.

.PARAMETER RequiredTags
    Kommaseparerad lista med obligatoriska taggar att kontrollera.
    Standard: "Environment,Owner,CostCenter"

.PARAMETER SkipAdvisor
    Hoppa över Azure Advisor-hämtning (snabbare körning).

.PARAMETER OpenReport
    Öppna HTML-rapporten automatiskt i webbläsaren efter körning.

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutputPath "C:\AuditReports"

.EXAMPLE
    .\Invoke-AzureAudit.ps1 -RequiredTags "Environment,Owner,Project" -SkipAdvisor -OpenReport

.NOTES
    Kräver läsrättigheter (Reader) på prenumerationsnivå.
    Rekommenderas att köra med Security Reader för fullständiga säkerhetskontroller.
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
# LADDA IN DELMODULER
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
  ║   Säkerhet · Kostnad · Infrastruktur · Compliance    ║
  ╚══════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Write-Host "`nLoggar in mot Azure..." -ForegroundColor Yellow
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

Write-Host "`n  Prenumeration : $subName" -ForegroundColor White
Write-Host "  ID            : $subId"    -ForegroundColor Gray
Write-Host "  Tenant        : $tenant"   -ForegroundColor Gray
Write-Host "  Starttid      : $(Get-Date -Format 'HH:mm:ss')`n" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────
# KÖR KONTROLLER
# ─────────────────────────────────────────────────────────────

Invoke-SecurityChecks       -SubscriptionId $subId -SubscriptionName $subName
Invoke-CostChecks
Invoke-InfrastructureChecks
Invoke-ComplianceChecks     -RequiredTags $reqTags
Invoke-AdvisorChecks        -SkipAdvisor:$SkipAdvisor

# ─────────────────────────────────────────────────────────────
# GENERERA RAPPORTER
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
# SAMMANFATTNING
# ─────────────────────────────────────────────────────────────

$sevCount = @{
    Critical = ($findings | Where-Object Allvarlighet -eq "Critical").Count
    High     = ($findings | Where-Object Allvarlighet -eq "High").Count
    Medium   = ($findings | Where-Object Allvarlighet -eq "Medium").Count
    Low      = ($findings | Where-Object Allvarlighet -eq "Low").Count
    Info     = ($findings | Where-Object Allvarlighet -eq "Info").Count
}

Write-Host @"

  ╔══════════════════════════════════════════════════╗
  ║              AUDIT KLAR                          ║
  ╠══════════════════════════════════════════════════╣
  ║  Totalt    : $($findings.Count.ToString().PadRight(38))║
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
    Write-Host "`n  Öppnar rapport i webbläsaren..." -ForegroundColor Green
    Start-Process $htmlPath
} else {
    $open = Read-Host "`n  Öppna HTML-rapporten i webbläsaren? (j/n)"
    if ($open -eq "j") { Start-Process $htmlPath }
}