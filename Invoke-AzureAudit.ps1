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
# HELPERS
# ─────────────────────────────────────────────────────────────

function Write-Step { param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "  $Msg" -ForegroundColor $Color }

function Write-Section { param([string]$Msg)
    Write-Host "`n[$Msg]" -ForegroundColor Magenta }

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param(
        [ValidateSet("Säkerhet","Kostnad","Infrastruktur","Compliance","Advisor")][string]$Category,
        [ValidateSet("Critical","High","Medium","Low","Info")][string]$Severity,
        [string]$Resource,
        [string]$ResourceType,
        [string]$Finding,
        [string]$Recommendation
    )
    $findings.Add([PSCustomObject]@{
        Kategori       = $Category
        Allvarlighet   = $Severity
        Resurs         = $Resource
        Resurstyp      = $ResourceType
        Fynd           = $Finding
        Rekommendation = $Recommendation
        Tidstämpel     = (Get-Date -Format "yyyy-MM-dd HH:mm")
    })
}

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
# 1. SÄKERHET
# ─────────────────────────────────────────────────────────────

Write-Section "1/5 · SÄKERHET"

# NSG – farliga inbound-regler
Write-Step "Kontrollerar Network Security Groups..."
$nsgs = Get-AzNetworkSecurityGroup
$dangerousPorts = @("22","3389","1433","3306","5432","23","21","445","5985","5986")

foreach ($nsg in $nsgs) {
    foreach ($rule in $nsg.SecurityRules | Where-Object { $_.Direction -eq "Inbound" -and $_.Access -eq "Allow" }) {
        $fromInternet = ($rule.SourceAddressPrefix -in @("*","Internet","0.0.0.0/0","Any"))
        if (-not $fromInternet) { continue }

        $portStr = if ($rule.DestinationPortRange) { $rule.DestinationPortRange }
                   else { ($rule.DestinationPortRanges -join ", ") }

        $isWildcard = ($portStr -eq "*")
        $matchPort  = $dangerousPorts | Where-Object { $portStr -match "\b$_\b" }

        if ($isWildcard -or $matchPort) {
            $sev = if ($portStr -match "\b3389\b|\b22\b") { "Critical" }
                   elseif ($isWildcard)                    { "Critical" }
                   else                                    { "High" }

            Add-Finding -Category "Säkerhet" -Severity $sev `
                -Resource "$($nsg.Name) › $($rule.Name)" `
                -ResourceType "NSG-regel" `
                -Finding "Inbound port $portStr öppen mot Internet (0.0.0.0/0)" `
                -Recommendation "Begränsa källan till specifika IP-intervall, eller använd Azure Bastion/VPN i stället för direkt RDP/SSH-exponering."
        }
    }
}
Write-Step "  $($nsgs.Count) NSG:er granskade." "Gray"

# Lösa oassocierade Public IPs
Write-Step "Kontrollerar Public IP-adresser..."
$pubIPs = Get-AzPublicIpAddress
foreach ($pip in $pubIPs) {
    if (-not $pip.IpConfiguration) {
        Add-Finding -Category "Säkerhet" -Severity "Low" `
            -Resource $pip.Name `
            -ResourceType "Public IP" `
            -Finding "Ej associerad Public IP ($($pip.IpAddress ?? 'ej allokerad'))" `
            -Recommendation "Ta bort oanvända Public IPs för att minska attackytan och kostnaderna."
    }
}

# RBAC – för många Owner på prenumerationsnivå
Write-Step "Kontrollerar RBAC-tilldelningar..."
$ownerAssignments = Get-AzRoleAssignment -RoleDefinitionName "Owner" |
                    Where-Object { $_.Scope -eq "/subscriptions/$subId" }

if ($ownerAssignments.Count -gt 3) {
    Add-Finding -Category "Säkerhet" -Severity "High" `
        -Resource "Prenumeration: $subName" `
        -ResourceType "RBAC" `
        -Finding "$($ownerAssignments.Count) Owner-roller på prenumerationsnivå (rekommenderat ≤3)" `
        -Recommendation "Följ minsta-privilegs-principen. Använd Contributor/Reader där Owner inte krävs."
}

# Klassiska administratörer (legacy)
$classicAdmins = Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -match "CoAdministrator|ServiceAdministrator" }
foreach ($admin in $classicAdmins) {
    Add-Finding -Category "Säkerhet" -Severity "Medium" `
        -Resource ($admin.SignInName ?? $admin.DisplayName ?? "Okänd") `
        -ResourceType "Klassisk admin" `
        -Finding "Legacy-rollen '$($admin.RoleDefinitionName)' är fortfarande tilldelad" `
        -Recommendation "Migrera till Azure RBAC. Klassiska administratörsroller är deprecerade av Microsoft."
}

Write-Step "  Säkerhetskontroller klara." "Gray"

# ─────────────────────────────────────────────────────────────
# 2. KOSTNAD & OANVÄNDA RESURSER
# ─────────────────────────────────────────────────────────────

Write-Section "2/5 · KOSTNAD & OANVÄNDA RESURSER"

# Ohängda managed disks
Write-Step "Kontrollerar ohängda diskar..."
$unattachedDisks = Get-AzDisk | Where-Object { $_.DiskState -eq "Unattached" }
foreach ($disk in $unattachedDisks) {
    Add-Finding -Category "Kostnad" -Severity "Medium" `
        -Resource "$($disk.Name) ($($disk.ResourceGroupName))" `
        -ResourceType "Managed Disk" `
        -Finding "Ohängd disk: $($disk.DiskSizeGB) GB, SKU: $($disk.Sku.Name)" `
        -Recommendation "Radera eller snapshoota ohängda diskar. En disk på 1 TB P30 kostar ~450 SEK/mån i onödan."
}
Write-Step "  $($unattachedDisks.Count) ohängda diskar hittade." "Gray"

# Stoppade/deallocated VMs
Write-Step "Kontrollerar VM-status..."
$allVMs = Get-AzVM -Status
foreach ($vm in $allVMs) {
    $state = ($vm.Statuses | Where-Object { $_.Code -match "^PowerState/" }).DisplayStatus
    if ($state -in @("VM stopped","VM deallocated")) {
        Add-Finding -Category "Kostnad" -Severity "Low" `
            -Resource $vm.Name `
            -ResourceType "Virtual Machine" `
            -Finding "VM är stoppad ($state) – lagringskostnader löper fortfarande" `
            -Recommendation "Radera VM om den inte behövs. Deallocated VM betalar inte compute, men diskarna kostar."
    }
}

# Lösa NICs
Write-Step "Kontrollerar oanvända nätverksgränssnitt..."
$looseNICs = Get-AzNetworkInterface | Where-Object { -not $_.VirtualMachine }
foreach ($nic in $looseNICs) {
    Add-Finding -Category "Kostnad" -Severity "Low" `
        -Resource "$($nic.Name) ($($nic.ResourceGroupName))" `
        -ResourceType "Nätverksgränssnitt" `
        -Finding "NIC är inte kopplad till någon VM" `
        -Recommendation "Ta bort lösa NIC:ar för att hålla miljön ren."
}

# Tomma resursgrupper
Write-Step "Kontrollerar tomma resursgrupper..."
$emptyRGs = Get-AzResourceGroup | Where-Object {
    (Get-AzResource -ResourceGroupName $_.ResourceGroupName).Count -eq 0
}
foreach ($rg in $emptyRGs) {
    Add-Finding -Category "Kostnad" -Severity "Info" `
        -Resource $rg.ResourceGroupName `
        -ResourceType "Resursgrupp" `
        -Finding "Tom resursgrupp utan resurser" `
        -Recommendation "Radera tomma resursgrupper för att hålla prenumerationen strukturerad."
}

Write-Step "  Kostnadskontroller klara." "Gray"

# ─────────────────────────────────────────────────────────────
# 3. INFRASTRUKTURHÄLSA
# ─────────────────────────────────────────────────────────────

Write-Section "3/5 · INFRASTRUKTURHÄLSA"

# VM-diskkryptering
Write-Step "Kontrollerar VM-diskkryptering..."
foreach ($vm in (Get-AzVM)) {
    try {
        $enc = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction Stop
        if ($enc.OsVolumeEncrypted -ne "Encrypted") {
            Add-Finding -Category "Infrastruktur" -Severity "High" `
                -Resource "$($vm.Name) ($($vm.ResourceGroupName))" `
                -ResourceType "Virtual Machine" `
                -Finding "OS-disk är INTE krypterad (Azure Disk Encryption)" `
                -Recommendation "Aktivera Azure Disk Encryption (ADE) eller Encryption at Host för alla VM:ar."
        }
    } catch { }
}

# Key Vault – certifikat som löper ut
Write-Step "Kontrollerar Key Vault-certifikat..."
$keyVaults = Get-AzKeyVault
foreach ($kv in $keyVaults) {
    try {
        $certs = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction Stop
        foreach ($certRef in $certs) {
            $cert  = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -Name $certRef.Name
            $expiry = $cert.Certificate.NotAfter
            $days   = [math]::Round(($expiry - (Get-Date)).TotalDays)
            if ($days -le 90) {
                $sev = if ($days -le 14) { "Critical" } elseif ($days -le 30) { "High" } else { "Medium" }
                Add-Finding -Category "Infrastruktur" -Severity $sev `
                    -Resource "$($kv.VaultName) › $($certRef.Name)" `
                    -ResourceType "KV-certifikat" `
                    -Finding "Certifikat löper ut om $days dagar ($($expiry.ToString('yyyy-MM-dd')))" `
                    -Recommendation "Förnya certifikatet. Aktivera automatisk förnyelse i Key Vault-principen."
            }
        }
    } catch { }
}

# Storage – blob soft delete
Write-Step "Kontrollerar Storage soft-delete..."
$storageAccounts = Get-AzStorageAccount
foreach ($sa in $storageAccounts) {
    try {
        $blobSvc = Get-AzStorageBlobServiceProperty -StorageAccount $sa -ErrorAction Stop
        if (-not $blobSvc.DeleteRetentionPolicy.Enabled) {
            Add-Finding -Category "Infrastruktur" -Severity "Medium" `
                -Resource $sa.StorageAccountName `
                -ResourceType "Storage Account" `
                -Finding "Blob soft-delete är INTE aktiverat" `
                -Recommendation "Aktivera soft-delete (minst 7 dagar) som skydd mot oavsiktlig radering."
        }
    } catch { }
}

Write-Step "  Infrastrukturkontroller klara." "Gray"

# ─────────────────────────────────────────────────────────────
# 4. COMPLIANCE & POLICY
# ─────────────────────────────────────────────────────────────

Write-Section "4/5 · COMPLIANCE & POLICY"

# Storage – HTTPS, TLS, publik blob-åtkomst
Write-Step "Kontrollerar Storage Account-konfiguration..."
foreach ($sa in $storageAccounts) {
    if (-not $sa.EnableHttpsTrafficOnly) {
        Add-Finding -Category "Compliance" -Severity "High" `
            -Resource $sa.StorageAccountName `
            -ResourceType "Storage Account" `
            -Finding "'Secure transfer required' (HTTPS only) är INTE aktiverat" `
            -Recommendation "Aktivera 'Secure transfer required' på alla Storage Accounts."
    }

    $tlsVersion = $sa.MinimumTlsVersion
    if ($tlsVersion -notin @("TLS1_2","TLS1_3")) {
        Add-Finding -Category "Compliance" -Severity "High" `
            -Resource $sa.StorageAccountName `
            -ResourceType "Storage Account" `
            -Finding "Lägsta TLS-version är $tlsVersion (ska vara TLS 1.2+)" `
            -Recommendation "Sätt MinimumTlsVersion till TLS1_2. Microsoft fasade ut TLS 1.0/1.1 den 31 aug 2025."
    }

    if ($sa.AllowBlobPublicAccess -eq $true) {
        Add-Finding -Category "Compliance" -Severity "High" `
            -Resource $sa.StorageAccountName `
            -ResourceType "Storage Account" `
            -Finding "Publik blobaåtkomst (AllowBlobPublicAccess) är AKTIVERAD" `
            -Recommendation "Inaktivera AllowBlobPublicAccess om inte explicit anonym läsning krävs."
    }
}

# App Services – HTTPS, TLS, autentisering
Write-Step "Kontrollerar App Services..."
$webApps = Get-AzWebApp
foreach ($appRef in $webApps) {
    try {
        $app = Get-AzWebApp -ResourceGroupName $appRef.ResourceGroup -Name $appRef.Name -ErrorAction Stop
        if (-not $app.HttpsOnly) {
            Add-Finding -Category "Compliance" -Severity "High" `
                -Resource $app.Name `
                -ResourceType "App Service" `
                -Finding "HTTPS Only är INTE aktiverat på App Service" `
                -Recommendation "Aktivera HTTPS Only i App Service-konfigurationen."
        }
        if ($app.SiteConfig.MinTlsVersion -notin @("1.2","1.3")) {
            Add-Finding -Category "Compliance" -Severity "High" `
                -Resource $app.Name `
                -ResourceType "App Service" `
                -Finding "Lägsta TLS-version är $($app.SiteConfig.MinTlsVersion) (ska vara 1.2+)" `
                -Recommendation "Sätt minTlsVersion till 1.2 i App Service General Settings."
        }
    } catch { }
}

# Key Vault – soft delete + purge protection
Write-Step "Kontrollerar Key Vault-skydd..."
foreach ($kv in $keyVaults) {
    $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName
    if (-not $kvDetail.EnableSoftDelete) {
        Add-Finding -Category "Compliance" -Severity "High" `
            -Resource $kv.VaultName `
            -ResourceType "Key Vault" `
            -Finding "Soft Delete är INTE aktiverat" `
            -Recommendation "Aktivera soft delete (obligatoriskt sedan 2021) och purge protection på alla Key Vaults."
    }
    if (-not $kvDetail.EnablePurgeProtection) {
        Add-Finding -Category "Compliance" -Severity "Medium" `
            -Resource $kv.VaultName `
            -ResourceType "Key Vault" `
            -Finding "Purge Protection är INTE aktiverat" `
            -Recommendation "Aktivera purge protection för att förhindra permanent radering under kvarhållningsperioden."
    }
}

# Taggkontroll
Write-Step "Kontrollerar resurstaggar (obligatoriska: $($reqTags -join ', '))..."
$allResources = Get-AzResource
$taggedCount  = 0
foreach ($res in $allResources) {
    $missing = $reqTags | Where-Object { (-not $res.Tags) -or (-not $res.Tags.ContainsKey($_)) }
    if ($missing.Count -gt 0) {
        $taggedCount++
        Add-Finding -Category "Compliance" -Severity "Low" `
            -Resource "$($res.Name) ($($res.ResourceGroupName))" `
            -ResourceType $res.ResourceType `
            -Finding "Saknar taggar: $($missing -join ', ')" `
            -Recommendation "Lägg till standardtaggar för kostnadsspårning, ägande och miljöklassificering."
    }
}
Write-Step "  $taggedCount av $($allResources.Count) resurser saknar minst en obligatorisk tagg." "Gray"
Write-Step "  Compliance-kontroller klara." "Gray"

# ─────────────────────────────────────────────────────────────
# 5. AZURE ADVISOR
# ─────────────────────────────────────────────────────────────

Write-Section "5/5 · AZURE ADVISOR"

if ($SkipAdvisor) {
    Write-Step "Hoppade över Advisor (parametern -SkipAdvisor angiven)." "DarkGray"
} else {
    Write-Step "Hämtar Azure Advisor-rekommendationer..."
    try {
        $advisorRecs = Get-AzAdvisorRecommendation -ErrorAction Stop
        Write-Step "  $($advisorRecs.Count) rekommendationer hittades." "Gray"

        foreach ($rec in $advisorRecs) {
            $sev = switch ($rec.Impact) {
                "High"   { "High" }
                "Medium" { "Medium" }
                "Low"    { "Low" }
                default  { "Info" }
            }
            $cat = "Advisor ($($rec.Category))"
            Add-Finding -Category "Advisor" -Severity $sev `
                -Resource ($rec.ImpactedValue ?? $rec.ImpactedField ?? "N/A") `
                -ResourceType ($rec.ImpactedField ?? "Okänd") `
                -Finding ($rec.ShortDescription.Problem ?? "Se Azure Advisor") `
                -Recommendation ($rec.ShortDescription.Solution ?? "Se Azure Advisor-portalen")
        }
    } catch {
        Write-Step "  Kunde inte hämta Advisor-data. Kontrollera att Az.Advisor-modulen är installerad." "DarkYellow"
    }
}

# ─────────────────────────────────────────────────────────────
# EXPORTERA CSV
# ─────────────────────────────────────────────────────────────

Write-Section "GENERERAR RAPPORTER"
Write-Step "Sparar CSV..."
$findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Step "  $csvPath" "Gray"

# ─────────────────────────────────────────────────────────────
# GENERERA HTML-RAPPORT
# ─────────────────────────────────────────────────────────────

Write-Step "Bygger HTML-rapport..."

$sevOrder = @{ "Critical"=0; "High"=1; "Medium"=2; "Low"=3; "Info"=4 }
$sorted   = $findings | Sort-Object { $sevOrder[$_.Allvarlighet] }

$sevCount = @{
    Critical = ($findings | Where-Object Allvarlighet -eq "Critical").Count
    High     = ($findings | Where-Object Allvarlighet -eq "High").Count
    Medium   = ($findings | Where-Object Allvarlighet -eq "Medium").Count
    Low      = ($findings | Where-Object Allvarlighet -eq "Low").Count
    Info     = ($findings | Where-Object Allvarlighet -eq "Info").Count
}

$catStats = $findings | Group-Object Kategori | Sort-Object Count -Descending

$badgeColors = @{
    "Critical" = "#c0392b"; "High" = "#e67e22"
    "Medium"   = "#d4ac0d"; "Low"  = "#27ae60"; "Info" = "#2980b9"
}

function Get-Badge($sev) {
    $c = $badgeColors[$sev] ?? "#95a5a6"
    "<span style='background:$c;color:#fff;padding:2px 10px;border-radius:12px;font-size:.76rem;font-weight:700;white-space:nowrap'>$sev</span>"
}

$tableRows = ($sorted | ForEach-Object {
    $badge = Get-Badge $_.Allvarlighet
    "<tr>
      <td>$($_.Kategori)</td>
      <td>$badge</td>
      <td style='font-size:.82rem;color:#555'>$($_.Resurstyp)</td>
      <td style='font-family:Consolas,monospace;font-size:.8rem;color:#0078d4'>$([System.Web.HttpUtility]::HtmlEncode($_.Resurs))</td>
      <td>$([System.Web.HttpUtility]::HtmlEncode($_.Fynd))</td>
      <td style='font-size:.82rem;color:#555'>$([System.Web.HttpUtility]::HtmlEncode($_.Rekommendation))</td>
    </tr>"
}) -join "`n"

$catRows = ($catStats | ForEach-Object {
    "<tr><td>$($_.Name)</td><td><strong>$($_.Count)</strong></td></tr>"
}) -join "`n"

# Severity-bar width
$total = [math]::Max($findings.Count, 1)
function Get-Pct($n) { [math]::Round($n / $total * 100, 1) }

$html = @"
<!DOCTYPE html>
<html lang="sv">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure Audit – $subName</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f2f5;color:#2c3e50;font-size:14px}
  a{color:#0078d4}
  header{background:linear-gradient(135deg,#0078d4 0%,#004e8c 100%);color:#fff;padding:2rem 2.5rem}
  header h1{font-size:1.7rem;font-weight:700;letter-spacing:-.3px}
  header p{opacity:.85;margin-top:.4rem;font-size:.9rem}
  .container{max-width:1400px;margin:2rem auto;padding:0 1.5rem}
  .grid-5{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}
  .card{background:#fff;border-radius:10px;padding:1.2rem 1rem;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.07);border-top:4px solid #dee}
  .card.c-crit{border-color:#c0392b}.card.c-high{border-color:#e67e22}
  .card.c-med{border-color:#d4ac0d}.card.c-low{border-color:#27ae60}.card.c-info{border-color:#2980b9}
  .card .num{font-size:2rem;font-weight:800;line-height:1}
  .card.c-crit .num{color:#c0392b}.card.c-high .num{color:#e67e22}
  .card.c-med .num{color:#d4ac0d}.card.c-low .num{color:#27ae60}.card.c-info .num{color:#2980b9}
  .card .lbl{font-size:.78rem;color:#7f8c8d;margin-top:.3rem;text-transform:uppercase;letter-spacing:.5px}
  .panel{background:#fff;border-radius:10px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 2px 8px rgba(0,0,0,.07)}
  .panel h2{font-size:1rem;font-weight:700;color:#0078d4;border-bottom:2px solid #e8f0fe;padding-bottom:.6rem;margin-bottom:1rem}
  table{width:100%;border-collapse:collapse}
  th{background:#f8f9fa;text-align:left;padding:.6rem .8rem;font-size:.82rem;font-weight:700;color:#555;border-bottom:2px solid #ddd}
  td{padding:.6rem .8rem;border-bottom:1px solid #f2f2f2;vertical-align:top;line-height:1.4}
  tr:hover td{background:#fafbff}
  .bar-wrap{background:#eee;border-radius:6px;height:8px;margin-top:.3rem}
  .bar{height:8px;border-radius:6px}
  footer{text-align:center;padding:1.5rem;color:#aaa;font-size:.8rem}
  @media print{
    body{background:#fff}
    header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .panel{box-shadow:none;border:1px solid #ddd}
  }
</style>
</head>
<body>
<header>
  <h1>🔍 Azure Environment Audit</h1>
  <p>
    <strong>$subName</strong> &nbsp;|&nbsp; $subId<br>
    Tenant: $tenant &nbsp;|&nbsp; Genererad: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
  </p>
</header>

<div class="container">

  <div class="grid-5">
    <div class="card c-crit"><div class="num">$($sevCount.Critical)</div><div class="lbl">Critical</div></div>
    <div class="card c-high"><div class="num">$($sevCount.High)</div><div class="lbl">High</div></div>
    <div class="card c-med" ><div class="num">$($sevCount.Medium)</div><div class="lbl">Medium</div></div>
    <div class="card c-low" ><div class="num">$($sevCount.Low)</div><div class="lbl">Low</div></div>
    <div class="card c-info"><div class="num">$($sevCount.Info)</div><div class="lbl">Info</div></div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 2fr;gap:1.5rem;margin-bottom:1.5rem">
    <div class="panel">
      <h2>📊 Fynd per kategori</h2>
      <table>
        <thead><tr><th>Kategori</th><th>Antal</th></tr></thead>
        <tbody>$catRows</tbody>
      </table>
    </div>
    <div class="panel">
      <h2>📈 Fördelning per allvarlighet</h2>
      <table>
        <thead><tr><th>Nivå</th><th>Antal</th><th style="width:40%">Andel</th></tr></thead>
        <tbody>
          <tr><td>Critical</td><td>$($sevCount.Critical)</td><td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Critical)%;background:#c0392b"></div></div></td></tr>
          <tr><td>High</td>    <td>$($sevCount.High)</td>    <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.High)%;background:#e67e22"></div></div></td></tr>
          <tr><td>Medium</td>  <td>$($sevCount.Medium)</td>  <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Medium)%;background:#d4ac0d"></div></div></td></tr>
          <tr><td>Low</td>     <td>$($sevCount.Low)</td>     <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Low)%;background:#27ae60"></div></div></td></tr>
          <tr><td>Info</td>    <td>$($sevCount.Info)</td>    <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Info)%;background:#2980b9"></div></div></td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <h2>📋 Alla fynd ($($findings.Count) totalt) – sorterade efter allvarlighet</h2>
    <table>
      <thead>
        <tr>
          <th style="width:100px">Kategori</th>
          <th style="width:90px">Nivå</th>
          <th style="width:120px">Resurstyp</th>
          <th style="width:200px">Resurs</th>
          <th>Fynd</th>
          <th style="width:250px">Rekommendation</th>
        </tr>
      </thead>
      <tbody>
        $tableRows
      </tbody>
    </table>
  </div>

</div>

<footer>
  Azure Audit Script &nbsp;·&nbsp; $(Get-Date -Format 'yyyy-MM-dd') &nbsp;·&nbsp;
  Totalt $($findings.Count) fynd &nbsp;·&nbsp;
  <a href="$(Split-Path $csvPath -Leaf)">Ladda ned CSV</a>
</footer>
</body>
</html>
"@

Add-Type -AssemblyName System.Web
$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Step "  $htmlPath" "Gray"

# ─────────────────────────────────────────────────────────────
# SAMMANFATTNING
# ─────────────────────────────────────────────────────────────

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
