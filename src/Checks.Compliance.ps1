# ─────────────────────────────────────────────────────────────
# Checks.Compliance.ps1
# Compliance & Policy: HTTPS/TLS, blob-åtkomst, App Services, Key Vault-skydd, taggning.
# ─────────────────────────────────────────────────────────────

function Invoke-ComplianceChecks {
    param(
        [Parameter(Mandatory)][string[]]$RequiredTags
    )

    Write-Section "4/5 · COMPLIANCE & POLICY"

    # Storage – HTTPS, TLS, publik blob-åtkomst
    Write-Step "Kontrollerar Storage Account-konfiguration..."
    $storageAccounts = Get-AzStorageAccount
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
    $keyVaults = Get-AzKeyVault
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
    Write-Step "Kontrollerar resurstaggar (obligatoriska: $($RequiredTags -join ', '))..."
    $allResources = Get-AzResource
    $taggedCount  = 0
    foreach ($res in $allResources) {
        $missing = $RequiredTags | Where-Object { (-not $res.Tags) -or (-not $res.Tags.ContainsKey($_)) }
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
}
