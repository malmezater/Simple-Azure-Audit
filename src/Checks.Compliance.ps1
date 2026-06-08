# ─────────────────────────────────────────────────────────────
# Checks.Compliance.ps1
# Compliance & Policy: HTTPS/TLS, blob access, App Services, Key Vault protection, tagging.
# ─────────────────────────────────────────────────────────────

function Invoke-ComplianceChecks {
    param(
        [Parameter(Mandatory)][string[]]$RequiredTags
    )

    Write-Section "4/5 - COMPLIANCE & POLICY"

    # Storage - HTTPS, TLS, public blob access
    Write-Step "Checking Storage Account configuration..."
    $storageAccounts = Get-AzStorageAccount
    foreach ($sa in $storageAccounts) {
        if (-not $sa.EnableHttpsTrafficOnly) {
            Add-Finding -Category "Compliance" -Severity "High" `
                -Resource $sa.StorageAccountName `
                -ResourceType "Storage Account" `
                -Finding "'Secure transfer required' (HTTPS only) is NOT enabled" `
                -Recommendation "Enable 'Secure transfer required' on all Storage Accounts."
        }

        $tlsVersion = $sa.MinimumTlsVersion
        if ($tlsVersion -notin @("TLS1_2","TLS1_3")) {
            Add-Finding -Category "Compliance" -Severity "High" `
                -Resource $sa.StorageAccountName `
                -ResourceType "Storage Account" `
                -Finding "Minimum TLS version is $tlsVersion (should be TLS 1.2+)" `
                -Recommendation "Set MinimumTlsVersion to TLS1_2. Microsoft retired TLS 1.0/1.1 on 31 Aug 2025."
        }

        if ($sa.AllowBlobPublicAccess -eq $true) {
            Add-Finding -Category "Compliance" -Severity "High" `
                -Resource $sa.StorageAccountName `
                -ResourceType "Storage Account" `
                -Finding "Public blob access (AllowBlobPublicAccess) is ENABLED" `
                -Recommendation "Disable AllowBlobPublicAccess unless anonymous read access is explicitly required."
        }
    }

    # App Services - HTTPS, TLS
    Write-Step "Checking App Services..."
    $webApps = Get-AzWebApp
    foreach ($appRef in $webApps) {
        try {
            $app = Get-AzWebApp -ResourceGroupName $appRef.ResourceGroup -Name $appRef.Name -ErrorAction Stop
            if (-not $app.HttpsOnly) {
                Add-Finding -Category "Compliance" -Severity "High" `
                    -Resource $app.Name `
                    -ResourceType "App Service" `
                    -Finding "HTTPS Only is NOT enabled on the App Service" `
                    -Recommendation "Enable HTTPS Only in the App Service configuration."
            }
            if ($app.SiteConfig.MinTlsVersion -notin @("1.2","1.3")) {
                Add-Finding -Category "Compliance" -Severity "High" `
                    -Resource $app.Name `
                    -ResourceType "App Service" `
                    -Finding "Minimum TLS version is $($app.SiteConfig.MinTlsVersion) (should be 1.2+)" `
                    -Recommendation "Set minTlsVersion to 1.2 in App Service General Settings."
            }
        } catch { }
    }

    # Key Vault - soft delete + purge protection
    Write-Step "Checking Key Vault protection..."
    $keyVaults = Get-AzKeyVault
    foreach ($kv in $keyVaults) {
        $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName
        if (-not $kvDetail.EnableSoftDelete) {
            Add-Finding -Category "Compliance" -Severity "High" `
                -Resource $kv.VaultName `
                -ResourceType "Key Vault" `
                -Finding "Soft Delete is NOT enabled" `
                -Recommendation "Enable soft delete (mandatory since 2021) and purge protection on all Key Vaults."
        }
        if (-not $kvDetail.EnablePurgeProtection) {
            Add-Finding -Category "Compliance" -Severity "Medium" `
                -Resource $kv.VaultName `
                -ResourceType "Key Vault" `
                -Finding "Purge Protection is NOT enabled" `
                -Recommendation "Enable purge protection to prevent permanent deletion during the retention period."
        }
    }

    # Tag check
    Write-Step "Checking resource tags (required: $($RequiredTags -join ', '))..."
    $allResources = Get-AzResource
    $untaggedCount = 0
    foreach ($res in $allResources) {
        $missing = $RequiredTags | Where-Object { (-not $res.Tags) -or (-not $res.Tags.ContainsKey($_)) }
        if ($missing.Count -gt 0) {
            $untaggedCount++
            Add-Finding -Category "Compliance" -Severity "Low" `
                -Resource "$($res.Name) ($($res.ResourceGroupName))" `
                -ResourceType $res.ResourceType `
                -Finding "Missing tags: $($missing -join ', ')" `
                -Recommendation "Add standard tags for cost tracking, ownership and environment classification."
        }
    }
    Write-Step "  $untaggedCount of $($allResources.Count) resources are missing at least one required tag." "Gray"
    Write-Step "  Compliance checks complete." "Gray"
}
