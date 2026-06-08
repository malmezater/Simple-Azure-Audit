# ─────────────────────────────────────────────────────────────
# Checks.Infrastructure.ps1
# Infrastructure health: VM disk encryption, Key Vault certificates, Storage soft-delete.
# ─────────────────────────────────────────────────────────────

function Invoke-InfrastructureChecks {
    Write-Section "3/5 - INFRASTRUCTURE HEALTH"

    # VM disk encryption
    Write-Step "Checking VM disk encryption..."
    foreach ($vm in (Get-AzVM)) {
        try {
            $enc = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction Stop
            if ($enc.OsVolumeEncrypted -ne "Encrypted") {
                Add-Finding -Category "Infrastructure" -Severity "High" `
                    -Resource "$($vm.Name) ($($vm.ResourceGroupName))" `
                    -ResourceType "Virtual Machine" `
                    -Finding "OS disk is NOT encrypted (Azure Disk Encryption)" `
                    -Recommendation "Enable Azure Disk Encryption (ADE) or Encryption at Host for all VMs."
            }
        } catch { }
    }

    # Key Vault - expiring certificates
    Write-Step "Checking Key Vault certificates..."
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
                    Add-Finding -Category "Infrastructure" -Severity $sev `
                        -Resource "$($kv.VaultName) > $($certRef.Name)" `
                        -ResourceType "KV certificate" `
                        -Finding "Certificate expires in $days days ($($expiry.ToString('yyyy-MM-dd')))" `
                        -Recommendation "Renew the certificate. Enable automatic renewal in the Key Vault policy."
                }
            }
        } catch { }
    }

    # Storage - blob soft delete
    Write-Step "Checking Storage soft-delete..."
    $storageAccounts = Get-AzStorageAccount
    foreach ($sa in $storageAccounts) {
        try {
            $blobSvc = Get-AzStorageBlobServiceProperty -StorageAccount $sa -ErrorAction Stop
            if (-not $blobSvc.DeleteRetentionPolicy.Enabled) {
                Add-Finding -Category "Infrastructure" -Severity "Medium" `
                    -Resource $sa.StorageAccountName `
                    -ResourceType "Storage Account" `
                    -Finding "Blob soft-delete is NOT enabled" `
                    -Recommendation "Enable soft-delete (at least 7 days) as protection against accidental deletion."
            }
        } catch { }
    }

    Write-Step "  Infrastructure checks complete." "Gray"
}
