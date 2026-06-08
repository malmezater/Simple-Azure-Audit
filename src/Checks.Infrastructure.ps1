# ─────────────────────────────────────────────────────────────
# Checks.Infrastructure.ps1
# Infrastrukturhälsa: VM-diskkryptering, Key Vault-certifikat, Storage soft-delete.
# ─────────────────────────────────────────────────────────────

function Invoke-InfrastructureChecks {
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
}
