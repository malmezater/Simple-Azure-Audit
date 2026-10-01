# ─────────────────────────────────────────────────────────────
# Checks.Infrastructure.ps1
# Infrastructure health: VM disk encryption, Key Vault certificates, secrets/keys without
# expiry, Storage soft-delete.
# ─────────────────────────────────────────────────────────────

function Invoke-InfrastructureChecks {
    Write-Section "3/5 - INFRASTRUCTURE HEALTH"

    # VM disk encryption
    Write-Step "Checking VM disk encryption..."
    foreach ($vm in (Get-AzVM)) {
        try {
            # Encryption at host or a disk encryption set counts as encrypted, not just ADE.
            $encAtHost = [bool](Get-PropValue $vm @("SecurityProfile","EncryptionAtHost"))
            $des       = Get-PropValue $vm @("StorageProfile","OsDisk","ManagedDisk","DiskEncryptionSet","Id")
            if ($encAtHost -or $des) { continue }

            $enc = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction Stop
            if ($enc.OsVolumeEncrypted -ne "Encrypted") {
                Add-Finding -Category "Infrastructure" -Severity "High" `
                    -CheckId "NATIVE-INFRA-001" -Title "VM OS disk not encrypted (ADE / encryption at host)" `
                    -Resource "$($vm.Name) ($($vm.ResourceGroupName))" `
                    -ResourceId $vm.Id `
                    -ResourceType "Virtual Machine" `
                    -Finding "OS disk is NOT encrypted with Azure Disk Encryption, encryption at host or a customer-managed key" `
                    -Recommendation "Enable Encryption at Host (preferred) or Azure Disk Encryption for all VMs."
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
                        -CheckId "NATIVE-INFRA-002" -Title "Key Vault certificate expires within 90 days" `
                        -Resource "$($kv.VaultName) > $($certRef.Name)" `
                        -ResourceId $kv.ResourceId `
                        -ResourceType "KV certificate" `
                        -Finding "Certificate expires in $days days ($($expiry.ToString('yyyy-MM-dd')))" `
                        -Recommendation "Renew the certificate. Enable automatic renewal in the Key Vault policy."
                }
            }
        } catch { }
    }

    # Key Vault - secrets and keys without an expiry date (one finding per vault)
    # Certificate-backed secrets/keys are skipped: they follow the certificate's own validity.
    Write-Step "Checking Key Vault secrets and keys without expiry..."
    foreach ($kv in $keyVaults) {
        try {
            $secrets = @(Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction Stop | Where-Object {
                $_.Enabled -ne $false -and -not $_.Expires -and "$($_.ContentType)" -notmatch 'pkcs12|pem-file'
            })
            $keys = @(Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction Stop | Where-Object {
                $_.Enabled -ne $false -and -not $_.Expires -and -not (Get-PropValue $_ 'Managed')
            })
        } catch { continue }   # no data-plane read permission or firewall - nothing to judge
        $names = @($secrets | ForEach-Object { "secret:$($_.Name)" }) + @($keys | ForEach-Object { "key:$($_.Name)" })
        if ($names.Count -eq 0) { continue }
        $list = ($names | Select-Object -First 10) -join ", "
        if ($names.Count -gt 10) { $list += ", … (+$($names.Count - 10))" }
        Add-Finding -Category "Infrastructure" -Severity "Low" `
            -CheckId "NATIVE-INFRA-004" -Title "Key Vault secrets or keys without an expiry date" `
            -Resource $kv.VaultName `
            -ResourceId $kv.ResourceId `
            -ResourceType "Key Vault" `
            -Finding "$($secrets.Count) secret(s) and $($keys.Count) key(s) have no expiry date: $list" `
            -Recommendation "Set an expiry date on every secret and key, rotate them before it passes (key rotation policy / Event Grid near-expiry events), and remove those no longer used. Secrets that never expire tend to live on long after the person or system that created them."
    }

    # Storage - blob soft delete
    Write-Step "Checking Storage soft-delete..."
    $storageAccounts = Get-AzStorageAccount
    foreach ($sa in $storageAccounts) {
        try {
            $blobSvc = Get-AzStorageBlobServiceProperty -StorageAccount $sa -ErrorAction Stop
            if (-not $blobSvc.DeleteRetentionPolicy.Enabled) {
                Add-Finding -Category "Infrastructure" -Severity "Medium" `
                    -CheckId "NATIVE-INFRA-003" -Title "Blob soft delete not enabled" `
                    -Resource $sa.StorageAccountName `
                    -ResourceId $sa.Id `
                    -ResourceType "Storage Account" `
                    -Finding "Blob soft-delete is NOT enabled" `
                    -Recommendation "Enable soft-delete (at least 7 days) as protection against accidental deletion."
            }
        } catch { }
    }

    Write-Step "  Infrastructure checks complete." "Gray"
}
