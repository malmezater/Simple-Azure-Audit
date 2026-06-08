# ─────────────────────────────────────────────────────────────
# Checks.Cost.ps1
# Cost checks: unattached disks, stopped VMs, orphaned NICs, empty RGs.
# ─────────────────────────────────────────────────────────────

function Invoke-CostChecks {
    Write-Section "2/5 - COST & UNUSED RESOURCES"

    # Unattached managed disks
    Write-Step "Checking unattached disks..."
    $unattachedDisks = Get-AzDisk | Where-Object { $_.DiskState -eq "Unattached" }
    foreach ($disk in $unattachedDisks) {
        Add-Finding -Category "Cost" -Severity "Medium" `
            -Resource "$($disk.Name) ($($disk.ResourceGroupName))" `
            -ResourceType "Managed Disk" `
            -Finding "Unattached disk: $($disk.DiskSizeGB) GB, SKU: $($disk.Sku.Name)" `
            -Recommendation "Delete or snapshot unattached disks. A 1 TB P30 disk costs roughly 40 USD/month for nothing."
    }
    Write-Step "  $($unattachedDisks.Count) unattached disks found." "Gray"

    # Stopped/deallocated VMs
    Write-Step "Checking VM status..."
    $allVMs = Get-AzVM -Status
    foreach ($vm in $allVMs) {
        $state = ($vm.Statuses | Where-Object { $_.Code -match "^PowerState/" }).DisplayStatus
        if ($state -in @("VM stopped","VM deallocated")) {
            Add-Finding -Category "Cost" -Severity "Low" `
                -Resource $vm.Name `
                -ResourceType "Virtual Machine" `
                -Finding "VM is stopped ($state) - storage costs still apply" `
                -Recommendation "Delete the VM if it is not needed. A deallocated VM pays no compute, but its disks still cost."
        }
    }

    # Orphaned NICs
    Write-Step "Checking unused network interfaces..."
    $looseNICs = Get-AzNetworkInterface | Where-Object { -not $_.VirtualMachine }
    foreach ($nic in $looseNICs) {
        Add-Finding -Category "Cost" -Severity "Low" `
            -Resource "$($nic.Name) ($($nic.ResourceGroupName))" `
            -ResourceType "Network Interface" `
            -Finding "NIC is not attached to any VM" `
            -Recommendation "Remove orphaned NICs to keep the environment clean."
    }

    # Empty resource groups
    Write-Step "Checking empty resource groups..."
    $emptyRGs = Get-AzResourceGroup | Where-Object {
        (Get-AzResource -ResourceGroupName $_.ResourceGroupName).Count -eq 0
    }
    foreach ($rg in $emptyRGs) {
        Add-Finding -Category "Cost" -Severity "Info" `
            -Resource $rg.ResourceGroupName `
            -ResourceType "Resource Group" `
            -Finding "Empty resource group with no resources" `
            -Recommendation "Delete empty resource groups to keep the subscription tidy."
    }

    Write-Step "  Cost checks complete." "Gray"
}
