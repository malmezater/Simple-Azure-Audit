# ─────────────────────────────────────────────────────────────
# Checks.Cost.ps1
# Kostnadskontroller: ohängda diskar, stoppade VMs, lösa NICs, tomma RGs.
# ─────────────────────────────────────────────────────────────

function Invoke-CostChecks {
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
}
