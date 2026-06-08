# ─────────────────────────────────────────────────────────────
# Checks.Security.ps1
# Säkerhetskontroller: NSG-regler, lösa Public IPs, RBAC/Owner, klassiska admins.
# ─────────────────────────────────────────────────────────────

function Invoke-SecurityChecks {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName
    )

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
                -Finding "Ej associerad Public IP ($(if ($pip.IpAddress) { $pip.IpAddress } else { 'ej allokerad' }))" `
                -Recommendation "Ta bort oanvända Public IPs för att minska attackytan och kostnaderna."
        }
    }

    # RBAC – för många Owner på prenumerationsnivå
    Write-Step "Kontrollerar RBAC-tilldelningar..."
    $ownerAssignments = Get-AzRoleAssignment -RoleDefinitionName "Owner" |
                        Where-Object { $_.Scope -eq "/subscriptions/$SubscriptionId" }

    if ($ownerAssignments.Count -gt 3) {
        Add-Finding -Category "Säkerhet" -Severity "High" `
            -Resource "Prenumeration: $SubscriptionName" `
            -ResourceType "RBAC" `
            -Finding "$($ownerAssignments.Count) Owner-roller på prenumerationsnivå (rekommenderat ≤3)" `
            -Recommendation "Följ minsta-privilegs-principen. Använd Contributor/Reader där Owner inte krävs."
    }

    # Klassiska administratörer (legacy)
    $classicAdmins = Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -match "CoAdministrator|ServiceAdministrator" }
    foreach ($admin in $classicAdmins) {
        Add-Finding -Category "Säkerhet" -Severity "Medium" `
            -Resource $(if ($admin.SignInName) { $admin.SignInName } elseif ($admin.DisplayName) { $admin.DisplayName } else { "Okänd" }) `
            -ResourceType "Klassisk admin" `
            -Finding "Legacy-rollen '$($admin.RoleDefinitionName)' är fortfarande tilldelad" `
            -Recommendation "Migrera till Azure RBAC. Klassiska administratörsroller är deprecerade av Microsoft."
    }

    Write-Step "  Säkerhetskontroller klara." "Gray"
}
