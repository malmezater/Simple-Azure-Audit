# ─────────────────────────────────────────────────────────────
# Checks.Security.ps1
# Security checks: NSG rules, orphaned Public IPs, RBAC/Owner, classic admins.
# ─────────────────────────────────────────────────────────────

function Invoke-SecurityChecks {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName
    )

    Write-Section "1/5 - SECURITY"

    # NSG - dangerous inbound rules
    Write-Step "Checking Network Security Groups..."
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

                Add-Finding -Category "Security" -Severity $sev `
                    -Resource "$($nsg.Name) > $($rule.Name)" `
                    -ResourceType "NSG rule" `
                    -Finding "Inbound port $portStr open to the Internet (0.0.0.0/0)" `
                    -Recommendation "Restrict the source to specific IP ranges, or use Azure Bastion/VPN instead of exposing RDP/SSH directly."
            }
        }
    }
    Write-Step "  $($nsgs.Count) NSGs reviewed." "Gray"

    # Orphaned, unassociated Public IPs
    Write-Step "Checking Public IP addresses..."
    $pubIPs = Get-AzPublicIpAddress
    foreach ($pip in $pubIPs) {
        if (-not $pip.IpConfiguration) {
            Add-Finding -Category "Security" -Severity "Low" `
                -Resource $pip.Name `
                -ResourceType "Public IP" `
                -Finding "Unassociated Public IP ($(if ($pip.IpAddress) { $pip.IpAddress } else { 'not allocated' }))" `
                -Recommendation "Remove unused Public IPs to reduce the attack surface and cost."
        }
    }

    # RBAC - too many Owners at subscription scope
    Write-Step "Checking RBAC assignments..."
    $ownerAssignments = Get-AzRoleAssignment -RoleDefinitionName "Owner" |
                        Where-Object { $_.Scope -eq "/subscriptions/$SubscriptionId" }

    if ($ownerAssignments.Count -gt 3) {
        Add-Finding -Category "Security" -Severity "High" `
            -Resource "Subscription: $SubscriptionName" `
            -ResourceType "RBAC" `
            -Finding "$($ownerAssignments.Count) Owner roles at subscription scope (recommended <=3)" `
            -Recommendation "Follow the principle of least privilege. Use Contributor/Reader where Owner is not required."
    }

    # Classic administrators (legacy)
    $classicAdmins = Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -match "CoAdministrator|ServiceAdministrator" }
    foreach ($admin in $classicAdmins) {
        Add-Finding -Category "Security" -Severity "Medium" `
            -Resource $(if ($admin.SignInName) { $admin.SignInName } elseif ($admin.DisplayName) { $admin.DisplayName } else { "Unknown" }) `
            -ResourceType "Classic admin" `
            -Finding "Legacy role '$($admin.RoleDefinitionName)' is still assigned" `
            -Recommendation "Migrate to Azure RBAC. Classic administrator roles are deprecated by Microsoft."
    }

    Write-Step "  Security checks complete." "Gray"
}
