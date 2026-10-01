# ─────────────────────────────────────────────────────────────
# Checks.Security.ps1
# Security checks: NSG rules, orphaned Public IPs, RBAC/Owner, privileged roles on users,
# storage shared key access, classic admins.
# ─────────────────────────────────────────────────────────────

function Invoke-SecurityChecks {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName
    )

    Write-Section "1/5 - SECURITY"

    # NSG - dangerous inbound rules
    Write-Step "Checking Network Security Groups..."
    $nsgs = @(Get-AzNetworkSecurityGroup)
    $dangerousPorts = @("22","3389","1433","3306","5432","23","21","445","5985","5986")

    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules | Where-Object { $_.Direction -eq "Inbound" -and $_.Access -eq "Allow" }) {
            $sources = @($rule.SourceAddressPrefix) + @($rule.SourceAddressPrefixes) | Where-Object { $_ }
            $fromInternet = [bool]($sources | Where-Object { $_ -in @("*","Internet","0.0.0.0/0","Any") })
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
                    -CheckId "NATIVE-SEC-001" -Title "Management or database ports open to the Internet" `
                    -Resource "$($nsg.Name) > $($rule.Name)" `
                    -ResourceId $nsg.Id `
                    -ResourceType "NSG rule" `
                    -Finding "Inbound port $portStr open to the Internet (0.0.0.0/0)" `
                    -Recommendation "Restrict the source to specific IP ranges, or use Azure Bastion/VPN instead of exposing RDP/SSH directly."
            }
        }
    }
    Write-Step "  $($nsgs.Count) NSGs reviewed." "Gray"

    # Orphaned, unassociated Public IPs
    Write-Step "Checking Public IP addresses..."
    $pubIPs = @(Get-AzPublicIpAddress)
    foreach ($pip in $pubIPs) {
        if (-not $pip.IpConfiguration -and -not $pip.NatGateway) {
            Add-Finding -Category "Security" -Severity "Low" `
                -CheckId "NATIVE-SEC-002" -Title "Unassociated Public IP address" `
                -Resource $pip.Name `
                -ResourceId $pip.Id `
                -ResourceType "Public IP" `
                -Finding "Unassociated Public IP ($(if ($pip.IpAddress) { $pip.IpAddress } else { 'not allocated' }))" `
                -Recommendation "Remove unused Public IPs to reduce the attack surface and cost."
        }
    }

    # RBAC - too many Owners at subscription scope
    Write-Step "Checking RBAC assignments..."
    $ownerAssignments = @(Get-AzRoleAssignment -RoleDefinitionName "Owner" |
                          Where-Object { $_.Scope -eq "/subscriptions/$SubscriptionId" })

    if ($ownerAssignments.Count -gt 3) {
        Add-Finding -Category "Security" -Severity "High" `
            -CheckId "NATIVE-SEC-003" -Title "Too many Owner assignments at subscription scope" `
            -Resource "Subscription: $SubscriptionName" `
            -ResourceId "/subscriptions/$SubscriptionId" `
            -ResourceType "RBAC" `
            -Finding "$($ownerAssignments.Count) Owner roles at subscription scope (recommended <=3)" `
            -Recommendation "Follow the principle of least privilege. Use Contributor/Reader where Owner is not required."
    }

    # RBAC - privileged roles assigned directly to users (not via a group or a PIM activation)
    # Inherited management group assignments are left out so they are not repeated per subscription.
    $privilegedRoles = @{ "Owner" = "High"; "User Access Administrator" = "High"; "Role Based Access Control Administrator" = "High"; "Contributor" = "Medium" }
    $pimActivated = @{}
    try {
        foreach ($i in @(Get-AzRoleAssignmentScheduleInstance -Scope "/subscriptions/$SubscriptionId" -ErrorAction Stop |
                         Where-Object { $_.AssignmentType -eq "Activated" })) {
            $pimActivated["$($i.PrincipalId)|$(("$($i.RoleDefinitionId)" -split '/')[-1])|$($i.Scope)".ToLower()] = $true
        }
    } catch { }
    $directUsers = @(Get-AzRoleAssignment | Where-Object {
        $_.ObjectType -eq "User" -and $privilegedRoles.ContainsKey($_.RoleDefinitionName) -and
        $_.Scope -like "/subscriptions/$SubscriptionId*" -and
        -not $pimActivated.ContainsKey("$($_.ObjectId)|$($_.RoleDefinitionId)|$($_.Scope)".ToLower())
    })
    foreach ($ra in $directUsers) {
        $who = if ($ra.SignInName) { $ra.SignInName } elseif ($ra.DisplayName) { $ra.DisplayName } else { $ra.ObjectId }
        $scopeText = if ($ra.Scope -eq "/subscriptions/$SubscriptionId") { "subscription $SubscriptionName" } else { $ra.Scope }
        Add-Finding -Category "Identity" -Severity $privilegedRoles[$ra.RoleDefinitionName] `
            -CheckId "NATIVE-SEC-006" -Title "Privileged role assigned permanently and directly to a user" `
            -Resource "$who > $($ra.RoleDefinitionName)" `
            -ResourceId $ra.Scope `
            -ResourceType "RBAC" `
            -Finding "$who has a permanent, direct '$($ra.RoleDefinitionName)' assignment on $scopeText" `
            -Recommendation "Assign privileged roles to Entra ID groups and make them eligible through Privileged Identity Management (just-in-time, approval, time limit), so no user holds standing Owner/Contributor access."
    }
    Write-Step "  $($directUsers.Count) permanent privileged role assignment(s) directly on users." "Gray"

    # Storage - shared key (account key / SAS) authorization
    Write-Step "Checking Storage shared key access..."
    foreach ($sa in @(Get-AzStorageAccount)) {
        # $null means the setting was never changed, and then shared key access is allowed
        if ($sa.AllowSharedKeyAccess -ne $false) {
            Add-Finding -Category "Security" -Severity "Medium" `
                -CheckId "NATIVE-SEC-005" -Title "Storage account allows shared key access" `
                -Resource $sa.StorageAccountName `
                -ResourceId $sa.Id `
                -ResourceType "Storage Account" `
                -Finding "Shared key authorization is allowed: anyone with an account key or a SAS signed with it has full access, and key use is not tied to an identity" `
                -Recommendation "Use Entra ID (RBAC) and managed identities for data access and set AllowSharedKeyAccess to false. Check first that nothing still uses the keys (e.g. AzureWebJobsStorage connection strings, SMB file shares, older tools)."
        }
    }

    # Classic administrators (legacy)
    $classicAdmins = Get-AzRoleAssignment -IncludeClassicAdministrators |
                     Where-Object { $_.RoleDefinitionName -match "CoAdministrator|ServiceAdministrator" }
    foreach ($admin in $classicAdmins) {
        Add-Finding -Category "Security" -Severity "Medium" `
            -CheckId "NATIVE-SEC-004" -Title "Classic administrator role still assigned" `
            -Resource $(if ($admin.SignInName) { $admin.SignInName } elseif ($admin.DisplayName) { $admin.DisplayName } else { "Unknown" }) `
            -ResourceId "/subscriptions/$SubscriptionId" `
            -ResourceType "Classic admin" `
            -Finding "Legacy role '$($admin.RoleDefinitionName)' is still assigned" `
            -Recommendation "Migrate to Azure RBAC. Classic administrator roles are deprecated by Microsoft."
    }

    Write-Step "  Security checks complete." "Gray"
}
