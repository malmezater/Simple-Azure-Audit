# ─────────────────────────────────────────────────────────────
# Tools.AzGovViz.ps1
# Azure Governance Visualizer (https://aka.ms/AzGovViz) - MIT
# Runs AzGovVizParallel.ps1, then imports:
#   *_ResourcesCostOptimizationAndCleanup.csv  orphaned / unused resources
#   *_RoleAssignments.csv                      orphaned identities, Owner on SPs, custom Owner roles
#   *_MDfCCoverage.csv                         Defender for Cloud plans not enabled
#
# Install: the script is downloaded to <ToolsPath>\Azure-Governance-Visualizer
#          (-InstallMissing) or cloned manually from GitHub. AzGovViz installs
#          its own dependency (AzAPICall) on first run.
# Note:    AzGovViz's -DoPSRule integration is paused upstream; PSRule runs as its own tool (Tools.PSRule.ps1).
# Access:  Reader on the management group that is scanned (default: tenant root)
#          plus the ability to read Entra ID users/groups/service principals.
# ─────────────────────────────────────────────────────────────

function Get-AzGovVizScriptPath {
    param([Parameter(Mandatory)][string]$ToolsPath, [switch]$InstallMissing)

    $root   = Join-Path $ToolsPath "Azure-Governance-Visualizer"
    $script = Join-Path (Join-Path $root "pwsh") "AzGovVizParallel.ps1"
    if (Test-Path $script) { return $script }
    if (-not $InstallMissing) { return $null }

    Write-Step "  Downloading Azure Governance Visualizer from GitHub..." "Yellow"
    try {
        New-Item -ItemType Directory -Force -Path $ToolsPath | Out-Null
        $zip = Join-Path $ToolsPath "azgovviz.zip"
        Invoke-WebRequest -Uri "https://github.com/Azure/Azure-Governance-Visualizer/archive/refs/heads/master.zip" -OutFile $zip -UseBasicParsing
        $extract = Join-Path $ToolsPath "_azgovviz_extract"
        Expand-Archive -Path $zip -DestinationPath $extract -Force
        $inner = Get-ChildItem -Path $extract -Directory | Select-Object -First 1
        if (Test-Path $root) { Remove-Item $root -Recurse -Force }
        Move-Item -Path $inner.FullName -Destination $root
        Remove-Item $zip, $extract -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Step "  Download failed: $($_.Exception.Message)" "DarkYellow"
        return $null
    }
    if (Test-Path $script) { return $script }
    return $null
}

function Invoke-AzGovVizScan {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [string]$ManagementGroupId,
        [Parameter(Mandatory)][string]$ToolsPath,
        [switch]$InstallMissing
    )

    $scriptPath = Get-AzGovVizScriptPath -ToolsPath $ToolsPath -InstallMissing:$InstallMissing
    if (-not $scriptPath) {
        Write-Step "  AzGovViz not found in $ToolsPath. Run with -InstallMissing or clone https://github.com/Azure/Azure-Governance-Visualizer there." "DarkYellow"
        Save-ToolRunState -RawFolder $RawFolder -State @{ Status = "NotInstalled"; Message = "AzGovVizParallel.ps1 not found under the tools folder. Use -InstallMissing." }
        return
    }
    if (-not $ManagementGroupId) { $ManagementGroupId = $TenantId }

    $versionFile = Join-Path (Split-Path (Split-Path $scriptPath)) "version.json"
    $version = if (Test-Path $versionFile) { "$(Get-PropValue (Read-JsonFile $versionFile) 'ProductVersion')" } else { "" }

    $script = @"
& $(ConvertTo-PSLiteral $scriptPath) ``
    -ManagementGroupId $(ConvertTo-PSLiteral $ManagementGroupId) ``
    -SubscriptionId4AzContext $(ConvertTo-PSLiteral $SubscriptionId) ``
    -TenantId4AzContext $(ConvertTo-PSLiteral $TenantId) ``
    -SubscriptionIdWhitelist @($(ConvertTo-PSLiteral $SubscriptionId)) ``
    -OutputPath $(ConvertTo-PSLiteral $RawFolder) ``
    -NoPIMEligibility ``
    -StatsOptOut
"@

    Write-Step "  Scanning management group '$ManagementGroupId' (subscription filter: $SubscriptionId)..." "Gray"
    $r = Invoke-ToolProcess -Name "AzGovViz" -ScriptText $script -WorkingDirectory $RawFolder -LogDirectory $LogDirectory
    $hasOutput = [bool](Get-LatestFile -Path $RawFolder -Filter "AzGovViz_*.html" -Recurse)
    $status = if ($r.ExitCode -eq 0 -and $hasOutput) { "Succeeded" } elseif ($hasOutput) { "PartiallySucceeded" } else { "Failed" }
    Save-ToolRunState -RawFolder $RawFolder -State @{
        Status = $status
        Message = $(if ($status -ne "Succeeded") { "AzGovViz exited with code $($r.ExitCode) - see logs/azgovviz.log. Reader on management group '$ManagementGroupId' is required." } else { "" })
        DurationSeconds = $r.DurationSeconds
        Version = $version
        ManagementGroupId = $ManagementGroupId
    }
}

function Import-AzGovVizCsv {
    param([Parameter(Mandatory)][string]$RawFolder, [Parameter(Mandatory)][string]$Suffix)
    $file = Get-LatestFile -Path $RawFolder -Filter "AzGovViz_*$Suffix" -Recurse
    if (-not $file) { return @() }
    $firstLine = Get-Content -LiteralPath $file.FullName -TotalCount 1
    $delimiter = if (($firstLine -split ';').Count -ge ($firstLine -split ',').Count) { ';' } else { ',' }
    return @(Import-Csv -LiteralPath $file.FullName -Delimiter $delimiter -Encoding utf8)
}

function Import-AzGovVizResults {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [string]$SubscriptionId
    )

    $html = Get-ChildItem -Path $RawFolder -Filter "AzGovViz_*.html" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '_(DefinitionInsights|HierarchyMap)' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $html) {
        Complete-ToolImport -Tool "AzGovViz" -RawFolder $RawFolder -NoResults
        return
    }

    Write-Step "Importing AzGovViz CSV exports..."
    $inScope = { param($subId) (-not $SubscriptionId) -or (-not $subId) -or ($subId -eq $SubscriptionId) }
    $count = 0

    # ── Orphaned / unused resources ─────────────────────────
    foreach ($o in @(Import-AzGovVizCsv -RawFolder $RawFolder -Suffix "_ResourcesCostOptimizationAndCleanup.csv")) {
        if (-not (& $inScope $o.SubscriptionId)) { continue }
        $costSaving = "$($o.Intent)" -match 'cost'
        $costText = if ($o.PSObject.Properties['Cost'] -and $o.Cost) { " Cost last period: $($o.Cost) $($o.Currency)." } else { "" }
        $typeName = ("$($o.Type)" -split '/')[-1]
        Add-Finding -Source "AzGovViz" -Category "Cost" -Severity $(if ($costSaving) { "Medium" } else { "Low" }) `
            -CheckId "AZGOVVIZ-ORPHAN::$($o.Type)" -Title "Orphaned resource: $typeName" `
            -ResourceId "$($o.Resource)" -ResourceType "$($o.Type)" -SubscriptionId "$($o.SubscriptionId)" `
            -Finding "Resource appears orphaned or unused (intent: $($o.Intent)).$costText" `
            -Recommendation "Confirm the resource is not needed and delete it, or document why it is kept." `
            -Reference "https://github.com/Azure/Azure-Governance-Visualizer"
        $count++
    }

    # ── RBAC security findings ──────────────────────────────
    $seen = @{}
    foreach ($ra in @(Import-AzGovVizCsv -RawFolder $RawFolder -Suffix "_RoleAssignments.csv")) {
        $raId = "$(Get-PropValue $ra 'RoleAssignmentId')"
        if (-not $raId -or $seen.ContainsKey($raId)) { continue }
        $seen[$raId] = $true
        if (-not (& $inScope "$(Get-PropValue $ra 'SubscriptionId')")) { continue }

        $who   = "$(Get-FirstValue $ra @(@('ObjectDisplayName'), @('ObjectSignInName'), @('ObjectId')))"
        $role  = "$(Get-FirstValue $ra @(@('RoleClear'), @('RoleId')))"
        $scope = "$(Get-PropValue $ra 'Scope')"
        $base  = @{ Source = "AzGovViz"; ResourceType = "Role assignment"; ResourceId = $raId; SubscriptionId = "$(Get-PropValue $ra 'SubscriptionId')" }

        if ("$(Get-PropValue $ra 'ObjectType')" -eq "Unknown") {
            Add-Finding @base -Category "Identity" -Severity "Medium" `
                -CheckId "AZGOVVIZ-RBAC-ORPHANED" -Title "Role assignment for a deleted identity" `
                -Resource "$role @ $scope" `
                -Finding "Role '$role' is assigned to object $(Get-PropValue $ra 'ObjectId'), which no longer exists in Entra ID." `
                -Recommendation "Remove orphaned role assignments; they clutter RBAC reviews and can be re-used if an object ID is restored."
            $count++
        }
        if ("$(Get-PropValue $ra 'RoleSecurityOwnerAssignmentSP')" -eq "1") {
            Add-Finding @base -Category "Identity" -Severity "High" `
                -CheckId "AZGOVVIZ-RBAC-OWNER-SP" -Title "Owner role assigned to a service principal" `
                -Resource "$who @ $scope" `
                -Finding "Service principal '$who' has Owner at '$scope'." `
                -Recommendation "Replace Owner with a least-privilege role (e.g. Contributor plus a scoped User Access Administrator condition)."
            $count++
        }
        if ("$(Get-PropValue $ra 'RoleSecurityCustomRoleOwner')" -eq "1") {
            Add-Finding @base -Category "Identity" -Severity "High" `
                -CheckId "AZGOVVIZ-RBAC-CUSTOM-OWNER" -Title "Custom role with Owner-equivalent permissions" `
                -Resource "$who @ $scope" `
                -Finding "Custom role '$role' grants '*' actions including role assignment write, and is assigned to '$who'." `
                -Recommendation "Narrow the custom role's actions or use a built-in role."
            $count++
        }
    }

    # ── Defender for Cloud plans ────────────────────────────
    foreach ($p in @(Import-AzGovVizCsv -RawFolder $RawFolder -Suffix "_MDfCCoverage.csv")) {
        if (-not (& $inScope $p.subscriptionId)) { continue }
        if ("$($p.pricingTier)" -ne "Free") { continue }
        Add-Finding -Source "AzGovViz" -Category "Security" -Severity "Low" `
            -CheckId "AZGOVVIZ-MDFC::$($p.plan)" -Title "Defender for Cloud plan not enabled" `
            -Resource "$($p.plan) ($($p.subscriptionName))" -ResourceType "Defender plan" `
            -ResourceId "/subscriptions/$($p.subscriptionId)/providers/Microsoft.Security/pricings/$($p.plan)" `
            -SubscriptionId "$($p.subscriptionId)" `
            -Finding "Microsoft Defender plan '$($p.plan)' is on the Free tier." `
            -Recommendation "Enable the Defender plan if the subscription runs this workload type, or document the accepted risk." `
            -Reference "https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction"
        $count++
    }

    $reports = @(
        New-ReportLink -Label "AzGovViz HTML report" -File $html -RunFolder $RunFolder
    ) | Where-Object { $_ }

    Write-Step "  $count findings imported." "Gray"
    $state = Get-ToolRunState $RawFolder
    $mg = "$(Get-PropValue $state 'ManagementGroupId')"
    Complete-ToolImport -Tool "AzGovViz" -RawFolder $RawFolder -FindingCount $count `
        -Scope $(if ($mg) { "Management group: $mg" } else { "" }) -Reports $reports
}
