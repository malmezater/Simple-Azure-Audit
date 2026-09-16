# ─────────────────────────────────────────────────────────────
# Tools.WARA.ps1
# Well-Architected Reliability Assessment (https://github.com/Azure/Well-Architected-Reliability-Assessment) - MIT
# Runs Start-WARACollector and imports the WARA-File-*.json output:
#   impactedResources  confirmed APRL (Azure Proactive Resiliency Library) findings
#   retirements        active Azure service retirements affecting the subscription
# Recommendation texts are resolved from the same recommendations.json that the
# collector uses (downloaded at import time and cached in raw/wara).
#
# Install: Install-Module WARA -Scope CurrentUser
# ─────────────────────────────────────────────────────────────

$script:WARARecommendationUri = "https://azure.github.io/WARA-Build/objects/recommendations.json"

function Invoke-WARAScan {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [switch]$InstallMissing
    )

    if (-not (Install-AuditModule -Name "WARA" -InstallMissing:$InstallMissing)) {
        Write-Step "  WARA module not installed. Run with -InstallMissing or: Install-Module WARA -Scope CurrentUser" "DarkYellow"
        Save-ToolRunState -RawFolder $RawFolder -State @{ Status = "NotInstalled"; Message = "Module WARA is required (Install-Module WARA -Scope CurrentUser)." }
        return
    }

    $script = @"
Import-Module WARA -ErrorAction Stop
Start-WARACollector -TenantID $(ConvertTo-PSLiteral $TenantId) -SubscriptionIds $(ConvertTo-PSArrayLiteral (@($SubscriptionIds) | ForEach-Object { "/subscriptions/$_" }))
"@

    Write-Step "  Running Start-WARACollector..." "Gray"
    $r = Invoke-ToolProcess -Name "WARA" -ScriptText $script -WorkingDirectory $RawFolder -LogDirectory $LogDirectory
    $hasOutput = [bool](Get-LatestFile -Path $RawFolder -Filter "WARA-File-*.json")
    $status = if ($hasOutput) { "Succeeded" } else { "Failed" }
    Save-ToolRunState -RawFolder $RawFolder -State @{
        Status = $status
        Message = $(if (-not $hasOutput) { "No WARA-File-*.json produced (exit code $($r.ExitCode)) - see logs/wara.log. The collector refuses to run when a newer WARA module exists: Update-Module WARA." } else { "" })
        DurationSeconds = $r.DurationSeconds
        Version = (Get-ModuleVersionString "WARA")
    }
}

function Get-WARARecommendationIndex {
    param([Parameter(Mandatory)][string]$RawFolder)
    $cache = Join-Path $RawFolder "recommendations.json"
    if (-not (Test-Path $cache)) {
        try {
            Invoke-WebRequest -Uri $script:WARARecommendationUri -OutFile $cache -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-Step "  Could not download WARA recommendation texts: $($_.Exception.Message)" "DarkYellow"
            return @{}
        }
    }
    $index = @{}
    foreach ($rec in @(Read-JsonFile $cache)) {
        $guid = "$(Get-PropValue $rec 'aprlGuid')"
        if ($guid -and -not $index.ContainsKey($guid)) { $index[$guid] = $rec }
    }
    return $index
}

function Import-WARAResults {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder
    )

    $json = Get-LatestFile -Path $RawFolder -Filter "WARA-File-*.json"
    if (-not $json) {
        Complete-ToolImport -Tool "WARA" -RawFolder $RawFolder -NoResults
        return
    }

    Write-Step "Importing $($json.Name)..."
    $data  = Read-JsonFile $json.FullName
    $recs  = Get-WARARecommendationIndex -RawFolder $RawFolder
    $count = 0
    $manual = 0

    foreach ($ir in @(Get-PropValue $data 'impactedResources')) {
        $action = "$(Get-PropValue $ir 'validationAction')"
        if ($action -ne "APRL - Queries") { $manual++; continue }   # "IMPORTANT - validate manually" rows are not confirmed findings

        $guid = "$(Get-PropValue $ir 'recommendationId')"
        $rec  = if ($recs.ContainsKey($guid)) { $recs[$guid] } else { $null }
        $impact = "$(Get-PropValue $rec 'recommendationImpact')"
        $severity = if ($impact -in @("High","Medium","Low")) { $impact } else { "Medium" }
        $title = "$(Get-PropValue $rec 'description')"
        if (-not $title) { $title = "APRL recommendation $guid" }
        $links = @(Get-PropValue $rec 'learnMoreLink') | ForEach-Object { Get-PropValue $_ 'url' } | Where-Object { $_ }

        $recommendation = ConvertTo-PlainText "$(Get-PropValue $rec 'longDescription')" 900
        $benefit = "$(Get-PropValue $rec 'potentialBenefits')"
        if ($benefit) { $recommendation = "$recommendation Benefit: $benefit".Trim() }

        $detailParts = @("param1","param2","param3") | ForEach-Object { "$(Get-PropValue $ir $_)" } | Where-Object { $_ }
        $finding = if ($detailParts) { "$title ($($detailParts -join '; '))" } else { $title }

        Add-Finding -Source "WARA" -Category "Reliability" -Severity $severity `
            -CheckId "APRL::$guid" -Title $title `
            -Resource "$(Get-PropValue $ir 'name')" `
            -ResourceId "$(Get-PropValue $ir 'id')" `
            -ResourceType "$(Get-PropValue $ir 'type')" `
            -SubscriptionId "$(Get-PropValue $ir 'subscriptionId')" `
            -Finding $finding `
            -Recommendation $(if ($recommendation) { $recommendation } else { "See the Azure Proactive Resiliency Library for guidance." }) `
            -Reference $(if ($links) { $links[0] } else { "https://azure.github.io/WARA-Build/" }) `
            -Frameworks "WAF: Reliability$(if (Get-PropValue $rec 'recommendationControl') { " / $(Get-PropValue $rec 'recommendationControl')" })"
        $count++
    }

    foreach ($ret in @(Get-PropValue $data 'retirements')) {
        $status = "$(Get-PropValue $ret 'Status')"
        if ($status -and $status -ne "Active") { continue }
        $title = "$(Get-FirstValue $ret @(@('Title'), @('Header')))"
        if (-not $title) { continue }
        Add-Finding -Source "WARA" -Category "Reliability" -Severity "Medium" `
            -CheckId "WARA-RETIREMENT::$(Get-PropValue $ret 'TrackingId')" -Title "Service retirement: $title" `
            -Resource "$(Get-FirstValue $ret @(@('ImpactedService'), @('SubscriptionId')))" `
            -ResourceType "Service retirement" `
            -ResourceId "" `
            -SubscriptionId "$(Get-PropValue $ret 'SubscriptionId')" `
            -Finding (ConvertTo-PlainText "$(Get-FirstValue $ret @(@('Summary'), @('Description')))" 900) `
            -Recommendation "Plan the migration before the retirement date. Tracking ID: $(Get-PropValue $ret 'TrackingId')." `
            -Reference "https://aka.ms/servicehealth"
        $count++
    }

    $reports = @(New-ReportLink -Label "WARA collector JSON" -File $json -RunFolder $RunFolder) | Where-Object { $_ }
    Write-Step "  $count findings imported ($manual items need manual validation and were left out)." "Gray"
    Complete-ToolImport -Tool "WARA" -RawFolder $RawFolder -FindingCount $count `
        -Version "$(Get-PropValue $data @('scriptDetails','Version'))" `
        -Scope "Subscriptions: $(@(Get-PropValue $data @('scriptDetails','SubscriptionIds')) -join ', ')" -Reports $reports
}
