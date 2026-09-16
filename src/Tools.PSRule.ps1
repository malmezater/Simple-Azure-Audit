# ─────────────────────────────────────────────────────────────
# Tools.PSRule.ps1
# PSRule for Azure (https://azure.github.io/PSRule.Rules.Azure) - MIT
# Exports the subscription's live resource configuration with Export-AzRuleData
# and evaluates it against the Well-Architected rules (all five pillars).
#
# Install: Install-Module PSRule.Rules.Azure -Scope CurrentUser   (pulls in PSRule)
#
# Note: AzGovViz used to run PSRule with -DoPSRule, but that integration has been
# paused upstream, so PSRule runs as its own tool here.
# ─────────────────────────────────────────────────────────────

function Invoke-PSRuleScan {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [switch]$InstallMissing
    )

    if (-not (Install-AuditModule -Name "PSRule.Rules.Azure" -InstallMissing:$InstallMissing)) {
        Write-Step "  PSRule.Rules.Azure not installed. Run with -InstallMissing or: Install-Module PSRule.Rules.Azure -Scope CurrentUser" "DarkYellow"
        Save-ToolRunState -RawFolder $RawFolder -State @{ Status = "NotInstalled"; Message = "Module PSRule.Rules.Azure is required (Install-Module PSRule.Rules.Azure -Scope CurrentUser)." }
        return
    }

    $resultsPath = Join-Path $RawFolder "psrule-results.json"
    # The child script is a literal template; values are filled in below (no escaping of $ needed).
    $template = @'
Import-Module PSRule.Rules.Azure -ErrorAction Stop
$ProgressPreference = 'Continue'
$export = Join-Path __RAW__ 'export'
New-Item -ItemType Directory -Force -Path $export | Out-Null
Set-AzContext -Subscription __FIRSTSUB__ -Tenant __TENANT__ | Out-Null
$subscriptions = __SUBS__
$activity = 'PSRule for Azure'

# ── 1. Export ────────────────────────────────────────────────────────────────
# Export-AzRuleData has no progress of its own, but its verbose stream reports
# "Added N resources from subscription" and then "Expanding resource: <id>" per resource.
# Run it in a thread job and turn those messages into a progress bar.
Write-Host "Exporting resource configuration from $($subscriptions.Count) subscription(s) (Export-AzRuleData)..."
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$exportWarnings = @()
$job = $null
if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
    $job = Start-ThreadJob -ScriptBlock {
        param($Subs, $Out)
        Import-Module PSRule.Rules.Azure -ErrorAction Stop
        $w = @()
        Export-AzRuleData -Subscription $Subs -OutputPath $Out -Verbose -WarningAction SilentlyContinue -WarningVariable w | Out-Null
        # Hand the warnings back as plain strings (collected on the job output).
        $w | ForEach-Object { "WARNING::$($_.Message)" }
    } -ArgumentList (,$subscriptions), $export
    # Thread jobs keep their streams on the job object itself.
    $total = 0; $expanded = 0; $seen = 0
    $readVerbose = {
        $verbose = $job.Verbose
        for ($i = $seen; $i -lt $verbose.Count; $i++) {
            $msg = "$($verbose[$i].Message)"
            if ($msg -match '^Added (\d+) resources from subscription') { $total += [int]$Matches[1] }
            elseif ($msg -like 'Expanding resource:*') { $expanded++ }
        }
        $seen = $verbose.Count
    }
    while ($job.State -in 'NotStarted', 'Running') {
        . $readVerbose
        $elapsed = '{0:mm\:ss}' -f $sw.Elapsed
        if ($total -gt 0) {
            $pct = [math]::Min(99, [int](100 * $expanded / $total))
            Write-Progress -Activity $activity -Status "Exporting: $expanded of $total resources ($elapsed)" -PercentComplete $pct
        } else {
            Write-Progress -Activity $activity -Status "Listing resources in $($subscriptions.Count) subscription(s) ($elapsed)"
        }
        Start-Sleep -Milliseconds 750
    }
    . $readVerbose
    $exportWarnings = @(Receive-Job -Job $job -ErrorAction Continue | Where-Object { "$_" -like 'WARNING::*' } | ForEach-Object { "$_".Substring(9) })
    Remove-Job -Job $job -Force
    Write-Host "  Exported $total resources in $('{0:mm\:ss}' -f $sw.Elapsed)"
}
else {
    Write-Progress -Activity $activity -Status 'Exporting (no progress available without ThreadJob)...'
    Export-AzRuleData -Subscription $subscriptions -OutputPath $export -WarningAction SilentlyContinue -WarningVariable exportWarnings | Out-Null
}

# Export-AzRuleData warns once per sub-resource it cannot read (e.g. the retired classicAdministrators
# API, or DefenderForStorageSettings on every storage account). Print a summary instead.
if ($exportWarnings.Count -gt 0) {
    Write-Host "Export-AzRuleData could not read $($exportWarnings.Count) sub-resource(s) (not fatal):"
    $exportWarnings | ForEach-Object {
        $m = if ($_ -is [string]) { $_ } else { "$($_.Message)" }
        $type = if ($m -match '/providers/(?:.*/providers/)?([^/?]+/[^/?]+)(?:/[^/?]+)?\?') { $Matches[1] } else { 'other' }
        $code = if ($m -match '"code":"([^"]+)"') { $Matches[1] } elseif ($m -match 'status=(\d+)') { "HTTP $($Matches[1])" } else { 'unknown' }
        "$type ($code)"
    } | Group-Object | Sort-Object Count -Descending | ForEach-Object { Write-Host ("  {0,4} x {1}" -f $_.Count, $_.Name) }
}

$files = @(Get-ChildItem -Path $export -Filter '*.json' -File)
if ($files.Count -eq 0 -and $job) {
    # Safety net: if the export did not work inside the thread job, run it directly without progress.
    Write-Host 'No export files from the background export - running Export-AzRuleData directly...'
    Write-Progress -Activity $activity -Status 'Exporting (no progress)...'
    Export-AzRuleData -Subscription $subscriptions -OutputPath $export -WarningAction SilentlyContinue -WarningVariable exportWarnings | Out-Null
    $files = @(Get-ChildItem -Path $export -Filter '*.json' -File)
}
Write-Host "Exported $($files.Count) file(s). PSRule $((Get-Module PSRule).Version), PSRule.Rules.Azure $((Get-Module PSRule.Rules.Azure).Version)"

# ── 2. Evaluate ──────────────────────────────────────────────────────────────
# The exported resources are passed in as objects (reading the files with -InputPath depends on the
# PSRule version: v3 needs the JSON format enabled, and 2.9 returned nothing in testing).
# PSRule evaluates each object as it arrives, so counting objects on the way in gives real progress.
$objects = @(foreach ($f in $files) { Get-Content -Path $f.FullName -Raw | ConvertFrom-Json -Depth 100 | ForEach-Object { $_ } })
Write-Host "Evaluating $($objects.Count) resources against the Azure rules (Invoke-PSRule)..."
$sw.Restart()
$n = 0
$results = @($objects | ForEach-Object {
    $n++
    if ($n -eq 1 -or $n % 5 -eq 0 -or $n -eq $objects.Count) {
        Write-Progress -Activity $activity -Status "Evaluating: $n of $($objects.Count) resources ($('{0:mm\:ss}' -f $sw.Elapsed))" -PercentComplete ([int](100 * $n / [math]::Max(1, $objects.Count)))
    }
    $_
} | Invoke-PSRule -Module 'PSRule.Rules.Azure' -Outcome Fail, Pass -WarningAction SilentlyContinue)
Write-Progress -Activity $activity -Completed

$rows = foreach ($r in $results) {
    $ann = $r.Info.Annotations
    $target = $r.TargetObject
    [PSCustomObject]@{
        rule           = "$($r.RuleName)"
        displayName    = "$($r.Info.DisplayName)"
        synopsis       = "$($r.Info.Synopsis)"
        description    = "$($r.Info.Description)"
        recommendation = "$($r.Info.Recommendation)"
        pillar         = "$($ann.pillar)"
        category       = "$($ann.category)"
        severity       = "$($ann.severity)"
        link           = "$($ann.'online version')"
        resourceId     = "$(if ($target -and $target.id) { $target.id } else { $r.TargetName })"
        resourceName   = "$($r.TargetName)"
        resourceType   = "$($r.TargetType)"
        outcome        = "$($r.Outcome)"
    }
}
ConvertTo-Json -InputObject @($rows) -Depth 4 | Set-Content -Path __RESULTS__ -Encoding utf8
$failCount = @($results | Where-Object { "$($_.Outcome)" -eq 'Fail' }).Count
Write-Host "$($results.Count) rule results written ($failCount failed) in $('{0:mm\:ss}' -f $sw.Elapsed)."

# The export holds the full resource configuration; remove it once evaluated.
Remove-Item -Path $export -Recurse -Force -ErrorAction SilentlyContinue
'@
    $script = $template.
        Replace('__RAW__', (ConvertTo-PSLiteral $RawFolder)).
        Replace('__FIRSTSUB__', (ConvertTo-PSLiteral $SubscriptionIds[0])).
        Replace('__TENANT__', (ConvertTo-PSLiteral $TenantId)).
        Replace('__SUBS__', (ConvertTo-PSArrayLiteral $SubscriptionIds)).
        Replace('__RESULTS__', (ConvertTo-PSLiteral $resultsPath))

    Write-Step "  Exporting and evaluating resources with PSRule for Azure..." "Gray"
    $r = Invoke-ToolProcess -Name "PSRule" -ScriptText $script -WorkingDirectory $RawFolder -LogDirectory $LogDirectory
    # An empty result set means nothing was evaluated (a subscription always yields some passes).
    $hasOutput = (Test-Path $resultsPath) -and @(Read-JsonFile $resultsPath).Count -gt 0
    Save-ToolRunState -RawFolder $RawFolder -State @{
        Status = $(if ($hasOutput) { "Succeeded" } else { "Failed" })
        Message = $(if (-not $hasOutput) { "PSRule produced no rule results (exit code $($r.ExitCode)) - see logs/psrule.log." } else { "" })
        DurationSeconds = $r.DurationSeconds
        Version = (Get-ModuleVersionString "PSRule.Rules.Azure")
    }
}

function Import-PSRuleResults {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [string[]]$SubscriptionIds
    )

    $json = Get-LatestFile -Path $RawFolder -Filter "psrule-results.json"
    if (-not $json) {
        Complete-ToolImport -Tool "PSRule" -RawFolder $RawFolder -NoResults
        return
    }

    Write-Step "Importing $($json.Name)..."
    $passed = 0; $failed = 0; $count = 0

    foreach ($r in @(Read-JsonFile $json.FullName)) {
        $outcome = "$(Get-PropValue $r 'outcome')"
        if ($outcome -eq "Pass") { $passed++; continue }
        if ($outcome -ne "Fail") { continue }
        $failed++

        $pillar = "$(Get-PropValue $r 'pillar')"
        $category = switch -Regex ($pillar) {
            'Reliab'      { "Reliability"; break }
            'Secur'       { "Security"; break }
            'Cost'        { "Cost"; break }
            'Operational' { "Operations"; break }
            'Performance' { "Performance"; break }
            default       { "Governance" }
        }
        $severity = switch -Regex ("$(Get-PropValue $r 'severity')") {
            'Critical'  { "High"; break }
            'Important' { "Medium"; break }
            default     { "Low" }     # Awareness
        }

        $rule     = "$(Get-PropValue $r 'rule')"
        $synopsis = Get-FirstValue $r @(@('synopsis'), @('description'))
        $display  = "$(Get-PropValue $r 'displayName')"
        # Rule names look like Azure.Storage.SoftDelete; the synopsis reads better as a title.
        $title = if ($synopsis) { ConvertTo-PlainText $synopsis 300 } elseif ($display) { $display } else { $rule }
        $resourceId = "$(Get-PropValue $r 'resourceId')"

        Add-Finding -Source "PSRule" -Category $category -Severity $severity `
            -CheckId "PSRULE::$rule" -Title $title `
            -Resource $(if ("$(Get-PropValue $r 'resourceName')") { "$(Get-PropValue $r 'resourceName')" } else { Get-ResourceNameFromId $resourceId }) `
            -ResourceId $(if ($resourceId -like "/subscriptions/*") { $resourceId } else { "" }) `
            -ResourceType "$(Get-PropValue $r 'resourceType')" `
            -Finding $(if ($display -and $display -ne $rule) { "$display ($rule)" } else { $rule }) `
            -Recommendation (ConvertTo-PlainText "$(Get-PropValue $r 'recommendation')") `
            -Reference "$(Get-PropValue $r 'link')" `
            -Frameworks "WAF: $pillar$(if (Get-PropValue $r 'category') { " / $(Get-PropValue $r 'category')" })"
        $count++
    }

    $reports = @(New-ReportLink -Label "PSRule results (JSON)" -File $json -RunFolder $RunFolder) | Where-Object { $_ }
    Write-Step "  $failed failed / $passed passed rule evaluations imported." "Gray"
    Complete-ToolImport -Tool "PSRule" -RawFolder $RawFolder -FindingCount $count `
        -Passed $passed -Failed $failed -Total ($passed + $failed) -Scope "Subscriptions: $(@($SubscriptionIds).Count)" -Reports $reports
}
