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
    $script = @"
Import-Module PSRule.Rules.Azure -ErrorAction Stop
`$export = Join-Path $(ConvertTo-PSLiteral $RawFolder) 'export'
New-Item -ItemType Directory -Force -Path `$export | Out-Null
Set-AzContext -Subscription $(ConvertTo-PSLiteral $SubscriptionIds[0]) -Tenant $(ConvertTo-PSLiteral $TenantId) | Out-Null

Write-Host 'Exporting resource configuration (Export-AzRuleData)...'
Export-AzRuleData -Subscription $(ConvertTo-PSArrayLiteral $SubscriptionIds) -OutputPath `$export | Out-Null

Write-Host 'Evaluating rules (Invoke-PSRule)...'
`$results = @(Invoke-PSRule -InputPath `$export -Module 'PSRule.Rules.Azure' -Outcome Fail, Pass -WarningAction SilentlyContinue)

`$rows = foreach (`$r in `$results) {
    `$ann = `$r.Info.Annotations
    `$target = `$r.TargetObject
    [PSCustomObject]@{
        rule           = "`$(`$r.RuleName)"
        displayName    = "`$(`$r.Info.DisplayName)"
        synopsis       = "`$(`$r.Info.Synopsis)"
        description    = "`$(`$r.Info.Description)"
        recommendation = "`$(`$r.Info.Recommendation)"
        pillar         = "`$(`$ann.pillar)"
        category       = "`$(`$ann.category)"
        severity       = "`$(`$ann.severity)"
        link           = "`$(`$ann.'online version')"
        resourceId     = "`$(if (`$target -and `$target.id) { `$target.id } else { `$r.TargetName })"
        resourceName   = "`$(`$r.TargetName)"
        resourceType   = "`$(`$r.TargetType)"
        outcome        = "`$(`$r.Outcome)"
    }
}
ConvertTo-Json -InputObject @(`$rows) -Depth 4 | Set-Content -Path $(ConvertTo-PSLiteral $resultsPath) -Encoding utf8
Write-Host "`$(`$results.Count) rule results written."

# The export holds the full resource configuration; remove it once evaluated.
Remove-Item -Path `$export -Recurse -Force -ErrorAction SilentlyContinue
"@

    Write-Step "  Exporting and evaluating resources with PSRule for Azure..." "Gray"
    $r = Invoke-ToolProcess -Name "PSRule" -ScriptText $script -WorkingDirectory $RawFolder -LogDirectory $LogDirectory
    $hasOutput = Test-Path $resultsPath
    Save-ToolRunState -RawFolder $RawFolder -State @{
        Status = $(if ($hasOutput) { "Succeeded" } else { "Failed" })
        Message = $(if (-not $hasOutput) { "No PSRule results produced (exit code $($r.ExitCode)) - see logs/psrule.log." } else { "" })
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
