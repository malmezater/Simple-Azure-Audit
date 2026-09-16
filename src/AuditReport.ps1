# ─────────────────────────────────────────────────────────────
# AuditReport.ps1
# Generates the CSV, the merged JSON data file and the interactive HTML report.
# The HTML layout lives in src\report-template.html; the findings are embedded
# as JSON so the report is a single self-contained file.
# ─────────────────────────────────────────────────────────────

function New-AuditReport {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[PSCustomObject]]$Findings,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[PSCustomObject]]$ToolRuns,
        [Parameter(Mandatory)][object[]]$Subscriptions,     # @{ Id; Name }
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$HtmlPath,
        [string]$DataPath,
        [string]$CustomerName,
        [string]$PreparedBy,
        [string]$ScriptVersion,
        [string]$GeneratedAt = (Get-Date -Format "yyyy-MM-dd HH:mm")
    )

    Write-Section "GENERATING REPORTS"

    $subs = @($Subscriptions | Where-Object { $_ })
    $subNames = @{}
    foreach ($sub in $subs) { $subNames["$($sub.Id)".ToLower()] = "$($sub.Name)" }
    $scopeTitle = if ($subs.Count -eq 1) { "$($subs[0].Name)" } else { "$($subs.Count) subscriptions" }

    # Resolve the subscription name for every finding (tenant-level findings keep "-")
    $subNameProp = { $id = "$($_.SubscriptionId)".ToLower(); if ($subNames.ContainsKey($id)) { $subNames[$id] } elseif ($id -and $id -ne '-') { $id } else { "Tenant" } }

    $sevOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Info" = 4 }
    $sorted   = @($Findings | Sort-Object { $sevOrder[$_.Severity] }, Category, Title, Resource)

    # ── CSV ──────────────────────────────────────────────────
    Write-Step "Saving CSV..."
    $sorted | Select-Object Severity, Category, Source, CheckId, Title, Resource, ResourceType, ResourceId,
                            @{ Name = "SubscriptionName"; Expression = $subNameProp }, SubscriptionId,
                            Finding, Recommendation, Reference, Frameworks, Timestamp |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Step "  $CsvPath" "Gray"

    # ── Data model ───────────────────────────────────────────
    $data = [ordered]@{
        meta = [ordered]@{
            customerName     = $(if ($CustomerName) { $CustomerName } else { $scopeTitle })
            preparedBy       = $PreparedBy
            subscriptionName = $scopeTitle
            subscriptionId   = $(if ($subs.Count -eq 1) { "$($subs[0].Id)" } else { "" })
            subscriptions    = @($subs | ForEach-Object { [ordered]@{ id = "$($_.Id)"; name = "$($_.Name)" } })
            tenantId         = $TenantId
            generated        = $GeneratedAt
            scriptVersion    = $ScriptVersion
            fileBaseName     = [System.IO.Path]::GetFileNameWithoutExtension($HtmlPath)
        }
        tools    = @($ToolRuns)
        findings = @($sorted | Select-Object Source, Category, Severity, CheckId, Title, Resource, ResourceType, ResourceId,
                                             SubscriptionId, @{ Name = "SubscriptionName"; Expression = $subNameProp },
                                             Finding, Recommendation, Reference, Frameworks)
    }

    $json = $data | ConvertTo-Json -Depth 8 -Compress -EscapeHandling EscapeHtml
    if ($DataPath) {
        Write-Step "Saving merged data (JSON)..."
        $data | ConvertTo-Json -Depth 8 | Set-Content -Path $DataPath -Encoding utf8
        Write-Step "  $DataPath" "Gray"
    }

    # ── HTML ─────────────────────────────────────────────────
    Write-Step "Building HTML report..."
    $templatePath = Join-Path $PSScriptRoot "report-template.html"
    if (-not (Test-Path $templatePath)) { throw "Report template not found: $templatePath" }
    $template = Get-Content -LiteralPath $templatePath -Raw -Encoding utf8

    $title = "Azure assessment - $(if ($CustomerName) { $CustomerName } else { $scopeTitle })"
    $titleEncoded = [System.Net.WebUtility]::HtmlEncode($title)

    # String.Replace (not -replace) so '$' in the data is never treated as a regex substitution.
    $html = $template.Replace("__REPORT_TITLE__", $titleEncoded).Replace("__AUDIT_DATA__", $json)
    Set-Content -Path $HtmlPath -Value $html -Encoding utf8 -NoNewline
    Write-Step "  $HtmlPath" "Gray"
}
