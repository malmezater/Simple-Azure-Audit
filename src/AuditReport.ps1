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

function New-AuditReportPackage {
    <#
      Zips the report so it can be moved or shared.
        Report  (default)  HTML report, CSV, audit-data.json and the tool reports the HTML links to
                           (Prowler/Maester/AzGovViz HTML, ARI Excel, ...). Paths are kept, so the links work
                           after unzipping. Leaves out the intermediate raw data and logs.
        Full               The whole run folder, for archiving or rebuilding with -ImportFrom.
      The zip is written next to the run folder. Returns the FileInfo, or $null when nothing was written.
    #>
    param(
        [Parameter(Mandatory)][string]$RunFolder,
        [AllowEmptyCollection()][string[]]$ReportFiles = @(),
        [AllowEmptyCollection()][object[]]$ToolRuns = @(),
        [ValidateSet("Report","Full")][string]$Mode = "Report"
    )

    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $runFolder = (Resolve-Path -LiteralPath $RunFolder).Path.TrimEnd('\', '/')
    $folderName = Split-Path $runFolder -Leaf
    $zipPath = Join-Path (Split-Path $runFolder -Parent) $(if ($Mode -eq "Full") { "${folderName}_full.zip" } else { "$folderName.zip" })
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

    if ($Mode -eq "Full") {
        Write-Step "Zipping the whole run folder..."
        [System.IO.Compression.ZipFile]::CreateFromDirectory($runFolder, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    }
    else {
        Write-Step "Zipping the report..."
        $files = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $ReportFiles) { if ($f -and (Test-Path -LiteralPath $f -PathType Leaf)) { $files.Add((Resolve-Path -LiteralPath $f).Path) } }

        # Tool reports linked from the HTML (Tools & method tab)
        foreach ($run in @($ToolRuns)) {
            foreach ($link in @(Get-PropValue $run 'Reports')) {
                $rel = "$(Get-PropValue $link 'Path')"
                if (-not $rel) { continue }
                $full = Join-Path $runFolder ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
                if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
                $files.Add((Resolve-Path -LiteralPath $full).Path)
                # AzGovViz splits its report into several HTML files that link to each other
                if ((Split-Path $full -Leaf) -like "AzGovViz_*.html") {
                    Get-ChildItem -LiteralPath (Split-Path $full -Parent) -Filter "AzGovViz_*.html" -File |
                        ForEach-Object { $files.Add($_.FullName) }
                }
            }
        }

        $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($file in ($files | Select-Object -Unique)) {
                # Entry name relative to the run folder, inside a folder named like the run folder
                $relative = $file.Substring($runFolder.Length).TrimStart('\', '/') -replace '\\', '/'
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zip, $file, "$folderName/$relative", [System.IO.Compression.CompressionLevel]::Optimal)
            }
        }
        finally {
            $zip.Dispose()
        }
    }

    $item = Get-Item -LiteralPath $zipPath -ErrorAction SilentlyContinue
    if ($item) { Write-Step "  $zipPath ($([math]::Round($item.Length / 1MB, 1)) MB)" "Gray" }
    return $item
}
