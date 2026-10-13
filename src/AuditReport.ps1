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
        [string]$ActionPlanPath,
        [AllowEmptyCollection()][object[]]$Vulnerabilities = @(),   # from New-VulnerabilityCatalog
        $VulnerabilityScan,                                         # Defender for Cloud summary, or $null
        [string]$CustomerName,
        [string]$PreparedBy,
        [string]$ScriptVersion,
        [string]$GeneratedAt = (Get-Date -Format "yyyy-MM-dd HH:mm"),
        [string]$BrandingPath                                       # branding folder, see Get-ReportBranding
    )

    Write-Section "GENERATING REPORTS"

    $Branding = Get-ReportBranding -Path $BrandingPath
    if (-not $PreparedBy -and $Branding) { $PreparedBy = $Branding.PreparedBy }

    $subs = @($Subscriptions | Where-Object { $_ })
    $subNames = @{}
    foreach ($sub in $subs) { $subNames["$($sub.Id)".ToLower()] = "$($sub.Name)" }
    $scopeTitle = if ($subs.Count -eq 1) { "$($subs[0].Name)" } else { "$($subs.Count) subscriptions" }

    # Resolve the subscription name for every finding (tenant-level findings keep "-")
    $subNameProp = { $id = "$($_.SubscriptionId)".ToLower(); if ($subNames.ContainsKey($id)) { $subNames[$id] } elseif ($id -and $id -ne '-') { $id } else { "Tenant" } }

    # Same problem on the same resource from several tools -> one row (see FindingMerge.ps1)
    $merged = Merge-AuditFindings -Findings @($Findings)
    $mergedRows = @($merged | Where-Object { $_.Detections.Count -gt 1 })
    if ($mergedRows.Count) {
        $absorbed = ($mergedRows | ForEach-Object { $_.Detections.Count - 1 } | Measure-Object -Sum).Sum
        Write-Step "Merged $absorbed duplicate findings reported by more than one tool or check ($($Findings.Count) -> $($merged.Count) rows)." "Gray"
    }

    $sevOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Info" = 4 }
    $sorted   = @($merged | Sort-Object { $sevOrder[$_.Severity] }, Category, Title, Resource)

    # ── CSV ──────────────────────────────────────────────────
    # Source and CheckId list every tool and check when several reported the same problem.
    Write-Step "Saving CSV..."
    $sorted | Select-Object Severity, Category, @{ Name = "Source"; Expression = { $_.Sources } }, @{ Name = "CheckId"; Expression = { $_.CheckIds } },
                            Title, Resource, ResourceType, ResourceId,
                            @{ Name = "SubscriptionName"; Expression = $subNameProp }, SubscriptionId,
                            Finding, Recommendation, Reference, Frameworks, Vulnerabilities, Timestamp |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Step "  $CsvPath" "Gray"

    # ── Action plan ──────────────────────────────────────────
    Write-Step "Building action plan..."
    $plan = New-ActionPlan -Findings $sorted -Vulnerabilities $Vulnerabilities
    if ($ActionPlanPath) {
        Export-ActionPlanCsv -Plan $plan -Path $ActionPlanPath
        Write-Step "  $ActionPlanPath" "Gray"
    }

    # ── Data model ───────────────────────────────────────────
    $data = [ordered]@{
        meta = [ordered]@{
            customerName     = $(if ($CustomerName) { $CustomerName } else { $scopeTitle })
            preparedBy       = $PreparedBy
            eyebrow          = $(if ($Branding) { $Branding.Eyebrow } else { "" })
            subscriptionName = $scopeTitle
            subscriptionId   = $(if ($subs.Count -eq 1) { "$($subs[0].Id)" } else { "" })
            subscriptions    = @($subs | ForEach-Object { [ordered]@{ id = "$($_.Id)"; name = "$($_.Name)" } })
            tenantId         = $TenantId
            generated        = $GeneratedAt
            scriptVersion    = $ScriptVersion
            fileBaseName     = [System.IO.Path]::GetFileNameWithoutExtension($HtmlPath)
        }
        tools    = @($ToolRuns)
        findings = @($sorted | Select-Object Source, Sources, Category, Severity, CheckId, CheckIds, Topic, Title, Resource, ResourceType, ResourceId,
                                             SubscriptionId, @{ Name = "SubscriptionName"; Expression = $subNameProp },
                                             Finding, Recommendation, Reference, Frameworks, Vulnerabilities, Detections)
        vulnerabilities   = @($Vulnerabilities)
        vulnerabilityScan = $VulnerabilityScan
        plan              = $plan
    }

    $json = $data | ConvertTo-Json -Depth 8 -Compress -EscapeHandling EscapeHtml
    if ($DataPath) {
        Write-Step "Saving merged data (JSON)..."
        $data | ConvertTo-Json -Depth 8 | Set-Content -Path $DataPath -Encoding utf8
        Write-Step "  $DataPath" "Gray"
    }

    # ── HTML ─────────────────────────────────────────────────
    Write-Step "Building HTML report$(if ($Branding) { " (branding: $($Branding.Name))" })..."
    $title = "Azure assessment - $(if ($CustomerName) { $CustomerName } else { $scopeTitle })"
    $html = ConvertTo-AuditReportHtml -Json $json -Title $title -Branding $Branding
    Set-Content -Path $HtmlPath -Value $html -Encoding utf8 -NoNewline
    Write-Step "  $HtmlPath" "Gray"
}

function ConvertTo-AuditReportHtml {
    # Fills src\report-template.html with the report data (JSON, HTML-safe) and the branding.
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$Title,
        $Branding     # from Get-ReportBranding, or $null for the neutral look
    )
    $templatePath = Join-Path $PSScriptRoot "report-template.html"
    if (-not (Test-Path $templatePath)) { throw "Report template not found: $templatePath" }
    $template = Get-Content -LiteralPath $templatePath -Raw -Encoding utf8

    # String.Replace (not -replace) so '$' in the data is never treated as a regex substitution.
    return $template.
        Replace("__REPORT_TITLE__", [System.Net.WebUtility]::HtmlEncode($Title)).
        Replace("__BRAND_HEAD__", $(if ($Branding) { $Branding.HeadHtml } else { "" })).
        Replace("__BRAND_LOGO__", $(if ($Branding) { $Branding.LogoHtml } else { "" })).
        Replace("/*__BRAND_CSS__*/", $(if ($Branding) { $Branding.Css } else { "" })).
        Replace("__AUDIT_DATA__", $Json)
}

function Get-ReportBranding {
    <#
      Reads a branding folder and returns @{ Name; Eyebrow; PreparedBy; Css; LogoHtml; HeadHtml }, or $null
      when no folder is given. The folder holds (all optional):
        brand.json  { "name", "eyebrow", "preparedBy", "logo", "logoAlt", "favicon" }
        brand.css   CSS added after the report's own CSS: --brand-* and colour tokens, any overrides
        the logo and favicon files named in brand.json (png, jpg, svg, gif, webp, ico)
      Images are embedded as data URIs, so the report stays one self-contained file.
      See branding/README.md.
    #>
    param([string]$Path)
    if (-not $Path) { return $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Branding folder not found: $Path" }
    $folder = (Resolve-Path -LiteralPath $Path).Path

    $cfg = $null
    $cfgPath = Join-Path $folder "brand.json"
    if (Test-Path -LiteralPath $cfgPath) {
        try { $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding utf8 | ConvertFrom-Json }
        catch { throw "Could not read $cfgPath`: $($_.Exception.Message)" }
    }
    $get = { param($n) if ($cfg -and $cfg.PSObject.Properties[$n]) { "$($cfg.$n)".Trim() } else { "" } }

    $css = ""
    $cssPath = Join-Path $folder "brand.css"
    if (Test-Path -LiteralPath $cssPath) {
        $css = Get-Content -LiteralPath $cssPath -Raw -Encoding utf8
        if ($css -match '</style') { throw "$cssPath must not contain '</style'." }
    }

    $toDataUri = {
        param($file)
        $p = Join-Path $folder $file
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "Branding file not found: $p" }
        $mime = @{ ".png" = "image/png"; ".jpg" = "image/jpeg"; ".jpeg" = "image/jpeg"; ".svg" = "image/svg+xml"
                   ".gif" = "image/gif"; ".webp" = "image/webp"; ".ico" = "image/x-icon" }[[System.IO.Path]::GetExtension($p).ToLowerInvariant()]
        if (-not $mime) { throw "Unsupported image type for branding: $p (use png, jpg, svg, gif, webp or ico)" }
        "data:$mime;base64,$([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($p)))"
    }

    $name = & $get "name"
    if (-not $name) { $name = Split-Path $folder -Leaf }
    $logoHtml = ""
    $logo = & $get "logo"
    if ($logo) {
        $alt = & $get "logoAlt"
        if (-not $alt) { $alt = $name }
        $logoHtml = "<img class=`"brand-logo`" alt=`"$([System.Net.WebUtility]::HtmlEncode($alt))`" src=`"$(& $toDataUri $logo)`">"
    }
    $headHtml = ""
    $favicon = & $get "favicon"
    if ($favicon) { $headHtml = "<link rel=`"icon`" href=`"$(& $toDataUri $favicon)`">" }

    return [PSCustomObject]@{
        Name       = $name
        Eyebrow    = & $get "eyebrow"
        PreparedBy = & $get "preparedBy"
        Css        = $css
        LogoHtml   = $logoHtml
        HeadHtml   = $headHtml
    }
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
