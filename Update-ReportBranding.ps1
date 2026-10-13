#Requires -Version 7.2

<#
.SYNOPSIS
    Rebuilds an existing report HTML file with the current report template and a branding.

.DESCRIPTION
    Takes the data embedded in a report (for example Demo_AzureAudit_Report.html) and writes it into the
    current src\report-template.html with the chosen branding. The findings, plan and vulnerabilities are
    not recalculated; use Invoke-AzureAudit.ps1 -ImportFrom for that when you have the run folder.

    Typical use in a branded copy of the repo, after merging updates from the public repo:
        .\Update-ReportBranding.ps1 -Path .\Demo_AzureAudit_Report.html -PreparedBy "Contoso"

.PARAMETER Path
    The report HTML file to rebuild.

.PARAMETER Branding
    Branding folder (brand.json, brand.css, logo). Default: branding\custom next to this script when it
    exists. Use -NoBranding for the neutral look.

.PARAMETER NoBranding
    Rebuild with the neutral look, also when branding\custom exists.

.PARAMETER PreparedBy
    Replace the report's "prepared by" text. Omitted = keep the text the report has.

.PARAMETER OutFile
    Where to write the result. Default: overwrite -Path.

.EXAMPLE
    .\Update-ReportBranding.ps1 -Path .\Demo_AzureAudit_Report.html -Branding .\branding\example -OutFile .\demo-example.html
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$Branding,
    [switch]$NoBranding,
    [string]$PreparedBy,
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "src\AuditReport.ps1")

$source = (Resolve-Path -LiteralPath $Path).Path
if (-not $OutFile) { $OutFile = $source }
if ($NoBranding) { $Branding = "" }
elseif (-not $Branding) {
    $custom = Join-Path (Join-Path $PSScriptRoot "branding") "custom"
    if (Test-Path -LiteralPath $custom) { $Branding = $custom }
}
$brand = Get-ReportBranding -Path $Branding

$html = Get-Content -LiteralPath $source -Raw -Encoding utf8
$dataMatch = [regex]::Match($html, '<script type="application/json" id="audit-data">(.*?)</script>', 'Singleline')
if (-not $dataMatch.Success) { throw "$source does not look like a Simple Azure Audit report (no embedded audit-data)." }
$titleMatch = [regex]::Match($html, '<title>(.*?)</title>', 'Singleline')
$title = if ($titleMatch.Success) { [System.Net.WebUtility]::HtmlDecode($titleMatch.Groups[1].Value) } else { "Azure assessment" }

# Edit only the header fields; JsonNode keeps every other value exactly as it was (no date or number conversion).
$data = [System.Text.Json.Nodes.JsonNode]::Parse($dataMatch.Groups[1].Value)
$meta = $data["meta"]
if ($null -eq $meta) { throw "The embedded data has no 'meta' section." }
$meta["eyebrow"] = [System.Text.Json.Nodes.JsonValue]::Create($(if ($brand) { $brand.Eyebrow } else { "" }))
if ($PSBoundParameters.ContainsKey("PreparedBy")) { $meta["preparedBy"] = [System.Text.Json.Nodes.JsonValue]::Create($PreparedBy) }

# The default encoder escapes < > & ' as \uXXXX, so the JSON cannot close the <script> element.
$options = [System.Text.Json.JsonSerializerOptions]::new()
$options.Encoder = [System.Text.Encodings.Web.JavaScriptEncoder]::Default
$json = $data.ToJsonString($options)

$result = ConvertTo-AuditReportHtml -Json $json -Title $title -Branding $brand
Set-Content -LiteralPath $OutFile -Value $result -Encoding utf8 -NoNewline
Write-Host "Wrote $OutFile ($(if ($brand) { "branding: $($brand.Name)" } else { 'neutral look' }))." -ForegroundColor Green
