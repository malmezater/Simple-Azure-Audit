# ─────────────────────────────────────────────────────────────
# AuditCommon.ps1
# Shared helper functions, the common findings collection and the
# tool-run register. Dot-sourced from the main script (Invoke-AzureAudit.ps1).
# ─────────────────────────────────────────────────────────────

# Shared list that every check function and tool adapter writes its findings to.
$script:AuditFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

# One entry per tool (Native, Prowler, Maester, ...) describing how the run went.
$script:ToolRuns = [System.Collections.Generic.List[PSCustomObject]]::new()

# Subscription/tenant the current run is scoped to. Set by the main script.
$script:AuditContext = [PSCustomObject]@{
    SubscriptionId   = ""     # subscription currently being scanned by the built-in checks
    SubscriptionName = ""
    TenantId         = ""
    Subscriptions    = @()    # every subscription in scope: @{ Id; Name }
}

$script:AuditCategories = @(
    "Security", "Identity", "Governance", "Reliability", "Cost",
    "Operations", "Performance", "Infrastructure", "Compliance", "Advisor"
)
$script:AuditSeverities = @("Critical", "High", "Medium", "Low", "Info")

function Write-Step {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "  $Msg" -ForegroundColor $Color
}

function Write-Section {
    param([string]$Msg)
    Write-Host "`n[$Msg]" -ForegroundColor Magenta
}

function Get-PropValue {
    # Safely reads a (possibly nested) property without tripping Set-StrictMode.
    # Works on PSCustomObject (ConvertFrom-Json / Import-Csv), .NET objects and hashtables.
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string[]]$Path
    )
    $current = $InputObject
    foreach ($name in $Path) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($name)) { return $null }
            $current = $current[$name]
            continue
        }
        $prop = $current.PSObject.Properties[$name]
        if (-not $prop) { return $null }
        $current = $prop.Value
    }
    return $current
}

function Get-FirstValue {
    # Returns the first non-empty value among several candidate property paths.
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][object[]]$Candidates
    )
    foreach ($path in $Candidates) {
        $value = Get-PropValue -InputObject $InputObject -Path @($path)
        if ($null -ne $value -and "$value".Trim()) { return "$value".Trim() }
    }
    return $null
}

function Get-ResourceNameFromId {
    param([string]$ResourceId)
    if (-not $ResourceId) { return "" }
    return ($ResourceId.TrimEnd('/') -split '/')[-1]
}

function Get-SubscriptionIdFromResourceId {
    param([string]$ResourceId)
    if ($ResourceId -match '/subscriptions/([0-9a-fA-F-]{36})') { return $Matches[1].ToLower() }
    return ""
}

function Resolve-SubscriptionSelection {
    <#
      Parses an interactive selection such as "2", "1-3", "1,3,5", "1-3,6" or "all"
      into 0-based indexes. Returns $null when the input is invalid.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Selection, [Parameter(Mandatory)][int]$Count)
    $text = $Selection.Trim().ToLowerInvariant()
    if ($text -in @("all", "a", "*")) { return @(0..($Count - 1)) }
    if (-not $text) { return $null }

    $indexes = [System.Collections.Generic.List[int]]::new()
    foreach ($part in ($text -split '[,;\s]+' | Where-Object { $_ })) {
        if ($part -match '^(\d+)-(\d+)$') {
            $from = [int]$Matches[1]; $to = [int]$Matches[2]
            if ($from -gt $to) { $from, $to = $to, $from }
        }
        elseif ($part -match '^\d+$') {
            $from = [int]$part; $to = $from
        }
        else { return $null }
        if ($from -lt 1 -or $to -gt $Count) { return $null }
        foreach ($n in $from..$to) { if (-not $indexes.Contains($n - 1)) { $indexes.Add($n - 1) } }
    }
    return @($indexes)
}

function Get-ScopeLabel {
    param([object[]]$Subscriptions)
    $subs = @($Subscriptions)
    if ($subs.Count -eq 1) { return "Subscription: $($subs[0].Name)" }
    return "$($subs.Count) subscriptions"
}

function ConvertTo-PlainText {
    # Strips basic markdown/HTML so tool output reads cleanly in the report and CSV.
    param([AllowNull()][string]$Text, [int]$MaxLength = 1500)
    if (-not $Text) { return "" }
    # Markdown tables: "| a | b |" rows become "a · b", separator rows are dropped.
    $lines = foreach ($line in ($Text -split '\r?\n')) {
        $trim = $line.Trim()
        if ($trim -match '^\|?\s*:?-{2,}') { continue }
        if ($trim.StartsWith('|')) {
            (@($trim.Trim('|') -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' · ') + ';'
        } else { $line }
    }
    $t = ($lines -join "`n") -replace '<br\s*/?>', ' ' -replace '<[^>]+>', ''
    $t = $t -replace '\[([^\]]+)\]\([^)]+\)', '$1'        # [label](url) -> label
    $t = $t -replace '(\*\*|__|`)', ''
    $t = $t -replace '^\s*#+\s*', '' -replace '\r?\n\s*#+\s*', ' '
    $t = $t -replace '\s+', ' ' -replace ';\s*$', '' -replace ':\s*;', ':'
    $t = $t.Trim()
    if ($t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength).TrimEnd() + " …" }
    return $t
}

function Add-Finding {
    param(
        [ValidateSet("Security","Identity","Governance","Reliability","Cost","Operations","Performance","Infrastructure","Compliance","Advisor")]
        [string]$Category,
        [ValidateSet("Critical","High","Medium","Low","Info")][string]$Severity,
        [string]$Resource,
        [string]$ResourceType,
        [string]$Finding,
        [string]$Recommendation,
        # ── Fields used to merge results from several tools ──
        [string]$Source = "Native",
        [string]$CheckId,
        [string]$Title,
        [string]$ResourceId,
        [string]$SubscriptionId,
        [string]$Reference,
        [string]$Frameworks
    )

    if (-not $Title)          { $Title = $Finding }
    if (-not $CheckId)        { $CheckId = "$Source::$Title" }
    if (-not $SubscriptionId) { $SubscriptionId = Get-SubscriptionIdFromResourceId $ResourceId }
    if (-not $SubscriptionId) { $SubscriptionId = $script:AuditContext.SubscriptionId }
    if (-not $Resource -and $ResourceId) { $Resource = Get-ResourceNameFromId $ResourceId }

    $script:AuditFindings.Add([PSCustomObject]@{
        Source         = $Source
        Category       = $Category
        Severity       = $Severity
        CheckId        = $CheckId
        Title          = $Title
        Resource       = $Resource
        ResourceType   = $ResourceType
        ResourceId     = $ResourceId
        SubscriptionId = $SubscriptionId
        Finding        = $Finding
        Recommendation = $Recommendation
        Reference      = $Reference
        Frameworks     = $Frameworks
        Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm")
    })
}

function Import-FindingObjects {
    # Re-adds previously exported findings (e.g. raw/native.json) to the collection.
    param([Parameter(Mandatory)][object[]]$Items)
    foreach ($i in $Items) {
        $obj = [ordered]@{}
        foreach ($f in "Source","Category","Severity","CheckId","Title","Resource","ResourceType","ResourceId",
                      "SubscriptionId","Finding","Recommendation","Reference","Frameworks","Timestamp") {
            $obj[$f] = "$(Get-PropValue $i $f)"
        }
        if (-not $obj.Source)  { $obj.Source = "Native" }
        if (-not $obj.Title)   { $obj.Title = $obj.Finding }
        if (-not $obj.CheckId) { $obj.CheckId = "$($obj.Source)::$($obj.Title)" }
        $script:AuditFindings.Add([PSCustomObject]$obj)
    }
}

function Get-AuditFindings {
    # Returns the shared findings collection.
    , $script:AuditFindings
}

function Clear-AuditFindings {
    $script:AuditFindings.Clear()
    $script:ToolRuns.Clear()
}

function Add-ToolRun {
    param(
        [Parameter(Mandatory)][string]$Tool,
        [ValidateSet("Succeeded","PartiallySucceeded","Failed","Skipped","NotInstalled","Imported")][string]$Status,
        [string]$Scope,
        [string]$Description,
        [string]$Message,
        [string]$Version,
        [double]$DurationSeconds = 0,
        [int]$Passed = -1,
        [int]$Failed = -1,
        [int]$Total = -1,
        [int]$FindingCount = 0,
        [object[]]$Reports = @()   # @{ Label = "HTML report"; Path = "raw/prowler/x.html" }
    )
    $existing = $script:ToolRuns | Where-Object { $_.Tool -eq $Tool }
    foreach ($e in @($existing)) { [void]$script:ToolRuns.Remove($e) }

    $script:ToolRuns.Add([PSCustomObject]@{
        Tool            = $Tool
        Status          = $Status
        Scope           = $Scope
        Description     = $Description
        Message         = $Message
        Version         = $Version
        DurationSeconds = [math]::Round($DurationSeconds, 0)
        Passed          = $Passed
        Failed          = $Failed
        Total           = $Total
        FindingCount    = $FindingCount
        Reports         = @($Reports | ForEach-Object { [PSCustomObject]@{ Label = $_.Label; Path = $_.Path } })
    })
}

function Get-ToolRuns {
    , $script:ToolRuns
}

function Get-RelativeReportPath {
    # Path relative to the run folder, with forward slashes, for links in the HTML report.
    param([Parameter(Mandatory)][string]$BasePath, [Parameter(Mandatory)][string]$FullPath)
    $rel = [System.IO.Path]::GetRelativePath($BasePath, $FullPath)
    return ($rel -replace '\\', '/')
}
