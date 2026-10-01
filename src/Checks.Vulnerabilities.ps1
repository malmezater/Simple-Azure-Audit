# ─────────────────────────────────────────────────────────────
# Checks.Vulnerabilities.ps1
# Known vulnerabilities (CVE):
#   - Invoke-VulnerabilityChecks   reads Defender for Cloud vulnerability assessment results
#                                  (Defender for Servers / MDVM, Defender for Containers, SQL VA)
#   - Update-FindingVulnerabilities finds CVE / GHSA IDs in the findings of every tool
#   - New-VulnerabilityCatalog     one entry per ID, marked with CISA KEV (known exploited)
#
# The configuration scanners (Prowler, PSRule, Maester ...) check settings, not installed
# software, so CVEs come almost only from Defender for Cloud.
# ─────────────────────────────────────────────────────────────

$script:VulnIdPattern = '\b(CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b'
$script:KevFeedUrl    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

function Get-VulnerabilityIds {
    # Unique CVE / GHSA IDs in a text, upper-case CVE, lower-case GHSA body as published.
    param([AllowNull()][string]$Text)
    if (-not $Text) { return @() }
    $ids = foreach ($m in [regex]::Matches($Text, $script:VulnIdPattern, 'IgnoreCase')) {
        $v = $m.Value
        if ($v -match '^cve') { $v.ToUpperInvariant() } else { "GHSA" + $v.Substring(4).ToLowerInvariant() }
    }
    return @($ids | Select-Object -Unique)
}

function ConvertFrom-DefenderSeverity {
    param([string]$Severity, [double]$Cvss)
    if ($Cvss -ge 9) { return "Critical" }    # CVSS v3 "Critical" band
    switch ("$Severity") {
        "High"   { "High" }
        "Medium" { "Medium" }
        "Low"    { "Low" }
        default  { "Info" }
    }
}

function Get-DefenderCvss {
    # Best-effort CVSS base score; the layout differs between the Qualys and MDVM formats.
    param($Properties)
    foreach ($path in @(@('additionalData', 'cvss', '3.1', 'base'), @('additionalData', 'cvss', '3.0', 'base'),
                        @('additionalData', 'cvss', '2.0', 'base'), @('additionalData', 'cvssV3', 'baseScore'),
                        @('additionalData', 'cvssScore'), @('additionalData', 'score'))) {
        $v = Get-PropValue $Properties $path
        $d = 0.0
        if ($null -ne $v -and [double]::TryParse("$v", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d) -and $d -gt 0 -and $d -le 10) { return $d }
    }
    return 0.0
}

function Invoke-VulnerabilityChecks {
    <#
      Reads unhealthy Defender for Cloud sub-assessments (one per vulnerability per resource) in every
      subscription. Writes a summary to <RawFolder>\defender-va.json so -ImportFrom can show it again.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Subscriptions,
        [Parameter(Mandatory)][string]$RawFolder
    )

    Write-Section "VULNERABILITIES - DEFENDER FOR CLOUD (all subscriptions)"

    $summary = [ordered]@{ SubscriptionsChecked = 0; SubscriptionsFailed = 0; Vulnerabilities = 0; Resources = 0; Message = "" }
    $resources = @{}
    foreach ($sub in $Subscriptions) {
        Write-Step "Reading vulnerability assessments in $($sub.Name)..."
        $items = Invoke-GovArmList "/subscriptions/$($sub.Id)/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview"
        if ($null -eq $items) {
            Write-Step "  Could not read Defender for Cloud assessments - skipped." "DarkYellow"
            $summary.SubscriptionsFailed++
            continue
        }
        $summary.SubscriptionsChecked++
        $count = 0
        foreach ($sa in $items) {
            $p = $sa['properties']
            if ("$(Get-PropValue $p @('status', 'code'))" -ne "Unhealthy") { continue }

            # /subscriptions/../virtualMachines/vm1/providers/Microsoft.Security/assessments/<key>/subAssessments/<id>
            $resourceId = "$(Get-PropValue $p @('resourceDetails', 'id'))"
            if (-not $resourceId) { $resourceId = ("$($sa['id'])" -split '/providers/Microsoft\.Security/assessments/', 2)[0] }
            $resource = Get-ResourceNameFromId $resourceId
            $repo = "$(Get-PropValue $p @('additionalData', 'repositoryName'))"
            if ($repo) { $resource = "$resource/$repo" }    # container image in a registry

            $json = $p | ConvertTo-Json -Depth 8 -Compress
            $ids = Get-VulnerabilityIds $json
            $cvss = Get-DefenderCvss $p
            $vendorId = "$(Get-PropValue $p 'id')"
            $title = "$(Get-PropValue $p 'displayName')"
            if (-not $title) { $title = if ($ids) { $ids[0] } else { $vendorId } }
            $assessed = "$(Get-PropValue $p @('additionalData', 'assessedResourceType'))"

            $refs = @(@(Get-PropValue $p @('additionalData', 'vendorReferences')) + @(Get-PropValue $p @('additionalData', 'cve')) |
                      ForEach-Object { Get-PropValue $_ 'link' } | Where-Object { $_ -match '^https?://' })
            $reference = if ($refs) { $refs[0] } elseif ($ids) { "https://nvd.nist.gov/vuln/detail/$($ids[0])" } else { "" }

            $detail = @()
            if ($ids)  { $detail += ($ids -join ", ") }
            if ($cvss) { $detail += "CVSS $cvss" }
            $patchable = Get-PropValue $p @('additionalData', 'patchable')
            if ($patchable -eq $true) { $detail += "patch available" }
            $description = ConvertTo-PlainText "$(Get-PropValue $p 'description')" 600
            $finding = (@(($detail -join " · ")) + @($description) | Where-Object { $_ }) -join ". "

            $remediation = ConvertTo-PlainText "$(Get-PropValue $p 'remediation')" 800
            if (-not $remediation) { $remediation = "Install the vendor's security update or upgrade the affected software, then let Defender for Cloud rescan." }

            Add-Finding -Source "Defender for Cloud" -Category "Security" `
                -Severity (ConvertFrom-DefenderSeverity "$(Get-PropValue $p @('status', 'severity'))" $cvss) `
                -CheckId "DEFENDER-VA-$(if ($ids) { $ids[0] } elseif ($vendorId) { $vendorId } else { $title })" `
                -Title (ConvertTo-PlainText $title 300) `
                -Resource $resource -ResourceId $resourceId `
                -ResourceType $(if ($assessed) { $assessed } else { "Vulnerability assessment" }) `
                -Finding $finding -Recommendation $remediation -Reference $reference `
                -Vulnerabilities ($ids -join ", ")
            $resources[$resourceId.ToLower()] = $true
            $count++
        }
        $summary.Vulnerabilities += $count
        Write-Step "  $count open vulnerability finding(s)." "Gray"
    }
    $summary.Resources = $resources.Count

    $summary.Message = if ($summary.SubscriptionsChecked -eq 0) {
        "Defender for Cloud could not be read (missing Reader / Security Reader access)."
    } elseif ($summary.Vulnerabilities -eq 0) {
        "No open vulnerabilities reported by Defender for Cloud. Either none were found, or vulnerability assessment is not enabled (Defender for Servers, Defender for Containers, SQL vulnerability assessment)."
    } else {
        "$($summary.Vulnerabilities) open vulnerability finding(s) on $($summary.Resources) resource(s) from Defender for Cloud."
    }
    New-Item -ItemType Directory -Force -Path $RawFolder | Out-Null
    $summary | ConvertTo-Json | Set-Content -Path (Join-Path $RawFolder "defender-va.json") -Encoding utf8
    Write-Step "  $($summary.Message)" "Gray"
}

function Update-FindingVulnerabilities {
    # Adds CVE / GHSA IDs mentioned in any finding text (all tools) to its Vulnerabilities field.
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[PSCustomObject]]$Findings)
    foreach ($f in $Findings) {
        $existing = @("$($f.Vulnerabilities)" -split '\s*,\s*' | Where-Object { $_ })
        $found = Get-VulnerabilityIds "$($f.Title) $($f.Finding) $($f.Recommendation) $($f.Reference) $($f.CheckId)"
        $all = @($existing + $found | Select-Object -Unique)
        if ($all.Count -ne $existing.Count) { $f.Vulnerabilities = $all -join ", " }
    }
}

function Get-KevCatalog {
    <#
      CISA Known Exploited Vulnerabilities catalogue as a hashtable CVE -> entry. Uses the cached copy in
      <RunFolder>\raw\kev when present (so -ImportFrom works offline); otherwise downloads it unless -Offline.
      The download is a plain GET of a public file - nothing about the environment is sent.
    #>
    param([Parameter(Mandatory)][string]$RunFolder, [switch]$Offline)
    $kevFolder = Join-Path (Join-Path $RunFolder "raw") "kev"
    $kevFile = Join-Path $kevFolder "known_exploited_vulnerabilities.json"
    $catalog = @{}
    if (-not (Test-Path $kevFile)) {
        if ($Offline) { Write-Step "  CISA KEV lookup skipped (-Offline)." "DarkGray"; return $null }
        Write-Step "Downloading the CISA Known Exploited Vulnerabilities catalogue..."
        try {
            New-Item -ItemType Directory -Force -Path $kevFolder | Out-Null
            Invoke-WebRequest -Uri $script:KevFeedUrl -OutFile $kevFile -TimeoutSec 60 -UseBasicParsing -ErrorAction Stop | Out-Null
        } catch {
            Write-Step "  Could not download the KEV catalogue: $($_.Exception.Message)" "DarkYellow"
            Remove-Item -LiteralPath $kevFile -ErrorAction SilentlyContinue
            return $null
        }
    }
    $kev = Read-JsonFile $kevFile
    foreach ($v in @(Get-PropValue $kev 'vulnerabilities')) {
        $id = "$(Get-PropValue $v 'cveID')".ToUpperInvariant()
        if ($id) { $catalog[$id] = $v }
    }
    Write-Step "  CISA KEV catalogue $(Get-PropValue $kev 'catalogVersion'): $($catalog.Count) known exploited vulnerabilities." "Gray"
    return $catalog
}

function New-VulnerabilityCatalog {
    # One entry per CVE / GHSA ID across all findings, with KEV details and the affected resources.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[PSCustomObject]]$Findings,
        [Parameter(Mandatory)][string]$RunFolder,
        [switch]$Offline
    )
    $byId = [ordered]@{}
    foreach ($f in $Findings) {
        foreach ($id in @("$($f.Vulnerabilities)" -split '\s*,\s*' | Where-Object { $_ })) {
            if (-not $byId.Contains($id)) {
                $byId[$id] = [ordered]@{ id = $id; title = ""; severity = "Info"; sources = @{}; resources = @{}; findings = 0; cvss = 0.0 }
            }
            $e = $byId[$id]
            $e.findings++
            $e.sources[$f.Source] = $true
            $e.resources[("$(if ($f.ResourceId) { $f.ResourceId } else { $f.Resource })").ToLower()] = $true
            if (-not $e.title -or $e.title -eq $id) { $e.title = $f.Title }
            if ($script:AuditSeverities.IndexOf($f.Severity) -lt $script:AuditSeverities.IndexOf($e.severity)) { $e.severity = $f.Severity }
            if ($f.Finding -match 'CVSS ([0-9.]+)') { $e.cvss = [math]::Max($e.cvss, [double]$Matches[1]) }
        }
    }
    if ($byId.Count -eq 0) { return @() }

    $kev = Get-KevCatalog -RunFolder $RunFolder -Offline:$Offline
    $list = foreach ($e in $byId.Values) {
        $k = if ($kev -and $e.id -like "CVE-*") { $kev[$e.id] } else { $null }
        [PSCustomObject]@{
            Id                 = $e.id
            Title              = $e.title
            Severity           = $e.severity
            Cvss               = $e.cvss
            Findings           = $e.findings
            Resources          = $e.resources.Count
            Sources            = @($e.sources.Keys | Sort-Object)
            KnownExploited     = [bool]$k
            KevName            = "$(Get-PropValue $k 'vulnerabilityName')"
            KevDateAdded       = "$(Get-PropValue $k 'dateAdded')"
            KevDueDate         = "$(Get-PropValue $k 'dueDate')"
            KevRansomware      = "$(Get-PropValue $k 'knownRansomwareCampaignUse')" -eq "Known"
            KevRequiredAction  = "$(Get-PropValue $k 'requiredAction')"
            KevChecked         = $null -ne $kev
        }
    }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $sorted = @($list | Sort-Object @{ Expression = { -not $_.KnownExploited } }, @{ Expression = { $sevRank[$_.Severity] } },
                                    @{ Expression = { $_.Cvss }; Descending = $true }, @{ Expression = { $_.Resources }; Descending = $true })
    $kevCount = @($sorted | Where-Object KnownExploited).Count
    Write-Step "  $($sorted.Count) unique vulnerabilities (CVE/GHSA), $kevCount known to be exploited." "Gray"
    return $sorted
}
