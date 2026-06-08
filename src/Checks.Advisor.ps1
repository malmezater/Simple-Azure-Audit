# ─────────────────────────────────────────────────────────────
# Checks.Advisor.ps1
# Azure Advisor: fetches all active recommendations (requires Az.Advisor).
# ─────────────────────────────────────────────────────────────

function Get-AdvisorProperty {
    # Safely reads a (possibly nested) property without tripping Set-StrictMode.
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string[]]$Path
    )
    $current = $InputObject
    foreach ($name in $Path) {
        if ($null -eq $current) { return $null }
        $prop = $current.PSObject.Properties[$name]
        if (-not $prop) { return $null }
        $current = $prop.Value
    }
    return $current
}

function Get-AdvisorFirstValue {
    # Returns the first non-empty value among several candidate property paths.
    # Each candidate is an array of property names representing a (nested) path.
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][object[]]$Candidates
    )
    foreach ($path in $Candidates) {
        $value = Get-AdvisorProperty -InputObject $InputObject -Path @($path)
        if ($null -ne $value -and "$value".Trim()) { return "$value".Trim() }
    }
    return $null
}

function Invoke-AdvisorChecks {
    param(
        [switch]$SkipAdvisor
    )

    Write-Section "5/5 - AZURE ADVISOR"

    if ($SkipAdvisor) {
        Write-Step "Skipped Advisor (-SkipAdvisor specified)." "DarkGray"
        return
    }

    Write-Step "Fetching Azure Advisor recommendations..."

    # The fetch itself is the part that depends on the Az.Advisor module.
    try {
        $advisorRecs = Get-AzAdvisorRecommendation -ErrorAction Stop
    } catch {
        Write-Step "  Could not fetch Advisor data. Make sure the Az.Advisor module is installed." "DarkYellow"
        Write-Step "  ($($_.Exception.Message))" "DarkGray"
        return
    }

    Write-Step "  $($advisorRecs.Count) recommendations found." "Gray"

    foreach ($rec in $advisorRecs) {
        try {
            $impact = Get-AdvisorProperty -InputObject $rec -Path @("Impact")
            $sev = switch ($impact) {
                "High"   { "High" }
                "Medium" { "Medium" }
                "Low"    { "Low" }
                default  { "Info" }
            }

            $impactedValue = Get-AdvisorProperty -InputObject $rec -Path @("ImpactedValue")
            $impactedField = Get-AdvisorProperty -InputObject $rec -Path @("ImpactedField")

            # The problem/solution text lives under different property names depending
            # on the Az.Advisor version: flattened (ShortDescriptionProblem) in newer
            # builds, nested (ShortDescription.Problem) in older ones.
            $problem = Get-AdvisorFirstValue -InputObject $rec -Candidates @(
                @("ShortDescriptionProblem"),
                @("ShortDescription","Problem"),
                @("Problem"),
                @("Description")
            )
            $solution = Get-AdvisorFirstValue -InputObject $rec -Candidates @(
                @("ShortDescriptionSolution"),
                @("ShortDescription","Solution"),
                @("Solution")
            )

            Add-Finding -Category "Advisor" -Severity $sev `
                -Resource $(if ($impactedValue) { $impactedValue } elseif ($impactedField) { $impactedField } else { "N/A" }) `
                -ResourceType $(if ($impactedField) { $impactedField } else { "Unknown" }) `
                -Finding $(if ($problem) { $problem } else { "See Azure Advisor" }) `
                -Recommendation $(if ($solution) { $solution } else { "See the Azure Advisor portal" })
        } catch {
            Write-Step "  Skipped a recommendation that could not be parsed: $($_.Exception.Message)" "DarkGray"
        }
    }
}
