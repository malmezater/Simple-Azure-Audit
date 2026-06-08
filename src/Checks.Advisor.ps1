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
            $impact   = Get-AdvisorProperty -InputObject $rec -Path @("Impact")
            $sev = switch ($impact) {
                "High"   { "High" }
                "Medium" { "Medium" }
                "Low"    { "Low" }
                default  { "Info" }
            }

            $impactedValue = Get-AdvisorProperty -InputObject $rec -Path @("ImpactedValue")
            $impactedField = Get-AdvisorProperty -InputObject $rec -Path @("ImpactedField")
            $problem       = Get-AdvisorProperty -InputObject $rec -Path @("ShortDescription","Problem")
            $solution      = Get-AdvisorProperty -InputObject $rec -Path @("ShortDescription","Solution")

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
