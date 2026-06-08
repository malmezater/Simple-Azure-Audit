# ─────────────────────────────────────────────────────────────
# Checks.Advisor.ps1
# Azure Advisor: fetches all active recommendations (requires Az.Advisor).
# ─────────────────────────────────────────────────────────────

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
    try {
        $advisorRecs = Get-AzAdvisorRecommendation -ErrorAction Stop
        Write-Step "  $($advisorRecs.Count) recommendations found." "Gray"

        foreach ($rec in $advisorRecs) {
            $sev = switch ($rec.Impact) {
                "High"   { "High" }
                "Medium" { "Medium" }
                "Low"    { "Low" }
                default  { "Info" }
            }
            Add-Finding -Category "Advisor" -Severity $sev `
                -Resource $(if ($rec.ImpactedValue) { $rec.ImpactedValue } elseif ($rec.ImpactedField) { $rec.ImpactedField } else { "N/A" }) `
                -ResourceType $(if ($rec.ImpactedField) { $rec.ImpactedField } else { "Unknown" }) `
                -Finding $(if ($rec.ShortDescription.Problem) { $rec.ShortDescription.Problem } else { "See Azure Advisor" }) `
                -Recommendation $(if ($rec.ShortDescription.Solution) { $rec.ShortDescription.Solution } else { "See the Azure Advisor portal" })
        }
    } catch {
        Write-Step "  Could not fetch Advisor data. Make sure the Az.Advisor module is installed." "DarkYellow"
    }
}
