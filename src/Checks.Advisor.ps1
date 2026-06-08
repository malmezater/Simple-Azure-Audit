# ─────────────────────────────────────────────────────────────
# Checks.Advisor.ps1
# Azure Advisor: hämtar alla aktiva rekommendationer (kräver Az.Advisor).
# ─────────────────────────────────────────────────────────────

function Invoke-AdvisorChecks {
    param(
        [switch]$SkipAdvisor
    )

    Write-Section "5/5 · AZURE ADVISOR"

    if ($SkipAdvisor) {
        Write-Step "Hoppade över Advisor (parametern -SkipAdvisor angiven)." "DarkGray"
        return
    }

    Write-Step "Hämtar Azure Advisor-rekommendationer..."
    try {
        $advisorRecs = Get-AzAdvisorRecommendation -ErrorAction Stop
        Write-Step "  $($advisorRecs.Count) rekommendationer hittades." "Gray"

        foreach ($rec in $advisorRecs) {
            $sev = switch ($rec.Impact) {
                "High"   { "High" }
                "Medium" { "Medium" }
                "Low"    { "Low" }
                default  { "Info" }
            }
            Add-Finding -Category "Advisor" -Severity $sev `
                -Resource $(if ($rec.ImpactedValue) { $rec.ImpactedValue } elseif ($rec.ImpactedField) { $rec.ImpactedField } else { "N/A" }) `
                -ResourceType $(if ($rec.ImpactedField) { $rec.ImpactedField } else { "Okänd" }) `
                -Finding $(if ($rec.ShortDescription.Problem) { $rec.ShortDescription.Problem } else { "Se Azure Advisor" }) `
                -Recommendation $(if ($rec.ShortDescription.Solution) { $rec.ShortDescription.Solution } else { "Se Azure Advisor-portalen" })
        }
    } catch {
        Write-Step "  Kunde inte hämta Advisor-data. Kontrollera att Az.Advisor-modulen är installerad." "DarkYellow"
    }
}
