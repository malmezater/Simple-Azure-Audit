# ─────────────────────────────────────────────────────────────
# Checks.Advisor.ps1
# Azure Advisor: fetches all active recommendations (requires Az.Advisor).
# Recommendations are mapped to the matching Well-Architected category.
# ─────────────────────────────────────────────────────────────

function Get-AdvisorProperty {
    # Kept for backwards compatibility - use Get-PropValue in new code.
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string[]]$Path
    )
    Get-PropValue -InputObject $InputObject -Path $Path
}

function Get-AdvisorFirstValue {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][object[]]$Candidates
    )
    Get-FirstValue -InputObject $InputObject -Candidates $Candidates
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
        $advisorRecs = @(Get-AzAdvisorRecommendation -ErrorAction Stop)
    } catch {
        Write-Step "  Could not fetch Advisor data. Make sure the Az.Advisor module is installed." "DarkYellow"
        Write-Step "  ($($_.Exception.Message))" "DarkGray"
        return
    }

    Write-Step "  $($advisorRecs.Count) recommendations found." "Gray"

    foreach ($rec in $advisorRecs) {
        try {
            $impact = Get-PropValue -InputObject $rec -Path @("Impact")
            $sev = switch ($impact) {
                "High"   { "High" }
                "Medium" { "Medium" }
                "Low"    { "Low" }
                default  { "Info" }
            }

            $advisorCategory = Get-PropValue -InputObject $rec -Path @("Category")
            $category = switch ("$advisorCategory") {
                "Security"              { "Security" }
                "HighAvailability"      { "Reliability" }
                "Cost"                  { "Cost" }
                "OperationalExcellence" { "Operations" }
                "Performance"           { "Performance" }
                default                 { "Advisor" }
            }

            $impactedValue = Get-PropValue -InputObject $rec -Path @("ImpactedValue")
            $impactedField = Get-PropValue -InputObject $rec -Path @("ImpactedField")

            # The problem/solution text lives under different property names depending
            # on the Az.Advisor version: flattened (ShortDescriptionProblem) in newer
            # builds, nested (ShortDescription.Problem) in older ones.
            $problem = Get-FirstValue -InputObject $rec -Candidates @(
                @("ShortDescriptionProblem"),
                @("ShortDescription","Problem"),
                @("Problem"),
                @("Description")
            )
            $solution = Get-FirstValue -InputObject $rec -Candidates @(
                @("ShortDescriptionSolution"),
                @("ShortDescription","Solution"),
                @("Solution")
            )

            # Resource ID: either a dedicated property or the prefix of the recommendation ID.
            $resourceId = Get-FirstValue -InputObject $rec -Candidates @(
                @("ResourceMetadataResourceId"),
                @("ResourceMetadata","ResourceId")
            )
            if (-not $resourceId) {
                $recId = "$(Get-PropValue -InputObject $rec -Path @('Id'))"
                if ($recId -match '^(.+?)/providers/Microsoft\.Advisor/recommendations/') { $resourceId = $Matches[1] }
            }

            $typeId = Get-FirstValue -InputObject $rec -Candidates @(@("RecommendationTypeId"))
            $learnMore = Get-FirstValue -InputObject $rec -Candidates @(@("LearnMoreLink"))

            Add-Finding -Source "Azure Advisor" -Category $category -Severity $sev `
                -CheckId $(if ($typeId) { "ADVISOR-$typeId" } else { "" }) `
                -Title $(if ($problem) { $problem } else { "See Azure Advisor" }) `
                -Resource $(if ($impactedValue) { $impactedValue } elseif ($impactedField) { $impactedField } else { "N/A" }) `
                -ResourceId $resourceId `
                -ResourceType $(if ($impactedField) { $impactedField } else { "Unknown" }) `
                -Finding $(if ($problem) { $problem } else { "See Azure Advisor" }) `
                -Recommendation $(if ($solution) { $solution } else { "See the Azure Advisor portal" }) `
                -Reference $learnMore
        } catch {
            Write-Step "  Skipped a recommendation that could not be parsed: $($_.Exception.Message)" "DarkGray"
        }
    }
}
