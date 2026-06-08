# ─────────────────────────────────────────────────────────────
# AuditCommon.ps1
# Shared helper functions and the common findings collection.
# Dot-sourced from the main script (Invoke-AzureAudit.ps1).
# ─────────────────────────────────────────────────────────────

# Shared list that every check function writes its findings to.
$script:AuditFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Step {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "  $Msg" -ForegroundColor $Color
}

function Write-Section {
    param([string]$Msg)
    Write-Host "`n[$Msg]" -ForegroundColor Magenta
}

function Add-Finding {
    param(
        [ValidateSet("Security","Cost","Infrastructure","Compliance","Advisor")][string]$Category,
        [ValidateSet("Critical","High","Medium","Low","Info")][string]$Severity,
        [string]$Resource,
        [string]$ResourceType,
        [string]$Finding,
        [string]$Recommendation
    )
    $script:AuditFindings.Add([PSCustomObject]@{
        Category       = $Category
        Severity       = $Severity
        Resource       = $Resource
        ResourceType   = $ResourceType
        Finding        = $Finding
        Recommendation = $Recommendation
        Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm")
    })
}

function Get-AuditFindings {
    # Returns the shared findings collection.
    , $script:AuditFindings
}

function Clear-AuditFindings {
    $script:AuditFindings.Clear()
}
