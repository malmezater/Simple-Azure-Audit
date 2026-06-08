# ─────────────────────────────────────────────────────────────
# AuditCommon.ps1
# Gemensamma hjälpfunktioner och delad fyndsamling för Azure Audit.
# Dot-source:as in i huvudskriptet (Invoke-AzureAudit.ps1).
# ─────────────────────────────────────────────────────────────

# Delad lista som alla kontrollfunktioner skriver sina fynd till.
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
        [ValidateSet("Säkerhet","Kostnad","Infrastruktur","Compliance","Advisor")][string]$Category,
        [ValidateSet("Critical","High","Medium","Low","Info")][string]$Severity,
        [string]$Resource,
        [string]$ResourceType,
        [string]$Finding,
        [string]$Recommendation
    )
    $script:AuditFindings.Add([PSCustomObject]@{
        Kategori       = $Category
        Allvarlighet   = $Severity
        Resurs         = $Resource
        Resurstyp      = $ResourceType
        Fynd           = $Finding
        Rekommendation = $Recommendation
        Tidstämpel     = (Get-Date -Format "yyyy-MM-dd HH:mm")
    })
}

function Get-AuditFindings {
    # Returnerar den delade fyndsamlingen.
    , $script:AuditFindings
}

function Clear-AuditFindings {
    $script:AuditFindings.Clear()
}
