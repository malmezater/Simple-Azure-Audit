# ─────────────────────────────────────────────────────────────
# Tools.ARI.ps1
# Azure Resource Inventory (https://github.com/microsoft/ARI) - MIT
# Produces an Excel inventory and a draw.io network diagram. ARI has no
# pass/fail findings, so it is linked from the report as an appendix.
#
# Install: Install-Module AzureResourceInventory -Scope CurrentUser
# ─────────────────────────────────────────────────────────────

function Invoke-ARIScan {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [switch]$InstallMissing
    )

    if (-not (Install-AuditModule -Name "AzureResourceInventory" -InstallMissing:$InstallMissing)) {
        Write-Step "  AzureResourceInventory not installed. Run with -InstallMissing or: Install-Module AzureResourceInventory -Scope CurrentUser" "DarkYellow"
        Save-ToolRunState -RawFolder $RawFolder -State @{ Status = "NotInstalled"; Message = "Module AzureResourceInventory is required (Install-Module AzureResourceInventory -Scope CurrentUser)." }
        return
    }

    # Advisor and Defender data are already covered by the other checks, so ARI stays an inventory.
    $script = @"
Import-Module AzureResourceInventory -ErrorAction Stop
Invoke-ARI -TenantID $(ConvertTo-PSLiteral $TenantId) -SubscriptionID $(ConvertTo-PSArrayLiteral $SubscriptionIds) ``
    -ReportDir $(ConvertTo-PSLiteral $RawFolder) -ReportName 'ARI' -IncludeTags -SkipAdvisory -NoAutoUpdate
"@

    Write-Step "  Running Invoke-ARI..." "Gray"
    $r = Invoke-ToolProcess -Name "ARI" -ScriptText $script -WorkingDirectory $RawFolder -LogDirectory $LogDirectory
    $hasOutput = [bool](Get-LatestFile -Path $RawFolder -Filter "*.xlsx" -Recurse)
    Save-ToolRunState -RawFolder $RawFolder -State @{
        Status = $(if ($hasOutput) { "Succeeded" } else { "Failed" })
        Message = $(if (-not $hasOutput) { "No Excel inventory produced (exit code $($r.ExitCode)) - see logs/ari.log." } else { "" })
        DurationSeconds = $r.DurationSeconds
        Version = (Get-ModuleVersionString "AzureResourceInventory")
    }
}

function Import-ARIResults {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder
    )

    $xlsx = Get-LatestFile -Path $RawFolder -Filter "*.xlsx" -Recurse
    if (-not $xlsx) {
        Complete-ToolImport -Tool "ARI" -RawFolder $RawFolder -NoResults
        return
    }
    $diagram = Get-LatestFile -Path $RawFolder -Filter "*.xml" -Recurse

    $reports = @(
        New-ReportLink -Label "Resource inventory (Excel)" -File $xlsx -RunFolder $RunFolder
        New-ReportLink -Label "Network diagram (draw.io)"  -File $diagram -RunFolder $RunFolder
    ) | Where-Object { $_ }

    Write-Step "  Inventory linked: $($xlsx.Name)" "Gray"
    Complete-ToolImport -Tool "ARI" -RawFolder $RawFolder -FindingCount 0 -Reports $reports
}
