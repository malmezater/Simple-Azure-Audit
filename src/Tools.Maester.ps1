# ─────────────────────────────────────────────────────────────
# Tools.Maester.ps1
# Maester (https://maester.dev) - MIT
# Runs the Maester test suite (Entra ID, Conditional Access, EIDSCA,
# CISA/CIS, Azure) in a child process and imports the JSON results.
#
# Install: Install-Module Maester, Pester -Scope CurrentUser
# Auth:    Connect-Maester -Service Azure,Graph (interactive, delegated).
#          Needs a user that can read the directory and Conditional Access policies
#          (Global Reader is recommended).
# ─────────────────────────────────────────────────────────────

function Invoke-MaesterScan {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ToolsPath,
        [switch]$InstallMissing
    )

    $ok = (Install-AuditModule -Name "Pester" -InstallMissing:$InstallMissing) -and
          (Install-AuditModule -Name "Maester" -InstallMissing:$InstallMissing)
    if (-not $ok) {
        Write-Step "  Maester/Pester not installed. Run with -InstallMissing or: Install-Module Maester, Pester -Scope CurrentUser" "DarkYellow"
        Save-ToolRunState -RawFolder $RawFolder -State @{ Status = "NotInstalled"; Message = "Modules Maester and Pester are required (Install-Module Maester, Pester -Scope CurrentUser)." }
        return
    }

    $testsPath = Join-Path $ToolsPath "maester-tests"
    $script = @"
Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
Import-Module Maester -ErrorAction Stop
`$tests = $(ConvertTo-PSLiteral $testsPath)
if (-not (Test-Path (Join-Path `$tests '*'))) {
    New-Item -ItemType Directory -Force -Path `$tests | Out-Null
    Install-MaesterTests -Path `$tests
} else {
    try { Update-MaesterTests -Path `$tests } catch { Write-Host "Could not update Maester tests: `$(`$_.Exception.Message)" -ForegroundColor DarkYellow }
}
Connect-Maester -Service Azure,Graph -TenantId $(ConvertTo-PSLiteral $TenantId)
Invoke-Maester -Path `$tests -OutputFolder $(ConvertTo-PSLiteral $RawFolder) -OutputFolderFileName 'maester' -NonInteractive -NoLogo -SkipGraphConnect
"@

    Write-Step "  Starting Maester (a browser sign-in to Microsoft Graph may open)..." "Gray"
    $r = Invoke-ToolProcess -Name "Maester" -ScriptText $script -WorkingDirectory $RawFolder -LogDirectory $LogDirectory
    $status = if ($r.ExitCode -eq 0) { "Succeeded" } else { "Failed" }
    Save-ToolRunState -RawFolder $RawFolder -State @{
        Status = $status
        Message = $(if ($status -eq "Failed") { "Maester exited with code $($r.ExitCode) - see logs/maester.log" } else { "" })
        DurationSeconds = $r.DurationSeconds
        Version = (Get-ModuleVersionString "Maester")
    }
}

function Get-MaesterCategory {
    param([string[]]$Tags, [string]$Id)
    $joined = (@($Tags) + @($Id)) -join " "
    if ($joined -match '\bAzure\b')                            { return "Security" }
    if ($joined -match '\b(XSPM|Defender|MDI|MDE)\b')          { return "Security" }
    if ($joined -match '\b(Exchange|EXO|ORCA|Teams|SharePoint|SPO)\b') { return "Security" }
    return "Identity"
}

function Import-MaesterResults {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder
    )

    $json = Get-ChildItem -Path $RawFolder -Filter "*.json" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne "_run.json" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $json) {
        Complete-ToolImport -Tool "Maester" -RawFolder $RawFolder -NoResults
        return
    }

    Write-Step "Importing $($json.Name)..."
    $data  = Read-JsonFile $json.FullName
    $tests = @(Get-PropValue $data 'Tests')
    $tenantName = "$(Get-PropValue $data 'TenantName')"
    $tenantId   = "$(Get-PropValue $data 'TenantId')"
    $resourceLabel = if ($tenantName) { "Tenant: $tenantName" } else { "Tenant: $tenantId" }
    $count = 0

    foreach ($t in $tests) {
        $result = "$(Get-PropValue $t 'Result')"
        if ($result -notin @("Failed", "Investigate")) { continue }

        $sevRaw = "$(Get-PropValue $t 'Severity')"
        $severity = if ($result -eq "Investigate") { "Info" }
                    elseif ($sevRaw -in $script:AuditSeverities) { $sevRaw }
                    else { "Medium" }

        $id    = "$(Get-PropValue $t 'Id')"
        $title = "$(Get-PropValue $t 'Title')"
        if (-not $title) { $title = "$(Get-PropValue $t 'Name')" }
        $tags  = @(Get-PropValue $t 'Tag') | Where-Object { $_ }

        $description = ConvertTo-PlainText "$(Get-PropValue $t @('ResultDetail','TestDescription'))" 1200
        $detail      = ConvertTo-PlainText "$(Get-PropValue $t @('ResultDetail','TestResult'))" 1200
        if ($result -eq "Investigate") { $detail = "Needs manual investigation. $detail" }

        Add-Finding -Source "Maester" `
            -Category (Get-MaesterCategory -Tags $tags -Id $id) `
            -Severity $severity `
            -CheckId $id `
            -Title $title `
            -Resource $resourceLabel `
            -ResourceType "Microsoft Entra tenant" `
            -ResourceId "" `
            -SubscriptionId "-" `
            -Finding $(if ($detail) { $detail } else { $title }) `
            -Recommendation $(if ($description) { $description } else { "See the Maester documentation for this test." }) `
            -Reference "$(Get-PropValue $t 'HelpUrl')" `
            -Frameworks (@($tags | Where-Object { $_ -match '^(CIS|CISA|EIDSCA|MS\.|ORCA)' }) -join ", ")
        $count++
    }

    $passedCount = [int]("$(Get-PropValue $data 'PassedCount')" -replace '\D', '0')
    $failedCount = [int]("$(Get-PropValue $data 'FailedCount')" -replace '\D', '0')

    $reports = @(
        New-ReportLink -Label "Maester HTML report" -File (Get-LatestFile -Path $RawFolder -Filter "*.html") -RunFolder $RunFolder
        New-ReportLink -Label "Maester Markdown"    -File (Get-ChildItem -Path $RawFolder -Filter "*.md" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*-summary.md" } | Select-Object -First 1) -RunFolder $RunFolder
    ) | Where-Object { $_ }

    Write-Step "  $failedCount failed / $passedCount passed tests imported." "Gray"
    Complete-ToolImport -Tool "Maester" -RawFolder $RawFolder -FindingCount $count `
        -Passed $passedCount -Failed $failedCount -Total ($passedCount + $failedCount) `
        -Version "$(Get-PropValue $data 'CurrentVersion')" -Scope $resourceLabel -Reports $reports
}
