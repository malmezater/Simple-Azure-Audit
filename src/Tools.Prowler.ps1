# ─────────────────────────────────────────────────────────────
# Tools.Prowler.ps1
# Prowler (https://github.com/prowler-cloud/prowler) - Apache 2.0
# Runs `prowler azure` and imports the OCSF JSON output.
#
# Install: pip install prowler      (Python 3.10 - 3.13)
# Auth:    reuses `az login` when the Azure CLI is signed in to the same tenant,
#          otherwise interactive browser sign-in (--browser-auth).
# ─────────────────────────────────────────────────────────────

function Invoke-ProwlerScan {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SubscriptionId
    )

    $exe = Get-Command prowler -ErrorAction SilentlyContinue
    if (-not $exe) {
        Write-Step "  Prowler not found. Install it with: pip install prowler" "DarkYellow"
        Save-ToolRunState -RawFolder $RawFolder -State @{ Status = "NotInstalled"; Message = "Prowler CLI not found. Install with 'pip install prowler' (Python 3.10-3.13)." }
        return
    }

    New-Item -ItemType Directory -Force -Path $RawFolder, $LogDirectory | Out-Null

    # Prefer the Azure CLI session when it already points at the right tenant.
    $authArgs = @("--browser-auth", "--tenant-id", $TenantId)
    if (Get-Command az -ErrorAction SilentlyContinue) {
        $cliTenant = (& az account show --query tenantId -o tsv 2>$null)
        if ($LASTEXITCODE -eq 0 -and "$cliTenant".Trim() -eq $TenantId) {
            $authArgs = @("--az-cli-auth")
        }
    }
    Write-Step "  Auth mode: $($authArgs[0])" "Gray"

    $version = "$(& prowler --version 2>$null)".Trim()
    $prowlerArgs = @("azure") + $authArgs + @(
        "--subscription-ids", $SubscriptionId,
        "--output-formats", "csv", "json-ocsf", "html",
        "--output-directory", $RawFolder,
        "--output-filename", "prowler",
        "--no-banner"
    )

    Write-Step "  Running: prowler $($prowlerArgs -join ' ')" "Gray"
    $log = Join-Path $LogDirectory "prowler.log"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & prowler @prowlerArgs 2>&1 | Tee-Object -FilePath $log | Out-Host
    $exit = $LASTEXITCODE
    $sw.Stop()

    # Exit code 3 means "scan completed and at least one check failed".
    $status  = if ($exit -in 0, 3) { "Succeeded" } else { "Failed" }
    $message = if ($status -eq "Failed") { "prowler exited with code $exit - see logs/prowler.log" } else { "" }
    Save-ToolRunState -RawFolder $RawFolder -State @{
        Status = $status; Message = $message; DurationSeconds = $sw.Elapsed.TotalSeconds; Version = $version; ExitCode = $exit
    }
}

function ConvertFrom-ProwlerSeverity {
    param([string]$Severity)
    switch -Regex ("$Severity") {
        '^crit'  { "Critical"; break }
        '^high'  { "High"; break }
        '^med'   { "Medium"; break }
        '^low'   { "Low"; break }
        default  { "Info" }
    }
}

function Get-ProwlerCategory {
    param([string]$Service)
    switch -Regex ("$Service".ToLower()) {
        '^(entra|iam|identity)'  { "Identity"; break }
        '^(policy)'              { "Governance"; break }
        '^(monitor|appinsights)' { "Operations"; break }
        default                  { "Security" }
    }
}

function Import-ProwlerResults {
    param(
        [Parameter(Mandatory)][string]$RawFolder,
        [Parameter(Mandatory)][string]$RunFolder
    )

    $json = Get-LatestFile -Path $RawFolder -Filter "*.ocsf.json"
    if (-not $json) {
        Complete-ToolImport -Tool "Prowler" -RawFolder $RawFolder -NoResults
        return
    }

    Write-Step "Importing $($json.Name)..."
    $items = @(Read-JsonFile $json.FullName)
    $passed = 0; $failed = 0; $count = 0; $version = ""; $scope = ""

    foreach ($f in $items) {
        if (-not $version) { $version = "$(Get-PropValue $f @('metadata','product','version'))" }
        $statusCode = "$(Get-PropValue $f 'status_code')".ToUpper()
        $muted      = "$(Get-PropValue $f 'status')" -eq "Suppressed"
        if ($statusCode -eq "PASS") { $passed++; continue }
        if ($statusCode -ne "FAIL" -or $muted) { continue }
        $failed++

        $resource = @(Get-PropValue $f 'resources') | Select-Object -First 1
        $service  = "$(Get-PropValue $resource @('group','name'))"
        $subId    = "$(Get-PropValue $f @('cloud','account','uid'))"
        if (-not $scope) { $scope = "$(Get-PropValue $f @('cloud','account','name'))" }

        # Compliance mapping: { "CIS-3.0": ["2.1.1"], "ISO27001-2022": ["A.8.1"] }
        $frameworks = ""
        $compliance = Get-PropValue $f @('unmapped','compliance')
        if ($compliance) {
            $frameworks = (@($compliance.PSObject.Properties | ForEach-Object {
                "$($_.Name): $(@($_.Value) -join ', ')"
            }) -join "; ")
            if ($frameworks.Length -gt 400) { $frameworks = $frameworks.Substring(0, 400) + " …" }
        }

        $references = @(Get-PropValue $f @('remediation','references')) | Where-Object { $_ }
        $reference  = if ($references) { $references[0] } else { "$(Get-PropValue $f @('unmapped','related_url'))" }

        Add-Finding -Source "Prowler" `
            -Category (Get-ProwlerCategory $service) `
            -Severity (ConvertFrom-ProwlerSeverity (Get-PropValue $f 'severity')) `
            -CheckId "$(Get-PropValue $f @('metadata','event_code'))" `
            -Title (ConvertTo-PlainText "$(Get-PropValue $f @('finding_info','title'))" 300) `
            -Resource "$(Get-PropValue $resource 'name')" `
            -ResourceId "$(Get-PropValue $resource 'uid')" `
            -ResourceType "$(Get-PropValue $resource 'type')" `
            -SubscriptionId $subId `
            -Finding (ConvertTo-PlainText "$(Get-FirstValue $f @(@('status_detail'), @('message')))") `
            -Recommendation (ConvertTo-PlainText "$(Get-PropValue $f @('remediation','desc'))") `
            -Reference $reference `
            -Frameworks $frameworks
        $count++
    }

    $reports = @(
        New-ReportLink -Label "Prowler HTML report" -File (Get-LatestFile -Path $RawFolder -Filter "*.html") -RunFolder $RunFolder
        New-ReportLink -Label "Prowler CSV"         -File (Get-LatestFile -Path $RawFolder -Filter "*.csv")  -RunFolder $RunFolder
    ) | Where-Object { $_ }

    Write-Step "  $failed failed / $passed passed checks imported." "Gray"
    Complete-ToolImport -Tool "Prowler" -RawFolder $RawFolder -FindingCount $count `
        -Passed $passed -Failed $failed -Total ($passed + $failed) -Version $version -Scope $scope -Reports $reports
}
