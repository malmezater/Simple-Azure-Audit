# ─────────────────────────────────────────────────────────────
# Checks.Governance.ps1
# Governance & clean-up: resources that look temporary (temp, tmp, tillfällig, delete-me),
# test/PoC/demo resources outside a test environment, old copies and leftovers, and
# resources past the date in their own expiry tag, resource groups without an owner, and
# temporary/test resources reachable from the Internet.
#
# Runs once for all subscriptions in scope, so a naming convention that spans
# subscriptions (rg-app-test in one, rg-app-prod in another) is recognised.
# ─────────────────────────────────────────────────────────────

# Words looked for in names. Kind decides how a hit is judged:
#   Temporary  always reported - nothing named temp/tmp is meant to live for ever
#   Test       reported only when the word is not an environment (see Test-EnvironmentContext)
#   Leftover   old copies and resources marked as unused
# Names are lower-cased and å/ä/ö folded to a/a/o before matching.
$script:GovNameKeywords = @{
    "temp" = "Temporary"; "tmp" = "Temporary"; "temporary" = "Temporary"
    "tillfallig" = "Temporary"; "tillfalligt" = "Temporary"; "tillfalliga" = "Temporary"; "tillf" = "Temporary"
    "throwaway" = "Temporary"; "scratch" = "Temporary"; "dummy" = "Temporary"; "junk" = "Temporary"
    "trash" = "Temporary"; "skrap" = "Temporary"; "delete" = "Temporary"; "deleteme" = "Temporary"

    "test" = "Test"; "tests" = "Test"; "testing" = "Test"; "tst" = "Test"; "testa" = "Test"
    "prova" = "Test"; "poc" = "Test"; "demo" = "Test"; "trial" = "Test"; "experiment" = "Test"
    "sandbox" = "Test"; "sbx" = "Test"; "lab" = "Test"; "playground" = "Test"

    "old" = "Leftover"; "gammal" = "Leftover"; "gamla" = "Leftover"; "copy" = "Leftover"; "kopia" = "Leftover"
    "unused" = "Leftover"; "oanvand" = "Leftover"; "deprecated" = "Leftover"; "obsolete" = "Leftover"
}

# Also matched inside names without separators (storage accounts: sttempdata01, vmtest01).
$script:GovGlueKeywords = @("temporary", "tillfallig", "temp", "tmp", "test", "throwaway", "dummy")
# Multi-word markers, matched against the whole name with separators removed (to-delete, ta_bort).
$script:GovPhraseKeywords = @("deleteme", "todelete", "removeme", "tabort", "donotuse", "dontuse")
# Ordinary words that contain a glue keyword and must not count as a hit.
$script:GovFalsePositives = @("template", "temperature", "tempest", "tempo", "temporal", "contemporar",
    "latest", "attest", "contest", "protest", "detest", "testament", "testimon", "greatest", "fastest",
    "smartest", "shortest", "intestin")

# Environment designators in naming conventions. Production ones are excluded from "non-production".
$script:GovEnvTokens = @("dev", "devel", "develop", "development", "test", "tst", "qa", "uat", "acc", "acpt",
    "accept", "acceptance", "stage", "staging", "stg", "preprod", "pre", "nonprod", "int", "sit", "perf",
    "sandbox", "sbx", "lab", "demo", "prod", "production", "prd", "live")
$script:GovProdTokens = @("prod", "production", "prd", "live", "produktion")

$script:GovEnvTagKey    = '^(env|environment|environment[-_ ]?(name|type)|miljo|miljö|stage|lifecycle)$'
$script:GovOwnerTagKey  = '^(owner|owners|owned[-_ ]?by|owner[-_ ]?(email|name|team)|contact|technical[-_ ]?contact|responsible|team|agare|ägare|ansvarig|created[-_ ]?by)$'
$script:GovOwnerlessDays = 90    # resource groups younger than this are not reported as ownerless
$script:GovExpiryTagKey ='(expir|delete[-_ ]?(after|on|by|date)|remove[-_ ]?(after|on|by)|end[-_ ]?date|valid[-_ ]?until|ta[-_ ]?bort|utg[aå]r)'

function ConvertTo-GovNormalizedName {
    param([string]$Name)
    return ($Name.ToLowerInvariant() -replace '[åä]', 'a' -replace 'ö', 'o')
}

function Get-GovNameTokens {
    # "vmTempWeb01" -> vm, temp, web ; "rg-app_test.2" -> rg, app, test
    param([string]$Name)
    $n = $Name -creplace '(\p{Ll})(\p{Lu})', '$1 $2'
    $n = $n -replace '(\p{L})(\p{N})', '$1 $2' -replace '(\p{N})(\p{L})', '$1 $2'
    $n = ConvertTo-GovNormalizedName $n
    return @($n -split '[^\p{L}\p{N}]+' | Where-Object { $_ -and $_ -notmatch '^\d+$' })
}

function Find-GovNameHits {
    # Returns @{ Word; Kind } for every keyword found in the name.
    param([string]$Name)
    $tokens = Get-GovNameTokens $Name
    $hits = [ordered]@{}
    foreach ($t in $tokens) {
        if ($script:GovNameKeywords.ContainsKey($t)) { $hits[$t] = $script:GovNameKeywords[$t]; continue }
        foreach ($w in $script:GovGlueKeywords) {
            if ($t.Length -le $w.Length -or -not $t.Contains($w)) { continue }
            if (@($script:GovFalsePositives | Where-Object { $_.Contains($w) -and $t.Contains($_) }).Count -gt 0) { continue }
            $hits[$w] = $script:GovNameKeywords[$w]
            break
        }
    }
    $joined = $tokens -join ''
    foreach ($p in $script:GovPhraseKeywords) {
        if ($joined.Contains($p)) { $hits[$p] = "Temporary" }
    }
    return @($hits.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Word = $_.Key; Kind = $_.Value } })
}

function Test-GovNonProdName {
    # True when a resource group / subscription name marks a non-production environment.
    param([string]$Name)
    if (-not $Name) { return $false }
    if ((ConvertTo-GovNormalizedName $Name) -match 'non[-_ ]?prod') { return $true }
    $nonProd = $script:GovEnvTokens | Where-Object { $_ -notin $script:GovProdTokens }
    return @(Get-GovNameTokens $Name | Where-Object { $_ -in $nonProd }).Count -gt 0
}

function Test-GovEnvSibling {
    # True when the same name exists with the word swapped for another environment,
    # e.g. "app-test-func" next to "app-prod-func" - then "test" is an environment, not a test.
    param([string]$Name, [string]$Word, [System.Collections.Generic.HashSet[string]]$KnownNames)
    if ($Word -notin $script:GovEnvTokens) { return $false }
    $lname = ConvertTo-GovNormalizedName $Name
    $bounded = "(?<![a-z])$([regex]::Escape($Word))(?![a-z])"
    foreach ($e in $script:GovEnvTokens) {
        if ($e -eq $Word) { continue }
        $candidate = [regex]::Replace($lname, $bounded, $e)
        if ($candidate -ne $lname -and $KnownNames.Contains($candidate)) { return $true }
        $candidate = $lname.Replace($Word, $e)
        if ($candidate -ne $lname -and $KnownNames.Contains($candidate)) { return $true }
    }
    return $false
}

function Get-GovEnvTag {
    # Value of the first Environment-like tag, or $null.
    param($Tags)
    if (-not $Tags) { return $null }
    foreach ($key in @($Tags.Keys)) {
        if ($key -match $script:GovEnvTagKey -and "$($Tags[$key])".Trim()) {
            return [PSCustomObject]@{ Key = $key; Value = "$($Tags[$key])".Trim() }
        }
    }
    return $null
}

function Test-GovOwnerTag {
    # True when an owner-like tag (Owner, Contact, CreatedBy, Ägare ...) has a value.
    param($Tags)
    if (-not $Tags) { return $false }
    return @($Tags.Keys | Where-Object { $_ -match $script:GovOwnerTagKey -and "$($Tags[$_])".Trim() }).Count -gt 0
}

function Get-GovExpiredTag {
    # First expiry-like tag (DeleteAfter, ExpiresOn, ...) whose date has passed, or $null.
    param($Tags)
    if (-not $Tags) { return $null }
    $formats = [string[]]@("yyyy-MM-dd", "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-dd HH:mm",
                          "yyyyMMdd", "yyyy/MM/dd", "dd/MM/yyyy", "dd.MM.yyyy", "dd-MM-yyyy")
    foreach ($key in @($Tags.Keys)) {
        if ($key -notmatch $script:GovExpiryTagKey) { continue }
        $value = "$($Tags[$key])".Trim()
        $date = [datetime]::MinValue
        $ok = [datetime]::TryParseExact($value, $formats, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)
        if (-not $ok) { $ok = [datetime]::TryParse($value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date) }
        if ($ok -and $date.Date -lt (Get-Date).Date) {
            return [PSCustomObject]@{ Key = $key; Value = $value; Date = $date }
        }
    }
    return $null
}

function ConvertTo-GovDate {
    param($Value)
    if (-not $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $date = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$date)) { return $date }
    return $null
}

function Invoke-GovArmList {
    # GET an ARM list endpoint and follow nextLink. Returns $null when the call fails.
    param([Parameter(Mandatory)][string]$Path)
    $items = [System.Collections.Generic.List[object]]::new()
    $resp = Invoke-AzRestMethod -Path $Path -Method GET
    while ($resp) {
        if ($resp.StatusCode -ne 200) { return $null }
        $page = $resp.Content | ConvertFrom-Json -AsHashtable
        foreach ($v in @($page['value'])) { if ($v) { $items.Add($v) } }
        $next = $page['nextLink']
        $resp = if ($next) { Invoke-AzRestMethod -Uri $next -Method GET } else { $null }
    }
    return , $items
}

function Get-GovAgeText {
    param($Created, $Changed)
    $parts = @()
    if ($Created) { $parts += "Created $($Created.ToString('yyyy-MM-dd')) ($([int]((Get-Date) - $Created).TotalDays) days ago)" }
    if ($Changed) { $parts += "last changed $($Changed.ToString('yyyy-MM-dd'))" }
    if ($parts.Count -eq 0) { return "" }
    return " $($parts -join ', ')."
}

function Invoke-GovernanceChecks {
    param(
        [Parameter(Mandatory)][object[]]$Subscriptions    # @{ Id; Name }
    )

    Write-Section "GOVERNANCE - TEMPORARY, OWNERLESS & EXPOSED RESOURCES (all subscriptions)"

    # ── Collect resource groups and resources (with created/changed time) ──
    $data = @()
    foreach ($sub in $Subscriptions) {
        Write-Step "Reading resources in $($sub.Name)..."
        $rgs = Invoke-GovArmList "/subscriptions/$($sub.Id)/resourcegroups?api-version=2021-04-01"
        $res = Invoke-GovArmList "/subscriptions/$($sub.Id)/resources?`$expand=createdTime,changedTime&api-version=2021-04-01"
        if ($null -eq $rgs -or $null -eq $res) {
            Write-Step "  Could not list resources in $($sub.Name) - skipped." "DarkYellow"
            continue
        }
        $data += [PSCustomObject]@{ Sub = $sub; ResourceGroups = $rgs; Resources = $res }
    }

    # Every name in scope, for recognising naming conventions (app-test / app-prod)
    $knownNames = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($d in $data) {
        [void]$knownNames.Add((ConvertTo-GovNormalizedName $d.Sub.Name))
        foreach ($rg in $d.ResourceGroups) { [void]$knownNames.Add((ConvertTo-GovNormalizedName "$($rg['name'])")) }
        foreach ($r in $d.Resources) { [void]$knownNames.Add((ConvertTo-GovNormalizedName (("$($r['name'])" -split '/')[-1]))) }
    }

    $recommendation = @{
        Temporary = "Confirm with the owner whether it is still needed and delete it if not. If it must stay, rename it and add Owner and Environment tags. Temporary resources are often created outside normal hardening, monitoring and backup (open NSG rules, public endpoints, shared keys, no patching) and are easily forgotten. Give temporary work an expiry tag (e.g. DeleteAfter) or a sandbox subscription with a budget and automatic clean-up."
        Test      = "Move test, PoC and demo workloads to a dedicated dev/test subscription or resource group with its own policies, or tag them with Environment and Owner. Delete them when the test is finished. Test resources in production scope often have weaker settings but still reach production networks and data."
        Leftover  = "Check whether the old copy or unused resource is still needed. Old copies keep data, keys and credentials that are no longer maintained or monitored. Delete them, or keep them as a backup with a defined retention."
    }
    $titles = @{
        Temporary = @("NATIVE-GOV-001", "Resource name suggests a temporary resource")
        Test      = @("NATIVE-GOV-002", "Test, PoC or demo resource outside a test environment")
        Leftover  = @("NATIVE-GOV-003", "Resource name suggests an old copy or unused leftover")
    }

    # Judges one name. Returns $null or @{ Kind; Words; Note } after removing Test hits that are environments.
    $evaluate = {
        param([string]$Name, $Tags, $ParentTags, [string[]]$Containers, [switch]$NoTestKind)
        $hits = @(Find-GovNameHits $Name)

        # An Environment tag of "Temp" / "Temporary" is as telling as the name
        $envTag = Get-GovEnvTag $Tags
        if (-not $envTag) { $envTag = Get-GovEnvTag $ParentTags }
        if ($envTag) {
            foreach ($h in @(Find-GovNameHits $envTag.Value | Where-Object { $_.Kind -eq "Temporary" })) {
                $hits += [PSCustomObject]@{ Word = "$($envTag.Key)=$($envTag.Value)"; Kind = "Temporary" }
            }
        }

        $note = ""
        $testHits = @($hits | Where-Object { $_.Kind -eq "Test" })
        if ($testHits.Count -gt 0) {
            $isEnvironment = $NoTestKind.IsPresent
            if (-not $isEnvironment -and $envTag) {
                if ((Get-GovNameTokens $envTag.Value | Where-Object { $_ -in $script:GovProdTokens })) {
                    $note = " it is tagged $($envTag.Key)=$($envTag.Value)."
                } else { $isEnvironment = $true }
            }
            if (-not $isEnvironment -and -not $note) {
                $isEnvironment = @($Containers | Where-Object { Test-GovNonProdName $_ }).Count -gt 0
            }
            if (-not $isEnvironment) {
                $isEnvironment = @($testHits | Where-Object { Test-GovEnvSibling -Name $Name -Word $_.Word -KnownNames $knownNames }).Count -gt 0
            }
            if ($isEnvironment) { $hits = @($hits | Where-Object { $_.Kind -ne "Test" }) }
        }
        if ($hits.Count -eq 0) { return $null }

        $kind = foreach ($k in "Temporary", "Test", "Leftover") { if ($hits.Kind -contains $k) { $k; break } }
        [PSCustomObject]@{ Kind = $kind; Words = @($hits.Word | Select-Object -Unique); Note = $note }
    }

    $severityFor = {
        param([string]$Kind, $Created, [string]$Note)
        $young = $Created -and ((Get-Date) - $Created).TotalDays -lt 30
        switch ($Kind) {
            "Temporary" { if ($young) { "Low" } else { "Medium" } }
            "Test"      { if ($Note) { "Medium" } elseif ($young) { "Info" } else { "Low" } }
            default     { if ($young) { "Info" } else { "Low" } }
        }
    }

    $counts = @{ Temporary = 0; Test = 0; Leftover = 0; Expired = 0; Ownerless = 0; Exposed = 0 }
    $flagged = @{}    # lower-case id of every reported subscription / RG / resource -> Kind
    $addHit = {
        param($Hit, [string]$Resource, [string]$ResourceId, [string]$ResourceType, [string]$SubscriptionId, $Created, $Changed, [string]$Extra)
        $words = ($Hit.Words | ForEach-Object { "'$_'" }) -join ", "
        $text = switch ($Hit.Kind) {
            "Temporary" { "Name contains $words, which marks it as temporary." }
            "Test"      {
                if ($Hit.Note) { "Name contains $words, but$($Hit.Note)" }
                else { "Name contains $words, but it is not part of a test environment (no non-production Environment tag, resource group or subscription, and no matching dev/prod sibling)." }
            }
            default     { "Name contains $words, which suggests an old copy or a leftover." }
        }
        Add-Finding -Category "Governance" -Severity (& $severityFor $Hit.Kind $Created $Hit.Note) `
            -CheckId $titles[$Hit.Kind][0] -Title $titles[$Hit.Kind][1] `
            -Resource $Resource -ResourceId $ResourceId -ResourceType $ResourceType -SubscriptionId $SubscriptionId `
            -Finding "$text$Extra$(Get-GovAgeText $Created $Changed)" `
            -Recommendation $recommendation[$Hit.Kind]
        $counts[$Hit.Kind]++
        $flagged[$ResourceId.ToLower()] = $Hit.Kind
    }
    # Kind and name of the reported scope a resource id falls under (itself, its RG or its subscription), or $null
    $flaggedScope = {
        param([string]$ResourceId)
        $id = $ResourceId.ToLower()
        $candidates = @($id)
        if ($id -match '^(/subscriptions/[^/]+/resourcegroups/[^/]+)') { $candidates += $Matches[1] }
        if ($id -match '^(/subscriptions/[^/]+)') { $candidates += $Matches[1] }
        foreach ($c in $candidates) {
            if ($flagged.ContainsKey($c)) { return [PSCustomObject]@{ Kind = $flagged[$c]; Name = Get-ResourceNameFromId $c } }
        }
        return $null
    }
    $addExpired = {
        param($Expired, [string]$Resource, [string]$ResourceId, [string]$ResourceType, [string]$SubscriptionId)
        Add-Finding -Category "Governance" -Severity "Medium" `
            -CheckId "NATIVE-GOV-004" -Title "Resource is past the date in its expiry tag" `
            -Resource $Resource -ResourceId $ResourceId -ResourceType $ResourceType -SubscriptionId $SubscriptionId `
            -Finding "Tag $($Expired.Key)=$($Expired.Value) passed $([int]((Get-Date) - $Expired.Date).TotalDays) days ago." `
            -Recommendation "The resource's own expiry tag says it should have been removed. Delete it, or set a new date and an Owner tag if it is still needed."
        $counts.Expired++
    }

    foreach ($d in $data) {
        $sub = $d.Sub
        $subId = "$($sub.Id)".ToLower()

        # Subscription name: only temporary/leftover - "Test" is a normal subscription environment
        $hit = & $evaluate -Name $sub.Name -NoTestKind
        if ($hit) {
            & $addHit $hit $sub.Name "/subscriptions/$subId" "Subscription" $subId $null $null ""
        }

        # Resources per resource group, for RG age and size
        $byRg = @{}
        foreach ($r in $d.Resources) {
            if ("$($r['id'])" -match '/resourceGroups/([^/]+)/') {
                $key = $Matches[1].ToLower()
                if (-not $byRg.ContainsKey($key)) { $byRg[$key] = [System.Collections.Generic.List[object]]::new() }
                $byRg[$key].Add($r)
            }
        }

        $skipRgs = @{}    # managed RGs (AKS MC_*, Databricks, ...) and RGs already reported as a whole
        $rgTags  = @{}
        foreach ($rg in $d.ResourceGroups) {
            $rgName = "$($rg['name'])"
            $key = $rgName.ToLower()
            $rgTags[$key] = $rg['tags']
            if ($rg['managedBy']) { $skipRgs[$key] = $true; continue }

            $members = if ($byRg.ContainsKey($key)) { $byRg[$key] } else { @() }
            # RG age = its oldest resource, last change = its most recently changed resource
            $created = $members | ForEach-Object { ConvertTo-GovDate $_['createdTime'] } | Where-Object { $_ } | Sort-Object | Select-Object -First 1
            $changed = $members | ForEach-Object { ConvertTo-GovDate $_['changedTime'] } | Where-Object { $_ } | Sort-Object | Select-Object -Last 1

            $hit = & $evaluate -Name $rgName -Tags $rg['tags'] -Containers @($sub.Name)
            if ($hit) {
                $count = @($members).Count
                $extra = if ($count -gt 0) { " The resource group holds $count resource(s); they are not listed separately." } else { " The resource group is empty." }
                & $addHit $hit $rgName "$($rg['id'])" "Resource Group" $subId $created $changed $extra
                $skipRgs[$key] = $true
            }
            elseif (@($members).Count -gt 0 -and $created -and ((Get-Date) - $created).TotalDays -ge $script:GovOwnerlessDays -and
                    -not (Test-GovOwnerTag $rg['tags']) -and @($members | Where-Object { Test-GovOwnerTag $_['tags'] }).Count -eq 0) {
                Add-Finding -Category "Governance" -Severity "Low" `
                    -CheckId "NATIVE-GOV-005" -Title "Resource group without an owner" `
                    -Resource $rgName -ResourceId "$($rg['id'])" -ResourceType "Resource Group" -SubscriptionId $subId `
                    -Finding "Neither the resource group nor any of its $(@($members).Count) resource(s) has an owner tag (Owner, Contact, CreatedBy ...).$(Get-GovAgeText $created $changed)" `
                    -Recommendation "Find out who is responsible and add an Owner tag to the resource group (inherit it to resources with Azure Policy). Require an Owner tag on new resource groups with the built-in policy 'Require a tag on resource groups'. Without an owner nobody approves changes, answers alerts or decides when it can be removed."
                $counts.Ownerless++
            }
            $expired = Get-GovExpiredTag $rg['tags']
            if ($expired) { & $addExpired $expired $rgName "$($rg['id'])" "Resource Group" $subId }
        }

        foreach ($r in $d.Resources) {
            $id = "$($r['id'])"
            $rgKey = if ($id -match '/resourceGroups/([^/]+)/') { $Matches[1].ToLower() } else { "" }
            if ($rgKey -and $skipRgs.ContainsKey($rgKey)) { continue }

            $fullName = "$($r['name'])"
            $leaf = ($fullName -split '/')[-1]
            $rgName = if ($rgKey -and $id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { "" }
            $display = if ($rgName) { "$fullName ($rgName)" } else { $fullName }
            $type = "$($r['type'])"

            $hit = & $evaluate -Name $leaf -Tags $r['tags'] -ParentTags $rgTags[$rgKey] -Containers @($rgName, $sub.Name)
            if ($hit) {
                & $addHit $hit $display $id $type $subId (ConvertTo-GovDate $r['createdTime']) (ConvertTo-GovDate $r['changedTime']) ""
            }
            $expired = Get-GovExpiredTag $r['tags']
            if ($expired) { & $addExpired $expired $display $id $type $subId }
        }

        # ── Temporary / test resources reachable from the Internet ──
        if ($flagged.Count -eq 0) { continue }
        $exposures = [System.Collections.Generic.List[object]]::new()   # @{ Id; What }

        # Public IPs: flagged when the IP itself, the resource it is attached to or that resource's VM is flagged
        $pips = Invoke-GovArmList "/subscriptions/$subId/providers/Microsoft.Network/publicIPAddresses?api-version=2023-09-01"
        $nics = Invoke-GovArmList "/subscriptions/$subId/providers/Microsoft.Network/networkInterfaces?api-version=2023-09-01"
        $nicVm = @{}
        foreach ($nic in @($nics)) {
            $vmId = Get-PropValue $nic @('properties', 'virtualMachine', 'id')
            if ($vmId) { $nicVm["$($nic['id'])".ToLower()] = "$vmId" }
        }
        foreach ($pip in @($pips)) {
            $configId = "$(Get-PropValue $pip @('properties', 'ipConfiguration', 'id'))"
            if (-not $configId) { continue }   # unattached IPs are covered by NATIVE-SEC-002
            $parentId = ($configId -split '/')[0..8] -join '/'     # /subscriptions/x/resourceGroups/y/providers/ns/type/name
            $related = @("$($pip['id'])", $parentId)
            if ($nicVm.ContainsKey($parentId.ToLower())) { $related += $nicVm[$parentId.ToLower()] }
            $ip = Get-PropValue $pip @('properties', 'ipAddress')
            foreach ($rid in $related) {
                $scope = & $flaggedScope $rid
                if ($scope) {
                    $exposures.Add([PSCustomObject]@{ Id = $rid; Scope = $scope; What = "public IP $($pip['name'])$(if ($ip) { " ($ip)" })" })
                    break
                }
            }
        }

        # Storage accounts open to all networks
        $storage = Invoke-GovArmList "/subscriptions/$subId/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01"
        foreach ($sa in @($storage)) {
            $scope = & $flaggedScope "$($sa['id'])"
            if (-not $scope) { continue }
            $publicAccess = "$(Get-PropValue $sa @('properties', 'publicNetworkAccess'))"
            $defaultAction = "$(Get-PropValue $sa @('properties', 'networkAcls', 'defaultAction'))"
            if ($publicAccess -ne "Disabled" -and $defaultAction -ne "Deny") {
                $exposures.Add([PSCustomObject]@{ Id = "$($sa['id'])"; Scope = $scope; What = "a storage endpoint open to all networks" })
            }
        }

        foreach ($e in $exposures) {
            $label = switch ($e.Scope.Kind) { "Temporary" { "temporary" } "Test" { "test/PoC" } default { "leftover" } }
            $via = if ((Get-ResourceNameFromId $e.Id) -eq $e.Scope.Name) { "" } else { " (via '$($e.Scope.Name)')" }
            Add-Finding -Category "Security" -Severity "High" `
                -CheckId "NATIVE-GOV-006" -Title "Temporary or test resource reachable from the Internet" `
                -ResourceId $e.Id -ResourceType "$(($e.Id -split '/')[6..7] -join '/')" -SubscriptionId $subId `
                -Finding "Reported as $label$via and exposed through $($e.What)." `
                -Recommendation "Remove the resource, or at least the public exposure: delete the public IP and use Azure Bastion/VPN, or set the storage account to 'Disabled' / selected networks with a private endpoint. Temporary and test resources are rarely patched, monitored or hardened, which makes them a common way in."
            $counts.Exposed++
        }
    }

    Write-Step "  Temporary: $($counts.Temporary)  Test outside test env: $($counts.Test)  Leftovers: $($counts.Leftover)  Expired tags: $($counts.Expired)" "Gray"
    Write-Step "  Resource groups without owner: $($counts.Ownerless)  Temporary/test exposed to the Internet: $($counts.Exposed)" "Gray"
    Write-Step "  Governance checks complete." "Gray"
}
