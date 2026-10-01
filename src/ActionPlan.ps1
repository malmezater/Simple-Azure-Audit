# ─────────────────────────────────────────────────────────────
# ActionPlan.ps1
# Turns the findings into a project plan: every issue (one check, many resources) is placed in a
# workstream (what to do, why and how) and in a phase (when). Used by AuditReport.ps1 for the
# "Action plan" tab and <name>_ActionPlan.csv.
# ─────────────────────────────────────────────────────────────

# Phases, in order. An issue goes to the first phase whose rule matches (see Get-PlanPhase).
$script:PlanPhases = @(
    [ordered]@{ id = "now";     name = "Phase 1 – Act now";       timeframe = "0–2 weeks"
                goal = "Remove what can be exploited today: critical issues, vulnerabilities known to be exploited, and high-risk exposure to the Internet." }
    [ordered]@{ id = "next";    name = "Phase 2 – Reduce risk";   timeframe = "2–6 weeks"
                goal = "Fix the high severity issues: privileged access, identity protection, data protection and missing patches." }
    [ordered]@{ id = "plan";    name = "Phase 3 – Harden";        timeframe = "1–3 months"
                goal = "Close the best-practice gaps in security, resilience and governance as planned work." }
    [ordered]@{ id = "ongoing"; name = "Phase 4 – Improve and maintain"; timeframe = "Ongoing"
                goal = "Hygiene, cost and optimisation. Add it to the regular backlog and keep it from coming back with policy and routines." }
)

# Workstreams, in priority order. Matching (first hit wins):
#   CheckIds  exact or wildcard check IDs        Sources  finding source (tool)
#   Pattern   regex on the issue title           Categories  fallback on the area
$script:PlanWorkstreams = @(
    [ordered]@{
        id = "exposure"; name = "Close exposure to the Internet"; effort = "Small–Medium"; owner = "Network / platform team"
        why = "Services reachable from the Internet are found by automated scanning within hours. Open management ports (RDP, SSH, WinRM), databases with public endpoints and anonymous storage access are among the most common ways into a cloud environment."
        how = @(
            "List every NSG rule, public IP and public endpoint in the issues below, and confirm with the owner which ones really must be public."
            "Remove public access to management ports. Use Azure Bastion, a VPN or just-in-time VM access instead."
            "Put PaaS services (Storage, SQL, Key Vault, App Service) behind private endpoints or service endpoints, and set public network access to Disabled or selected networks."
            "Turn off anonymous blob access and delete public IPs that are not used."
            "Prevent it from coming back with Azure Policy (deny public IPs / public network access) and Defender for Cloud recommendations.")
        checkIds = @("NATIVE-SEC-001", "NATIVE-SEC-002", "NATIVE-GOV-006", "NATIVE-COMP-003")
        pattern = 'public (network )?access|public ip|publicly|internet|0\.0\.0\.0|any source|open port|management port|\bnsg\b|network security group|firewall|private (endpoint|link)|anonymous|\brdp\b|\bssh\b|jit|just-in-time'
    }
    [ordered]@{
        id = "vulnerabilities"; name = "Patch known vulnerabilities"; effort = "Medium"; owner = "Server / application owners"
        why = "Published vulnerabilities (CVEs) are actively scanned for and exploited, often within days of disclosure. Vulnerabilities on CISA's Known Exploited Vulnerabilities list are already used in real attacks and should be fixed first."
        how = @(
            "Start with the vulnerabilities marked Known exploited, then Critical (CVSS 9+) and High, on Internet-facing resources first."
            "Install the vendor's security update or upgrade the affected software. Rebuild and redeploy container images from a patched base image."
            "Enable automatic patching with Azure Update Manager (patch schedules / maintenance configurations) for VMs and Arc servers."
            "Make sure Defender for Servers and Defender for Containers cover every subscription, so new vulnerabilities are found continuously."
            "Agree on a patch SLA, e.g. Known exploited and Critical within 14 days, High within 30 days.")
        sources = @("Defender for Cloud")
        pattern = 'vulnerab|\bcve-|security update|system update|missing (patch|update)|patch|end of (life|support)|unsupported (os|version)'
    }
    [ordered]@{
        id = "privileged"; name = "Secure privileged access"; effort = "Medium"; owner = "Identity / security team"
        why = "A compromised account with Owner or Global Administrator rights gives full control over the environment and its data. Standing, permanent privileges on personal accounts make every phishing attack against those people a direct path to the whole platform."
        how = @(
            "Review every Owner, User Access Administrator and Contributor assignment in the issues below, and remove the ones that are not needed."
            "Assign roles to Entra ID groups instead of individual users."
            "Make privileged roles eligible through Privileged Identity Management (PIM): just-in-time activation, approval, MFA and a time limit."
            "Keep two break-glass accounts, excluded from Conditional Access only where needed, monitored and stored safely."
            "Remove classic administrators and review service principals with high privileges.")
        checkIds = @("NATIVE-SEC-003", "NATIVE-SEC-004", "NATIVE-SEC-006")
        pattern = '\bowner|(?<!non-)privileged|\bpim\b|global admin|administrator|role assignment|classic admin|co-?admin|break.?glass|emergency access|custom role|service principal|guest'
    }
    [ordered]@{
        id = "identity"; name = "Strengthen identity protection"; effort = "Medium"; owner = "Identity / security team"
        why = "Most cloud breaches start with a stolen or guessed password. Multi-factor authentication, blocking legacy authentication and Conditional Access stop the large majority of account takeover attempts."
        how = @(
            "Require phishing-resistant or at least app-based MFA for all users, and always for administrators."
            "Block legacy authentication protocols with Conditional Access."
            "Use risk-based Conditional Access policies (sign-in and user risk) if the licence allows it."
            "Restrict who can register applications, consent to apps and invite guests."
            "Test policy changes in report-only mode first, and keep the break-glass accounts out of scope.")
        pattern = '\bmfa\b|multi-?factor|conditional access|legacy auth|authentication|sign-?in|password|consent|\bentra\b|azure ad|security defaults|risky (users|sign)|user risk'
        categories = @("Identity")
    }
    [ordered]@{
        id = "data"; name = "Protect data in transit and at rest"; effort = "Small–Medium"; owner = "Platform team / application owners"
        why = "Old TLS versions, unencrypted traffic and shared access keys make it possible to read or change data without a trace of who did it. Encryption and identity-based access are basic requirements in most compliance frameworks (ISO 27001, NIS2, CIS)."
        how = @(
            "Set minimum TLS 1.2 and HTTPS only on Storage accounts, App Services and databases. Check first that old clients can handle it."
            "Turn off shared key access on Storage accounts and use Entra ID (RBAC) with managed identities instead of account keys and SAS."
            "Enable encryption at host or disk encryption for VMs; use customer-managed keys where the requirements say so."
            "Use Azure Policy to require these settings on new resources.")
        checkIds = @("NATIVE-COMP-001", "NATIVE-COMP-002", "NATIVE-COMP-004", "NATIVE-COMP-005", "NATIVE-INFRA-001", "NATIVE-SEC-005")
        pattern = '\btls\b|https|ssl|encrypt|shared key|\bsas\b|customer.managed key|\bcmk\b|in transit|at rest|secure transfer|minimum version'
    }
    [ordered]@{
        id = "monitoring"; name = "Detect and respond"; effort = "Medium"; owner = "Security operations / platform team"
        why = "Without logs and alerts, an attack or a mistake is found late or not at all, and it cannot be investigated afterwards. Defender for Cloud plans, diagnostic settings and the activity log are the base for detection."
        how = @(
            "Enable the Defender for Cloud plans that match the workloads (Servers, Storage, SQL, Key Vault, Containers, Resource Manager)."
            "Send the activity log and diagnostic logs to a central Log Analytics workspace with a retention that meets the requirements."
            "Set up alert rules and an action group so that someone is notified, and decide who responds."
            "Consider Microsoft Sentinel or another SIEM for correlation and longer retention.")
        pattern = 'diagnostic|\blogs?\b|logging|monitor|defender|alert|audit|sentinel|activity log|retention|threat|security contact|email notification'
        categories = @("Operations")
    }
    [ordered]@{
        id = "secrets"; name = "Manage keys, secrets and certificates"; effort = "Small"; owner = "Platform team / application owners"
        why = "Secrets without an expiry date live on long after the system or person that created them, and expired certificates cause outages. A Key Vault without soft delete and purge protection can lose every key in one mistake or attack."
        how = @(
            "Renew certificates that are about to expire and turn on automatic renewal."
            "Set an expiry date on every secret and key, and rotate them with a rotation policy or near-expiry events."
            "Replace secrets with managed identities where the service supports it."
            "Enable soft delete and purge protection on every Key Vault, and use the RBAC permission model.")
        checkIds = @("NATIVE-INFRA-002", "NATIVE-INFRA-004", "NATIVE-COMP-006", "NATIVE-COMP-007")
        pattern = 'key ?vault|certificate|secret|\bkeys?\b|purge protection|rotation|expir'
    }
    [ordered]@{
        id = "resilience"; name = "Backup and resilience"; effort = "Medium–Large"; owner = "Platform team / application owners"
        why = "Ransomware, accidental deletion and regional outages happen. Without tested backups, soft delete and redundancy, a single incident can mean lost data or a long outage."
        how = @(
            "Back up VMs, databases and file shares with Azure Backup, with immutable vaults and soft delete turned on."
            "Enable blob soft delete and versioning on Storage accounts with business data."
            "Use availability zones or zone-redundant SKUs for production workloads, as the WARA recommendations describe."
            "Write down RTO/RPO per system, and test a restore at least once a year.")
        checkIds = @("NATIVE-INFRA-003")
        pattern = 'backup|soft delete|versioning|\bzones?\b|zone.redundan|redundan|availability|geo|replica|failover|disaster|resilien|\bsla\b|health probe'
        categories = @("Reliability")
    }
    [ordered]@{
        id = "lifecycle"; name = "Replace retiring services"; effort = "Medium"; owner = "Application owners"
        why = "Services and SKUs that Microsoft retires stop getting security updates and eventually stop working. Planning the move ahead is cheaper than an emergency migration."
        how = @(
            "List the retirements and their dates from the issues below and from Azure Service Health."
            "Plan the migration per system, starting with the earliest retirement date."
            "Upgrade runtimes, SDKs and API versions as part of normal releases.")
        checkIds = @("WARA-RETIREMENT-*")
        pattern = 'retire|retirement|deprecat|end of life|\beol\b|upgrade|outdated|old version|newer (runtime|version)|latest version|runtime (stack )?version|classic'
    }
    [ordered]@{
        id = "cleanup"; name = "Clean up temporary and forgotten resources"; effort = "Small"; owner = "Resource owners"
        why = "Temporary, test and leftover resources are rarely patched, monitored or hardened, yet they often keep network access and data. Removing them reduces both the attack surface and the cost."
        how = @(
            "Send the list of resources below to their owners (or the resource group's creator) with a deadline to answer."
            "Delete what nobody claims, after a snapshot or backup where data may be needed."
            "Rename and tag resources that must stay, with Owner and Environment."
            "Give temporary work a sandbox subscription with a budget and an expiry tag (DeleteAfter), and review it monthly.")
        checkIds = @("NATIVE-GOV-001", "NATIVE-GOV-002", "NATIVE-GOV-003", "NATIVE-GOV-004", "NATIVE-COST-001", "NATIVE-COST-002", "NATIVE-COST-003", "NATIVE-COST-004")
        pattern = 'orphan|unused|unattached|not attached|idle|empty|stopped|deallocated|leftover|temporary'
    }
    [ordered]@{
        id = "governance"; name = "Governance: ownership, tags and policy"; effort = "Medium"; owner = "Cloud governance / CCoE"
        why = "When nobody owns a resource, nobody approves changes, answers alerts or decides when it can go. Tags and Azure Policy make ownership, cost allocation and guardrails automatic instead of manual."
        how = @(
            "Decide the mandatory tags (e.g. Owner, Environment, CostCenter) and the naming convention."
            "Require them with Azure Policy on resource groups, and inherit them to resources."
            "Assign the Microsoft cloud security benchmark and the policies the organisation needs at management group level."
            "Use resource locks on critical production resources.")
        checkIds = @("NATIVE-GOV-005", "NATIVE-COMP-008")
        pattern = '\btags?\b|tagging|polic(y|ies)|owner tag|naming|\block\b|management group|blueprint'
        categories = @("Governance", "Compliance")
    }
    [ordered]@{
        id = "cost"; name = "Optimise cost"; effort = "Small–Medium"; owner = "FinOps / application owners"
        why = "Over-sized and idle resources cost money every month without adding value. The savings can often pay for the security improvements in this plan."
        how = @(
            "Right-size or shut down under-used VMs and databases as Azure Advisor suggests."
            "Buy reservations or savings plans for workloads that run all the time."
            "Set budgets and cost alerts per subscription, and review cost monthly with the owners.")
        categories = @("Cost")
    }
    [ordered]@{
        id = "performance"; name = "Improve performance"; effort = "Small–Medium"; owner = "Application owners"
        why = "Performance recommendations point at limits that cause slow responses or failures under load."
        how = @(
            "Review the recommendations with the application owner and test changes in a non-production environment first."
            "Monitor the effect with Azure Monitor metrics after the change.")
        categories = @("Performance")
    }
    [ordered]@{
        id = "other"; name = "Other improvements"; effort = "Varies"; owner = "Platform team"
        why = "Best-practice recommendations that do not belong to one of the workstreams above."
        how = @(
            "Go through the issues with the platform team and decide per issue whether to fix it, accept the risk or mark it as not applicable."
            "Record accepted risks with a reason and a date for the next review.")
    }
)

function Get-PlanWorkstream {
    # Id of the workstream an issue belongs to.
    param([Parameter(Mandatory)]$Issue)
    $title = "$($Issue.Title)".ToLower()
    foreach ($ws in $script:PlanWorkstreams) {
        foreach ($c in @($ws['checkIds'])) { if ($c -and $Issue.CheckId -like $c) { return $ws.id } }
    }
    foreach ($ws in $script:PlanWorkstreams) {
        if (@($ws['sources']) -contains $Issue.Source) { return $ws.id }
    }
    if ($Issue.Vulnerabilities) { return "vulnerabilities" }
    # A retirement is about the service's lifecycle, whatever service it names ("Retirement: Basic SKU public IP")
    if ($title -match '\bretire|deprecat') { return "lifecycle" }
    foreach ($ws in $script:PlanWorkstreams) {
        if ($ws['pattern'] -and $title -match $ws['pattern']) { return $ws.id }
    }
    foreach ($ws in $script:PlanWorkstreams) {
        if (@($ws['categories']) -contains $Issue.Category) { return $ws.id }
    }
    if ($Issue.Category -eq "Security") { return "data" }
    return "other"
}

function Get-PlanPhase {
    param([Parameter(Mandatory)]$Issue, [Parameter(Mandatory)][string]$Workstream)
    if ($Issue.Severity -eq "Critical" -or $Issue.KnownExploited) { return "now" }
    if ($Issue.Severity -eq "High" -and $Workstream -eq "exposure") { return "now" }
    switch ($Issue.Severity) {
        "High"   { return "next" }
        "Medium" { return "plan" }
        default  { return "ongoing" }
    }
}

function New-ActionPlan {
    <#
      Groups findings into issues (Source + CheckId, the same key as the HTML report) and places each
      issue in a workstream and a phase. Returns @{ phases; workstreams; items } for audit-data.json.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [AllowEmptyCollection()][object[]]$Vulnerabilities = @()
    )
    $kev = @{}
    foreach ($v in $Vulnerabilities) { if ($v.KnownExploited) { $kev[$v.Id] = $true } }

    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $issues = [ordered]@{}
    foreach ($f in $Findings) {
        $key = "$($f.Source)::$(if ($f.CheckId) { $f.CheckId } else { $f.Title })"
        if (-not $issues.Contains($key)) {
            $issues[$key] = [ordered]@{ Key = $key; Title = $f.Title; Source = $f.Source; Category = $f.Category; CheckId = $f.CheckId
                                        Severity = $f.Severity; Recommendation = $f.Recommendation; Resources = @{}; Findings = 0; Ids = @{} }
        }
        $i = $issues[$key]
        $i.Findings++
        $i.Resources[("$(if ($f.ResourceId) { $f.ResourceId } else { $f.Resource })").ToLower()] = $true
        if ($sevRank[$f.Severity] -lt $sevRank[$i.Severity]) { $i.Severity = $f.Severity }
        foreach ($id in @("$($f.Vulnerabilities)" -split '\s*,\s*' | Where-Object { $_ })) { $i.Ids[$id] = $true }
    }

    $items = foreach ($i in $issues.Values) {
        $ids = @($i.Ids.Keys | Sort-Object)
        $issue = [PSCustomObject]@{
            Key = $i.Key; Title = $i.Title; Source = $i.Source; Category = $i.Category; CheckId = $i.CheckId; Severity = $i.Severity
            Recommendation = $i.Recommendation; Resources = $i.Resources.Count; Findings = $i.Findings
            Vulnerabilities = ($ids -join ", "); KnownExploited = @($ids | Where-Object { $kev.ContainsKey($_) }).Count -gt 0
            Workstream = ""; Phase = ""
        }
        $issue.Workstream = Get-PlanWorkstream $issue
        $issue.Phase = Get-PlanPhase -Issue $issue -Workstream $issue.Workstream
        $issue
    }

    # Order inside a phase: workstream priority, known exploited first, severity, resources affected
    $wsOrder = @{}; for ($n = 0; $n -lt $script:PlanWorkstreams.Count; $n++) { $wsOrder[$script:PlanWorkstreams[$n].id] = $n }
    $phOrder = @{}; for ($n = 0; $n -lt $script:PlanPhases.Count; $n++) { $phOrder[$script:PlanPhases[$n].id] = $n }
    $sortedItems = @($items | Sort-Object @{ Expression = { $phOrder[$_.Phase] } }, @{ Expression = { $wsOrder[$_.Workstream] } },
        @{ Expression = { -not $_.KnownExploited } }, @{ Expression = { $sevRank[$_.Severity] } },
        @{ Expression = { $_.Resources }; Descending = $true }, @{ Expression = { $_.Title } })

    return [ordered]@{
        phases      = $script:PlanPhases
        workstreams = @($script:PlanWorkstreams | ForEach-Object {
            [ordered]@{ id = $_.id; name = $_.name; why = $_.why; how = @($_.how); effort = $_.effort; owner = $_.owner }
        })
        items       = $sortedItems
    }
}

function Export-ActionPlanCsv {
    # One row per issue, in plan order, for Planner / Azure DevOps / Excel.
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][string]$Path)
    $phases = @{}; foreach ($p in $Plan.phases) { $phases[$p.id] = $p }
    $ws = @{}; foreach ($w in $Plan.workstreams) { $ws[$w.id] = $w }
    $n = 0
    @($Plan.items) | ForEach-Object {
        $n++
        $w = $ws[$_.Workstream]; $p = $phases[$_.Phase]
        [PSCustomObject]@{
            Order = $n; Phase = $p.name; Timeframe = $p.timeframe; Workstream = $w.name; Owner = $w.owner; Effort = $w.effort
            Severity = $_.Severity; Issue = $_.Title; Area = $_.Category; Source = $_.Source; CheckId = $_.CheckId
            Resources = $_.Resources; Findings = $_.Findings
            KnownExploited = $(if ($_.KnownExploited) { "Yes" } else { "" }); Vulnerabilities = $_.Vulnerabilities
            Recommendation = $_.Recommendation; Why = $w.why; How = ($w.how -join " | ")
        }
    } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Delimiter ";"
}
