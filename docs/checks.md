# Checks

A run combines the script's own **built-in checks** with up to six **external tools**. Every result becomes a finding with a severity (Critical, High, Medium, Low, Info), an area and a stable check ID. Findings with the same check ID are grouped into one issue in the report.

- [Built-in checks](#built-in-checks)
  - [Security](#security)
  - [Cost](#cost)
  - [Infrastructure](#infrastructure)
  - [Compliance](#compliance)
  - [Governance](#governance)
  - [Azure Advisor](#azure-advisor)
  - [Vulnerabilities (Defender for Cloud)](#vulnerabilities-defender-for-cloud)
- [CVE references and known exploited vulnerabilities](#cve-references-and-known-exploited-vulnerabilities)
- [Action plan](#action-plan)
- [External tools](#external-tools)
- [Severity and area normalisation](#severity-and-area-normalisation)

## Built-in checks

Run with `-Tools Native` (included in `All`). They need the Az modules listed in [Prerequisites](prerequisites.md) and Reader on the subscription.

### Security

| ID | Finding | Severity | Area |
|----|---------|----------|------|
| `NATIVE-SEC-001` | NSG rule allows management or database ports (22, 3389, 1433, 3306, 5432, 23, 21, 445, 5985, 5986) or all ports from the Internet | Critical (RDP/SSH or all ports), otherwise High | Security |
| `NATIVE-SEC-002` | Public IP address not attached to anything | Low | Security |
| `NATIVE-SEC-003` | More than three Owner assignments at subscription scope | High | Security |
| `NATIVE-SEC-004` | Classic administrator (Co-/Service Administrator) still assigned | Medium | Security |
| `NATIVE-SEC-005` | Storage account allows shared key access, so account keys and SAS give full access without an identity | Medium | Security |
| `NATIVE-SEC-006` | Owner, User Access Administrator or RBAC Administrator assigned permanently and directly to a user, at subscription or resource group scope | High | Identity |
| | The same for Contributor | Medium | Identity |

`NATIVE-SEC-006` does not report:

- assignments to groups,
- active PIM activations,
- assignments inherited from a management group (otherwise they would repeat for every subscription).

`NATIVE-SEC-005` treats an unset `AllowSharedKeyAccess` as allowed, which is the Azure default. Before turning shared keys off, check that nothing still uses them, such as `AzureWebJobsStorage` connection strings, SMB file shares or older tools.

### Cost

| ID | Finding | Severity |
|----|---------|----------|
| `NATIVE-COST-001` | Unattached managed disk | Medium |
| `NATIVE-COST-002` | VM stopped or deallocated (its disks still cost) | Low |
| `NATIVE-COST-003` | Network interface not attached to a VM, Private Endpoint or Private Link Service | Low |
| `NATIVE-COST-004` | Empty resource group | Info |

### Infrastructure

| ID | Finding | Severity |
|----|---------|----------|
| `NATIVE-INFRA-001` | VM OS disk not encrypted with Azure Disk Encryption, encryption at host or a disk encryption set | High |
| `NATIVE-INFRA-002` | Key Vault certificate expires within 90 days | Critical ≤ 14 days, High ≤ 30, otherwise Medium |
| `NATIVE-INFRA-003` | Blob soft delete not enabled | Medium |
| `NATIVE-INFRA-004` | Enabled Key Vault secrets or keys without an expiry date. One finding per vault, listing up to ten names. Certificate-backed secrets and keys are excluded. | Low |

`NATIVE-INFRA-002` and `NATIVE-INFRA-004` need read access to the vault's data plane. Vaults that cannot be read are skipped. See [Permissions](prerequisites.md#permissions).

### Compliance

| ID | Finding | Severity |
|----|---------|----------|
| `NATIVE-COMP-001` | Storage account allows HTTP (secure transfer not required) | High |
| `NATIVE-COMP-002` | Storage account minimum TLS version below 1.2 | High |
| `NATIVE-COMP-003` | Storage account allows anonymous public blob access | High |
| `NATIVE-COMP-004` | App Service does not enforce HTTPS | High |
| `NATIVE-COMP-005` | App Service minimum TLS version below 1.2 | High |
| `NATIVE-COMP-006` | Key Vault soft delete disabled | High |
| `NATIVE-COMP-007` | Key Vault purge protection disabled | Medium |
| `NATIVE-COMP-008` | Resource missing one or more of the tags in `-RequiredTags` (default `Environment,Owner,CostCenter`) | Low |

### Governance

Resources created "just for a while" are rarely hardened, monitored or patched, and are often never removed. The governance check runs **once across all subscriptions in scope**, so a naming convention spread over several subscriptions is recognised.

| ID | Finding | Severity |
|----|---------|----------|
| `NATIVE-GOV-001` | Name marks the resource as temporary: *temp, tmp, temporary, tillfällig, throwaway, scratch, dummy, junk, delete, delete-me, to-delete, remove-me, ta-bort, do-not-use* … An `Environment` tag of *Temp* counts too. | Medium (Low if created in the last 30 days) |
| `NATIVE-GOV-002` | Name contains a test word outside a test environment: *test, tst, testing, poc, demo, trial, experiment, sandbox, lab, playground, prova* … | Low (Info if created in the last 30 days, Medium if tagged as production) |
| `NATIVE-GOV-003` | Name suggests an old copy or leftover: *old, gammal, copy, kopia, unused, oanvänd, deprecated, obsolete* | Low (Info if created in the last 30 days) |
| `NATIVE-GOV-004` | An expiry tag (`DeleteAfter`, `ExpiresOn`, `ExpirationDate`, `EndDate`, `ValidUntil`, `TaBortEfter` …) holds a date that has passed | Medium |
| `NATIVE-GOV-005` | Resource group whose oldest resource is more than 90 days old, where neither the group nor any of its resources has an owner tag (`Owner`, `Contact`, `Team`, `CreatedBy`, `Ägare`, `Ansvarig` …) | Low |
| `NATIVE-GOV-006` | A resource reported by GOV-001/002/003, or one inside a reported resource group or subscription, is reachable from the Internet. This covers an attached public IP (directly, or through its network interface and VM) or a storage account open to all networks. | High (area Security) |

#### When is "test" an environment?

Many organisations have dev, test, acceptance and production environments, so *test* in a name is often correct. A test word is **not** reported when any of the following is true:

1. The resource or its resource group has an `Environment`/`Env`/`Stage` tag with a non-production value.
2. The resource group or subscription is a non-production environment: its name contains *dev, test, tst, qa, uat, acc, acceptance, stage, staging, preprod, nonprod, int, sit, perf, sandbox, lab* or *demo*.
3. The same name exists with another environment in its place, in any subscription in scope. For example, `app-test-func` is not reported when `app-prod-func`, `app-dev-func` or `app-acc-func` exists.

A test-named resource tagged `Environment=Production` is always reported, with severity Medium.

Subscription names are only checked for temporary and leftover words, because *Test* is a normal name for a subscription.

#### How names are matched

- **Parts of a name.** Names are split on separators, camelCase and digits, so `vm-temp-01`, `TempVM` and `temp01` all contain *temp*. Å, ä and ö are matched as a, a and o.
- **Names without separators.** The most telling words (*temp, tmp, temporary, tillfällig, test, throwaway, dummy*) are also found inside such names, for example `sttempdata01` and `vmtest01`.
- **Ordinary words.** Words that only look like a match, such as *template, temperature, tempo, latest, contest* and *attestation*, are not hits.
- **Reported resource groups.** When a whole resource group is reported, its resources are not listed one by one. The finding states how many resources it holds.
- **Managed resource groups.** Groups managed by Azure, such as AKS `MC_*` and Databricks, are skipped.
- **Age.** The creation and last-change time in each finding come from the ARM API (`$expand=createdTime,changedTime`). A resource group's age is the age of its oldest resource.

The word lists, the false-positive list and the 90-day threshold for `NATIVE-GOV-005` are at the top of `src\Checks.Governance.ps1`.

### Azure Advisor

All active Azure Advisor recommendations for the subscription (requires `Az.Advisor`; skip with `-SkipAdvisor`).

| ID | Finding | Severity | Area |
|----|---------|----------|------|
| `ADVISOR-<recommendation type>` | One finding per recommendation, on the resource it applies to | Advisor impact High/Medium/Low (otherwise Info) | Advisor category: Security, Reliability (High Availability), Cost, Operations (Operational Excellence), Performance |

### Vulnerabilities (Defender for Cloud)

Vulnerabilities in installed software (CVEs) come from **Microsoft Defender for Cloud**. The configuration scanners in this report check settings, not installed software. The check reads Defender's vulnerability assessment results (*sub-assessments*) in every selected subscription:

| Defender plan | What it reports |
|---------------|-----------------|
| Defender for Servers (Microsoft Defender Vulnerability Management) | Vulnerable software on VMs and Arc-enabled servers |
| Defender for Containers / Defender CSPM | Vulnerable packages in images in Azure Container Registry |
| SQL vulnerability assessment | Database configuration weaknesses (rule IDs such as `VA2108`, usually no CVE) |

| ID | Finding | Severity | Area |
|----|---------|----------|------|
| `DEFENDER-VA-<CVE or rule ID>` | One finding per vulnerability per resource. All resources with the same CVE form one issue. Each finding shows the CVE IDs, CVSS score, whether a patch is available, and Defender's description and remediation. | Critical when CVSS ≥ 9.0, otherwise Defender's High/Medium/Low | Security |

When Defender's vulnerability assessment is not enabled, there is nothing to read. The report then says so on the **Vulnerabilities** tab, and an empty list does **not** mean the environment has no vulnerabilities. Defender plan coverage itself is reported by AzGovViz and Prowler.

## CVE references and known exploited vulnerabilities

After all tools have run, every finding from every tool is searched for vulnerability IDs:

- **CVE** (`CVE-2024-12345`) and **GitHub Security Advisory** (`GHSA-xxxx-xxxx-xxxx`) IDs in the title, detail, recommendation or reference are added to the finding's `Vulnerabilities` field.
- Each CVE is looked up in the **CISA Known Exploited Vulnerabilities (KEV)** catalogue. A CVE on the list has been used in real attacks; the report marks it *Known exploited* (and *ransomware* when CISA says so), shows CISA's required action and due date, and puts the issue in phase 1 of the action plan.
- The catalogue is downloaded once per run from cisa.gov and kept in `raw\kev\` so `-ImportFrom` works offline. It is only downloaded when at least one CVE was found. Use `-Offline` to skip the download.

Every CVE links to the sources where it can be looked up:

| Source | What it gives |
|--------|---------------|
| [NVD](https://nvd.nist.gov/) (NIST) | CVSS score and vector, affected products (CPE), weakness type (CWE) |
| [CVE.org](https://www.cve.org/) (MITRE) | The official CVE record and references |
| [MSRC Security Update Guide](https://msrc.microsoft.com/update-guide) | For Microsoft products: the KB/security update, affected versions, Microsoft's exploitability assessment |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Evidence of exploitation, required action, due date, ransomware use |
| [GitHub Advisory Database](https://github.com/advisories) | Vulnerabilities in open-source packages (GHSA IDs) |
| [EPSS](https://www.first.org/epss/) (FIRST) | Probability of exploitation in the next 30 days (explained in the report, not looked up) |

The **Vulnerabilities** tab in the report lists every ID with these links, and explains the sources and the CVSS scale.

## Action plan

Every issue is placed in a **workstream** (what to do) and a **phase** (when). The plan is shown on the **Action plan** tab and written to `<name>_ActionPlan.csv`. Each workstream has a description of why it matters, numbered steps for how to do it, an effort estimate and the role that usually owns it.

### Phases

| Phase | Timeframe | Contains |
|-------|-----------|----------|
| 1 – Act now | 0–2 weeks | Critical issues, vulnerabilities on the CISA KEV list, and High issues in *Close exposure to the Internet* |
| 2 – Reduce risk | 2–6 weeks | Other High issues |
| 3 – Harden | 1–3 months | Medium issues |
| 4 – Improve and maintain | Ongoing | Low and Info issues |

Within a phase, issues are ordered by workstream (the order below), then known exploited first, then severity and number of affected resources.

### Workstreams

| # | Workstream | Typical owner | Gets |
|---|------------|---------------|------|
| 1 | Close exposure to the Internet | Network / platform team | NSG rules, public IPs, public endpoints, anonymous access (`NATIVE-SEC-001/002`, `NATIVE-GOV-006`, `NATIVE-COMP-003`) |
| 2 | Patch known vulnerabilities | Server / application owners | Defender for Cloud vulnerabilities, any finding with a CVE, missing updates, unsupported versions |
| 3 | Secure privileged access | Identity / security team | Owner/admin roles, PIM, classic admins, service principals, guests (`NATIVE-SEC-003/004/006`) |
| 4 | Strengthen identity protection | Identity / security team | MFA, Conditional Access, legacy authentication (Maester and Entra checks) |
| 5 | Protect data in transit and at rest | Platform team / application owners | TLS, HTTPS, encryption, shared keys (`NATIVE-COMP-001/002/004/005`, `NATIVE-INFRA-001`, `NATIVE-SEC-005`) |
| 6 | Detect and respond | Security operations / platform team | Diagnostic settings, logs, Defender plans, alerts |
| 7 | Manage keys, secrets and certificates | Platform team / application owners | Key Vault, certificates, secret expiry (`NATIVE-INFRA-002/004`, `NATIVE-COMP-006/007`) |
| 8 | Backup and resilience | Platform team / application owners | Backup, soft delete, availability zones, redundancy (`NATIVE-INFRA-003`, Reliability) |
| 9 | Replace retiring services | Application owners | Service retirements (WARA), deprecated versions and runtimes |
| 10 | Clean up temporary and forgotten resources | Resource owners | `NATIVE-GOV-001…004`, `NATIVE-COST-*`, orphaned resources |
| 11 | Governance: ownership, tags and policy | Cloud governance / CCoE | `NATIVE-GOV-005`, `NATIVE-COMP-008`, policy and tagging |
| 12 | Optimise cost | FinOps / application owners | Cost recommendations |
| 13 | Improve performance | Application owners | Performance recommendations |
| 14 | Other improvements | Platform team | Everything else |

An issue goes to the first workstream that matches, in this order: its check ID, its source (Defender for Cloud), whether it has a CVE, keywords in its title, and finally its area. The texts, rules and phases are in `src\ActionPlan.ps1`.

## External tools

All tools are free and read-only. Each writes its own report to `raw\<tool>`, which is linked from the **Tools & method** tab.

| Tool | What it checks | Runs against |
|------|----------------|--------------|
| **[Prowler](https://github.com/prowler-cloud/prowler)** | CIS, NIST, ISO 27001 and other security frameworks for Azure and Entra ID | All selected subscriptions + tenant |
| **[Maester](https://maester.dev)** | Entra ID, Conditional Access, EIDSCA and CISA identity tests | Tenant |
| **[PSRule for Azure](https://azure.github.io/PSRule.Rules.Azure/)** | Well-Architected rules for all five pillars, evaluated against the exported live configuration | All selected subscriptions |
| **[Azure Governance Visualizer](https://github.com/Azure/Azure-Governance-Visualizer)** | Orphaned resources, risky RBAC assignments (Owner on service principals, orphaned assignments), Defender for Cloud plan coverage, plus its own governance HTML report | Management group (default tenant root), filtered to the selected subscriptions |
| **[WARA](https://github.com/Azure/Well-Architected-Reliability-Assessment)** | Microsoft's reliability recommendations (APRL) and upcoming service retirements | All selected subscriptions |
| **[Azure Resource Inventory](https://github.com/microsoft/ARI)** | Excel inventory and draw.io network diagram. Linked as an appendix and produces no findings. | All selected subscriptions |

## Severity and area normalisation

Each tool has its own scale. They are mapped onto one scale so the report can sort and filter across tools.

| Tool | Severity mapping | Area |
|------|------------------|------|
| Built-in checks | As in the tables above | Security, Identity, Cost, Infrastructure, Compliance, Governance |
| Azure Advisor | Impact High/Medium/Low | Advisor category → Security, Reliability, Cost, Operations, Performance |
| Defender for Cloud | CVSS ≥ 9.0 → Critical, otherwise Defender's High/Medium/Low | Security |
| Prowler | Critical/High/Medium/Low/Informational | Security (Entra/IAM → Identity, Monitor → Operations, Policy → Governance) |
| Maester | Test severity (Investigate → Info) | Identity (Azure-tagged tests → Security) |
| PSRule for Azure | Critical → High, Important → Medium, Awareness → Low | Well-Architected pillar |
| AzGovViz | Orphaned resources Low/Medium, Owner on SP High, orphaned assignments Medium, Defender plan off Low | Cost, Identity, Security |
| WARA | Recommendation impact | Reliability |
