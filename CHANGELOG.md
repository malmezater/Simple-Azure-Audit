# Changelog

All notable changes to Simple Azure Audit are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). The version number is the `$ScriptVersion` shown in the report. How to add entries is described in [docs/development.md](docs/development.md#changelog-and-versions).

## [Unreleased]

## [2.1.0] - 2026-10-13

One row per problem when several tools report it, sign-in as an app registration, and report branding.

### Added

- Findings where several tools report the same problem on the same resource are merged into one row, marked *Found by N tools*. The row keeps the highest severity, and the issue lists each tool's own title and check ID under *Reported by*. The rules are in the new `src\FindingMerge.ps1` and cover storage accounts, Key Vault, App Service, App Service plans, API Management, Cosmos DB, container registries, virtual networks, VMs, NSGs, SQL, AKS and settings common to many resource types (public network access, private endpoints, zone/geo redundancy, diagnostics, CMK, local auth, managed identity, tags).
- Sign-in as an app registration (service principal) with `-ClientId` and `-CertificateThumbprint` (recommended) or a client secret (`-ClientSecret` as a SecureString, or a prompt without echo). Nothing about the app is saved: the Az context autosave is off for the process, Graph uses `-ContextScope Process`, the tools get the details through environment variables that only exist while they run, and `run.json`, scripts and logs hold no IDs or secrets. Prowler supports a client secret only and is skipped with a certificate. The new `src\AuditAuth.ps1` holds the sign-in code.
- Report branding: `-Branding <folder>` (default `branding\custom` when it exists) adds a logo, favicon, colours and header texts from `brand.json` and `brand.css`, without changing the template. `branding/example/` shows the format, and `branding/custom/` is ignored by git so a company copy of the repo can keep its branding there and merge updates without conflicts. The new `Update-ReportBranding.ps1` rebuilds an existing report, such as the demo, with the current template and a branding.
- Resource type filter on the Findings and Resources tabs, a subscription filter on the Resources tab, and sortable columns (resource, type, findings) in the Resources table.

### Changed

- Resource types are shown with readable names, so `Storage Account` and `Microsoft.Storage/storageAccounts` are both *Storage account*. This also covers types such as WAF policies, activity log alerts, metric alerts, Key Vault keys and secrets, and role definitions.
- Action plan: DDoS protection findings go to *Close exposure to the Internet*, and cross-tenant replication to *Protect data in transit and at rest*.
- In the findings CSV, the action plan CSV and the CSV export, `Source` and `CheckId` list every tool and check of a merged row, comma-separated.
- Documentation: a machine with at least 16 GB of RAM is recommended for a full run (docs/prerequisites.md#hardware).

## [2.0.0] - 2026-10-01

A rewrite that merges the built-in checks with free external assessment tools into one report, with a prioritised action plan and known vulnerabilities (CVE). This version also includes the work that was published on GitHub as 1.0.x (tag `public-release`, 2026-09-16/17) without release notes.

### Added

- External tools, each optional and reported as *Not installed* when missing:
  - Prowler: CIS, NIST and ISO checks for Azure and Entra ID.
  - Maester: Entra ID, Conditional Access, EIDSCA and CISA tests.
  - PSRule for Azure: Well-Architected rules.
  - Azure Governance Visualizer.
  - WARA: reliability recommendations and service retirements.
  - Azure Resource Inventory: Excel inventory and network diagram.
- `-Tools`, `-ExcludeTools`, `-ManagementGroupId`, `-ToolsPath` and `-InstallMissing`.
- Several subscriptions in one report: `-SubscriptionId` with a list, `-AllSubscriptions`, or an interactive selection (`2`, `1-3`, `1,3,5`, `all`). The report gets a *By subscription* table and filter.
- `-ImportFrom`, to rebuild the report from an existing run folder without scanning.
- `-Zip Report|Full|None`, to package the report, the CSV files and the linked tool reports for sharing (default `Report`).
- New interactive report:
  - Overview, Action plan, Findings grouped per issue, Resources, Vulnerabilities, and Tools & method tabs.
  - The overview points to phase 1 of the action plan, and warns when vulnerabilities known to be exploited were found.
  - CSV export of the current filter, print to PDF, light and dark theme.
- `audit-data.json` with all merged, normalised findings, and a run folder with raw output and logs per tool.
- `Install-AuditPrerequisites.ps1`: installs modules, installs Prowler in its own venv, enables long paths and downloads AzGovViz and the Maester tests.
- `Demo_AzureAudit_Report.html`, an example report built from fictional data.
- Severity and area normalisation across all tools, and stable check IDs (`NATIVE-*`, `ADVISOR-*`) on the built-in checks.
- **Governance check** (`src\Checks.Governance.ps1`). It runs once across all selected subscriptions and reports:
  - `NATIVE-GOV-001`: resources with a temporary name (temp, tmp, tillfällig, delete-me, ta-bort …).
  - `NATIVE-GOV-002`: test, PoC and demo resources outside a test environment. Environments in a naming convention (dev/test/acc/prod) are recognised through Environment tags, non-production resource group and subscription names, and sibling names such as `app-test-func` next to `app-prod-func`.
  - `NATIVE-GOV-003`: old copies and leftovers (old, copy, kopia, unused …).
  - `NATIVE-GOV-004`: resources past the date in an expiry tag (`DeleteAfter`, `ExpiresOn` …).
  - `NATIVE-GOV-005`: resource groups older than 90 days with no owner tag on the group or its resources.
  - `NATIVE-GOV-006`: temporary or test resources reachable from the Internet, through a public IP or a storage account open to all networks.
  - Each finding includes when the resource was created and last changed.
- `NATIVE-SEC-005`: storage accounts that allow shared key access.
- `NATIVE-SEC-006`: Owner, User Access Administrator, RBAC Administrator and Contributor assigned permanently and directly to users instead of groups with PIM. Active PIM activations are excluded.
- `NATIVE-INFRA-004`: Key Vault secrets and keys without an expiry date.
- **Action plan** (`src\ActionPlan.ps1`):
  - A new report tab that turns the issues into a project plan in four phases: act now (0–2 weeks), reduce risk (2–6 weeks), harden (1–3 months), improve and maintain (ongoing).
  - Issues are grouped into 14 workstreams. Each workstream explains why it matters and how to do it in numbered steps, with an effort estimate and a typical owner.
  - The plan is also written to `<name>_ActionPlan.csv` and can be downloaded from the report, for Planner, Azure DevOps or Excel.
- **Known vulnerabilities** (`src\Checks.Vulnerabilities.ps1`):
  - New check that reads Defender for Cloud vulnerability assessment results (Defender for Servers / MDVM, Defender for Containers, SQL VA). There is one issue per CVE, and CVSS ≥ 9.0 is reported as Critical.
  - CVE and GHSA IDs in the findings of every tool are collected in a new `Vulnerabilities` field (report, CSV, audit-data.json).
  - CVEs are looked up in the CISA Known Exploited Vulnerabilities catalogue. Known exploited CVEs are marked (incl. ransomware use and CISA due date) and go to phase 1 of the plan.
  - A new Vulnerabilities tab with links to NVD, CVE.org, MSRC, CISA KEV and GitHub Advisory, and an explanation of the sources and the CVSS scale.
  - `-Offline` switch to skip the KEV download.
- `docs/` folder: prerequisites, usage, a catalogue of all checks, what the script does in the environment, report and output, troubleshooting and development.
- This changelog.

### Changed

- The script is split into modules under `src\`; the HTML layout moved to `src\report-template.html`.
- VM disk encryption also accepts encryption at host and disk encryption sets.
- Orphaned network interfaces exclude those owned by Private Endpoints and Private Link Services.
- The README is now a short introduction with a quick start; the details moved to `docs/`.

### Fixed

- Prowler: `UnicodeEncodeError` on Windows, by running Prowler with UTF-8 output.
- Prowler: pip install fails on long paths.
- AzGovViz: stops on the retired classic administrators API. A patched copy that skips the call is used; the original file is untouched.
- AzGovViz: thousands of JSON export files that OneDrive/SharePoint cannot sync. The JSON export is now turned off with `-NoJsonExport`.
- Maester: Graph sign-in conflict with Az.Accounts (`InteractiveBrowserCredential`), and Azure tests skipped because of a missing sign-in. An ARM token is now handed over to Maester.
- PSRule: no rule results with PSRule 2.9/v3.
- ARI: `Class not registered` when Excel is missing. ARI now runs in `-Lite` mode.

## [1.0.0] - 2026-06-09

First version. The script did not yet report a version number.

### Added

- Review of one subscription from five perspectives:
  - Security: NSG rules with open management/database ports, unassociated public IPs, too many Owners, classic administrators.
  - Cost: unattached disks, stopped VMs, orphaned NICs, empty resource groups.
  - Infrastructure: VM disk encryption, Key Vault certificates expiring within 90 days, blob soft delete.
  - Compliance: storage HTTPS/TLS/public blob access, App Service HTTPS/TLS, Key Vault soft delete and purge protection, required tags.
  - Azure Advisor: all active recommendations.
- Color-coded HTML report with filters, and a CSV for Excel.
- Sign-in scoped to a tenant with `-TenantID`.

[Unreleased]: https://github.com/malmezater/Simple-Azure-Audit/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/malmezater/Simple-Azure-Audit/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/malmezater/Simple-Azure-Audit/releases/tag/v2.0.0
