# 🔍 Simple Azure Audit

A PowerShell script that reviews an Azure subscription and its Entra ID tenant, runs a set of free assessment tools, and merges everything into **one interactive HTML report** plus a CSV for Excel / Power BI.

| Source | What it adds |
|--------|--------------|
| **Built-in checks** | NSG exposure, RBAC, classic admins, unused resources, encryption, Key Vault certificates and protection, storage and App Service TLS/HTTPS, tagging, Azure Advisor |
| **[Prowler](https://github.com/prowler-cloud/prowler)** | CIS, NIST, ISO 27001 and more security checks for Azure and Entra ID |
| **[Maester](https://maester.dev)** | Entra ID, Conditional Access, EIDSCA and CISA identity tests |
| **[PSRule for Azure](https://azure.github.io/PSRule.Rules.Azure/)** | Well-Architected rules for all five pillars, evaluated against the live resource configuration |
| **[Azure Governance Visualizer](https://github.com/Azure/Azure-Governance-Visualizer)** | Orphaned resources, risky RBAC assignments, Defender for Cloud plan coverage, plus its own governance HTML report |
| **[WARA](https://github.com/Azure/Well-Architected-Reliability-Assessment)** | Microsoft's reliability recommendations (APRL) and upcoming service retirements |
| **[Azure Resource Inventory](https://github.com/microsoft/ARI)** | Excel inventory and draw.io network diagram, linked as an appendix |

All tools are free and run **read-only**.

---

## ✨ The report

Each run creates a folder with a self-contained HTML file that works offline and can be sent to a customer.

- **Overview** – number of critical/high issues, severity tiles, *where the risk is* per area, tool coverage with pass rates, and the top 10 priorities.
- **Findings** – grouped per issue (one check, many resources) or as a flat list. Filter by severity, area, source and free text. Every issue shows recommendation, reference link, compliance mapping and affected resources.
- **Resources** – the most affected resources, with which tools flagged them.
- **Tools & method** – status, version, duration and links to each tool's own raw report, plus how severities and areas are normalised.
- **Export CSV** of the current filter, **Print / PDF**, light and dark theme.

### Findings vs issues

A *finding* is one failed check on one resource. An *issue* groups all findings from the same check, so "missing tags" on 300 resources is **one issue with 300 findings**. Issues are prioritised by severity and number of affected resources.

### Severity and area normalisation

| Tool | Severity mapping | Area |
|------|------------------|------|
| Built-in checks | as defined in each check | Security, Cost, Infrastructure, Compliance |
| Azure Advisor | Impact High/Medium/Low | Advisor category → Security, Reliability, Cost, Operations, Performance |
| Prowler | Critical/High/Medium/Low/Informational | Security (Entra/IAM → Identity, Monitor → Operations, Policy → Governance) |
| Maester | Test severity (Investigate → Info) | Identity (Azure-tagged tests → Security) |
| PSRule for Azure | Critical → High, Important → Medium, Awareness → Low | Well-Architected pillar |
| AzGovViz | Orphaned resources Low/Medium, Owner on SP High, orphaned assignments Medium, Defender plan off Low | Cost, Identity, Security |
| WARA | Recommendation impact | Reliability |

---

## 📋 Prerequisites

| Requirement | Needed for |
|-------------|------------|
| **PowerShell 7.0+** | Everything |
| `Az.Accounts`, `Az.Compute`, `Az.Network`, `Az.Storage`, `Az.KeyVault`, `Az.Resources`, `Az.Websites` | Built-in checks |
| `Az.Advisor` (optional) | Azure Advisor in the built-in checks |
| Python 3.10–3.13 + `pip install prowler` | Prowler |
| `Maester`, `Pester`, `Microsoft.Graph.Authentication` modules | Maester |
| `PSRule.Rules.Azure` module (pulls in `PSRule`) | PSRule for Azure |
| `WARA` module | WARA |
| `AzureResourceInventory`, `ImportExcel` modules | ARI |
| AzGovViz script (downloaded by `-InstallMissing`), `AzAPICall` module | AzGovViz |
| Azure CLI (optional) | Lets Prowler reuse `az login` instead of opening a browser |

### Option 1 – prepare a dedicated machine (recommended)

1. Install the winget apps and PowerShell modules listed in [`PAWDeploy-AzureAudit.xml`](PAWDeploy-AzureAudit.xml) (PowerShell 7, Azure CLI, Python 3.12 + all modules).
2. Run the prerequisites script from an elevated PowerShell 7 prompt. It installs/updates the modules, installs Prowler in a Python venv under `%ProgramData%\SimpleAzureAudit\prowler` (added to PATH), downloads AzGovViz and the Maester tests into `.\tools`:

```powershell
pwsh -ExecutionPolicy Bypass -File .\Install-AuditPrerequisites.ps1
```

Run it again later to update everything.

### Option 2 – install on demand

```powershell
Install-Module Az, Az.ResourceGraph, Az.CostManagement -Scope CurrentUser
pip install prowler

# Let the audit script install the remaining PowerShell modules and download AzGovViz:
.\Invoke-AzureAudit.ps1 -InstallMissing
```

Tools that are missing are shown as **Not installed** in the report and the rest of the run continues.

### Permissions

| Scope | Role | Used by |
|-------|------|---------|
| Subscription | **Reader** (Security Reader recommended) | Built-in checks, Prowler, PSRule, WARA, ARI |
| Management group (default: tenant root) | **Reader** | AzGovViz |
| Entra ID | **Global Reader** | Maester, Prowler Entra checks, AzGovViz identity resolution |

Checks that cannot run because of missing permissions produce no findings – a low count is not proof of compliance.

---

## 🚀 Usage

```powershell
.\Invoke-AzureAudit.ps1 [-TenantID <string>] [-SubscriptionId <string>] [-OutputPath <string>]
                        [-Tools <All|Native|Prowler|Maester|PSRule|AzGovViz|WARA|ARI>[]] [-ExcludeTools <string[]>]
                        [-ManagementGroupId <string>] [-ToolsPath <string>] [-InstallMissing]
                        [-CustomerName <string>] [-PreparedBy <string>] [-RequiredTags <string>]
                        [-SkipAdvisor] [-OpenReport] [-ImportFrom <string>]
```

### Sign-in

1. The script signs in with `Connect-AzAccount` (scoped to `-TenantID` when given) and selects the subscription, prompting when several are available.
2. PowerShell-based tools (PSRule, AzGovViz, WARA, ARI) run in a child `pwsh` process and reuse that Az sign-in.
3. **Maester** signs in to Microsoft Graph interactively (`Connect-Maester`).
4. **Prowler** reuses `az login` when the Azure CLI is signed in to the same tenant; otherwise it opens a browser sign-in.

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-TenantID` | Active context | Tenant to sign in to. |
| `-SubscriptionId` | Prompt | Subscription to audit. |
| `-OutputPath` | `.` | Where the run folder is created. |
| `-Tools` | `All` | Which assessments to run. |
| `-ExcludeTools` | – | Tools to skip, e.g. `-ExcludeTools ARI,AzGovViz`. |
| `-ManagementGroupId` | Tenant root | Starting point for AzGovViz. The subscription filter is always applied. |
| `-ToolsPath` | `.\tools` | Downloaded tool content (AzGovViz script, Maester tests). |
| `-InstallMissing` | Off | Install missing PowerShell modules and download AzGovViz. |
| `-CustomerName` | Subscription name | Title of the report. |
| `-PreparedBy` | – | Shown in the report header, e.g. your company name. |
| `-RequiredTags` | `Environment,Owner,CostCenter` | Tags the tagging check requires. |
| `-SkipAdvisor` | Off | Skip Azure Advisor in the built-in checks. |
| `-OpenReport` | Off | Open the report when done. |
| `-ImportFrom` | – | Rebuild the report from an existing run folder without scanning. |

### Examples

**Full assessment for a customer:**

```powershell
.\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-..." -SubscriptionId "xxxxxxxx-..." `
    -OutputPath "C:\Temp\AuditReports" -CustomerName "Contoso AB" -PreparedBy "Malmesater Cloud" -OpenReport
```

**Quick run – built-in checks, Prowler and Maester only:**

```powershell
.\Invoke-AzureAudit.ps1 -Tools Native,Prowler,Maester -OpenReport
```

**Everything except the slow tools:**

```powershell
.\Invoke-AzureAudit.ps1 -ExcludeTools AzGovViz,ARI
```

**Rebuild the report after editing the template or rerunning one tool:**

```powershell
.\Invoke-AzureAudit.ps1 -ImportFrom "C:\Temp\AuditReports\AzureAudit_Contoso_Prod_2026-09-16_08-12" -OpenReport
```

---

## 📊 Output

```
AzureAudit_<Subscription>_<timestamp>/
├── AzureAudit_<Subscription>_<timestamp>.html   # Interactive report (self-contained)
├── AzureAudit_<Subscription>_<timestamp>.csv    # All findings, semicolon-separated, UTF-8
├── audit-data.json                              # Merged, normalised data (findings + tool runs)
├── run.json                                     # Run metadata used by -ImportFrom
├── logs/                                        # Transcript per external tool
└── raw/
    ├── native/     findings.json
    ├── prowler/    prowler.ocsf.json, prowler.html, prowler.csv, compliance/
    ├── maester/    maester.json, maester.html, maester.md
    ├── psrule/     psrule-results.json
    ├── azgovviz/   AzGovViz_*.html, *_RoleAssignments.csv, *_MDfCCoverage.csv, ...
    ├── wara/       WARA-File-*.json, recommendations.json
    └── ari/        *.xlsx, *.xml (draw.io)
```

### CSV columns

| Column | Content |
|--------|---------|
| Severity | Critical / High / Medium / Low / Info |
| Category | Security, Identity, Governance, Reliability, Cost, Operations, Performance, Infrastructure, Compliance |
| Source | Native, Azure Advisor, Prowler, Maester, PSRule, AzGovViz, WARA |
| CheckId | Stable ID of the check (used to group findings into issues and compare runs) |
| Title | Name of the issue |
| Resource / ResourceType / ResourceId / SubscriptionId | Affected resource |
| Finding | Detail for this resource |
| Recommendation | Suggested action |
| Reference | Documentation link |
| Frameworks | Compliance mapping (CIS, ISO, NIST, EIDSCA, WAF pillar ...) |
| Timestamp | When the finding was recorded |

---

## 🗂️ Project structure

```
Invoke-AzureAudit.ps1            # Parameters, sign-in, orchestration, summary
Install-AuditPrerequisites.ps1   # Installs modules, Prowler, AzGovViz and Maester tests (no audit)
PAWDeploy-AzureAudit.xml         # Winget apps + PowerShell modules for PAWDeploy
src/
├── AuditCommon.ps1              # Helpers, Add-Finding, tool-run register
├── Checks.Security.ps1          # Built-in: NSG, public IPs, RBAC, classic admins
├── Checks.Cost.ps1              # Built-in: disks, stopped VMs, NICs, empty RGs
├── Checks.Infrastructure.ps1    # Built-in: VM encryption, KV certificates, soft delete
├── Checks.Compliance.ps1        # Built-in: TLS/HTTPS, public blob access, KV protection, tags
├── Checks.Advisor.ps1           # Built-in: Azure Advisor
├── Tools.Common.ps1             # Child-process runner, module installs, dispatcher
├── Tools.Prowler.ps1            # Run + import Prowler (OCSF JSON)
├── Tools.Maester.ps1            # Run + import Maester (JSON)
├── Tools.PSRule.ps1             # Export-AzRuleData + Invoke-PSRule, import results
├── Tools.AzGovViz.ps1           # Run + import AzGovViz CSV exports
├── Tools.WARA.ps1               # Run + import WARA collector JSON
├── Tools.ARI.ps1                # Run ARI, link Excel + diagram
├── AuditReport.ps1              # CSV, audit-data.json and HTML generation
└── report-template.html         # Report layout (HTML/CSS/JS); data is injected as JSON
```

### Adding a check or a tool

- **Built-in check:** call `Add-Finding` with `-CheckId` and `-Title` (so findings group into one issue) and `-ResourceId` (so the Resources tab can correlate across tools).
- **New tool:** add `src\Tools.<Name>.ps1` with `Invoke-<Name>Scan` (writes to `raw\<name>` and calls `Save-ToolRunState`) and `Import-<Name>Results` (calls `Add-Finding -Source <Name>` and `Complete-ToolImport`), then register it in `Invoke-AuditTools` and the `-Tools` parameter.

---

## 🛠️ Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Tool shows **Not installed** | Run `Install-AuditPrerequisites.ps1`, or rerun with `-InstallMissing` (Prowler needs `pip install prowler`). |
| **Prowler not found right after installing** | Open a new terminal so the updated PATH is loaded. |
| **WARA failed** | `Start-WARACollector` refuses to run when a newer module exists in PowerShell Gallery – run `Update-Module WARA`. |
| **PSRule failed** | `Export-AzRuleData` needs Reader on the subscription; see `logs\psrule.log`. Large subscriptions can take a while. |
| **AzGovViz failed / partial** | Reader on the management group is required. Use `-ManagementGroupId` for a management group you can read, or `-ExcludeTools AzGovViz`. See `logs\azgovviz.log`. |
| **Maester has few results** | The account needs Global Reader; Exchange/Teams tests are skipped because only Azure and Graph are connected. |
| **Prowler asks for a browser sign-in** | Run `az login --tenant <tenant>` first to let Prowler reuse the CLI session. |
| **"Could not fetch Advisor data"** | Install `Az.Advisor` or run with `-SkipAdvisor`. |
| **Run aborts with a `??` parse error** | Use `pwsh` (PowerShell 7), not Windows PowerShell 5.1. |
| **Garbled characters (å/ä/ö, box drawing)** | Keep the `.ps1` files saved as UTF-8 with BOM. |
| **Report links to raw reports don't open** | Keep the run folder intact – links are relative to the HTML file. |

---

## ⚠️ Disclaimer

The script and the tools it runs perform **read-only operations**. Recommendations are general guidance – evaluate each finding against the organisation's requirements before changing anything. Each external tool is subject to its own license (Prowler: Apache 2.0; Maester, PSRule for Azure, AzGovViz, WARA, ARI: MIT).
