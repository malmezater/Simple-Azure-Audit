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

> **Example:** open [`Demo_AzureAudit_Report.html`](Demo_AzureAudit_Report.html) to see a report built from fictional data (Northwind Traders, two made-up subscriptions).

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

1. Install the apps with winget (or deploy the machine with a PAWDeploy profile that includes the *Security Audit* package):

```powershell
winget install --id Microsoft.PowerShell -e
winget install --id Microsoft.AzureCLI -e
winget install --id Python.Python.3.12 -e
```

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
.\Invoke-AzureAudit.ps1 [-TenantID <string>] [-SubscriptionId <string[]> | -AllSubscriptions] [-OutputPath <string>]
                        [-Tools <All|Native|Prowler|Maester|PSRule|AzGovViz|WARA|ARI>[]] [-ExcludeTools <string[]>]
                        [-ManagementGroupId <string>] [-ToolsPath <string>] [-InstallMissing]
                        [-CustomerName <string>] [-PreparedBy <string>] [-RequiredTags <string>]
                        [-SkipAdvisor] [-OpenReport] [-Zip <Report|Full|None>] [-ImportFrom <string>]
```

### Sign-in

1. The script signs in with `Connect-AzAccount` (scoped to `-TenantID` when given) and resolves the subscriptions in scope (see below).
2. PowerShell-based tools (PSRule, AzGovViz, WARA, ARI) run in a child `pwsh` process and reuse that Az sign-in.
3. **Maester** signs in to Microsoft Graph interactively (`Connect-MgGraph`, the window can open behind other windows) and reuses the Az sign-in for its Azure tests.
4. **Prowler** reuses `az login` when the Azure CLI is signed in to the same tenant; otherwise it opens a browser sign-in.

### Choosing subscriptions

| How | Result |
|-----|--------|
| `-SubscriptionId "<id>"` | One subscription. |
| `-SubscriptionId "<id1>","<id2>"` or `"<id1>,<id2>"` | Several subscriptions (IDs or names). |
| `-AllSubscriptions` | Every **enabled** subscription the account can see in the tenant. |
| Neither | The tenant has one subscription: it is used. Otherwise a numbered list is shown and you answer e.g. `2`, `1-3`, `1,3,5`, `1-3,6` or `all`. |

All selected subscriptions end up in **one** report. The built-in checks run once per subscription; Prowler, PSRule, WARA, ARI and AzGovViz receive the whole list in a single run; Maester runs once for the tenant. With more than one subscription the report adds a **By subscription** table on the overview and a subscription filter on the Findings tab, and the CSV gets a `SubscriptionName` column.

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-TenantID` | Active context | Tenant to sign in to. |
| `-SubscriptionId` | Prompt | One or more subscription IDs or names to audit. |
| `-AllSubscriptions` | Off | Audit every enabled subscription in the tenant without prompting. |
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
| `-Zip` | `Report` | `Report` zips the HTML, CSV and linked tool reports next to the run folder (`<RunFolder>.zip`). `Full` zips the whole run folder (`<RunFolder>_full.zip`). `None` skips it. |
| `-ImportFrom` | – | Rebuild the report from an existing run folder without scanning. |

### Examples

**Full assessment for a customer:**

```powershell
.\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-..." -SubscriptionId "xxxxxxxx-..." `
    -OutputPath "C:\Temp\AuditReports" -CustomerName "Contoso AB" -PreparedBy "Company Name" -OpenReport
```

**Whole tenant in one report:**

```powershell
.\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-..." -AllSubscriptions -CustomerName "Contoso AB" -PreparedBy "Company Name" -OpenReport
```

**A few selected subscriptions:**

```powershell
.\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-..." -SubscriptionId "sub-id-1","sub-id-2","sub-id-3" -OpenReport
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
AzureAudit_<Subscription | Customer_Nsubs>_<timestamp>.zip    # Report to share (-Zip Report, default)
AzureAudit_<Subscription | Customer_Nsubs>_<timestamp>/
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

### Sharing the report

Share the **zip**, not the run folder. The run folder holds all raw tool output (often several hundred MB and thousands of files), which is only needed to rebuild the report with `-ImportFrom`.

| Zip | Contains | Use |
|-----|----------|-----|
| `<RunFolder>.zip` (`-Zip Report`, default) | HTML report, CSV, `audit-data.json`, and the tool reports linked from the report: Prowler HTML/CSV, Maester HTML/Markdown, AzGovViz HTML, PSRule and WARA JSON, ARI Excel and draw.io diagram. | Send to the customer, upload to OneDrive/SharePoint. Unzip and open the HTML – the links to the tool reports work. |
| `<RunFolder>_full.zip` (`-Zip Full`) | The whole run folder including raw data and logs. | Archive, or move the run to another machine and rebuild with `-ImportFrom`. |

To zip an older run, rebuild it: `.\Invoke-AzureAudit.ps1 -ImportFrom "<RunFolder>" -Zip Report`.

### CSV columns

| Column | Content |
|--------|---------|
| Severity | Critical / High / Medium / Low / Info |
| Category | Security, Identity, Governance, Reliability, Cost, Operations, Performance, Infrastructure, Compliance |
| Source | Native, Azure Advisor, Prowler, Maester, PSRule, AzGovViz, WARA |
| CheckId | Stable ID of the check (used to group findings into issues and compare runs) |
| Title | Name of the issue |
| Resource / ResourceType / ResourceId | Affected resource |
| SubscriptionName / SubscriptionId | Subscription the finding belongs to (`Tenant` for Entra ID checks) |
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
Demo_AzureAudit_Report.html      # Example report built from fictional data
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
| **pip: "No such file or directory ... Long Path support"** | Prowler's dependencies exceed 260-character paths. `Install-AuditPrerequisites.ps1` enables `LongPathsEnabled` when run elevated; otherwise set `HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1` and rerun. |
| **WARA failed** | `Start-WARACollector` refuses to run when a newer module exists in PowerShell Gallery – run `Update-Module WARA`. |
| **PSRule failed** | `Export-AzRuleData` needs Reader on the subscription; see `logs\psrule.log`. Large subscriptions can take a while. |
| **AzGovViz failed / partial** | Reader on the management group is required. Use `-ManagementGroupId` for a management group you can read, or `-ExcludeTools AzGovViz`. See `logs\azgovviz.log`. |
| **Prowler: `UnicodeEncodeError: 'charmap' codec`** | Fixed in the script (Prowler now runs with UTF-8 output). Update to the latest files. |
| **AzGovViz: `classicAdministrators ... 404 InvalidResourceType`** | Microsoft retired classic administrators and AzGovViz stops on the error. The script runs a patched copy (`AzGovVizParallel.SimpleAzureAudit.ps1`) that skips that call; the original file is untouched. |
| **PSRule: "0 rule results written"** | Reading the export with `-InputPath` returned nothing with PSRule 2.9 and needs extra settings in v3, so the script passes the exported resources to PSRule as objects instead. |
| **PSRule: "Export-AzRuleData could not read N sub-resource(s)"** | Not fatal. Typically `DefenderForStorageSettings (UnsupportedApiVersion)` per storage account and the retired `classicAdministrators` API; the rest of the export is evaluated. |
| **Maester: `Connect-MgGraph: Method not found ... InteractiveBrowserCredential`** | Az.Accounts and Microsoft.Graph.Authentication load different Azure.Identity versions. The script now signs in to Graph before Az is loaded. |
| **ARI: `80040154 Class not registered`** | Excel is not installed, so ARI's COM styling step fails. The script uses `-Lite` automatically when Excel is missing; the Excel inventory is written either way. |
| **WARA: "No recommendation found for ..."** | Informational – WARA has no rules for that resource type (e.g. WAF policies). The collection still completes. |
| **Maester has few results** | The account needs Global Reader; Exchange/Teams tests are skipped because only Azure and Graph are connected. |
| **Maester: "Not connected to Azure" / "Azure tests will be skipped"** | Once the Graph module is loaded, Az.Accounts cannot refresh the saved sign-in silently in the same process ("User interaction is required"). The main script therefore hands Maester a short-lived Azure Resource Manager token through an environment variable (never written to the script or log). If it still fails, the log line after the Graph sign-in says why. Exchange, Teams, SharePoint, Azure DevOps and GitHub tests are always skipped (not connected). |
| **Maester seems to hang after "Connected to Microsoft Graph"** | It is running the tests (usually 10–20 minutes) and only shows a progress bar. A summary line is printed when it is done. |
| **AzGovViz: "FAILED: importing previous CSV"** | Informational. AzGovViz compares with a previous run in the same folder; every audit run uses a new folder, so there is nothing to compare with. |
| **Prowler asks for a browser sign-in** | Run `az login --tenant <tenant>` first to let Prowler reuse the CLI session. |
| **"Could not fetch Advisor data"** | Install `Az.Advisor` or run with `-SkipAdvisor`. |
| **Run aborts with a `??` parse error** | Use `pwsh` (PowerShell 7), not Windows PowerShell 5.1. |
| **Garbled characters (å/ä/ö, box drawing)** | Keep the `.ps1` files saved as UTF-8 with BOM. |
| **Report links to raw reports don't open** | Keep the run folder intact, or unzip the report zip – links are relative to the HTML file. |
| **OneDrive/SharePoint: "has no content" / thousands of files not uploaded** | The run folder contains raw tool output that cloud sync handles badly (empty files, very many files). Upload the report zip instead. Runs created before this version also include AzGovViz's JSON export (thousands of GUID-named files); it is now turned off with `-NoJsonExport`. |

---

## ⚠️ Disclaimer

The script and the tools it runs perform **read-only operations**. Recommendations are general guidance – evaluate each finding against the organisation's requirements before changing anything. Each external tool is subject to its own license (Prowler: Apache 2.0; Maester, PSRule for Azure, AzGovViz, WARA, ARI: MIT).
