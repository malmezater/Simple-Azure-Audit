# 🔍 Simple Azure Audit

A PowerShell script that reviews Azure subscriptions and their Entra ID tenant, runs a set of free assessment tools, and merges everything into **one interactive HTML report** with a prioritised **action plan**, plus CSV files for Excel / Power BI / Planner.

| Source | What it adds |
|--------|--------------|
| **Built-in checks** | NSG exposure, RBAC and privileged roles directly on users, classic admins, unused resources, encryption, Key Vault certificates, secrets and protection, storage shared key access, TLS/HTTPS, tagging, forgotten temporary/test resources and missing owners, Azure Advisor |
| **Defender for Cloud** | Known vulnerabilities (CVEs) on VMs, container images and SQL, when Defender's vulnerability assessment is enabled |
| **[Prowler](https://github.com/prowler-cloud/prowler)** | CIS, NIST, ISO 27001 and more security checks for Azure and Entra ID |
| **[Maester](https://maester.dev)** | Entra ID, Conditional Access, EIDSCA and CISA identity tests |
| **[PSRule for Azure](https://azure.github.io/PSRule.Rules.Azure/)** | Well-Architected rules for all five pillars, evaluated against the live resource configuration |
| **[Azure Governance Visualizer](https://github.com/Azure/Azure-Governance-Visualizer)** | Orphaned resources, risky RBAC assignments, Defender for Cloud plan coverage, plus its own governance HTML report |
| **[WARA](https://github.com/Azure/Well-Architected-Reliability-Assessment)** | Microsoft's reliability recommendations (APRL) and upcoming service retirements |
| **[Azure Resource Inventory](https://github.com/microsoft/ARI)** | Excel inventory and draw.io network diagram, linked as an appendix |

All tools are free and run **read-only**. Results stay on the machine that runs the script.

The report turns the findings into a **project plan in four phases** – what to start with, why and how – and links every CVE to NVD, CVE.org, MSRC and the CISA list of vulnerabilities known to be exploited.

> **Example:** open [`Demo_AzureAudit_Report.html`](Demo_AzureAudit_Report.html) to see a report built from fictional data.

## 🚀 Quick start

1. Install PowerShell 7, Azure CLI and Python, then the modules and tools (elevated PowerShell 7):

   ```powershell
   winget install --id Microsoft.PowerShell -e
   winget install --id Microsoft.AzureCLI -e
   winget install --id Python.Python.3.12 -e

   pwsh -ExecutionPolicy Bypass -File .\Install-AuditPrerequisites.ps1
   ```

2. Make sure the account has **Reader** on the subscriptions, **Reader** on the management group and **Global Reader** in Entra ID.

3. Run the audit:

   ```powershell
   az login --tenant "xxxxxxxx-..."      # optional: lets Prowler reuse the sign-in
   .\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-..." -AllSubscriptions -CustomerName "Contoso AB" -OpenReport
   ```

4. Share the `.zip` that is created next to the run folder.

## 📚 Documentation

| | |
|---|---|
| [Prerequisites](docs/prerequisites.md) | Software, installation options and the permissions the account needs |
| [Usage](docs/usage.md) | Sign-in, choosing subscriptions, all parameters and examples |
| [Checks](docs/checks.md) | Every built-in check with ID and severity, CVE/KEV handling, how the action plan is built, and what each external tool adds |
| [How it works](docs/how-it-works.md) | What the script reads, which sign-ins it uses and what it writes to disk |
| [Report and output](docs/report.md) | The report tabs (incl. Action plan and Vulnerabilities), the run folder, CSV columns and sharing |
| [Troubleshooting](docs/troubleshooting.md) | Known errors and fixes, per tool |
| [Development](docs/development.md) | Project structure, adding checks or tools, conventions |
| [Changelog](CHANGELOG.md) | All changes, per version |

## ⚠️ Disclaimer

The script and the tools it runs perform **read-only operations**. Recommendations are general guidance; evaluate each finding against the organisation's requirements before changing anything. Each external tool is subject to its own license (Prowler: Apache 2.0; Maester, PSRule for Azure, AzGovViz, WARA, ARI: MIT).
