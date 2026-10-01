# Troubleshooting

Every external tool writes a transcript to `logs\<tool>.log` in the run folder. The **Tools & method** tab in the report shows each tool's status and message.

## Installation and start

| Symptom | Cause / fix |
|---------|-------------|
| Tool shows **Not installed** | Run `Install-AuditPrerequisites.ps1`, or rerun with `-InstallMissing`. Prowler needs `pip install prowler`. |
| **Prowler not found right after installing** | Open a new terminal so the updated PATH is loaded. |
| **pip: "No such file or directory ... Long Path support"** | Prowler's dependencies exceed 260-character paths. `Install-AuditPrerequisites.ps1` enables `LongPathsEnabled` when run elevated. Otherwise set `HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1` and rerun. |
| **"Could not load src\\…" / blocked by execution policy** | The files are marked as downloaded from the internet. Run `Get-ChildItem . -Recurse -File \| Unblock-File`, or start with `pwsh -ExecutionPolicy Bypass -File .\Invoke-AzureAudit.ps1`. |
| **Run aborts with a `??` parse error** | Use `pwsh` (PowerShell 7), not Windows PowerShell 5.1. |
| **Garbled characters (å/ä/ö, box drawing)** | Keep the `.ps1` files saved as UTF-8 with BOM. |

## Built-in checks

| Symptom | Cause / fix |
|---------|-------------|
| **"Could not fetch Advisor data"** | Install `Az.Advisor`, or run with `-SkipAdvisor`. |
| **No Key Vault certificate or secret findings** | Reader on the subscription does not cover the vault's data plane. Give the account **Key Vault Reader** (RBAC vaults) or *List* permissions (access policy vaults). Vaults behind a firewall are skipped too. |
| **Governance: "Could not list resources in … - skipped"** | The ARM REST call for that subscription failed, usually because of missing Reader access. The other subscriptions are still checked. |
| **A test environment is reported as `NATIVE-GOV-002`** | The resource has no `Environment` tag, its resource group and subscription carry no environment name, and no sibling with another environment exists. Add an `Environment` tag, or see [When is "test" an environment?](checks.md#when-is-test-an-environment). |
| **Vulnerabilities tab is empty** | Defender for Cloud has no vulnerability results: Defender for Servers / Containers / SQL vulnerability assessment is not enabled, or no machine has been scanned yet. The message at the top of the tab says which. The configuration tools rarely report CVEs. |
| **"Could not download the KEV catalogue"** | The machine cannot reach `www.cisa.gov` (proxy or firewall). CVEs are still listed but not marked as known exploited. Copy `known_exploited_vulnerabilities.json` into `<RunFolder>\raw\kev\` and rebuild with `-ImportFrom`, or run with `-Offline`. |
| **An issue is in the wrong workstream of the action plan** | It was placed by keywords in its title. Add its check ID to the right workstream's `checkIds` in `src\ActionPlan.ps1` and rebuild with `-ImportFrom`. |
| **Active PIM activations reported as `NATIVE-SEC-006`** | The account could not read role assignment schedule instances. Use an account with Reader on the subscription. |

## Prowler

| Symptom | Cause / fix |
|---------|-------------|
| **Prowler asks for a browser sign-in** | Run `az login --tenant <tenant>` first to let Prowler reuse the CLI session. |
| **`UnicodeEncodeError: 'charmap' codec`** | Fixed in the script (Prowler now runs with UTF-8 output). Update to the latest files. |

## Maester

| Symptom | Cause / fix |
|---------|-------------|
| **`Connect-MgGraph: Method not found ... InteractiveBrowserCredential`** | Az.Accounts and Microsoft.Graph.Authentication load different Azure.Identity versions. The script now signs in to Graph before Az is loaded. |
| **Seems to hang after "Connected to Microsoft Graph"** | It is running the tests, which usually takes 10–20 minutes, and only shows a progress bar. A summary line is printed when it is done. |
| **Few results** | The account needs Global Reader. Exchange and Teams tests are skipped because only Azure and Graph are connected. |
| **"Not connected to Azure" / "Azure tests will be skipped"** | Once the Graph module is loaded, Az.Accounts cannot refresh the saved sign-in silently in the same process ("User interaction is required"). The main script therefore hands Maester a short-lived ARM token through an environment variable, which is never written to the script or log. If it still fails, the log line after the Graph sign-in says why. Exchange, Teams, SharePoint, Azure DevOps and GitHub tests are always skipped (not connected). |

## PSRule

| Symptom | Cause / fix |
|---------|-------------|
| **PSRule failed** | `Export-AzRuleData` needs Reader on the subscription. See `logs\psrule.log`. Large subscriptions can take a while. |
| **"0 rule results written"** | Reading the export with `-InputPath` returned nothing with PSRule 2.9 and needs extra settings in v3. The script therefore passes the exported resources to PSRule as objects. |
| **"Export-AzRuleData could not read N sub-resource(s)"** | Not fatal. Typically `DefenderForStorageSettings (UnsupportedApiVersion)` per storage account and the retired `classicAdministrators` API. The rest of the export is evaluated. |

## AzGovViz

| Symptom | Cause / fix |
|---------|-------------|
| **Failed / partial** | Reader on the management group is required. Use `-ManagementGroupId` for a management group you can read, or `-ExcludeTools AzGovViz`. See `logs\azgovviz.log`. |
| **`classicAdministrators ... 404 InvalidResourceType`** | Microsoft retired classic administrators, and AzGovViz stops on the error. The script runs a patched copy (`AzGovVizParallel.SimpleAzureAudit.ps1`) that skips that call. The original file is untouched. |
| **"FAILED: importing previous CSV"** | Informational. AzGovViz compares with a previous run in the same folder. Every audit run uses a new folder, so there is nothing to compare with. |

## WARA and ARI

| Symptom | Cause / fix |
|---------|-------------|
| **WARA failed** | `Start-WARACollector` refuses to run when a newer module exists in PowerShell Gallery. Run `Update-Module WARA`. |
| **WARA: "No recommendation found for ..."** | Informational. WARA has no rules for that resource type (e.g. WAF policies). The collection still completes. |
| **ARI: `80040154 Class not registered`** | Excel is not installed, so ARI's COM styling step fails. The script uses `-Lite` automatically when Excel is missing. The Excel inventory is written either way. |

## Report and sharing

| Symptom | Cause / fix |
|---------|-------------|
| **Links to raw reports don't open** | Keep the run folder intact, or unzip the report zip. Links are relative to the HTML file. |
| **OneDrive/SharePoint: "has no content" / thousands of files not uploaded** | The run folder contains raw tool output that cloud sync handles badly (empty files, very many files). Upload the report zip instead. Runs created by older versions of the script also include AzGovViz's JSON export (thousands of GUID-named files); it is now turned off with `-NoJsonExport`. |
