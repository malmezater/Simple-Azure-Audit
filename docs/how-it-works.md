# How it works

This page describes what a run does, so it can be approved before it is used against a customer environment.

## In short

- **Read-only in Azure and Entra ID.** No resource, setting, role or policy is created, changed or deleted.
- **Runs as the signed-in user.** No app registration, service principal or secret is created. Access follows the roles described in [Prerequisites](prerequisites.md#permissions).
- **Results stay on the machine.** Everything is written to a local run folder. Nothing is uploaded, and the report works offline.
- **One public download outside Azure.** When a CVE is found, the public CISA KEV catalogue is downloaded from cisa.gov (a plain GET, nothing about the environment is sent). `-Offline` turns it off.

## Run flow

```
Invoke-AzureAudit.ps1
 1. Sign in (Connect-AzAccount) and choose subscriptions
 2. Built-in checks, per subscription:  Security → Cost → Infrastructure → Compliance → Advisor
 3. Governance and Defender for Cloud vulnerability checks, once across all selected subscriptions
 4. External tools, one at a time:      Prowler → Maester → PSRule → AzGovViz → WARA → ARI
 5. Import every tool's output and normalise it into one list of findings
 6. Find CVE/GHSA IDs in all findings and look them up in the CISA KEV catalogue
 7. Build the action plan (workstreams and phases)
 8. Write the HTML report, findings CSV, action plan CSV and audit-data.json, then zip the report
```

A tool that is not installed, or that fails, is recorded with its status and the run continues. With `-ImportFrom`, steps 1–4 are skipped and the report is rebuilt from an existing run folder; steps 6–8 run again, so a rebuilt report gets the current plan and vulnerability view.

## What is read

| Part | How it reads | Data |
|------|--------------|------|
| Built-in checks | Az PowerShell cmdlets (`Get-AzNetworkSecurityGroup`, `Get-AzStorageAccount`, `Get-AzRoleAssignment`, `Get-AzKeyVault*` …) and ARM REST through `Invoke-AzRestMethod` | Resource configuration, role assignments, PIM schedule instances, Advisor recommendations, Key Vault certificate, secret and key **metadata** (names, expiry dates, enabled state), Defender for Cloud vulnerability assessment results (`Microsoft.Security/subAssessments`) |
| CVE lookup | HTTPS GET of `known_exploited_vulnerabilities.json` from cisa.gov | The public KEV catalogue. Only when a CVE was found, and not with `-Offline`. |
| Prowler | Azure Resource Manager and Microsoft Graph | Resource configuration, Entra ID settings |
| Maester | Microsoft Graph (delegated read scopes) and ARM | Entra ID, Conditional Access and authentication settings |
| PSRule | `Export-AzRuleData` | Exported resource configuration (JSON) |
| AzGovViz | ARM and Microsoft Graph | Management group hierarchy, policies, role assignments, Defender plans |
| WARA | Azure Resource Graph and ARM | Resource configuration, service retirements |
| ARI | Azure Resource Graph | Resource inventory |

**Key Vault secret values are never read.** The built-in checks list secrets and keys only to read their expiry date and enabled state.

## Sign-ins and tokens

| Sign-in | Used by | Notes |
|---------|---------|-------|
| `Connect-AzAccount` | The main script and the PowerShell tools | PSRule, AzGovViz, WARA and ARI run in a child `pwsh` process that reuses this sign-in. |
| `Connect-MgGraph` (interactive, delegated) | Maester | The window can open behind other windows. Maester also gets a short-lived ARM access token through an environment variable of its child process. The token is never written to a script file or log. |
| `az login`, or Prowler's browser sign-in | Prowler | When the Azure CLI is signed in to the same tenant, Prowler uses it. Otherwise Prowler opens a browser. |

## What is written to disk

| Where | What | When |
|-------|------|------|
| `<OutputPath>\AzureAudit_<scope>_<timestamp>\` | The run folder: report, findings and action plan CSV, `audit-data.json`, `run.json`, `raw\<tool>\` output, the KEV catalogue in `raw\kev\` and `logs\` transcripts. See [Report and output](report.md#output). | Every run |
| `<OutputPath>\AzureAudit_<scope>_<timestamp>.zip` | The report package to share | Unless `-Zip None` |
| `.\tools\` | AzGovViz script, Maester tests, and a patched copy `AzGovVizParallel.SimpleAzureAudit.ps1` that skips the retired classic administrators API. The original AzGovViz file is not changed. | `-InstallMissing` / `Install-AuditPrerequisites.ps1` |
| PowerShell module folder (current user) | Missing modules | `-InstallMissing` only |
| `%ProgramData%\SimpleAzureAudit\prowler` | Python venv with Prowler, added to PATH | `Install-AuditPrerequisites.ps1` only |
| Registry `LongPathsEnabled` | Enables long paths, which Prowler's dependencies need | `Install-AuditPrerequisites.ps1`, when run elevated |

> **The run folder contains customer data**: resource names, IP addresses, role assignments and user names. Store and share it accordingly. `.gitignore` excludes `AzureAudit_*` so run folders are not committed by mistake.
