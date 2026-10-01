# Usage

```powershell
.\Invoke-AzureAudit.ps1 [-TenantID <string>] [-SubscriptionId <string[]> | -AllSubscriptions] [-OutputPath <string>]
                        [-Tools <All|Native|Prowler|Maester|PSRule|AzGovViz|WARA|ARI>[]] [-ExcludeTools <string[]>]
                        [-ManagementGroupId <string>] [-ToolsPath <string>] [-InstallMissing]
                        [-CustomerName <string>] [-PreparedBy <string>] [-RequiredTags <string>]
                        [-SkipAdvisor] [-Offline] [-OpenReport] [-Zip <Report|Full|None>] [-ImportFrom <string>]
```

## Sign-in

1. The script signs in with `Connect-AzAccount` (scoped to `-TenantID` when given) and resolves the subscriptions in scope (see below).
2. PowerShell-based tools (PSRule, AzGovViz, WARA, ARI) run in a child `pwsh` process and reuse that Az sign-in.
3. **Maester** signs in to Microsoft Graph interactively (`Connect-MgGraph`). The window can open behind other windows. Maester reuses the Az sign-in for its Azure tests.
4. **Prowler** reuses `az login` when the Azure CLI is signed in to the same tenant. Otherwise it opens a browser sign-in. Run `az login --tenant <tenant>` first to avoid it.

## Choosing subscriptions

| How | Result |
|-----|--------|
| `-SubscriptionId "<id>"` | One subscription. |
| `-SubscriptionId "<id1>","<id2>"` or `"<id1>,<id2>"` | Several subscriptions (IDs or names). |
| `-AllSubscriptions` | Every **enabled** subscription the account can see in the tenant. |
| Neither | If the tenant has one subscription, it is used. Otherwise a numbered list is shown and you answer e.g. `2`, `1-3`, `1,3,5`, `1-3,6` or `all`. |

All selected subscriptions end up in **one** report:

- The built-in checks run once per subscription. The governance check runs once across all of them, so naming conventions that span subscriptions are recognised.
- Prowler, PSRule, WARA, ARI and AzGovViz receive the whole list in a single run.
- Maester runs once for the tenant.

With more than one subscription, the report adds a **By subscription** table on the overview and a subscription filter on the Findings tab, and the CSV gets a `SubscriptionName` column.

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-TenantID` | Active context | Tenant to sign in to. |
| `-SubscriptionId` | Prompt | One or more subscription IDs or names to audit. |
| `-AllSubscriptions` | Off | Audit every enabled subscription in the tenant without prompting. |
| `-OutputPath` | `.` | Where the run folder is created. |
| `-Tools` | `All` | Which assessments to run: `All`, `Native`, `Prowler`, `Maester`, `PSRule`, `AzGovViz`, `WARA`, `ARI`. |
| `-ExcludeTools` | – | Tools to skip, e.g. `-ExcludeTools ARI,AzGovViz`. |
| `-ManagementGroupId` | Tenant root | Starting point for AzGovViz. The subscription filter is always applied. |
| `-ToolsPath` | `.\tools` | Downloaded tool content (AzGovViz script, Maester tests). |
| `-InstallMissing` | Off | Install missing PowerShell modules and download AzGovViz. |
| `-CustomerName` | Subscription name | Title of the report. |
| `-PreparedBy` | – | Shown in the report header, e.g. your company name. |
| `-RequiredTags` | `Environment,Owner,CostCenter` | Tags the tagging check (`NATIVE-COMP-008`) requires. |
| `-SkipAdvisor` | Off | Skip Azure Advisor in the built-in checks. |
| `-Offline` | Off | Do not download the CISA Known Exploited Vulnerabilities catalogue. CVEs are still listed, but not marked as known exploited. A copy already in the run folder is still used. |
| `-OpenReport` | Off | Open the report when done. |
| `-Zip` | `Report` | `Report` zips the HTML, CSV and linked tool reports next to the run folder (`<RunFolder>.zip`). `Full` zips the whole run folder (`<RunFolder>_full.zip`). `None` skips it. |
| `-ImportFrom` | – | Rebuild the report from an existing run folder without signing in or scanning. |

## Examples

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

**Zip an older run for sharing:**

```powershell
.\Invoke-AzureAudit.ps1 -ImportFrom "<RunFolder>" -Zip Report
```

## How long does it take?

Most of the run time is spent in the external tools. Maester usually takes 10–20 minutes, and PSRule, AzGovViz and ARI grow with the number of resources. The **Tools & method** tab shows the duration of each tool, so after a first run you know which ones to leave out with `-Tools` or `-ExcludeTools` for a shorter run.
