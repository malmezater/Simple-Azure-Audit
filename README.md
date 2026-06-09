# 🔍 Azure Audit Checker

A comprehensive PowerShell script that reviews an Azure subscription from five perspectives - **Security**, **Cost**, **Infrastructure**, **Compliance** and **Azure Advisor** - and generates a clean, color-coded HTML report together with a CSV file for further analysis in Excel.

---

## ✨ Features

The script performs the following checks:

### 1. 🔐 Security
- **NSG rules** - detects dangerous inbound rules that open sensitive ports (RDP `3389`, SSH `22`, SQL `1433`, MySQL `3306`, PostgreSQL `5432`, Telnet `23`, FTP `21`, SMB `445`, WinRM `5985/5986`) to the Internet (`0.0.0.0/0`).
- **Public IP addresses** - finds unassociated Public IPs that increase the attack surface and cost.
- **RBAC** - warns when more than 3 Owner roles exist at the subscription scope.
- **Classic administrators** - flags deprecated legacy roles (CoAdministrator / ServiceAdministrator).

### 2. 💰 Cost & unused resources
- **Unattached managed disks** - disks that are not attached to any VM but still cost money.
- **Stopped/deallocated VMs** - machines whose storage is still billed.
- **Orphaned NICs** - network interfaces with no associated VM.
- **Empty resource groups** - RGs with no resources at all.

### 3. 🏗️ Infrastructure health
- **VM disk encryption** - checks that OS disks are encrypted (Azure Disk Encryption).
- **Key Vault certificates** - warns about certificates expiring within 90 days (Critical <=14 days, High <=30 days, Medium <=90 days).
- **Storage soft-delete** - checks that blob soft-delete is enabled.

### 4. ✅ Compliance & policy
- **Storage Accounts** - `Secure transfer required` (HTTPS only), minimum TLS version (>=1.2) and public blob access.
- **App Services** - HTTPS Only and minimum TLS version.
- **Key Vault** - Soft Delete and Purge Protection.
- **Tagging** - checks that required tags exist on all resources.

### 5. 📈 Azure Advisor
- Fetches all active Azure Advisor recommendations (requires the `Az.Advisor` module).
- Includes each recommendation's actual problem and solution text in the report, mapped to a severity based on its impact. The property names are resolved across `Az.Advisor` versions (both the newer flattened and older nested shapes).

---

## 📋 Prerequisites

| Requirement | Detail |
|-------------|--------|
| **PowerShell** | Version 7.0 or later |
| **Az modules** | `Az.Accounts`, `Az.Compute`, `Az.Network`, `Az.Storage`, `Az.KeyVault`, `Az.Resources`, `Az.Websites` |
| **Optional module** | `Az.Advisor` (only required for the Advisor check) |
| **Permission** | At least **Reader** at the subscription scope. **Security Reader** is recommended for full security checks. |

### Install the required modules

```powershell
Install-Module Az.Accounts, Az.Compute, Az.Network, Az.Storage, Az.KeyVault, Az.Resources, Az.Websites -Scope CurrentUser

# Optional - for the Azure Advisor check
Install-Module Az.Advisor -Scope CurrentUser
```

---

## 🚀 Usage

```powershell
.\Invoke-AzureAudit.ps1 [-TenantID <string>] [-SubscriptionId <string>] [-OutputPath <string>] [-RequiredTags <string>] [-SkipAdvisor] [-OpenReport]
```

If you are not already signed in to Azure, the script automatically runs `Connect-AzAccount`. When a `-TenantID` is supplied, the sign-in is scoped to that tenant.

### 🔑 Sign-in & subscription selection

- Pass `-TenantID` to sign in to a specific Azure AD tenant.
- If you pass `-SubscriptionId`, the script runs against that subscription directly.
- If you omit `-SubscriptionId`, the script enumerates the **enabled** subscriptions in the tenant:
  - **One subscription** - it is selected automatically.
  - **Multiple subscriptions** - you are shown a numbered list and prompted to choose which one to audit, every run.
  - **No subscriptions** - the script stops with a clear error.

### 🗂️ Project structure

The code is split into a thin main script that orchestrates the run and a `src` folder where each check area lives in its own file. This makes the code easier to read, maintain and extend.

```
Invoke-AzureAudit.ps1            # Main script: parameters, sign-in, run checks, call the report
src/
├── AuditCommon.ps1              # Helper functions (Write-Step, Write-Section, Add-Finding) + shared findings collection
├── Checks.Security.ps1          # Invoke-SecurityChecks       (1. Security)
├── Checks.Cost.ps1              # Invoke-CostChecks           (2. Cost)
├── Checks.Infrastructure.ps1    # Invoke-InfrastructureChecks (3. Infrastructure)
├── Checks.Compliance.ps1        # Invoke-ComplianceChecks     (4. Compliance)
├── Checks.Advisor.ps1           # Invoke-AdvisorChecks        (5. Azure Advisor)
└── AuditReport.ps1              # New-AuditReport: generates the CSV + HTML report
```

The main script dot-sources the files in `src` at startup, so you still run everything via `Invoke-AzureAudit.ps1` just like before. To add a new check, create a function (or a new `Checks.*.ps1` file) that calls `Add-Finding` and invoke it from the main script.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-TenantID` | `string` | Active context | Azure AD tenant to sign in to and enumerate subscriptions from. |
| `-SubscriptionId` | `string` | Active context | Subscription ID to run against. Omitted = you are prompted to choose when the tenant has more than one enabled subscription. |
| `-OutputPath` | `string` | `.` (current directory) | Folder where the HTML report and CSV are saved. Created automatically if it does not exist. |
| `-RequiredTags` | `string` | `"Environment,Owner,CostCenter"` | Comma-separated list of required tags to check for. |
| `-SkipAdvisor` | `switch` | Off | Skips the Azure Advisor fetch (faster run). |
| `-OpenReport` | `switch` | Off | Opens the HTML report automatically in the browser after the run. |

### Examples

**Run against a specific subscription and save the report to a given folder:**

```powershell
.\Invoke-AzureAudit.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutputPath "C:\Temp\AuditReports"
```

**Sign in to a specific tenant and pick a subscription interactively:**

```powershell
.\Invoke-AzureAudit.ps1 -TenantID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Run with custom required tags, skip Advisor and open the report immediately:**

```powershell
.\Invoke-AzureAudit.ps1 -RequiredTags "Environment,Owner,Project" -SkipAdvisor -OpenReport
```

**Run against the active context with default settings:**

```powershell
.\Invoke-AzureAudit.ps1
```

---

## 📊 Output

Each run generates two files in `-OutputPath`, named after the subscription and a timestamp:

| File | Description |
|------|-------------|
| `AzureAudit_<Subscription>_<timestamp>.html` | Interactive, color-coded report with summary cards, distribution by severity, findings by category and a complete table sorted by severity. The **Findings by category** list is clickable - select a category to filter the **All findings** table to just that category, then **Show all** to reset. Print-friendly. |
| `AzureAudit_<Subscription>_<timestamp>.csv` | Semicolon-separated CSV (UTF-8) with all findings for further analysis in Excel. |

### Severity levels

Each finding is classified with one of the following levels:

| Level | Color | Meaning |
|-------|-------|---------|
| 🔴 **Critical** | Red | Requires immediate action (e.g. RDP/SSH open to the Internet). |
| 🟠 **High** | Orange | High risk that should be addressed soon. |
| 🟡 **Medium** | Yellow | Should be addressed but not urgent. |
| 🟢 **Low** | Green | Minor improvements / cleanup. |
| 🔵 **Info** | Blue | Informational findings with no direct risk. |

### Report columns

| Column | Content |
|--------|---------|
| Category | Security, Cost, Infrastructure, Compliance or Advisor |
| Severity | Critical / High / Medium / Low / Info |
| ResourceType | Type of resource the finding applies to |
| Resource | Name of the affected resource |
| Finding | Description of the identified issue |
| Recommendation | Suggested action |
| Timestamp | When the finding was recorded |

---

## 💡 Tips

- Run the script regularly (e.g. via a scheduled task or pipeline) to track the health of your environment over time.
- Use the CSV file to build trends and dashboards in Excel or Power BI.
- Because `$ErrorActionPreference` is set to `SilentlyContinue`, the run is not aborted if individual resources lack permissions - run with sufficient rights for a complete result.

---

## 🛠️ Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| **"Could not fetch Advisor data"** | The `Az.Advisor` module is missing or you are not signed in. Install it with `Install-Module Az.Advisor -Scope CurrentUser`, or run with `-SkipAdvisor`. The accompanying message in parentheses shows the underlying error. |
| **Advisor rows show "See Azure Advisor"** | The recommendation genuinely has no problem/solution text. Other recommendations are still populated from the live data. |
| **Run aborts with a `??` parse error** | The script targets PowerShell 7+. Run it with `pwsh`, not Windows PowerShell 5.1. |
| **Garbled characters (å/ä/ö, box drawing)** | The `.ps1` files are saved as UTF-8 with BOM. Keep that encoding when editing so the banners render correctly. |

---

## ⚠️ Disclaimer

The script performs **read-only operations** and makes no changes to your Azure environment. The recommendations are general guidelines - always evaluate each finding against your organization's needs and policies before taking action.
