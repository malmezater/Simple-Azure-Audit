# Prerequisites

## Software

| Requirement | Needed for |
|-------------|------------|
| **PowerShell 7.0+** | Everything (Windows PowerShell 5.1 does not work) |
| `Az.Accounts`, `Az.Compute`, `Az.Network`, `Az.Storage`, `Az.KeyVault`, `Az.Resources`, `Az.Websites` | Built-in checks |
| `Az.Advisor` (optional) | Azure Advisor in the built-in checks |
| Python 3.10–3.13 + `pip install prowler` | Prowler |
| `Maester`, `Pester`, `Microsoft.Graph.Authentication` modules | Maester |
| `PSRule.Rules.Azure` module (pulls in `PSRule`) | PSRule for Azure |
| `WARA` module | WARA |
| `AzureResourceInventory`, `ImportExcel` modules | ARI |
| AzGovViz script (downloaded by `-InstallMissing`), `AzAPICall` module | AzGovViz |
| Azure CLI (optional) | Lets Prowler reuse `az login` instead of opening a browser |
| Excel (optional) | ARI styling. Without Excel, ARI runs in `-Lite` mode and still writes the inventory |

Tools that are missing are shown as **Not installed** in the report, and the rest of the run continues. Only the built-in checks are required.

### Option 1 – prepare a dedicated machine (recommended)

1. Install the apps with winget (or deploy the machine with a PAWDeploy profile that includes the *Security Audit* package):

   ```powershell
   winget install --id Microsoft.PowerShell -e
   winget install --id Microsoft.AzureCLI -e
   winget install --id Python.Python.3.12 -e
   ```

2. Run the prerequisites script from an elevated PowerShell 7 prompt:

   ```powershell
   pwsh -ExecutionPolicy Bypass -File .\Install-AuditPrerequisites.ps1
   ```

   It installs or updates the PowerShell modules, installs Prowler in a Python venv under `%ProgramData%\SimpleAzureAudit\prowler` (added to PATH), enables Windows long path support, and downloads AzGovViz and the Maester tests into `.\tools`.

   Run it again later to update everything.

### Option 2 – install on demand

```powershell
Install-Module Az, Az.ResourceGraph, Az.CostManagement -Scope CurrentUser
pip install prowler

# Let the audit script install the remaining PowerShell modules and download AzGovViz:
.\Invoke-AzureAudit.ps1 -InstallMissing
```

`-InstallMissing` installs modules for the current user only. Prowler always has to be installed with pip.

### Files downloaded from the internet

If the folder was downloaded as a zip, Windows may block the scripts. Unblock them once:

```powershell
Get-ChildItem .\Simple-Azure-Audit -Recurse -File | Unblock-File
```

## Permissions

All checks are read-only. The account needs:

| Scope | Role | Used by |
|-------|------|---------|
| Subscription | **Reader** (Security Reader recommended) | Built-in checks, Prowler, PSRule, WARA, ARI |
| Management group (default: tenant root) | **Reader** | AzGovViz |
| Entra ID | **Global Reader** | Maester, Prowler Entra checks, AzGovViz identity resolution |
| Key Vault data plane | **Key Vault Reader** (RBAC vaults) or *List* on secrets and keys (access policy vaults) | `NATIVE-INFRA-002` certificates and `NATIVE-INFRA-004` secrets/keys without expiry |

Notes:

- **Microsoft Graph consent.** Maester signs in to Microsoft Graph with delegated read scopes. The first time it runs in a tenant, an administrator may need to consent for the *Microsoft Graph Command Line Tools* app.
- **Key Vault.** Reader on the subscription does not give access to secret or key metadata. Vaults that cannot be read, because of permissions or the vault firewall, are skipped without a finding.
- **Defender for Cloud.** Reader (or Security Reader) on the subscription is enough to read vulnerability assessment results. The results only exist when Defender for Servers, Defender for Containers or SQL vulnerability assessment is enabled.
- **Internet access.** To mark CVEs as known exploited, the machine needs to reach `www.cisa.gov` over HTTPS. Without it, or with `-Offline`, the CVEs are still listed.
- **PIM.** `NATIVE-SEC-006` reads role assignment schedule instances to leave out active PIM activations. Reader includes this permission. Without it, active PIM activations are reported as permanent assignments.

> Checks that cannot run because of missing permissions produce no findings. A low count is not proof of compliance. The **Tools & method** tab in the report shows which tools ran and which failed.
