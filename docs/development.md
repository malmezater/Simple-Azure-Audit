# Development

## Project structure

```
Invoke-AzureAudit.ps1            # Parameters, sign-in, orchestration, summary
Install-AuditPrerequisites.ps1   # Installs modules, Prowler, AzGovViz and Maester tests (no audit)
Demo_AzureAudit_Report.html      # Example report built from fictional data
CHANGELOG.md                     # All changes, per version
docs/                            # This documentation
src/
├── AuditCommon.ps1              # Helpers, Add-Finding, tool-run register
├── Checks.Security.ps1          # Built-in: NSG, public IPs, RBAC, users with privileged roles, shared key, classic admins
├── Checks.Cost.ps1              # Built-in: disks, stopped VMs, NICs, empty RGs
├── Checks.Infrastructure.ps1    # Built-in: VM encryption, KV certificates, secrets/keys without expiry, soft delete
├── Checks.Compliance.ps1        # Built-in: TLS/HTTPS, public blob access, KV protection, tags
├── Checks.Advisor.ps1           # Built-in: Azure Advisor
├── Checks.Governance.ps1        # Built-in: temporary/test/leftover resources, expired tags, owners, exposure
├── Checks.Vulnerabilities.ps1   # Built-in: Defender for Cloud vulnerabilities; CVE/GHSA extraction; CISA KEV lookup
├── ActionPlan.ps1               # Workstreams (why/how), phases and the rules that place issues in the plan
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

## Adding a built-in check

1. Put the check in the `src\Checks.<Area>.ps1` file it belongs to. A new file must also be added to `$srcFiles` in `Invoke-AzureAudit.ps1`, and its function called from the built-in checks block.
2. Call `Add-Finding` with:
   - `-CheckId`: a new, stable ID in the file's series (`NATIVE-SEC-007`, `NATIVE-GOV-007` …). Never reuse or renumber an ID; reports are compared across runs by it.
   - `-Title`, so findings group into one issue,
   - `-ResourceId`, so the Resources tab can correlate findings across tools,
   - `-Category` and `-Severity`, plus `-Finding` and `-Recommendation` texts.
3. Make the check read-only, and let it fail quietly (`try { } catch { }`) when a resource cannot be read, as the existing checks do.
4. Add the check ID to the right workstream's `checkIds` in `src\ActionPlan.ps1`, so it lands in the right place in the action plan. Without it, the issue is placed by keywords in its title.
5. If the check knows the CVE, pass it with `-Vulnerabilities "CVE-…"`. CVE IDs in the title or detail are picked up anyway.
6. Document it in [checks.md](checks.md) and add a line to [CHANGELOG.md](../CHANGELOG.md).

## Changing the action plan

Everything the plan says is in `src\ActionPlan.ps1`:

- `$script:PlanPhases`: the phases, their timeframe and goal. The rule that places an issue in a phase is `Get-PlanPhase`.
- `$script:PlanWorkstreams`: one entry per workstream with `why`, `how` (steps), `effort`, `owner`, and the matching rules `checkIds` (wildcards allowed), `sources`, `pattern` (regex on the issue title) and `categories`. The order of the list is both the matching order and the priority order inside a phase.

Rebuild an existing run with `-ImportFrom` to see the effect without scanning again.

## Demo report

`Demo_AzureAudit_Report.html` is built with the current template from fictional data. Rebuild it after changing the template or the plan, so the example stays current.

## Adding a tool

Add `src\Tools.<Name>.ps1` with two functions:

- `Invoke-<Name>Scan`: writes to `raw\<name>` and calls `Save-ToolRunState`.
- `Import-<Name>Results`: calls `Add-Finding -Source <Name>` and `Complete-ToolImport`.

Then register the tool in `Invoke-AuditTools` and in the `-Tools` / `-ExcludeTools` parameters, and describe it in [checks.md](checks.md#external-tools) and [prerequisites.md](prerequisites.md).

## Conventions

- **Encoding:** `.ps1` files are UTF-8 **with BOM**. Without it, Windows PowerShell tooling garbles å/ä/ö and box-drawing characters.
- **Strict mode:** the script runs with `Set-StrictMode -Version Latest`. Read properties that may be missing with `Get-PropValue`, and do not index arrays that can be empty.
- **Errors:** `$ErrorActionPreference` is `SilentlyContinue` so that one failing Az call does not stop the audit. Use `-ErrorAction Stop` inside `try` when a failure needs handling.
- **Language:** code, comments, report texts and documentation are in English.

## Changelog and versions

All changes are recorded in [CHANGELOG.md](../CHANGELOG.md), following [Keep a Changelog](https://keepachangelog.com/):

- Add each change under **[Unreleased]**, in *Added*, *Changed*, *Fixed* or *Removed*.
- At a release, rename *[Unreleased]* to the new version and date, and set `$ScriptVersion` in `Invoke-AzureAudit.ps1` to the same number. That version is shown in the report and stored in `run.json`.
- Versions follow [Semantic Versioning](https://semver.org/): new checks or features raise the minor version (2.1.0), fixes the patch version (2.0.1), and changes that break parameters or the report/CSV format the major version (3.0.0).
