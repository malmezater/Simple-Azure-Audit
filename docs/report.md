# Report and output

## The report

Each run creates a folder with a self-contained HTML file that works offline and can be sent to a customer.

> **Example:** open [`Demo_AzureAudit_Report.html`](../Demo_AzureAudit_Report.html) to see a report built from fictional data (Northwind Traders, two made-up subscriptions).

| Tab | Content |
|-----|---------|
| **Overview** | Number of critical and high issues, severity tiles, *where the risk is* per area, tool coverage with pass rates, and the top 10 priorities. With several subscriptions, also a **By subscription** table. |
| **Action plan** | A project plan in four phases (act now, reduce risk, harden, improve). Each phase holds workstreams with *why*, *how* (numbered steps), effort and owner, and the issues to fix. Select an issue to see its resources. **Download plan (CSV)** exports it for Planner, Azure DevOps or Excel. See [Action plan](checks.md#action-plan). |
| **Findings** | Grouped per issue (one check, many resources) or as a flat list. Filter by severity, area, source, subscription and free text (CVE IDs are searchable). Every issue shows recommendation, reference link, compliance mapping, vulnerabilities with links, and affected resources. |
| **Resources** | The most affected resources, and which tools flagged them. |
| **Vulnerabilities** | Every CVE and GHSA ID found, with *Known exploited* (CISA KEV) marking, CISA due date, CVSS, affected resources and links to NVD, CVE.org, MSRC, CISA KEV and GitHub Advisory. Also explains the vulnerability sources and why the list can be empty. See [CVE references](checks.md#cve-references-and-known-exploited-vulnerabilities). |
| **Tools & method** | Status, version and duration of each tool, links to each tool's own report, and how severities and areas are normalised. |

The report can also **export a CSV** of the current filter and **print to PDF**, and it has a light and a dark theme.

### Findings vs issues

A *finding* is one failed check on one resource. An *issue* groups all findings from the same check, so "missing tags" on 300 resources is **one issue with 300 findings**. Issues are prioritised by severity and number of affected resources.

How each tool's severity is mapped is described in [Checks](checks.md#severity-and-area-normalisation).

## Output

```
AzureAudit_<Subscription | Customer_Nsubs>_<timestamp>.zip    # Report to share (-Zip Report, default)
AzureAudit_<Subscription | Customer_Nsubs>_<timestamp>/
├── AzureAudit_<Subscription>_<timestamp>.html   # Interactive report (self-contained)
├── AzureAudit_<Subscription>_<timestamp>.csv    # All findings, semicolon-separated, UTF-8
├── AzureAudit_<Subscription>_<timestamp>_ActionPlan.csv   # The action plan, one row per issue
├── audit-data.json                              # Merged, normalised data (findings, tool runs, plan, vulnerabilities)
├── run.json                                     # Run metadata used by -ImportFrom
├── logs/                                        # Transcript per external tool
└── raw/
    ├── native/     findings.json, defender-va.json
    ├── kev/        known_exploited_vulnerabilities.json (CISA KEV, when a CVE was found)
    ├── prowler/    prowler.ocsf.json, prowler.html, prowler.csv, compliance/
    ├── maester/    maester.json, maester.html, maester.md
    ├── psrule/     psrule-results.json
    ├── azgovviz/   AzGovViz_*.html, *_RoleAssignments.csv, *_MDfCCoverage.csv, ...
    ├── wara/       WARA-File-*.json, recommendations.json
    └── ari/        *.xlsx, *.xml (draw.io)
```

## Sharing the report

Share the **zip**, not the run folder. The run folder holds all raw tool output, which is often several hundred MB and thousands of files. That output is only needed to rebuild the report with `-ImportFrom`.

| Zip | Contains | Use |
|-----|----------|-----|
| `<RunFolder>.zip` (`-Zip Report`, default) | HTML report, findings CSV, action plan CSV, `audit-data.json`, and the tool reports linked from the report: Prowler HTML/CSV, Maester HTML/Markdown, AzGovViz HTML, PSRule and WARA JSON, ARI Excel and draw.io diagram | Send to the customer, or upload to OneDrive/SharePoint. Unzip and open the HTML; the links to the tool reports work. |
| `<RunFolder>_full.zip` (`-Zip Full`) | The whole run folder, including raw data and logs | Archive, or move the run to another machine and rebuild with `-ImportFrom`. |

To zip an older run, rebuild it: `.\Invoke-AzureAudit.ps1 -ImportFrom "<RunFolder>" -Zip Report`.

## CSV columns

| Column | Content |
|--------|---------|
| Severity | Critical / High / Medium / Low / Info |
| Category | Security, Identity, Governance, Reliability, Cost, Operations, Performance, Infrastructure, Compliance |
| Source | Native, Azure Advisor, Prowler, Maester, PSRule, AzGovViz, WARA |
| CheckId | Stable ID of the check, used to group findings into issues and to compare runs. The built-in IDs are listed in [Checks](checks.md). |
| Title | Name of the issue |
| Resource / ResourceType / ResourceId | Affected resource |
| SubscriptionName / SubscriptionId | Subscription the finding belongs to (`Tenant` for Entra ID checks) |
| Finding | Detail for this resource |
| Recommendation | Suggested action |
| Reference | Documentation link |
| Frameworks | Compliance mapping (CIS, ISO, NIST, EIDSCA, WAF pillar …) |
| Vulnerabilities | CVE and GHSA IDs, comma-separated |
| Timestamp | When the finding was recorded |

## Action plan CSV columns

`<name>_ActionPlan.csv` has one row per issue, in the recommended order. The same file can be downloaded from the Action plan tab.

| Column | Content |
|--------|---------|
| Order | Position in the plan |
| Phase / Timeframe | E.g. *Phase 1 – Act now*, *0–2 weeks* |
| Workstream / Owner / Effort | What kind of work it is, the role that usually owns it, and a rough effort |
| Severity / Issue / Area / Source / CheckId | The issue |
| Resources / Findings | How many resources and findings the issue covers |
| KnownExploited | `Yes` when one of its CVEs is on the CISA KEV list |
| Vulnerabilities | CVE and GHSA IDs |
| Recommendation | The tool's recommendation for the issue |
| Why / How | The workstream's reason and steps (steps separated by `\|`) |
