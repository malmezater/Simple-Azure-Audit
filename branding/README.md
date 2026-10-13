# Report branding

The report's look (logo, colours, the line above the title) can be changed without touching `src\report-template.html`. A branding is a folder with up to three kinds of files:

```
branding/<name>/
├── brand.json   # name, texts and which images to use
├── brand.css    # colour tokens and any CSS overrides
└── logo.png     # logo and favicon (png, jpg, svg, gif, webp or ico)
```

`branding/example/` is a working example. Try it on the demo report:

```powershell
.\Update-ReportBranding.ps1 -Path .\Demo_AzureAudit_Report.html -Branding .\branding\example -OutFile .\demo-example.html
```

## Which branding is used

| Situation | Branding |
|-----------|----------|
| `-Branding <folder>` on `Invoke-AzureAudit.ps1` or `Update-ReportBranding.ps1` | That folder |
| No `-Branding`, and `branding/custom/` exists | `branding/custom/` |
| Neither | The neutral look |

`branding/custom/` is in `.gitignore` here, so a company's branding is never committed to the public repo by mistake.

## brand.json

| Field | Used for | Default |
|-------|----------|---------|
| `name` | Shown in the console when the report is built | The folder name |
| `eyebrow` | The small line above the report title | `Azure environment assessment` |
| `preparedBy` | Added to that line (`… · <preparedBy>`) when `-PreparedBy` is not given | – |
| `logo` | Image left of the title, 56 px high (40 px on phones) | No logo |
| `logoAlt` | The logo's alt text | `name` |
| `favicon` | Browser tab icon | None |

Images are embedded in the report as data URIs, so it stays one file that works offline. Use small images (a logo of about 100 px height is plenty).

## brand.css

The CSS is added after the report's own CSS, so it wins. Set the report's colour tokens for light mode in `:root`, and for dark mode in both `@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]){…} }` and `:root[data-theme="dark"]{…}` (the theme button sets `data-theme`).

| Token | What it colours |
|-------|-----------------|
| `--brand-band`, `--brand-band-ink` | Masthead background and title |
| `--brand-band-ink-2`, `--brand-band-muted` | Masthead details (subscription, tenant …) and the line above the title |
| `--brand-stripe`, `--brand-stripe-width` | Line under the masthead |
| `--accent`, `--accent-ink`, `--accent-wash`, `--link` | Buttons, active tab, links, highlights |
| `--page`, `--surface`, `--surface-2`, `--ink`, `--ink-2`, `--muted`, `--border`, `--border-strong`, `--grid`, `--axis` | Page and cards |
| `--sev-critical` … `--sev-info` | Severity colours in charts and chips |
| `--good`, `--warning`, `--serious`, `--critical`, `--meter-track`, `--meter-fill` | Status colours and meters |

The `--brand-*` tokens fall back to the neutral look when they are not set. Any other CSS can be added too, for example the masthead buttons on a dark band (see `branding/example/brand.css`). Keep overrides to colours and spacing; class names can change between versions, tokens are kept stable.

## Keeping a branded copy up to date

A company copy of the repo (for example in a private GitLab) can follow this repo with plain merges when all its own changes live in `branding/custom/`:

1. Once, in the company repo: add this repo as a remote, and commit the branding (it is ignored by `.gitignore`, so add it with `-f`):
   ```powershell
   git remote add public https://github.com/malmezater/Simple-Azure-Audit.git
   git add -f branding/custom
   git commit -m "Company branding"
   ```
2. For each update:
   ```powershell
   git fetch public
   git merge public/main --no-commit
   # The demo is generated: take the public one and brand it again
   git checkout public/main -- Demo_AzureAudit_Report.html
   .\Update-ReportBranding.ps1 -Path .\Demo_AzureAudit_Report.html -PreparedBy "<company>"
   git add Demo_AzureAudit_Report.html
   git commit -m "Merge public updates"
   ```

Every report the company copy builds then uses `branding/custom/` automatically, and nothing in `src/` differs from this repo, so merges do not conflict. Only the demo file conflicts, because both repos generate it; step 2 resolves that.
