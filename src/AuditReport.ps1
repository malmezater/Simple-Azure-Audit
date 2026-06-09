# ─────────────────────────────────────────────────────────────
# AuditReport.ps1
# Generates the CSV and HTML report from the collected findings.
# ─────────────────────────────────────────────────────────────

function New-AuditReport {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[PSCustomObject]]$Findings,
        [Parameter(Mandatory)][string]$SubscriptionName,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$HtmlPath
    )

    Write-Section "GENERATING REPORTS"

    # ── CSV ──────────────────────────────────────────────────
    Write-Step "Saving CSV..."
    $Findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Step "  $CsvPath" "Gray"

    # ── HTML ─────────────────────────────────────────────────
    Write-Step "Building HTML report..."

    $sevOrder = @{ "Critical"=0; "High"=1; "Medium"=2; "Low"=3; "Info"=4 }
    $sorted   = $Findings | Sort-Object { $sevOrder[$_.Severity] }

    $sevCount = @{
        Critical = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
        High     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
        Medium   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
        Low      = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
        Info     = @($Findings | Where-Object { $_.Severity -eq "Info" }).Count
    }

    $catStats = $Findings | Group-Object Category | Sort-Object Count -Descending

    $badgeColors = @{
        "Critical" = "#c0392b"; "High" = "#e67e22"
        "Medium"   = "#d4ac0d"; "Low"  = "#27ae60"; "Info" = "#2980b9"
    }

    function Get-Badge($sev) {
        $c = if ($badgeColors[$sev]) { $badgeColors[$sev] } else { "#95a5a6" }
        "<span style='background:$c;color:#fff;padding:2px 10px;border-radius:12px;font-size:.76rem;font-weight:700;white-space:nowrap'>$sev</span>"
    }

    Add-Type -AssemblyName System.Web

    $tableRows = ($sorted | ForEach-Object {
        $badge = Get-Badge $_.Severity
        $catAttr = [System.Web.HttpUtility]::HtmlAttributeEncode($_.Category)
        "<tr data-category='$catAttr'>
          <td>$($_.Category)</td>
          <td>$badge</td>
          <td style='font-size:.82rem;color:#555'>$($_.ResourceType)</td>
          <td style='font-family:Consolas,monospace;font-size:.8rem;color:#0078d4'>$([System.Web.HttpUtility]::HtmlEncode($_.Resource))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode($_.Finding))</td>
          <td style='font-size:.82rem;color:#555'>$([System.Web.HttpUtility]::HtmlEncode($_.Recommendation))</td>
        </tr>"
    }) -join "`n"

    $catRows = ($catStats | ForEach-Object {
        $catAttr = [System.Web.HttpUtility]::HtmlAttributeEncode($_.Name)
        "<tr class='cat-row' data-category='$catAttr' onclick='filterCategory(this)' style='cursor:pointer'><td>$($_.Name)</td><td><strong>$($_.Count)</strong></td></tr>"
    }) -join "`n"

    # Severity bar width
    $total = [math]::Max($Findings.Count, 1)
    function Get-Pct($n) { [math]::Round($n / $total * 100, 1) }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure Audit - $SubscriptionName</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f2f5;color:#2c3e50;font-size:14px}
  a{color:#0078d4}
  header{background:linear-gradient(135deg,#0078d4 0%,#004e8c 100%);color:#fff;padding:2rem 2.5rem}
  header h1{font-size:1.7rem;font-weight:700;letter-spacing:-.3px}
  header p{opacity:.85;margin-top:.4rem;font-size:.9rem}
  .container{max-width:1400px;margin:2rem auto;padding:0 1.5rem}
  .grid-5{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}
  .card{background:#fff;border-radius:10px;padding:1.2rem 1rem;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.07);border-top:4px solid #dee}
  .card.c-crit{border-color:#c0392b}.card.c-high{border-color:#e67e22}
  .card.c-med{border-color:#d4ac0d}.card.c-low{border-color:#27ae60}.card.c-info{border-color:#2980b9}
  .card .num{font-size:2rem;font-weight:800;line-height:1}
  .card.c-crit .num{color:#c0392b}.card.c-high .num{color:#e67e22}
  .card.c-med .num{color:#d4ac0d}.card.c-low .num{color:#27ae60}.card.c-info .num{color:#2980b9}
  .card .lbl{font-size:.78rem;color:#7f8c8d;margin-top:.3rem;text-transform:uppercase;letter-spacing:.5px}
  .panel{background:#fff;border-radius:10px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 2px 8px rgba(0,0,0,.07)}
  .panel h2{font-size:1rem;font-weight:700;color:#0078d4;border-bottom:2px solid #e8f0fe;padding-bottom:.6rem;margin-bottom:1rem}
  table{width:100%;border-collapse:collapse}
  th{background:#f8f9fa;text-align:left;padding:.6rem .8rem;font-size:.82rem;font-weight:700;color:#555;border-bottom:2px solid #ddd}
  td{padding:.6rem .8rem;border-bottom:1px solid #f2f2f2;vertical-align:top;line-height:1.4}
  tr:hover td{background:#fafbff}
  .cat-row:hover td{background:#e8f0fe}
  .cat-row.active td{background:#0078d4;color:#fff}
  .cat-row.active td strong{color:#fff}
  .filter-note{display:none;align-items:center;gap:.6rem;font-size:.82rem;color:#555;margin-bottom:.8rem}
  .filter-note.show{display:flex}
  .filter-note .clear-btn{cursor:pointer;background:#0078d4;color:#fff;border:none;border-radius:6px;padding:.25rem .7rem;font-size:.78rem;font-weight:600}
  .filter-note .clear-btn:hover{background:#005a9e}
  .bar-wrap{background:#eee;border-radius:6px;height:8px;margin-top:.3rem}
  .bar{height:8px;border-radius:6px}
  footer{text-align:center;padding:1.5rem;color:#aaa;font-size:.8rem}
  @media print{
    body{background:#fff}
    header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .panel{box-shadow:none;border:1px solid #ddd}
  }
</style>
</head>
<body>
<header>
  <h1>Azure Environment Audit</h1>
  <p>
    <strong>$SubscriptionName</strong> &nbsp;|&nbsp; $SubscriptionId<br>
    Tenant: $TenantId &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
  </p>
</header>

<div class="container">

  <div class="grid-5">
    <div class="card c-crit"><div class="num">$($sevCount.Critical)</div><div class="lbl">Critical</div></div>
    <div class="card c-high"><div class="num">$($sevCount.High)</div><div class="lbl">High</div></div>
    <div class="card c-med" ><div class="num">$($sevCount.Medium)</div><div class="lbl">Medium</div></div>
    <div class="card c-low" ><div class="num">$($sevCount.Low)</div><div class="lbl">Low</div></div>
    <div class="card c-info"><div class="num">$($sevCount.Info)</div><div class="lbl">Info</div></div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 2fr;gap:1.5rem;margin-bottom:1.5rem">
    <div class="panel">
      <h2>Findings by category</h2>
      <p style="font-size:.78rem;color:#7f8c8d;margin-bottom:.6rem">Click a category to filter the findings below.</p>
      <table>
        <thead><tr><th>Category</th><th>Count</th></tr></thead>
        <tbody>$catRows</tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Distribution by severity</h2>
      <table>
        <thead><tr><th>Level</th><th>Count</th><th style="width:40%">Share</th></tr></thead>
        <tbody>
          <tr><td>Critical</td><td>$($sevCount.Critical)</td><td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Critical)%;background:#c0392b"></div></div></td></tr>
          <tr><td>High</td>    <td>$($sevCount.High)</td>    <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.High)%;background:#e67e22"></div></div></td></tr>
          <tr><td>Medium</td>  <td>$($sevCount.Medium)</td>  <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Medium)%;background:#d4ac0d"></div></div></td></tr>
          <tr><td>Low</td>     <td>$($sevCount.Low)</td>     <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Low)%;background:#27ae60"></div></div></td></tr>
          <tr><td>Info</td>    <td>$($sevCount.Info)</td>    <td><div class="bar-wrap"><div class="bar" style="width:$(Get-Pct $sevCount.Info)%;background:#2980b9"></div></div></td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <h2>All findings ($($Findings.Count) total) - sorted by severity</h2>
    <div class="filter-note" id="filterNote">
      <span>Filtered by category: <strong id="filterLabel"></strong> (<span id="filterCount">0</span> shown)</span>
      <button class="clear-btn" onclick="clearFilter()">Show all</button>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width:100px">Category</th>
          <th style="width:90px">Level</th>
          <th style="width:120px">Resource type</th>
          <th style="width:200px">Resource</th>
          <th>Finding</th>
          <th style="width:250px">Recommendation</th>
        </tr>
      </thead>
      <tbody id="findingsBody">
        $tableRows
      </tbody>
    </table>
  </div>

</div>

<footer>
  Azure Audit Script &nbsp;·&nbsp; $(Get-Date -Format 'yyyy-MM-dd') &nbsp;·&nbsp;
  $($Findings.Count) findings total &nbsp;·&nbsp;
  <a href="$(Split-Path $CsvPath -Leaf)">Download CSV</a>
</footer>

<script>
  var activeCategory = null;

  function applyFilter(category) {
    var rows = document.querySelectorAll('#findingsBody tr');
    var shown = 0;
    rows.forEach(function (row) {
      if (category === null || row.getAttribute('data-category') === category) {
        row.style.display = '';
        shown++;
      } else {
        row.style.display = 'none';
      }
    });

    var catRows = document.querySelectorAll('.cat-row');
    catRows.forEach(function (cr) {
      if (category !== null && cr.getAttribute('data-category') === category) {
        cr.classList.add('active');
      } else {
        cr.classList.remove('active');
      }
    });

    var note = document.getElementById('filterNote');
    if (category === null) {
      note.classList.remove('show');
    } else {
      document.getElementById('filterLabel').textContent = category;
      document.getElementById('filterCount').textContent = shown;
      note.classList.add('show');
    }
  }

  function filterCategory(el) {
    var category = el.getAttribute('data-category');
    if (activeCategory === category) {
      clearFilter();
    } else {
      activeCategory = category;
      applyFilter(category);
    }
  }

  function clearFilter() {
    activeCategory = null;
    applyFilter(null);
  }
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $HtmlPath -Encoding UTF8
    Write-Step "  $HtmlPath" "Gray"
}
