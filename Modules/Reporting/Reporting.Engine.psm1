Set-StrictMode -Version Latest

function Escape-WGHtml {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Text
    )

    if ($null -eq $Text) { return "" }
    try {
        return [System.Net.WebUtility]::HtmlEncode($Text)
    } catch {
        return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
    }
}

function Export-WGJsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ReportObject,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $ReportObject | ConvertTo-Json -Depth 12 | Out-File -FilePath $Path -Encoding utf8
}

function Export-WGCsvReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Findings,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rows = foreach ($item in $Findings) {
        [PSCustomObject]@{
            Severity    = $item.Severity
            Category    = $item.Category
            CheckId     = $item.CheckId
            Title       = $item.Title
            Description = $item.Description
            Remediation = $item.Remediation
        }
    }

    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Export-WGSummaryTextReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)][object[]]$Findings,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $crit = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $warn = @($Findings | Where-Object { $_.Severity -eq "Warning" }).Count

    $prio = @()
    $prio += @($Findings | Where-Object { $_.Severity -eq "Critical" } | Select-Object -First 3)
    if ($prio.Count -lt 3) {
        $need = 3 - $prio.Count
        $prio += @($Findings | Where-Object { $_.Severity -eq "Warning" } | Select-Object -First $need)
    }
    $prio = @($prio | Select-Object -First 3)

    $lines = @()
    $verLine = "WinGuard-PS - Security summary"
    $sumTv = $Summary.PSObject.Properties['ToolVersion']
    if ($null -ne $sumTv -and $sumTv.Value) {
        $verLine = "WinGuard-PS v$([string]$sumTv.Value) - Security summary"
    }
    $lines += $verLine
    $lines += "Host: $($Summary.ComputerName) | User: $($Summary.UserName) | Time: $($Summary.ScanTime) | Mode: $($Summary.ScanMode)"
    if ($Summary.PSObject.Properties['DurationHuman'] -and $Summary.DurationHuman) {
        $lines += "Duration: $($Summary.DurationHuman)"
    }
    $lines += "Security score: $($Summary.Score)%"
    $lines += "Counts - Critical: $crit | Warning: $warn | Pass: $($Summary.Pass) | Info: $($Summary.Info)"
    $lines += ""
    $lines += "Top priorities (up to 3):"
    if (@($prio).Count -eq 0) {
        $lines += "- No Critical or Warning findings."
    } else {
        $n = 1
        foreach ($p in $prio) {
            $lines += "$n) [$($p.Severity)] $($p.Title)"
            $lines += "   Action: $($p.Remediation)"
            $n++
        }
    }

    $lines -join [Environment]::NewLine | Out-File -FilePath $Path -Encoding utf8
}

function Get-WGHtmlTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)][object[]]$Findings,
        $DeltaSummary = $null
    )

    $toolVer = "1.5.0"
    $tvProp = $Summary.PSObject.Properties['ToolVersion']
    if ($null -ne $tvProp -and $null -ne $tvProp.Value) { $toolVer = [string]$tvProp.Value }
    $durHuman = "n/a"
    $durProp = $Summary.PSObject.Properties['DurationHuman']
    if ($null -ne $durProp -and $null -ne $durProp.Value) { $durHuman = [string]$durProp.Value }

    $topFixes = @($Findings | Where-Object { $_.Severity -in @("Critical", "Warning") } | Select-Object -First 5)
    $fixList = if (@($topFixes).Count -gt 0) {
        ($topFixes | ForEach-Object { "<li>" + (Escape-WGHtml -Text "$($_.Title): $($_.Remediation)") + "</li>" }) -join ""
    } else {
        "<li>No urgent remediation actions found.</li>"
    }

    $execPrio = @()
    $execPrio += @($Findings | Where-Object { $_.Severity -eq "Critical" } | Select-Object -First 3)
    if ($execPrio.Count -lt 3) {
        $need = 3 - $execPrio.Count
        $execPrio += @($Findings | Where-Object { $_.Severity -eq "Warning" } | Select-Object -First $need)
    }
    $execPrio = @($execPrio | Select-Object -First 3)
    $execList = if (@($execPrio).Count -gt 0) {
        ($execPrio | ForEach-Object {
            "<li><strong>" + (Escape-WGHtml -Text $_.Severity) + ":</strong> " + (Escape-WGHtml -Text $_.Title) + "<br/><span class='small'>" + (Escape-WGHtml -Text $_.Remediation) + "</span></li>"
        }) -join ""
    } else {
        "<li>No Critical or Warning findings in this scan.</li>"
    }

    $execBlock = @"
<div class="card" id="execSummary">
  <h2>Executive summary (first priorities)</h2>
  <ol>$execList</ol>
</div>
"@

    $deltaBlock = ""
    if ($null -ne $DeltaSummary -and $DeltaSummary.Enabled) {
        $newList = ""
        if ($DeltaSummary.NewCount -gt 0 -and $DeltaSummary.NewFindings) {
            $newList = ($DeltaSummary.NewFindings | ForEach-Object { "<li>" + (Escape-WGHtml -Text "$($_.CheckId): $($_.Title)") + "</li>" }) -join ""
        } else {
            $newList = "<li>None</li>"
        }

        $removedList = ""
        if ($DeltaSummary.RemovedCount -gt 0 -and $DeltaSummary.RemovedEntries) {
            $removedList = ($DeltaSummary.RemovedEntries | ForEach-Object { "<li>" + (Escape-WGHtml -Text "$($_.checkId): $($_.title)") + "</li>" }) -join ""
        } else {
            $removedList = "<li>None</li>"
        }

        $hadBase = if ($DeltaSummary.HadBaseline) { "yes" } else { "no (first baseline will be created)" }
        $noteHtml = ""
        $noteProp = $DeltaSummary.PSObject.Properties['Note']
        if ($null -ne $noteProp -and $noteProp.Value) {
            $noteHtml = "<p class='small'>" + (Escape-WGHtml -Text ([string]$noteProp.Value)) + "</p>"
        }
        $deltaBlock = @"
<div class="card" id="deltaCard">
  <h2>Baseline Delta</h2>
  <p class="small">Compared to baseline: $hadBase</p>
  $noteHtml
  <div class="metrics">
    <div class="metric"><strong>New findings:</strong> $($DeltaSummary.NewCount)</div>
    <div class="metric"><strong>Removed since baseline:</strong> $($DeltaSummary.RemovedCount)</div>
  </div>
  <h3>New</h3>
  <ul>$newList</ul>
  <h3>Removed</h3>
  <ul>$removedList</ul>
</div>
"@
    }

    $categories = @($Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object)
    $catOptions = "<option value='all'>All categories</option>"
    foreach ($c in $categories) {
        $cv = Escape-WGHtml -Text $c
        $catOptions += "<option value='$cv'>$cv</option>"
    }

    $rows = foreach ($item in $Findings) {
        $cls = $item.Severity.ToLowerInvariant()
        $catCell = Escape-WGHtml -Text $item.Category
        $sevCell = Escape-WGHtml -Text $item.Severity
        $titleCell = Escape-WGHtml -Text $item.Title
        $descCell = Escape-WGHtml -Text $item.Description
        $remCell = Escape-WGHtml -Text $item.Remediation
        $catAttr = Escape-WGHtml -Text $item.Category
        $searchBlob = ("$($item.Severity) $($item.Category) $($item.Title) $($item.Description)").ToLowerInvariant()
        $searchAttr = Escape-WGHtml -Text $searchBlob
        "<tr class='$cls' data-severity='$($item.Severity)' data-category=""$catAttr"" data-text=""$searchAttr""><td>$sevCell</td><td>$catCell</td><td>$titleCell</td><td>$descCell</td><td>$remCell</td></tr>"
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinGuard-PS Security Report</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }
.card { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.metrics { display: flex; gap: 12px; flex-wrap: wrap; }
.metric { background: #1e293b; padding: 10px 14px; border-radius: 6px; }
.controls { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
input[type="search"], select { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 8px 10px; min-width: 200px; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #334155; padding: 8px; text-align: left; vertical-align: top; }
th { background: #1e293b; }
tr.critical { background: rgba(239, 68, 68, 0.2); }
tr.warning { background: rgba(245, 158, 11, 0.2); }
tr.pass { background: rgba(34, 197, 94, 0.2); }
tr.info { background: rgba(59, 130, 246, 0.2); }
tr.hidden { display: none; }
.small { color: #94a3b8; font-size: 12px; }
#execSummary ol { margin: 8px 0 0 18px; }
#execSummary li { margin-bottom: 10px; }
</style>
</head>
<body>
<h1>WinGuard-PS Security Audit Report</h1>
<div class="card">
  <div class="metrics">
    <div class="metric"><strong>Security Score:</strong> $($Summary.Score)%</div>
    <div class="metric"><strong>Critical:</strong> $($Summary.Critical)</div>
    <div class="metric"><strong>Warning:</strong> $($Summary.Warning)</div>
    <div class="metric"><strong>Pass:</strong> $($Summary.Pass)</div>
    <div class="metric"><strong>Info:</strong> $($Summary.Info)</div>
  </div>
  <p class="small">Scan time: $($Summary.ScanTime) | Duration: $durHuman | Host: $($Summary.ComputerName) | User: $($Summary.UserName) | Mode: $($Summary.ScanMode)</p>
</div>
$execBlock
$deltaBlock
<div class="card">
  <h2>Top Fixes</h2>
  <ul>$fixList</ul>
</div>
<div class="card">
  <h2>Findings</h2>
  <div class="controls">
    <label class="small" for="searchBox">Search</label>
    <input type="search" id="searchBox" placeholder="Filter by text..." />
    <label class="small" for="severityFilter">Severity</label>
    <select id="severityFilter">
      <option value="all">All</option>
      <option value="Critical">Critical</option>
      <option value="Warning">Warning</option>
      <option value="Pass">Pass</option>
      <option value="Info">Info</option>
    </select>
    <label class="small" for="categoryFilter">Category</label>
    <select id="categoryFilter">$catOptions</select>
  </div>
  <table id="findingsTable">
    <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Remediation</th></tr></thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
</div>
<script>
(function() {
  var table = document.getElementById('findingsTable');
  if (!table) return;
  var rows = table.querySelectorAll('tbody tr');
  var search = document.getElementById('searchBox');
  var severity = document.getElementById('severityFilter');
  var category = document.getElementById('categoryFilter');
  function apply() {
    var q = (search && search.value ? search.value.toLowerCase() : '');
    var sev = severity ? severity.value : 'all';
    var cat = category ? category.value : 'all';
    rows.forEach(function(row) {
      var ds = row.getAttribute('data-severity') || '';
      var dc = row.getAttribute('data-category') || '';
      var dt = row.getAttribute('data-text') || '';
      var okSev = (sev === 'all' || ds === sev);
      var okCat = (cat === 'all' || dc === cat);
      var okText = (!q || dt.indexOf(q) !== -1);
      if (okSev && okCat && okText) {
        row.classList.remove('hidden');
      } else {
        row.classList.add('hidden');
      }
    });
  }
  if (search) search.addEventListener('input', apply);
  if (severity) severity.addEventListener('change', apply);
  if (category) category.addEventListener('change', apply);
})();
</script>
<p class="small" style="margin-top:24px;">WinGuard-PS v$toolVer | Scan duration: $durHuman</p>
</body>
</html>
"@
}

function Export-WGHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)][object[]]$Findings,
        [Parameter(Mandatory = $true)][string]$Path,
        $DeltaSummary = $null
    )

    $html = Get-WGHtmlTemplate -Summary $Summary -Findings $Findings -DeltaSummary $DeltaSummary
    $html | Out-File -FilePath $Path -Encoding utf8
}

Export-ModuleMember -Function Export-WGJsonReport, Export-WGHtmlReport, Export-WGCsvReport, Export-WGSummaryTextReport
