[CmdletBinding()]
param(
    [ValidateSet("Quick", "Deep")]
    [string]$Mode = "Deep",
    [switch]$Delta,
    [switch]$SkipBaselineUpdate,
    [switch]$OpenReport,
    [switch]$OpenOnCritical,
    [switch]$Quiet,
    [switch]$FailOnCritical
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$rootPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Import-Module (Join-Path $rootPath "Modules\Common\Utils.psm1") -Force
Import-Module (Join-Path $rootPath "Modules\Core\Core.Engine.psm1") -Force
Import-Module (Join-Path $rootPath "Modules\Audit\Audit.Module.psm1") -Force
Import-Module (Join-Path $rootPath "Modules\Hunter\Hunter.Module.psm1") -Force
Import-Module (Join-Path $rootPath "Modules\Reporting\Reporting.Engine.psm1") -Force

if (-not $Quiet.IsPresent) {
    Write-Host "==================================================" -ForegroundColor DarkCyan
    Write-Host "            WinGuard-PS Security Scanner          " -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor DarkCyan
}

$ctx = New-WGScanContext -RootPath $rootPath

if (-not (Test-Path -Path $ctx.DataPath)) {
    New-Item -ItemType Directory -Path $ctx.DataPath -Force | Out-Null
}

if (-not (Test-WGAdministrator)) {
    Write-WGStatus -Type Fail -Message "[-] Administrator privileges are required. Re-run PowerShell as Administrator."
    exit 1
}

$scanStart = Get-Date

Write-WGLog -Path $ctx.LogPath -Level INFO -Message "Scan started." -Context @{ Mode = $Mode; Delta = $Delta.IsPresent; Quiet = $Quiet.IsPresent }
if (-not $Quiet.IsPresent) {
    Write-WGStatus -Type Info -Message "[*] Loading policy and rules..."
}
$config = Get-WGConfig -PolicyPath $ctx.ConfigPath -RulesPath $ctx.RulesPath

$allFindings = @()

if (-not $Quiet.IsPresent) {
    Write-WGStatus -Type Info -Message "[*] Phase 1: OS hardening audit ($Mode)..."
}
$auditFindings = Invoke-WGAuditModule -Policy $config.Policy -ScanMode $Mode
$allFindings += $auditFindings
Write-WGLog -Path $ctx.LogPath -Level INFO -Message "Audit phase complete." -Context @{ findings = @($auditFindings).Count }

if (-not $Quiet.IsPresent) {
    Write-WGStatus -Type Info -Message "[*] Phase 2: Threat hunting ($Mode)..."
}
$hunterFindings = Invoke-WGHunterModule -Policy $config.Policy -ScanMode $Mode
$allFindings += $hunterFindings
Write-WGLog -Path $ctx.LogPath -Level INFO -Message "Hunter phase complete." -Context @{ findings = @($hunterFindings).Count }

$counts = Get-WGSeverityCounts -Findings $allFindings
$score = Get-WGRiskScore -Findings $allFindings -Policy $config.Policy

$deltaSummary = [PSCustomObject]@{ Enabled = $false; Note = "" }
if ($Delta.IsPresent) {
    $baseline = Import-WGBaseline -Path $ctx.BaselinePath
    $deltaResult = Get-WGBaselineDelta -CurrentFindings $allFindings -BaselineObject $baseline
    if (-not $deltaResult.HasBaseline) {
        $deltaSummary = [PSCustomObject]@{
            Enabled         = $true
            HadBaseline     = $false
            NewFindings     = @($allFindings)
            NewCount        = @($allFindings).Count
            RemovedCount    = 0
            RemovedEntries  = @()
            Note            = "No baseline file yet; all current findings are listed as new. Next run will compare after baseline is saved."
        }
    } else {
        $deltaSummary = [PSCustomObject]@{
            Enabled        = $true
            HadBaseline    = $true
            NewFindings    = @($deltaResult.NewFindings)
            NewCount       = @($deltaResult.NewFindings).Count
            RemovedCount   = @($deltaResult.RemovedEntries).Count
            RemovedEntries = @($deltaResult.RemovedEntries)
            Note           = ""
        }
    }
    Write-WGLog -Path $ctx.LogPath -Level INFO -Message "Delta computed." -Context @{ new = $deltaSummary.NewCount; removed = $deltaSummary.RemovedCount }
}

$durationSec = [Math]::Round(((Get-Date) - $scanStart).TotalSeconds, 2)
$durationHuman = "$durationSec s"

$summary = [PSCustomObject]@{
    Score             = $score
    Critical          = $counts.Critical
    Warning           = $counts.Warning
    Pass              = $counts.Pass
    Info              = $counts.Info
    ScanTime          = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ScanMode          = $Mode
    ComputerName      = $env:COMPUTERNAME
    UserName          = $env:USERNAME
    DurationSeconds   = $durationSec
    DurationHuman     = $durationHuman
    ToolVersion       = "1.5.0"
}

$report = [PSCustomObject]@{
    Meta = [PSCustomObject]@{
        Tool              = "WinGuard-PS"
        Version           = "1.5.0"
        Timestamp         = (Get-Date).ToUniversalTime().ToString("o")
        ScanMode          = $Mode
        DurationSeconds   = $durationSec
        Delta             = $deltaSummary
    }
    Summary  = $summary
    Findings = $allFindings
}

if (-not $Quiet.IsPresent) {
    Write-WGStatus -Type Info -Message "[*] Exporting JSON/HTML/CSV/Summary reports..."
}
Export-WGJsonReport -ReportObject $report -Path $ctx.JsonReportPath
Export-WGHtmlReport -Summary $summary -Findings $allFindings -Path $ctx.HtmlReportPath -DeltaSummary $deltaSummary
Export-WGCsvReport -Findings $allFindings -Path $ctx.CsvReportPath
Export-WGSummaryTextReport -Summary $summary -Findings $allFindings -Path $ctx.SummaryTextPath
Write-WGLog -Path $ctx.LogPath -Level INFO -Message "Reports exported." -Context @{ json = $ctx.JsonReportPath; html = $ctx.HtmlReportPath; csv = $ctx.CsvReportPath; summary = $ctx.SummaryTextPath }

if (-not $SkipBaselineUpdate.IsPresent) {
    Export-WGBaseline -Findings $allFindings -Path $ctx.BaselinePath
    Write-WGLog -Path $ctx.LogPath -Level INFO -Message "Baseline updated." -Context @{ path = $ctx.BaselinePath }
}

if (-not $Quiet.IsPresent) {
    Write-WGStatus -Type Pass -Message "[+] Scan complete in $durationHuman."
    Write-WGStatus -Type Pass -Message "[+] JSON: $($ctx.JsonReportPath)"
    Write-WGStatus -Type Pass -Message "[+] HTML: $($ctx.HtmlReportPath)"
    Write-WGStatus -Type Pass -Message "[+] CSV: $($ctx.CsvReportPath)"
    Write-WGStatus -Type Pass -Message "[+] Summary: $($ctx.SummaryTextPath)"
} else {
    Write-Output $ctx.HtmlReportPath
}

if ($Delta.IsPresent -and -not $Quiet.IsPresent) {
    Write-WGStatus -Type Info -Message "[*] Delta: new=$($deltaSummary.NewCount) removed=$($deltaSummary.RemovedCount)"
}

$criticalHits = @($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
if ($OpenOnCritical.IsPresent -and $criticalHits -gt 0) {
    if (-not $Quiet.IsPresent) {
        Write-WGStatus -Type Warn -Message "[!] Critical findings detected; opening HTML report."
    }
    Start-Process $ctx.HtmlReportPath
} elseif ($OpenReport.IsPresent) {
    Start-Process $ctx.HtmlReportPath
}

if ($FailOnCritical.IsPresent -and $criticalHits -gt 0) {
    exit 2
}
exit 0
