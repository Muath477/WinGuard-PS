Set-StrictMode -Version Latest

function Test-WGAdministrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WGConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PolicyPath,
        [Parameter(Mandatory = $true)][string]$RulesPath
    )

    $policy = Get-Content -Path $PolicyPath -Raw | ConvertFrom-Json
    $rules = Get-Content -Path $RulesPath -Raw | ConvertFrom-Json

    return [PSCustomObject]@{
        Policy = $policy
        Rules  = $rules
    }
}

function Get-WGSeverityCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Findings
    )

    return [PSCustomObject]@{
        Critical = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
        Warning  = @($Findings | Where-Object { $_.Severity -eq "Warning" }).Count
        Pass     = @($Findings | Where-Object { $_.Severity -eq "Pass" }).Count
        Info     = @($Findings | Where-Object { $_.Severity -eq "Info" }).Count
    }
}

function Get-WGRiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Findings,
        [Parameter(Mandatory = $true)]$Policy
    )

    $weights = $Policy.weights
    $findingCount = @($Findings).Count
    $maxPenalty = [Math]::Max($findingCount, 1)

    $penalty = 0
    foreach ($item in $Findings) {
        switch ($item.Severity) {
            "Critical" { $penalty += [int]$weights.critical }
            "Warning" { $penalty += [int]$weights.warning }
            "Info" { $penalty += [int]$weights.info }
            default { $penalty += 0 }
        }
    }

    $maxPossible = $maxPenalty * [int]$weights.critical
    $raw = if ($maxPossible -gt 0) { 100 - [Math]::Round(($penalty / $maxPossible) * 100, 0) } else { 100 }
    $score = [Math]::Min([Math]::Max($raw, 0), 100)
    return [int]$score
}

function Import-WGBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        return $null
    }

    try {
        return Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Export-WGBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Findings,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $entries = @()
    foreach ($f in $Findings) {
        $fp = Get-WGFindingFingerprint -Finding $f
        $entries += [PSCustomObject]@{
            fingerprint = $fp
            checkId     = $f.CheckId
            title       = $f.Title
            severity    = $f.Severity
        }
    }

    $obj = [PSCustomObject]@{
        version   = 1
        updatedAt = (Get-Date).ToUniversalTime().ToString("o")
        entries   = $entries
    }

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $obj | ConvertTo-Json -Depth 6 | Out-File -FilePath $Path -Encoding utf8
}

function Get-WGBaselineDelta {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$CurrentFindings,
        $BaselineObject
    )

    $result = [PSCustomObject]@{
        HasBaseline    = $false
        NewFindings    = @()
        RemovedEntries = @()
    }

    if ($null -eq $BaselineObject -or $null -eq $BaselineObject.entries) {
        return $result
    }

    $result.HasBaseline = $true
    $oldMap = @{}
    foreach ($e in @($BaselineObject.entries)) {
        if ($e -and $e.fingerprint) { $oldMap[$e.fingerprint] = $e }
    }

    $currentFps = @{}
    foreach ($f in $CurrentFindings) {
        $fp = Get-WGFindingFingerprint -Finding $f
        $currentFps[$fp] = $true
        if (-not $oldMap.ContainsKey($fp)) {
            $result.NewFindings += $f
        }
    }

    foreach ($fp in $oldMap.Keys) {
        if (-not $currentFps.ContainsKey($fp)) {
            $result.RemovedEntries += $oldMap[$fp]
        }
    }

    return $result
}

function New-WGScanContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RootPath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    return [PSCustomObject]@{
        RootPath        = $RootPath
        ReportsPath     = Join-Path $RootPath "Reports"
        LogsPath        = Join-Path $RootPath "Logs"
        DataPath        = Join-Path $RootPath "Data"
        ConfigPath      = Join-Path $RootPath "Config\policy.json"
        RulesPath       = Join-Path $RootPath "Rules\default.rules.json"
        BaselinePath    = Join-Path $RootPath "Data\baseline.json"
        Timestamp       = $timestamp
        JsonReportPath  = Join-Path $RootPath "Reports\Audit_$timestamp.json"
        HtmlReportPath  = Join-Path $RootPath "Reports\Audit_$timestamp.html"
        CsvReportPath   = Join-Path $RootPath "Reports\Audit_$timestamp.csv"
        SummaryTextPath = Join-Path $RootPath "Reports\Audit_$timestamp.summary.txt"
        LogPath         = Join-Path $RootPath "Logs\Scan_$timestamp.log.jsonl"
    }
}

Export-ModuleMember -Function Test-WGAdministrator, Get-WGConfig, Get-WGSeverityCounts, Get-WGRiskScore, Import-WGBaseline, Export-WGBaseline, Get-WGBaselineDelta, New-WGScanContext
