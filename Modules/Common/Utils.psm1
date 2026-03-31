Set-StrictMode -Version Latest

function New-WGFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$CheckId,
        [Parameter(Mandatory = $true)][ValidateSet("Critical", "Warning", "Pass", "Info")][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$Remediation,
        [hashtable]$Data = @{}
    )

    return [PSCustomObject]@{
        TimeUtc     = (Get-Date).ToUniversalTime().ToString("o")
        Category    = $Category
        CheckId     = $CheckId
        Severity    = $Severity
        Title       = $Title
        Description = $Description
        Remediation = $Remediation
        Data        = $Data
    }
}

function Write-WGLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet("INFO", "WARN", "ERROR")][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Context = @{}
    )

    $entry = [PSCustomObject]@{
        timestamp = (Get-Date).ToString("o")
        level     = $Level
        message   = $Message
        context   = $Context
    }

    $entry | ConvertTo-Json -Depth 6 -Compress | Out-File -FilePath $Path -Append -Encoding utf8
}

function Write-WGStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("Info", "Pass", "Warn", "Fail")][string]$Type = "Info"
    )

    $color = switch ($Type) {
        "Pass" { "Green" }
        "Warn" { "Yellow" }
        "Fail" { "Red" }
        default { "Cyan" }
    }

    Write-Host $Message -ForegroundColor $color
}

function Get-WGFindingFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Finding
    )

    $dataJson = "{}"
    if ($null -ne $Finding.Data) {
        $dataJson = $Finding.Data | ConvertTo-Json -Depth 8 -Compress
    }

    $raw = "$($Finding.CheckId)|$($Finding.Title)|$dataJson"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes($raw)
    $hash = $sha.ComputeHash($bytes)
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

function Test-WGPathMatchesPrefix {
    [CmdletBinding()]
    param(
        [string]$Path,
        [string[]]$Prefixes
    )

    if (-not $Path -or -not $Prefixes) { return $false }
    foreach ($p in $Prefixes) {
        if (-not $p) { continue }
        if ($Path.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-WGIsExternalRemoteAddress {
    [CmdletBinding()]
    param([string]$Addr)

    if ([string]::IsNullOrWhiteSpace($Addr)) { return $false }
    $a = $Addr.Trim()
    if ($a -eq '127.0.0.1' -or $a -eq '0.0.0.0' -or $a -eq '::1' -or $a -eq '::') { return $false }
    if ($a -like '*::ffff:127.0.0.1*') { return $false }

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($a, [ref]$ip)) { return $true }

    if ($ip.AddressFamily -eq 'InterNetwork') {
        $b = $ip.GetAddressBytes()
        if ($b[0] -eq 10) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        return $true
    }

    if ($ip.AddressFamily -eq 'InterNetworkV6') {
        if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6Multicast) { return $false }
        $bytes = $ip.GetAddressBytes()
        if ($bytes[0] -eq 0xfc -or $bytes[0] -eq 0xfd) { return $false }
        if ($bytes[0] -eq 0xfe -and ($bytes[1] -band 0xc0) -eq 0x80) { return $false }
        return $true
    }

    return $true
}

Export-ModuleMember -Function New-WGFinding, Write-WGLog, Write-WGStatus, Get-WGFindingFingerprint, Test-WGPathMatchesPrefix, Test-WGIsExternalRemoteAddress
