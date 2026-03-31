Set-StrictMode -Version Latest

function Get-WGProcessExecutablePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId
    )

    if ($ProcessId -le 0) { return $null }
    $p = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if ($p) { return $p.ExecutablePath }
    return $null
}

function Get-WGSeverityRank {
    [CmdletBinding()]
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { return 4 }
        "Warning" { return 3 }
        "Info" { return 2 }
        "Pass" { return 1 }
        default { return 0 }
    }
}

function Get-WGSeverityFromRank {
    [CmdletBinding()]
    param([int]$Rank)
    if ($Rank -ge 4) { return "Critical" }
    if ($Rank -ge 3) { return "Warning" }
    if ($Rank -ge 2) { return "Info" }
    return "Pass"
}

function Test-WGPortSystemDowngrade {
    [CmdletBinding()]
    param(
        [int]$LocalPort,
        [string]$ExePath,
        [string]$ProcessName,
        $Policy
    )

    $cfg = $Policy.network.downgradeWhenWindowsSystemBinary
    if (-not $cfg -or -not $cfg.enabled) { return $false }
    $ports = @()
    if ($null -ne $cfg.ports) { $ports = @($cfg.ports) }
    if ($ports.Count -eq 0 -or $ports -notcontains $LocalPort) { return $false }
    if (-not $ExePath) { return $false }
    $root = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if (-not $ExePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if (-not $ProcessName) { return $false }
    if ($ProcessName.Equals("System", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($ProcessName.Equals("svchost", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

function Test-WGPortProcessAllowlist {
    [CmdletBinding()]
    param(
        [int]$LocalPort,
        [string]$ProcessName,
        $Policy
    )

    if (-not $Policy.allowlist -or -not $Policy.allowlist.portProcessAllow) { return $false }
    foreach ($rule in @($Policy.allowlist.portProcessAllow)) {
        if ([int]$rule.port -ne $LocalPort) { continue }
        $expected = [string]$rule.processName
        if (-not $expected) { continue }
        if ($ProcessName -and $ProcessName.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Invoke-WGUacCheck {
    [CmdletBinding()]
    param()

    $uacValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue
    $enabled = ($null -ne $uacValue -and $uacValue.EnableLUA -eq 1)

    if ($enabled) {
        return New-WGFinding -Category "Audit" -CheckId "UAC-001" -Severity "Pass" -Title "UAC Enabled" -Description "User Account Control is enabled." -Remediation "No action required." -Data @{ EnableLUA = 1 }
    }

    return New-WGFinding -Category "Audit" -CheckId "UAC-001" -Severity "Critical" -Title "UAC Disabled" -Description "User Account Control is disabled." -Remediation "Enable UAC from Local Security Policy or Registry (EnableLUA=1)." -Data @{ EnableLUA = 0 }
}

function Invoke-WGFirewallCheck {
    [CmdletBinding()]
    param()

    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if (-not $profiles) {
        return @(New-WGFinding -Category "Audit" -CheckId "FW-000" -Severity "Warning" -Title "Firewall Status Unknown" -Description "Unable to read firewall profiles." -Remediation "Run scan in elevated shell and verify NetSecurity module availability.")
    }

    $findings = @()
    foreach ($profile in $profiles) {
        $sev = if ($profile.Enabled) { "Pass" } else { "Warning" }
        $title = "Firewall Profile: $($profile.Name)"
        $desc = if ($profile.Enabled) { "Firewall profile is enabled." } else { "Firewall profile is disabled." }
        $rem = if ($profile.Enabled) { "No action required." } else { "Enable firewall profile: $($profile.Name)." }
        $findings += New-WGFinding -Category "Audit" -CheckId "FW-$($profile.Name)" -Severity $sev -Title $title -Description $desc -Remediation $rem -Data @{ Enabled = [bool]$profile.Enabled }
    }

    return $findings
}

function Invoke-WGLocalAdminsCheck {
    [CmdletBinding()]
    param(
        [int]$WarningThreshold = 3
    )

    $members = @()
    try {
        $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    } catch {
        return New-WGFinding -Category "Audit" -CheckId "ADM-000" -Severity "Warning" -Title "Local Admin Group Check Failed" -Description $_.Exception.Message -Remediation "Verify administrative permissions and LocalAccounts module."
    }

    $count = @($members).Count
    $sev = if ($count -gt $WarningThreshold) { "Warning" } else { "Pass" }
    $desc = "Administrators group contains $count account(s)."
    $rem = if ($sev -eq "Warning") { "Review admin group members and apply least privilege." } else { "No action required." }

    return New-WGFinding -Category "Audit" -CheckId "ADM-001" -Severity $sev -Title "Local Administrators Review" -Description $desc -Remediation $rem -Data @{ Count = $count; Members = @($members | ForEach-Object { $_.Name }) }
}

function Invoke-WGOpenPortsCheck {
    [CmdletBinding()]
    param(
        [int[]]$HighRiskPorts = @(3389, 445),
        [Parameter(Mandatory = $true)]$Policy
    )

    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) {
        return New-WGFinding -Category "Audit" -CheckId "NET-000" -Severity "Info" -Title "No Listening TCP Connections Found" -Description "No listening TCP ports were returned." -Remediation "No action required."
    }

    $findings = @()
    $risky = @($connections | Where-Object { $HighRiskPorts -contains $_.LocalPort })
    if (@($risky).Count -eq 0) {
        $findings += New-WGFinding -Category "Audit" -CheckId "NET-001" -Severity "Pass" -Title "No High-Risk Listening Ports" -Description "No high-risk ports are listening." -Remediation "No action required." -Data @{ CheckedPorts = $HighRiskPorts }
        return $findings
    }

    $mergeByPort = $true
    if ($null -ne $Policy.network.mergeListenersByPort) {
        $mergeByPort = [bool]$Policy.network.mergeListenersByPort
    }

    $listenerRows = @()
    foreach ($item in $risky) {
        $procName = (Get-Process -Id $item.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        if (-not $procName) { $procName = "Unknown" }
        $exePath = Get-WGProcessExecutablePath -ProcessId $item.OwningProcess
        $sigStatus = "N/A"
        if ($exePath -and (Test-Path -LiteralPath $exePath)) {
            $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
            if ($sig) { $sigStatus = $sig.Status.ToString() }
        }

        $allowed = Test-WGPortProcessAllowlist -LocalPort $item.LocalPort -ProcessName $procName -Policy $Policy
        $sysDown = Test-WGPortSystemDowngrade -LocalPort $item.LocalPort -ExePath $exePath -ProcessName $procName -Policy $Policy
        $targetSev = "Critical"
        if ($allowed) {
            $targetSev = "Warning"
        } elseif ($sysDown) {
            $cfgSev = "Info"
            $dw = $Policy.network.downgradeWhenWindowsSystemBinary
            if ($dw -and $dw.targetSeverity) {
                $cfgSev = [string]$dw.targetSeverity
            }
            $targetSev = $cfgSev
        }

        $listenerRows += [PSCustomObject]@{
            LocalAddress     = [string]$item.LocalAddress
            LocalPort        = [int]$item.LocalPort
            ProcessId        = $item.OwningProcess
            ProcessName      = $procName
            ProcessPath      = $exePath
            SignatureStatus  = $sigStatus
            AllowlistMatched = [bool]$allowed
            SystemDowngrade  = [bool]$sysDown
            Severity         = $targetSev
        }
    }

    if (-not $mergeByPort) {
        foreach ($row in $listenerRows) {
            $desc = "Port $($row.LocalPort) on $($row.LocalAddress) - $($row.ProcessName) (PID $($row.ProcessId)). Executable: $($row.ProcessPath). Signature: $($row.SignatureStatus)."
            if ($row.AllowlistMatched) { $desc += " (Policy allowlist match.)" }
            if ($row.SystemDowngrade) { $desc += ' (Common Windows listener under Windows folder - severity downgraded by policy.)' }
            $findings += New-WGFinding -Category "Audit" -CheckId "NET-PORT-$($row.LocalPort)" -Severity $row.Severity -Title "High-Risk Port Open: $($row.LocalPort)" -Description $desc -Remediation "Restrict access with firewall rules or disable unnecessary service. Verify the owning process and binary signature." -Data @{
                LocalAddress     = $row.LocalAddress
                LocalPort        = $row.LocalPort
                ProcessId        = $row.ProcessId
                ProcessName      = $row.ProcessName
                ProcessPath      = $row.ProcessPath
                SignatureStatus  = $row.SignatureStatus
                AllowlistMatched = $row.AllowlistMatched
                SystemDowngrade  = $row.SystemDowngrade
            }
        }
        return $findings
    }

    $groups = $listenerRows | Group-Object LocalPort
    foreach ($g in $groups) {
        $rows = @($g.Group)
        $maxRank = ($rows | ForEach-Object { Get-WGSeverityRank -Severity $_.Severity } | Measure-Object -Maximum).Maximum
        $finalSev = Get-WGSeverityFromRank -Rank $maxRank
        $port = [int]$g.Name
        $addrList = @($rows | Select-Object -ExpandProperty LocalAddress -Unique | Sort-Object)
        $addrText = ($addrList -join ", ")
        $pids = @($rows | Select-Object -ExpandProperty ProcessId -Unique)
        $pidText = ($pids -join ", ")
        $primary = $rows[0]
        $procNames = @($rows | Select-Object -ExpandProperty ProcessName -Unique | Sort-Object)
        $desc = "Port $port is listening on address(es): $addrText. Process(es): $($primary.ProcessName) (PID $pidText). Primary executable: $($primary.ProcessPath). Signature: $($primary.SignatureStatus). Merged $($rows.Count) listener row(s) (e.g. IPv4/IPv6)."
        if ($procNames.Count -gt 1) {
            $desc += " Distinct process names on this port: $($procNames -join ', ')."
        }
        if (@($rows | Where-Object { $_.AllowlistMatched }).Count -gt 0) {
            $desc += " At least one listener matched policy allowlist."
        }
        if (@($rows | Where-Object { $_.SystemDowngrade }).Count -gt 0) {
            $desc += " At least one listener matched Windows system-binary downgrade rules."
        }

        $findings += New-WGFinding -Category "Audit" -CheckId "NET-PORT-$port" -Severity $finalSev -Title "High-Risk Port Open: $port" -Description $desc -Remediation "Restrict access with firewall rules or disable unnecessary service. Verify the owning process and binary signature." -Data @{
            LocalPort        = $port
            LocalAddresses   = $addrList
            ListenerCount    = $rows.Count
            ProcessIds       = $pids
            ProcessName      = $primary.ProcessName
            ProcessPath      = $primary.ProcessPath
            SignatureStatus  = $primary.SignatureStatus
            Listeners        = @($rows | ForEach-Object {
                [PSCustomObject]@{
                    LocalAddress = $_.LocalAddress
                    ProcessId    = $_.ProcessId
                    ProcessName  = $_.ProcessName
                    Severity     = $_.Severity
                }
            })
        }
    }

    return $findings
}

function Invoke-WGDefenderCheck {
    [CmdletBinding()]
    param()

    $cmd = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return New-WGFinding -Category "Audit" -CheckId "DEF-001" -Severity "Info" -Title "Microsoft Defender Status Unavailable" -Description "Get-MpComputerStatus is not available on this system (e.g. Server Core without Defender, or third-party AV only)." -Remediation "Verify antivirus coverage manually." -Data @{ Reason = "CmdletMissing" }
    }

    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        return New-WGFinding -Category "Audit" -CheckId "DEF-001" -Severity "Info" -Title "Microsoft Defender Status Unreadable" -Description "Could not read Defender status: $($_.Exception.Message)" -Remediation "Verify Windows Defender / security product is installed and healthy." -Data @{ Error = $_.Exception.Message }
    }

    $rt = [bool]$s.RealTimeProtectionEnabled
    $av = $true
    if ($null -ne $s.PSObject.Properties['AntivirusEnabled']) {
        $av = [bool]$s.AntivirusEnabled
    }

    $sigDays = $null
    $sigStale = $false
    if ($null -ne $s.PSObject.Properties['AntivirusSignatureLastUpdated'] -and $s.AntivirusSignatureLastUpdated) {
        try {
            $sigDays = [Math]::Round(((Get-Date) - [datetime]$s.AntivirusSignatureLastUpdated).TotalDays, 1)
            if ($sigDays -gt 30) { $sigStale = $true }
        } catch { }
    }

    if (-not $rt -or -not $av) {
        return New-WGFinding -Category "Audit" -CheckId "DEF-001" -Severity "Critical" -Title "Microsoft Defender Protection Disabled" -Description "Real-time protection: $rt; Antivirus enabled: $av. At least one core protection feature is off." -Remediation "Enable real-time protection and ensure Defender (or managed AV) is active. In Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus." -Data @{
            RealTimeProtectionEnabled = $rt
            AntivirusEnabled          = $av
            SignatureAgeDays          = $sigDays
        }
    }

    if ($sigStale) {
        return New-WGFinding -Category "Audit" -CheckId "DEF-001" -Severity "Warning" -Title "Microsoft Defender Signatures Out of Date" -Description "Antivirus definitions appear older than 30 days (approx. $sigDays days)." -Remediation "Run Windows Update or `Update-MpSignature` to refresh definitions." -Data @{
            RealTimeProtectionEnabled = $rt
            AntivirusEnabled          = $av
            SignatureAgeDays          = $sigDays
        }
    }

    return New-WGFinding -Category "Audit" -CheckId "DEF-001" -Severity "Pass" -Title "Microsoft Defender Active" -Description "Real-time protection is on; signatures are current enough for policy (<=30 days)." -Remediation "No action required." -Data @{
        RealTimeProtectionEnabled = $rt
        AntivirusEnabled          = $av
        SignatureAgeDays          = $sigDays
    }
}

function Invoke-WGRdpNlaCheck {
    [CmdletBinding()]
    param()

    $deny = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
    $rdpDenied = $true
    if ($null -ne $deny -and $null -ne $deny.fDenyTSConnections) {
        $rdpDenied = ([int]$deny.fDenyTSConnections -ne 0)
    }

    if ($rdpDenied) {
        return New-WGFinding -Category "Audit" -CheckId "RDP-001" -Severity "Pass" -Title "Remote Desktop Disabled" -Description "Remote Desktop connections are denied by policy (fDenyTSConnections)." -Remediation "No action required for NLA; RDP is off." -Data @{ RdpEnabled = $false }
    }

    $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue
    $nlaRequired = $false
    if ($null -ne $nla -and $null -ne $nla.UserAuthentication) {
        $nlaRequired = ([int]$nla.UserAuthentication -eq 1)
    }

    if (-not $nlaRequired) {
        $uaVal = $null
        if ($null -ne $nla -and $null -ne $nla.UserAuthentication) { $uaVal = [int]$nla.UserAuthentication }
        return New-WGFinding -Category "Audit" -CheckId "RDP-001" -Severity "Warning" -Title "Remote Desktop Without Network Level Authentication" -Description "RDP is allowed but UserAuthentication (NLA) is not required. This exposes credential-grabbing risks." -Remediation "Enable NLA: System Properties > Remote > select 'Allow connections only from computers running Remote Desktop with Network Level Authentication', or set UserAuthentication=1 under HKLM\...\WinStations\RDP-Tcp." -Data @{ RdpEnabled = $true; UserAuthentication = $uaVal }
    }

    return New-WGFinding -Category "Audit" -CheckId "RDP-001" -Severity "Pass" -Title "Remote Desktop Uses Network Level Authentication" -Description "RDP is enabled and NLA (UserAuthentication) is required." -Remediation "Ensure firewall rules restrict RDP source IPs as needed." -Data @{ RdpEnabled = $true; UserAuthentication = 1 }
}

function Invoke-WGSmb1Check {
    [CmdletBinding()]
    param()

    $feat = $null
    try {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    } catch {
        return New-WGFinding -Category "Audit" -CheckId "SMB-001" -Severity "Info" -Title "SMB1 Feature Check Skipped" -Description "Could not query optional feature SMB1Protocol: $($_.Exception.Message)" -Remediation "Verify SMB1 is disabled via optional features or registry if required by your security baseline." -Data @{ Error = $_.Exception.Message }
    }

    if ($feat.State -eq "Enabled") {
        return New-WGFinding -Category "Audit" -CheckId "SMB-001" -Severity "Warning" -Title "SMB1 Protocol Enabled" -Description "The legacy SMB1 optional feature is installed and enabled (increases attack surface; e.g. EternalBlue-era risk)." -Remediation "Disable SMB1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -Remove, or use Server Manager / Turn Windows features on or off." -Data @{ State = $feat.State }
    }

    return New-WGFinding -Category "Audit" -CheckId "SMB-001" -Severity "Pass" -Title "SMB1 Protocol Not Enabled" -Description "SMB1 optional feature is not enabled (Disabled or Absent)." -Remediation "No action required." -Data @{ State = $feat.State }
}

function Test-WGIsBitLockerVolumeProtected {
    [CmdletBinding()]
    param($Volume)

    if ($null -eq $Volume) { return $false }
    $s = $Volume.ProtectionStatus
    if ($null -eq $s) { return $false }
    try {
        if ($s.ToString() -eq 'On') { return $true }
    } catch { }
    try {
        if ([int]$s -eq 1) { return $true }
    } catch { }
    return $false
}

function Invoke-WGBitLockerCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Policy
    )

    $mounts = @("C:")
    if ($Policy.bitLocker -and $Policy.bitLocker.mountPoints) {
        $mounts = @($Policy.bitLocker.mountPoints | ForEach-Object { [string]$_ })
    }
    $mounts = @($mounts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($mounts.Count -eq 0) { $mounts = @("C:") }

    $cmd = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return New-WGFinding -Category "Audit" -CheckId "BLK-001" -Severity "Info" -Title "BitLocker Status Unavailable" -Description "Get-BitLockerVolume is not available (e.g. Windows Home without BitLocker management, or feature not installed)." -Remediation "Verify disk encryption with manage-bde /status or Control Panel where supported." -Data @{ Reason = "CmdletMissing" }
    }

    try {
        $allVol = Get-BitLockerVolume -ErrorAction Stop
    } catch {
        return New-WGFinding -Category "Audit" -CheckId "BLK-001" -Severity "Info" -Title "BitLocker Query Failed" -Description "Could not enumerate BitLocker volumes: $($_.Exception.Message)" -Remediation "Run as Administrator and ensure BitLocker optional components are available." -Data @{ Error = $_.Exception.Message }
    }

    $issues = @()
    foreach ($mp in $mounts) {
        $m = $mp.Trim()
        if ($m.Length -eq 2 -and $m[1] -eq ':') { $m = $m + '\' }
        $v = $null
        foreach ($c in @($m, $m.TrimEnd('\'), ($m.TrimEnd('\') + ':'))) {
            $candidate = $allVol | Where-Object { $_.MountPoint -ieq $c } | Select-Object -First 1
            if ($null -ne $candidate) {
                $v = $candidate
                break
            }
        }
        if ($null -eq $v) {
            $v = Get-BitLockerVolume -MountPoint $m -ErrorAction SilentlyContinue
        }
        if ($null -eq $v) {
            $issues += [PSCustomObject]@{ MountPoint = $mp; Status = "NotFound" }
            continue
        }
        if (-not (Test-WGIsBitLockerVolumeProtected -Volume $v)) {
            $issues += [PSCustomObject]@{
                MountPoint         = $v.MountPoint
                ProtectionStatus   = $v.ProtectionStatus
                EncryptionPercentage = $v.EncryptionPercentage
            }
        }
    }

    if (@($issues).Count -eq 0) {
        return New-WGFinding -Category "Audit" -CheckId "BLK-001" -Severity "Pass" -Title "BitLocker Protection" -Description "Listed mount point(s) appear protected by BitLocker per policy.bitLocker.mountPoints." -Remediation "No action required." -Data @{ MountPointsChecked = $mounts }
    }

    $detail = ($issues | ForEach-Object { "$($_.MountPoint): $(if ($_.Status) { $_.Status } else { 'Protection off or partial' })" }) -join "; "
    return New-WGFinding -Category "Audit" -CheckId "BLK-001" -Severity "Warning" -Title "BitLocker Not Fully Protecting Configured Volumes" -Description "One or more configured volumes are missing BitLocker protection or could not be read: $detail" -Remediation "Enable BitLocker on fixed drives (manage-bde -on, or Control Panel), store recovery keys safely, and align with organizational policy." -Data @{ Issues = $issues }
}

function Invoke-WGWinRMCheck {
    [CmdletBinding()]
    param()

    $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if (-not $svc) {
        return New-WGFinding -Category "Audit" -CheckId "WINRM-001" -Severity "Info" -Title "WinRM Service Not Present" -Description "The WinRM service was not found on this system." -Remediation "No action required unless remote management is required." -Data @{}
    }

    $running = ($svc.Status.ToString() -eq 'Running')
    if ($running) {
        return New-WGFinding -Category "Audit" -CheckId "WINRM-001" -Severity "Info" -Title "WinRM Service Running" -Description "Windows Remote Management (WinRM) is active. Review firewall listeners (5985/5986) and authentication settings if this host should be management-hardened." -Remediation "If WinRM is not required, consider: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled; restrict listeners via winrm.cmd / GPO." -Data @{ Status = $svc.Status.ToString(); StartType = $svc.StartType.ToString() }
    }

    return New-WGFinding -Category "Audit" -CheckId "WINRM-001" -Severity "Pass" -Title "WinRM Service Not Running" -Description "WinRM service is stopped (not listening for remote management by default)." -Remediation "No action required unless you intend to enable remote PowerShell/WinRM." -Data @{ Status = $svc.Status.ToString(); StartType = $svc.StartType.ToString() }
}

function Invoke-WGAutoStartServicesCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [ValidateSet("Quick", "Deep")][string]$ScanMode = "Deep"
    )

    $services = Get-CimInstance Win32_Service -Filter "StartMode = 'Auto'" -ErrorAction SilentlyContinue
    if (-not $services) {
        return New-WGFinding -Category "Audit" -CheckId "SRV-000" -Severity "Info" -Title "Auto-Start Services Scan Empty" -Description "No auto-start services returned by CIM." -Remediation "No action required."
    }

    $cap = 0
    if ($Policy.scanModes -and $Policy.scanModes.quick -and $ScanMode -eq "Quick") {
        $cap = [int]$Policy.scanModes.quick.maxAutoStartServices
    }

    if ($cap -gt 0) {
        $services = @($services | Select-Object -First $cap)
    }

    $suspicious = @($services | Where-Object {
        $_.PathName -and (
            $_.PathName -match "\\Users\\" -or
            $_.PathName -match "\\Temp\\" -or
            $_.PathName -match "\\AppData\\"
        )
    })

    if (@($suspicious).Count -eq 0) {
        $note = if ($cap -gt 0) { " (Quick mode: analyzed first $cap auto-start service(s).)" } else { "" }
        return New-WGFinding -Category "Audit" -CheckId "SRV-001" -Severity "Pass" -Title "Auto-Start Services Path Review" -Description "No suspicious auto-start service paths detected.$note" -Remediation "No action required." -Data @{ Count = @($services).Count; QuickCap = $cap }
    }

    return New-WGFinding -Category "Audit" -CheckId "SRV-001" -Severity "Warning" -Title "Suspicious Auto-Start Service Paths" -Description "$(@($suspicious).Count) auto-start service(s) run from user-writable or temporary paths." -Remediation "Review service binaries and enforce trusted installation paths." -Data @{
        Count    = @($suspicious).Count
        Services = @($suspicious | Select-Object Name, DisplayName, State, PathName)
        QuickCap = $cap
    }
}

function Invoke-WGAuditModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [ValidateSet("Quick", "Deep")][string]$ScanMode = "Deep"
    )

    $findings = @()
    $findings += Invoke-WGUacCheck
    $findings += Invoke-WGFirewallCheck
    $findings += Invoke-WGDefenderCheck
    $findings += Invoke-WGRdpNlaCheck
    $findings += Invoke-WGSmb1Check
    $findings += Invoke-WGBitLockerCheck -Policy $Policy
    $findings += Invoke-WGWinRMCheck
    $findings += Invoke-WGLocalAdminsCheck -WarningThreshold ([int]$Policy.thresholds.localAdminWarningCount)
    $findings += Invoke-WGOpenPortsCheck -HighRiskPorts @($Policy.network.highRiskPorts) -Policy $Policy
    $findings += Invoke-WGAutoStartServicesCheck -Policy $Policy -ScanMode $ScanMode
    return $findings
}

Export-ModuleMember -Function Invoke-WGAuditModule
