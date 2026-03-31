Set-StrictMode -Version Latest

function Test-WGScheduledTaskAllowlisted {
    [CmdletBinding()]
    param(
        $Task,
        [string]$Execute,
        $Policy
    )

    if (-not $Policy.allowlist) { return $false }
    foreach ($fragment in @($Policy.allowlist.taskPathContains)) {
        if (-not $fragment) { continue }
        if ($Task.TaskPath -and $Task.TaskPath.ToLowerInvariant().Contains($fragment.ToLowerInvariant())) {
            return $true
        }
    }
    if ($Execute -and (Test-WGPathMatchesPrefix -Path $Execute -Prefixes @($Policy.allowlist.executablePathPrefixes))) {
        return $true
    }
    return $false
}

function Get-WGExecutableFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths
    )

    $files = @()
    foreach ($path in $Paths) {
        if (Test-Path -Path $path) {
            $files += Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Extension -in @(".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs")
            }
        }
    }
    return $files
}

function Invoke-WGStartupHashCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [ValidateSet("Quick", "Deep")][string]$ScanMode = "Deep"
    )

    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    $files = @(Get-WGExecutableFiles -Paths $startupPaths)
    if (@($files).Count -eq 0) {
        return New-WGFinding -Category "Hunter" -CheckId "HUNT-STARTUP-001" -Severity "Pass" -Title "Startup File Hashing" -Description "No executable files found in startup folders." -Remediation "No action required."
    }

    $maxHash = 0
    if ($Policy.scanModes) {
        $modeKey = if ($ScanMode -eq "Quick") { "quick" } else { "deep" }
        $maxHash = [int]$Policy.scanModes.$modeKey.maxStartupFilesToHash
    }

    if ($maxHash -gt 0 -and $files.Count -gt $maxHash) {
        $files = @($files | Sort-Object FullName | Select-Object -First $maxHash)
    }

    $rows = @()
    foreach ($file in $files) {
        try {
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop
            $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue

            $rows += [PSCustomObject]@{
                Name             = $file.Name
                Path             = $file.FullName
                SHA256           = $hash.Hash
                SignatureStatus  = if ($signature) { $signature.Status.ToString() } else { "Unknown" }
                SignatureSubject = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "" }
            }
        } catch {
            continue
        }
    }

    $prefixes = @()
    if ($Policy.allowlist -and $Policy.allowlist.executablePathPrefixes) {
        $prefixes = @($Policy.allowlist.executablePathPrefixes)
    }

    $unsigned = @($rows | Where-Object {
        $trusted = Test-WGPathMatchesPrefix -Path $_.Path -Prefixes $prefixes
        if ($trusted) { return $false }
        return ($_.SignatureStatus -notin @("Valid") -or $_.SignatureStatus -eq "NotSigned")
    })

    $sev = if (@($unsigned).Count -gt 0) { "Warning" } else { "Pass" }
    $modeNote = if ($ScanMode -eq "Quick") { " Quick mode may limit hashed files; see policy.scanModes.quick." } else { "" }
    $desc = "Hashed $(@($rows).Count) startup executable file(s). Issues (unsigned/untrusted outside allowlisted paths): $(@($unsigned).Count).$modeNote"
    $rem = if ($sev -eq "Warning") { "Validate startup binaries and remove unknown unsigned entries." } else { "No action required." }

    return New-WGFinding -Category "Hunter" -CheckId "HUNT-STARTUP-001" -Severity $sev -Title "Startup Hash Review" -Description $desc -Remediation $rem -Data @{
        Count    = @($rows).Count
        ScanMode = $ScanMode
        Files    = $rows
    }
}

function Invoke-WGScheduledTasksCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Policy
    )

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    if (-not $tasks) {
        return New-WGFinding -Category "Hunter" -CheckId "HUNT-TASK-000" -Severity "Info" -Title "Scheduled Task Scan Empty" -Description "No scheduled tasks could be enumerated." -Remediation "Run scan as Administrator and verify Task Scheduler service."
    }

    $suspicious = @()
    foreach ($task in $tasks) {
        foreach ($action in @($task.Actions)) {
            if ($null -eq $action) { continue }
            $execProp = $action.PSObject.Properties['Execute']
            if ($null -eq $execProp -or $null -eq $execProp.Value) { continue }
            $exec = [string]$execProp.Value
            if (-not $exec) { continue }
            if (Test-WGScheduledTaskAllowlisted -Task $task -Execute $exec -Policy $Policy) {
                continue
            }
            $argVal = $null
            $argProp = $action.PSObject.Properties['Arguments']
            if ($null -ne $argProp) { $argVal = $argProp.Value }
            if ($exec -match "\\Users\\" -or $exec -match "\\AppData\\" -or $exec -match "\\Temp\\") {
                $suspicious += [PSCustomObject]@{
                    TaskName  = $task.TaskName
                    TaskPath  = $task.TaskPath
                    Execute   = $exec
                    Arguments = $argVal
                    UserId    = $task.Principal.UserId
                }
            }
        }
    }

    if (@($suspicious).Count -eq 0) {
        return New-WGFinding -Category "Hunter" -CheckId "HUNT-TASK-001" -Severity "Pass" -Title "Scheduled Tasks Review" -Description "No suspicious scheduled task actions detected." -Remediation "No action required."
    }

    $detailLines = @($suspicious | ForEach-Object {
        $args = if ($null -eq $_.Arguments -or [string]::IsNullOrWhiteSpace([string]$_.Arguments)) { "(none)" } else { [string]$_.Arguments }
        "- $($_.TaskPath)$($_.TaskName) | Run: $($_.Execute) | Args: $args | RunAs: $($_.UserId)"
    })
    $descBody = "$(@($suspicious).Count) scheduled task action(s) execute from user-writable paths.`n`nDetails:`n" + ($detailLines -join "`n")

    return New-WGFinding -Category "Hunter" -CheckId "HUNT-TASK-001" -Severity "Critical" -Title "Suspicious Scheduled Tasks Found" -Description $descBody -Remediation "Disable unknown tasks and verify binary source/trust. Open Task Scheduler and review the task paths listed above." -Data @{
        Count = @($suspicious).Count
        Tasks = $suspicious
    }
}

function Get-WGRegistryRunEntries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$HiveLabel
    )

    $out = @()
    if (-not (Test-Path -LiteralPath $Path)) { return $out }
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return $out }
    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $val = $p.Value
        if ($null -eq $val) { continue }
        if ($val -is [System.Array]) {
            foreach ($s in $val) {
                if ($null -ne $s -and -not [string]::IsNullOrWhiteSpace([string]$s)) {
                    $out += [PSCustomObject]@{ Hive = $HiveLabel; Name = $p.Name; Command = [string]$s }
                }
            }
        } else {
            $out += [PSCustomObject]@{ Hive = $HiveLabel; Name = $p.Name; Command = [string]$val }
        }
    }
    return $out
}

function Test-WGRunCommandSuspicious {
    [CmdletBinding()]
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }
    return ($Command -match '\\Users\\' -or $Command -match '\\AppData\\' -or $Command -match '\\Temp\\')
}

function Invoke-WGRunKeysCheck {
    [CmdletBinding()]
    param()

    $paths = @(
        @{ P = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; L = 'HKLM\Run' }
        @{ P = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; L = 'HKLM\RunOnce' }
        @{ P = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; L = 'HKLM\WOW6432\Run' }
        @{ P = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; L = 'HKLM\WOW6432\RunOnce' }
        @{ P = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; L = 'HKCU\Run' }
        @{ P = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; L = 'HKCU\RunOnce' }
    )

    $all = @()
    foreach ($row in $paths) {
        $all += @(Get-WGRegistryRunEntries -Path $row.P -HiveLabel $row.L)
    }

    $suspicious = @($all | Where-Object { Test-WGRunCommandSuspicious -Command $_.Command })
    if (@($suspicious).Count -eq 0) {
        return New-WGFinding -Category "Hunter" -CheckId "HUNT-RUN-001" -Severity "Pass" -Title "Run / RunOnce Registry Review" -Description "No Run/RunOnce entries point to user-writable or temporary paths." -Remediation "No action required." -Data @{ EntryCount = @($all).Count }
    }

    $lines = @($suspicious | ForEach-Object { "- [$($_.Hive)] $($_.Name) = $($_.Command)" })
    $desc = "$(@($suspicious).Count) Run/RunOnce value(s) reference suspicious paths.`n`nDetails:`n" + ($lines -join "`n")
    return New-WGFinding -Category "Hunter" -CheckId "HUNT-RUN-001" -Severity "Warning" -Title "Suspicious Run / RunOnce Entries" -Description $desc -Remediation "Remove unknown persistence from registry Run keys or validate binaries. Compare with autoruns baselines." -Data @{
        Count = @($suspicious).Count
        Items = $suspicious
    }
}

function Invoke-WGWmiSubscriptionCheck {
    [CmdletBinding()]
    param()

    $suspicious = @()
    $cl = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    foreach ($c in @($cl)) {
        $exe = $null
        $tpl = $null
        if ($null -ne $c.PSObject.Properties['ExecutablePath']) { $exe = [string]$c.ExecutablePath }
        if ($null -ne $c.PSObject.Properties['CommandLineTemplate']) { $tpl = [string]$c.CommandLineTemplate }
        $blob = "$exe $tpl"
        if (Test-WGRunCommandSuspicious -Command $blob) {
            $suspicious += [PSCustomObject]@{ Kind = 'CommandLineEventConsumer'; Name = $c.Name; ExecutablePath = $exe; Detail = $tpl }
        }
    }

    $asc = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    foreach ($a in @($asc)) {
        $sf = $null
        $st = $null
        if ($null -ne $a.PSObject.Properties['ScriptFileName']) { $sf = [string]$a.ScriptFileName }
        if ($null -ne $a.PSObject.Properties['ScriptText']) { $st = [string]$a.ScriptText }
        $blob = "$sf $st"
        if (Test-WGRunCommandSuspicious -Command $blob) {
            $suspicious += [PSCustomObject]@{ Kind = 'ActiveScriptEventConsumer'; Name = $a.Name; ScriptFileName = $sf; ScriptText = if ($st -and $st.Length -gt 120) { $st.Substring(0, 120) + '...' } else { $st } }
        }
    }

    if (@($suspicious).Count -eq 0) {
        return New-WGFinding -Category "Hunter" -CheckId "HUNT-WMI-001" -Severity "Pass" -Title "WMI Event Subscription Consumers" -Description "No WMI event consumers in root\subscription reference suspicious user/temp paths." -Remediation "No action required." -Data @{}
    }

    $desc = "$(@($suspicious).Count) WMI permanent subscription consumer(s) reference suspicious paths.`nReview bindings in root\subscription."
    return New-WGFinding -Category "Hunter" -CheckId "HUNT-WMI-001" -Severity "Warning" -Title "Suspicious WMI Event Consumers" -Description $desc -Remediation "Inspect __EventFilter / __FilterToConsumerBinding in root\subscription; remove unauthorized persistence." -Data @{
        Count = @($suspicious).Count
        Items = $suspicious
    }
}

function Invoke-WGConnectionsCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [ValidateSet("Quick", "Deep")][string]$ScanMode = "Deep"
    )

    $suspiciousRemotePorts = @(4444, 4443, 1337, 6666, 9999, 8443)
    if ($Policy.hunter -and $Policy.hunter.suspiciousRemotePorts) {
        $suspiciousRemotePorts = @($Policy.hunter.suspiciousRemotePorts | ForEach-Object { [int]$_ })
    }
    if ($suspiciousRemotePorts.Count -eq 0) {
        $suspiciousRemotePorts = @(4444, 4443, 1337, 6666, 9999, 8443)
    }

    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
    if (-not $connections) {
        return New-WGFinding -Category "Hunter" -CheckId "HUNT-CONN-000" -Severity "Info" -Title "No Active TCP Connections" -Description "No TCP connections were returned." -Remediation "No action required."
    }

    $limit = 100
    if ($Policy.scanModes) {
        $modeKey = if ($ScanMode -eq "Quick") { "quick" } else { "deep" }
        $limit = [int]$Policy.scanModes.$modeKey.maxConnectionsSnapshot
    }

    if ($limit -le 0) {
        $limit = 5000
    }

    $top = @($connections | Select-Object -First $limit LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)

    $established = @($top | Where-Object { $_.State -eq 'Established' })
    $externalEst = @($established | Where-Object { Test-WGIsExternalRemoteAddress -Addr ([string]$_.RemoteAddress) })
    $extCount = @($externalEst).Count

    $suspHits = @($externalEst | Where-Object { $suspiciousRemotePorts -contains [int]$_.RemotePort })
    $suspCount = @($suspHits).Count

    $sample = @($externalEst | Select-Object -First 12 | ForEach-Object {
        $rn = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        if (-not $rn) { $rn = "Unknown" }
        "$($_.RemoteAddress):$($_.RemotePort) -> PID $($_.OwningProcess) ($rn)"
    })

    $sev = "Info"
    $extra = ""
    if ($suspCount -gt 0) {
        $sev = "Warning"
        $extra = " Flagged $suspCount established connection(s) to uncommon remote ports ($($suspiciousRemotePorts -join ', ')) - verify processes."
    }

    $desc = "Captured a snapshot of active TCP connections (limited to $limit rows). Established sessions to non-local addresses: $extCount" + $extra
    $rem = if ($sev -eq "Warning") { "Review listed PIDs and binaries; confirm outbound traffic is expected. Consider blocking or isolating unknown processes." } else { "Review unknown remote endpoints and investigate corresponding process IDs." }

    return New-WGFinding -Category "Hunter" -CheckId "HUNT-CONN-001" -Severity $sev -Title "Active Network Connections Snapshot" -Description $desc -Remediation $rem -Data @{
        Count                    = @($connections).Count
        Limit                    = $limit
        ExternalEstablishedCount = $extCount
        SuspiciousPortHits       = $suspCount
        ExternalSample           = $sample
        Connections              = $top
    }
}

function Invoke-WGHunterModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [ValidateSet("Quick", "Deep")][string]$ScanMode = "Deep"
    )

    $findings = @()
    $findings += Invoke-WGStartupHashCheck -Policy $Policy -ScanMode $ScanMode
    $findings += Invoke-WGScheduledTasksCheck -Policy $Policy
    $findings += Invoke-WGRunKeysCheck
    $findings += Invoke-WGWmiSubscriptionCheck
    $findings += Invoke-WGConnectionsCheck -Policy $Policy -ScanMode $ScanMode
    return $findings
}

Export-ModuleMember -Function Invoke-WGHunterModule
