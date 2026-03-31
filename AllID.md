WinGuard-PS – Technical Reference (EN)
======================================

This document is an English **reference** for the WinGuard-PS project: architecture, findings schema, policy configuration, modules, and run commands.  
Target audience: security engineers, blue-teamers, and system administrators who want to understand or extend the tool.

---

1. Project overview
-------------------

| Item | Description |
|------|-------------|
| Name | **WinGuard-PS** |
| Type | PowerShell 5.1 CLI tool for **Windows security auditing** and **lightweight threat hunting** |
| Phases | **Audit** (system hardening checks) + **Hunter** (persistence & network style indicators) |
| Inputs | Local Windows system, optional **policy file** `Config\policy.json`, rule metadata `Rules\default.rules.json` |
| Outputs | JSON, HTML dashboard, CSV, text summary, baseline JSON, structured JSONL logs |
| Baseline | Optional **delta** comparison against `Data\baseline.json` between runs |
| Config model | Policy-driven: weights, thresholds, high‑risk ports, allowlists, scan limits, suspicious remote ports, BitLocker mount points |

High–level flow:

1. Validate **administrator** privileges.
2. Build a scan context (paths for reports, logs, baseline).
3. Load **policy** and **rules**.
4. Run **Audit** module (hardening checks).
5. Run **Hunter** module (persistence / network / behavior checks).
6. Aggregate findings, compute severity counts and **risk score**.
7. Optionally load and compare against **baseline** (delta).
8. Export reports (JSON / HTML / CSV / text summary) and update baseline.
9. Handle CLI flags (quiet, open report, fail on critical).

---

2. Findings schema
------------------

All checks return a unified **Finding** object created via `New-WGFinding` in `Modules\Common\Utils.psm1`.

### 2.1 Finding shape

| Field | Type | Description |
|-------|------|-------------|
| `TimeUtc` | string (ISO 8601) | UTC timestamp when the finding was created. |
| `Category` | string | Logical group, e.g. `Audit`, `Hunter`. |
| `CheckId` | string | Stable identifier like `UAC-001`, `HUNT-RUN-001`. Links to `default.rules.json`. |
| `Severity` | string | One of `Critical`, `Warning`, `Pass`, `Info`. |
| `Title` | string | Short human-readable title. |
| `Description` | string | What was found and why it matters. |
| `Remediation` | string | Concrete next steps to fix or validate. |
| `Data` | hashtable | Structured details that depend on the specific check. |

Example (conceptual):

```powershell
[PSCustomObject]@{
  TimeUtc     = "2026-03-31T01:23:45.0000000Z"
  Category    = "Audit"
  CheckId     = "UAC-001"
  Severity    = "Critical"
  Title       = "UAC Disabled"
  Description = "User Account Control is disabled."
  Remediation = "Enable UAC from Local Security Policy or Registry (EnableLUA=1)."
  Data        = @{ EnableLUA = 0 }
}
```

### 2.2 Severity semantics

| Severity | Meaning |
|----------|---------|
| `Critical` | Strongly unsafe / exploitable by default; should be fixed immediately. |
| `Warning` | Risky or misaligned with best practice; investigate and fix when possible. |
| `Pass` | Configuration aligns with expected or better-than-baseline behavior. |
| `Info` | Informational or unknown; not considered dangerous by itself. |

---

3. Policy file – `Config\policy.json`
-------------------------------------

The policy file controls how WinGuard-PS interprets findings, which ports are high‑risk, and how Quick/Deep modes are limited.

### 3.1 Top-level keys

```json
{
  "weights": { ... },
  "thresholds": { ... },
  "network": { ... },
  "allowlist": { ... },
  "scanModes": { ... },
  "baseline": { ... },
  "hunter": { ... },
  "bitLocker": { ... }
}
```

### 3.2 `weights`

Controls how much each severity “costs” when computing the final **security score**.

| Key | Meaning |
|-----|---------|
| `critical` | Weight per Critical finding. |
| `warning`  | Weight per Warning finding. |
| `info`     | Weight per Info finding. |

The score is computed in `Get-WGRiskScore` based on the total penalty vs. an all‑Critical worst case.

### 3.3 `thresholds`

Currently:

| Key | Meaning |
|-----|---------|
| `localAdminWarningCount` | If local Administrators group has more members than this, raise a `Warning`. |

### 3.4 `network`

| Key | Meaning |
|-----|---------|
| `highRiskPorts` | Array of TCP ports considered high‑risk for **listening** sockets (e.g. 3389, 445…). |
| `mergeListenersByPort` | If `true`, merge multiple listeners on the same port (IPv4/IPv6, multiple addresses) into one finding per port. |
| `downgradeWhenWindowsSystemBinary` | Object with `enabled`, `ports`, `targetSeverity`: allows downgrading severity when the listener is a common Windows system binary (`System` / `svchost` under `%SystemRoot%`). |

### 3.5 `allowlist`

| Key | Meaning |
|-----|---------|
| `executablePathPrefixes` | Trusted path prefixes (e.g. `C:\Windows\System32\`) for startup / tasks / services. |
| `taskPathContains` | If a scheduled task path contains one of these fragments (e.g. `\Microsoft\Windows\`), it is treated as allowlisted. |
| `portProcessAllow` | Array of `{ "port": number, "processName": string }` that can downgrade a high‑risk listening port from Critical to Warning. |

### 3.6 `scanModes.quick` / `scanModes.deep`

| Key | Meaning |
|-----|---------|
| `maxStartupFilesToHash` | Max startup files to hash; `0` = no cap (Deep). |
| `maxConnectionsSnapshot` | Max TCP connection rows in the Hunter network snapshot. |
| `maxAutoStartServices` | Max auto‑start services to analyze in Quick; `0` = all in Deep. |

### 3.7 `baseline`

| Key | Meaning |
|-----|---------|
| `path` | Relative path to the baseline JSON file (normally `Data\baseline.json`). |

### 3.8 `hunter`

| Key | Meaning |
|-----|---------|
| `suspiciousRemotePorts` | Remote TCP ports which, when seen in **Established** outbound connections to external addresses, trigger a `Warning` in the Hunter network snapshot. Policy‑driven; defaults can be overridden freely. |

### 3.9 `bitLocker`

| Key | Meaning |
|-----|---------|
| `mountPoints` | Array of mount points to check for BitLocker protection (e.g. `"C:"`). Used by `BLK-001`. |

---

4. Rule metadata – `Rules\default.rules.json`
---------------------------------------------

This file gives **human names** and default severities for CheckIds. It does not control logic but documents expectations.

Example structure:

```json
{
  "version": "1.0.0",
  "rules": [
    { "id": "UAC-001", "name": "UAC must be enabled", "severityOnFail": "Critical" },
    { "id": "FW-ANY", "name": "Firewall profile should be enabled", "severityOnFail": "Warning" },
    ...
  ]
}
```

---

5. Modules and responsibilities
-------------------------------

### 5.1 `Modules\Common\Utils.psm1`

Core helper functions:

| Function | Purpose |
|----------|---------|
| `New-WGFinding` | Factory for the unified Finding object. |
| `Write-WGLog` | Append structured JSONL entries to the scan log. |
| `Write-WGStatus` | Colorized console status messages (Info/Pass/Warn/Fail). |
| `Get-WGFindingFingerprint` | Stable SHA256 fingerprint used for baseline comparison. |
| `Test-WGPathMatchesPrefix` | Check if a path starts with any configured trusted prefix. |
| `Test-WGIsExternalRemoteAddress` | Classify IP addresses as “external” (non‑loopback, non‑RFC1918/private, non‑link‑local). Used by Hunter network checks and tested via Pester. |

### 5.2 `Modules\Core\Core.Engine.psm1`

Core engine and scoring:

| Function | Purpose |
|----------|---------|
| `Test-WGAdministrator` | Validates the process is running as an Administrator. |
| `Get-WGConfig` | Loads `policy.json` and `default.rules.json`. |
| `Get-WGSeverityCounts` | Counts findings per severity (Critical/Warning/Pass/Info). |
| `Get-WGRiskScore` | Computes the 0–100 security score using policy weights. |
| `Import-WGBaseline` | Reads baseline findings (or returns `$null`). |
| `Export-WGBaseline` | Writes a compact baseline object (fingerprints + metadata). |
| `Get-WGBaselineDelta` | Computes new vs. removed findings between current scan and baseline. |
| `New-WGScanContext` | Builds all report/log/baseline paths with a timestamp suffix. |

### 5.3 `Modules\Audit\Audit.Module.psm1`

System hardening checks:

| CheckId | Function | Description |
|---------|----------|-------------|
| `UAC-001` | `Invoke-WGUacCheck` | UAC enabled/disabled via registry. |
| `FW-000/ FW-<Profile>` | `Invoke-WGFirewallCheck` | Firewall profiles (On/Off or unknown). |
| `ADM-001` | `Invoke-WGLocalAdminsCheck` | Local Administrators membership vs. policy threshold. |
| `NET-PORT-*` / `NET-001` / `NET-000` | `Invoke-WGOpenPortsCheck` | High‑risk listening ports, with process path, signature, allowlist/downgrade logic. |
| `DEF-001` | `Invoke-WGDefenderCheck` | Microsoft Defender state: real‑time protection, antivirus enabled flag, signature age. |
| `RDP-001` | `Invoke-WGRdpNlaCheck` | Remote Desktop disabled / enabled with or without Network Level Authentication. |
| `SMB-001` | `Invoke-WGSmb1Check` | SMB1 optional feature presence and state. |
| `SRV-001` / `SRV-000` | `Invoke-WGAutoStartServicesCheck` | Auto‑start services running from user‑writable / temp paths. |
| `BLK-001` | `Invoke-WGBitLockerCheck` | BitLocker protection for configured `bitLocker.mountPoints`. |
| `WINRM-001` | `Invoke-WGWinRMCheck` | WinRM service status (running vs. stopped vs. missing). |
| – | `Invoke-WGAuditModule` | Orchestrator: runs all Audit checks using the current Policy and ScanMode. |

### 5.4 `Modules\Hunter\Hunter.Module.psm1`

Threat‑hunting style checks:

| CheckId | Function | Description |
|---------|----------|-------------|
| `HUNT-STARTUP-001` | `Invoke-WGStartupHashCheck` | Hashes startup executables, evaluates signatures and trusted prefixes, counts issues. |
| `HUNT-TASK-001` / `HUNT-TASK-000` | `Invoke-WGScheduledTasksCheck` | Flags scheduled tasks that execute from user‑writable paths. |
| `HUNT-RUN-001` | `Invoke-WGRunKeysCheck` | Scans Run/RunOnce registry keys in HKLM/HKCU (+ WOW6432) for suspicious paths. |
| `HUNT-WMI-001` | `Invoke-WGWmiSubscriptionCheck` | Looks at WMI `CommandLineEventConsumer` / `ActiveScriptEventConsumer` in `root\subscription` for suspicious paths/scripts. |
| `HUNT-CONN-001` / `HUNT-CONN-000` | `Invoke-WGConnectionsCheck` | Captures TCP snapshot, counts external `Established` connections, applies `hunter.suspiciousRemotePorts`, and returns a sample (remote:port → PID/process). |
| – | `Invoke-WGHunterModule` | Orchestrator: runs all Hunter checks with the current Policy and ScanMode. |

### 5.5 `Modules\Reporting\Reporting.Engine.psm1`

Reporting utilities:

| Function | Purpose |
|----------|---------|
| `Export-WGJsonReport` | Writes full report object (Meta + Summary + Findings) as JSON. |
| `Export-WGCsvReport` | Exports Findings as CSV (`Severity, Category, CheckId, Title, Description, Remediation`). |
| `Export-WGSummaryTextReport` | Writes a plain‑text summary: score, counts, and top‑priority items. |
| `Get-WGHtmlTemplate` | Produces a modern HTML dashboard with score, metrics, executive summary, baseline delta block, and a filterable table of findings. |
| `Export-WGHtmlReport` | Writes the HTML file to disk. |

---

6. CLI entrypoint – `WinGuard-PS.ps1`
-------------------------------------

### 6.1 Parameters

```powershell
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
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `Mode` | `Deep` | `Quick` = lighter sampling; `Deep` = full coverage. Influences scan caps in `policy.json`. |
| `Delta` | Off | If set, compare current findings against baseline and include delta in reports. |
| `SkipBaselineUpdate` | Off | If set, do **not** write the new baseline after the scan (useful for “what if” runs). |
| `OpenReport` | Off | Open the HTML report after a successful scan. |
| `OpenOnCritical` | Off | Open the HTML report **only** when at least one Critical finding is present. |
| `Quiet` | Off | Reduce console output; in quiet mode the script prints only the HTML path at the end. |
| `FailOnCritical` | Off | If set, process exits with code `2` when any Critical findings exist. |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no special critical‑based failure). |
| `1` | Script was not run as Administrator. |
| `2` | Critical findings present **and** `-FailOnCritical` was specified. |

---

7. Run commands (cheat sheet)
-----------------------------

From an elevated PowerShell prompt:

### 7.1 Prepare session

```powershell
cd "C:\Users\moath\OneDrive\Desktop\Smart System Auditor (SSA)\WinGuard-PS"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 7.2 Core scans

| Scenario | Command |
|----------|---------|
| Default Deep scan | `.\WinGuard-PS.ps1` |
| Quick scan | `.\WinGuard-PS.ps1 -Mode Quick` |
| Explicit Deep scan | `.\WinGuard-PS.ps1 -Mode Deep` |

### 7.3 Reports and baseline

| Scenario | Command |
|----------|---------|
| Open HTML report after scan | `.\WinGuard-PS.ps1 -OpenReport` |
| Open HTML only on Critical findings | `.\WinGuard-PS.ps1 -OpenOnCritical` |
| Compare with baseline (delta) | `.\WinGuard-PS.ps1 -Delta` |
| Delta without updating baseline | `.\WinGuard-PS.ps1 -Delta -SkipBaselineUpdate` |
| Quiet mode (automation friendly) | `.\WinGuard-PS.ps1 -Quiet` |
| CI style: fail build if any Critical | `.\WinGuard-PS.ps1 -Quiet -FailOnCritical` |

Example combined commands:

```powershell
.\WinGuard-PS.ps1 -Mode Quick -OpenReport
.\WinGuard-PS.ps1 -Mode Deep -Delta -OpenOnCritical -FailOnCritical
```

---

8. Tests
--------

Pester tests live under `Tests\WinGuard.Utils.Tests.ps1`.

- Compatible with **Pester 3+** (default on Windows PowerShell 5.1).
- Focused on utility functions in `Utils.psm1`:
  - `Test-WGIsExternalRemoteAddress`
  - `Test-WGPathMatchesPrefix`

To run:

```powershell
cd "C:\Users\moath\OneDrive\Desktop\Smart System Auditor (SSA)\WinGuard-PS"
Invoke-Pester -Path .\Tests\WinGuard.Utils.Tests.ps1
```

---

9. Design notes
---------------

- **Transparent by design** – all checks are implemented as plain PowerShell, making it easy to audit and extend the logic.
- **Policy‑driven** – most “tuning knobs” live in `policy.json`, not hard‑coded in modules.
- **Two‑phase view** – separates configuration hardening (Audit) from persistence/behavioral hints (Hunter).
- **Automation‑ready** – quiet mode, structured JSON/CSV, and explicit exit codes support CI pipelines and scripted usage.
- **Education‑friendly** – descriptions and remediation text are written to help explain *why* a result matters and *where* to investigate manually.

