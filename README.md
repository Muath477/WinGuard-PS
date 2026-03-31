# WinGuard-PS

WinGuard-PS is an independent PowerShell 5.1 CLI security auditor and threat hunter for Windows systems.

**Full reference (Arabic):** run parameters, project layout, `Finding` schema, `policy.json` tables, PowerShell cmdlets used, and report outputs — see **[REFERENCE.md](REFERENCE.md)**.

## Features

- Administrator privilege validation before scan.
- Scan modes: **Quick** (lighter sampling) and **Deep** (full coverage).
- OS hardening audit: UAC, firewall, Defender, RDP/NLA, SMB1, **BitLocker** (policy-driven mount points), **WinRM** service status, local admins, high-risk ports, auto-start services.
- Threat hunting: startup hashing, suspicious scheduled tasks, **Run/RunOnce** registry paths, **WMI event consumers** (`root\subscription`), active TCP connections (external summary + **policy-driven suspicious remote ports**).
- Policy-driven allowlists for trusted paths, Microsoft scheduled task paths, and known port/process pairs.
- Baseline file with optional **delta** comparison between runs.
- Reporting engine: JSON, HTML (interactive filters + executive summary), CSV, and plain-text **summary** (`*.summary.txt`).
- High-risk ports: optional **merge** of duplicate listeners per port (IPv4/IPv6), and optional **downgrade** for common Windows listeners under `%SystemRoot%` (see `policy.json`).
- Suspicious scheduled tasks: **detailed listing** (task path, executable, args, run-as) inside the finding description.
- Structured JSONL runtime logging.

## Requirements

- Windows 10/11
- PowerShell 5.1
- Run terminal as Administrator

## Run

From the repo folder, use **one command per block** (easy copy-paste).

```powershell
cd "C:\Users\moath\OneDrive\Desktop\Smart System Auditor (SSA)\WinGuard-PS"
```

```powershell
.\WinGuard-PS.ps1
```

If scripts are blocked for this session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Quick scan:

```powershell
.\WinGuard-PS.ps1 -Mode Quick
```

Open HTML report automatically:

```powershell
.\WinGuard-PS.ps1 -OpenReport
```

Open report automatically when any **Critical** finding exists:

```powershell
.\WinGuard-PS.ps1 -OpenOnCritical
```

Compare against the last saved baseline (stored under `Data\baseline.json`):

```powershell
.\WinGuard-PS.ps1 -Delta
```

Skip updating the baseline after a run:

```powershell
.\WinGuard-PS.ps1 -SkipBaselineUpdate
```

Minimal console output (prints HTML path only at the end — useful for automation):

```powershell
.\WinGuard-PS.ps1 -Quiet
```

Fail batch/CI if any **Critical** finding (exit code **2**):

```powershell
.\WinGuard-PS.ps1 -FailOnCritical
```

**Exit codes:** `0` = success, `1` = not running as Administrator, `2` = Critical findings when `-FailOnCritical` is used.

## Output

- JSON reports: `Reports\Audit_yyyyMMdd_HHmmss.json`
- HTML reports: `Reports\Audit_yyyyMMdd_HHmmss.html` (search + severity/category filters)
- CSV reports: `Reports\Audit_yyyyMMdd_HHmmss.csv`
- Text summary: `Reports\Audit_yyyyMMdd_HHmmss.summary.txt`
- Logs: `Logs\Scan_yyyyMMdd_HHmmss.log.jsonl`
- Baseline: `Data\baseline.json` (updated each run unless `-SkipBaselineUpdate`)

## Configuration

Edit `Config\policy.json` to tune weights, thresholds, high-risk ports, scan mode caps, and allowlists without changing code.

- `hunter.suspiciousRemotePorts`: remote TCP ports that trigger a **Warning** when an *established* outbound connection uses them (defaults in `policy.json`; edit freely).
- `bitLocker.mountPoints`: drive mount points to evaluate (e.g. `C:`); requires `Get-BitLockerVolume` (not available on all editions).

Notable `network` keys:

- `mergeListenersByPort`: when `true`, one finding per TCP port with combined local addresses (reduces duplicate rows).
- `downgradeWhenWindowsSystemBinary`: when `enabled`, listed `ports` may be downgraded to `targetSeverity` (default `Info`) if the owning binary is under the Windows folder and the process is `System` or `svchost`.

## Architecture

- `WinGuard-PS.ps1`: entrypoint and orchestration
- `Modules\Core\Core.Engine.psm1`: context/config loading, scoring, baseline import/export
- `Modules\Audit\Audit.Module.psm1`: hardening checks
- `Modules\Hunter\Hunter.Module.psm1`: threat hunting checks
- `Modules\Reporting\Reporting.Engine.psm1`: JSON/HTML/CSV report generation
- `Modules\Common\Utils.psm1`: finding schema, logging, fingerprints, path helpers
- `Config\policy.json`: risk weights, thresholds, risky ports, allowlists, scan mode limits
- `Rules\default.rules.json`: baseline rule metadata

## Tests

Unit tests (Pester 3+): from the project folder run `Invoke-Pester -Path .\Tests\WinGuard.Utils.Tests.ps1`. Covers `Test-WGIsExternalRemoteAddress` and `Test-WGPathMatchesPrefix` in `Utils.psm1`.
