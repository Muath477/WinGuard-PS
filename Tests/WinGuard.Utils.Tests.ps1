# Pester 3/4/5 compatible tests. Run from WinGuard-PS: Invoke-Pester -Path .\Tests\WinGuard.Utils.Tests.ps1
# Pester 5 users: same file works if Describe wraps tests (Pester 3 style).

$ModuleRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $ModuleRoot "Modules\Common\Utils.psm1") -Force

Describe "Test-WGIsExternalRemoteAddress" {
    It "returns false for loopback IPv4" {
        Test-WGIsExternalRemoteAddress -Addr "127.0.0.1" | Should Be $false
    }
    It "returns false for private class A" {
        Test-WGIsExternalRemoteAddress -Addr "10.0.0.1" | Should Be $false
    }
    It "returns false for private class C" {
        Test-WGIsExternalRemoteAddress -Addr "192.168.1.1" | Should Be $false
    }
    It "returns false for link-local 169.254" {
        Test-WGIsExternalRemoteAddress -Addr "169.254.1.1" | Should Be $false
    }
    It "returns true for public IPv4" {
        Test-WGIsExternalRemoteAddress -Addr "8.8.8.8" | Should Be $true
    }
    It "returns false for empty" {
        Test-WGIsExternalRemoteAddress -Addr "" | Should Be $false
    }
    It "returns false for ::1" {
        Test-WGIsExternalRemoteAddress -Addr "::1" | Should Be $false
    }
}

Describe "Test-WGPathMatchesPrefix" {
    $Prefixes = @("C:\Windows\System32\", "C:\Program Files\")
    It "matches System32 prefix" {
        Test-WGPathMatchesPrefix -Path "C:\Windows\System32\cmd.exe" -Prefixes $Prefixes | Should Be $true
    }
    It "returns false for non-matching drive" {
        Test-WGPathMatchesPrefix -Path "D:\tools\app.exe" -Prefixes $Prefixes | Should Be $false
    }
}
