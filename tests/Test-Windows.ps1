# Parser and dry-run validation only. No Pester dependency; no elevation needed.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$count = 0
Get-ChildItem "$root\windows\*.ps1" | ForEach-Object {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ($errors | Out-String) }
    $count++
}
# Trap mutation functions: a preview must never reach them.
function New-NetFirewallRule { throw 'Unexpected mutation during plan' }
function Set-NetFirewallProfile { throw 'Unexpected mutation during plan' }
function Set-LocalUser { throw 'Unexpected password mutation' }
& "$root\windows\Firewall.ps1" -Config "$root\config\windows-web.example.json"
$count++
$temp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N') + '.json')
try {
    foreach ($bad in @('0.0.0.0/0', '::/0', '192.0.2.1/24', 'Any', '1.2.3.4;whoami')) {
        $c = Get-Content "$root\config\windows-web.example.json" -Raw | ConvertFrom-Json
        $c.management.sources = @($bad)
        $c | ConvertTo-Json -Depth 6 | Set-Content $temp -Encoding UTF8
        $rejected = $false
        try { & "$root\windows\Firewall.ps1" -Config $temp } catch { $rejected = $true }
        if (-not $rejected) { throw "Accepted bad source: $bad" }
        $count++
    }
    foreach ($badPort in @(0, 65536, '22', $true)) {
        $c = Get-Content "$root\config\windows-web.example.json" -Raw | ConvertFrom-Json
        $c.management.tcp_ports = @($badPort)
        $c | ConvertTo-Json -Depth 6 | Set-Content $temp -Encoding UTF8
        $rejected = $false
        try { & "$root\windows\Firewall.ps1" -Config $temp } catch { $rejected = $true }
        if (-not $rejected) { throw "Accepted bad port: $badPort" }
        $count++
    }
} finally { Remove-Item -LiteralPath $temp -ErrorAction SilentlyContinue }
Write-Host "Passed $count parser/plan checks. Live apply/rollback tests still required; see docs/LAB-TESTS.md."
