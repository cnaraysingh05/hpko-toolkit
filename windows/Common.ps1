Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Windows {
    if ($env:OS -ne 'Windows_NT') { throw 'This operation requires Windows.' }
}
function Assert-Administrator {
    Assert-Windows
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated.' }
}
function Read-Section([scriptblock]$Action) {
    try { @(& $Action) } catch { [pscustomobject]@{ Error = $_.Exception.Message } }
}
