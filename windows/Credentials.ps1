[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$User,
    [switch]$Apply,
    [switch]$AckServiceImpact
)
. "$PSScriptRoot\Common.ps1"
Assert-Windows
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    throw 'Domain controller detected. This script only rotates local SAM accounts.'
}
if ($User -match '[\\/@*?\[\]]') { throw 'Supply an exact local account name, without domain or wildcards.' }
$account = @(Get-LocalUser | Where-Object { $_.Name -ceq $User })
if ($account.Count -ne 1) { throw 'Name must match exactly one local account (case sensitive).' }
Write-Host "Selected $User / $($account[0].SID). Review service/task dependencies and EFS/DPAPI impact."
if (-not $Apply) { Write-Host 'DRY RUN: no password requested or changed.'; return }
Assert-Administrator
if (-not $AckServiceImpact) { throw 'Review dependencies, then supply -AckServiceImpact.' }
if ((Read-Host 'Type the exact account name to rotate') -cne $User) { throw 'Confirmation mismatch.' }
$password = $null
try {
    $password = Read-Host 'New password (store it in your approved password manager)' -AsSecureString
    if ($password.Length -lt 1) { throw 'Empty passwords are not allowed.' }
    Set-LocalUser -SID $account[0].SID -Password $password
    Write-Host 'Changed. Test a NEW login before closing this session. Existing sessions remain valid.'
} finally {
    if ($null -ne $password) { $password.Dispose() }
}
