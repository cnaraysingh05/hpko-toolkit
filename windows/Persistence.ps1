# Read-only evidence. Legitimate entries are expected; no automatic deletion.
[CmdletBinding()]
param()
. "$PSScriptRoot\Common.ps1"
Assert-Windows
$registryPaths = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
 'HKLM:\System\CurrentControlSet\Control\Session Manager'
)
$loadedUsers = Read-Section { Get-ChildItem Registry::HKEY_USERS | Select-Object -ExpandProperty PSChildName }
foreach ($sid in $loadedUsers) {
    if ($sid -is [string] -and $sid -match '^S-1-5-21-') {
        $registryPaths += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
        $registryPaths += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
}
$report = [ordered]@{
 HostName = $env:COMPUTERNAME
 UTC = [DateTime]::UtcNow.ToString('o')
 Tasks = Read-Section { Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Actions, Triggers, Principal }
 Services = Read-Section { Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, StartName, PathName }
 Drivers = Read-Section { Get-CimInstance Win32_SystemDriver | Select-Object Name, State, StartMode, PathName }
 WmiFilters = Read-Section { Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name, Query, EventNamespace }
 WmiConsumers = Read-Section { Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Select-Object * -ExcludeProperty Cim* }
 WmiBindings = Read-Section { Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Select-Object Filter, Consumer }
 Registry = @($registryPaths | ForEach-Object {
    $path = $_
    [pscustomobject]@{ Path = $path; Values = Read-Section { Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PS* } }
 })
 IFEOChildren = Read-Section { Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | Get-ItemProperty | Select-Object PSChildName, Debugger, GlobalFlag }
 Startup = Read-Section {
    $paths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    Get-CimInstance Win32_UserProfile | ForEach-Object {
        $paths += "$($_.LocalPath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) {
            Get-ChildItem -LiteralPath $path -Force -File | ForEach-Object {
                [pscustomobject]@{ Path = $_.FullName; Modified = $_.LastWriteTimeUtc; SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
            }
        }
    }
 }
 DefenderExclusions = Read-Section { Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension }
 Note = 'Review leads locally; no clean verdict. Unloaded user hives are not mounted or inspected. Reports may contain sensitive task/service arguments.'
}
$report | ConvertTo-Json -Depth 10
