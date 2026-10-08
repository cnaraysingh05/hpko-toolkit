# Read-only security settings to discuss with the host owner before remediation.
[CmdletBinding()]
param()
. "$PSScriptRoot\Common.ps1"
Assert-Windows
$report = [ordered]@{
    HostName = $env:COMPUTERNAME
    UTC = [DateTime]::UtcNow.ToString('o')
    LocalAdministrators = Read-Section { Get-LocalGroup -SID 'S-1-5-32-544' | Get-LocalGroupMember | Select-Object Name, SID, PrincipalSource }
    EnabledLocalUsers = Read-Section { Get-LocalUser | Where-Object Enabled | Select-Object Name, SID, PasswordRequired, PasswordLastSet, LastLogon }
    Defender = Read-Section { Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMRunningMode, AntivirusSignatureLastUpdated, IsTamperProtected }
    DefenderExclusions = Read-Section { Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension }
    RDP = Read-Section { Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Select-Object UserAuthentication, SecurityLayer, PortNumber }
    SMB = Read-Section { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData }
    UAC = Read-Section { Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA, LocalAccountTokenFilterPolicy, ConsentPromptBehaviorAdmin }
    RecentHotfixes = Read-Section { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn }
    ReviewGuide = @(
        'Match administrators and enabled users to the packet. Do not bulk disable accounts.',
        'Investigate inactive Defender or unexpected exclusions; another approved AV can explain passive mode.',
        'RDP UserAuthentication=1 requires NLA. Review client compatibility before changing it.',
        'Review enabled SMB1 and absent SMB signing against actual service requirements.',
        'EnableLUA=0 means UAC is disabled. Changes can require restart; coordinate first.',
        'Hotfix history is incomplete and does not prove the machine is fully patched.',
        'Review findings with persistence and recon reports. Missing data is not a pass. No settings changed.'
    )
}
$report | ConvertTo-Json -Depth 8
