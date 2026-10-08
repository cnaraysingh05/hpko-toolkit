# Read-only inventory. Run in 64-bit Windows PowerShell 5.1, preferably elevated.
[CmdletBinding()]
param()
. "$PSScriptRoot\Common.ps1"
Assert-Windows
$report = [ordered]@{
    HostName = $env:COMPUTERNAME
    UTC = [DateTime]::UtcNow.ToString('o')
    OS = Read-Section { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime }
    Computer = Read-Section { Get-CimInstance Win32_ComputerSystem | Select-Object Domain, PartOfDomain, DomainRole }
    Users = Read-Section { Get-LocalUser | Select-Object Name, Enabled, SID, LastLogon, PasswordLastSet }
    Administrators = Read-Section { Get-LocalGroup -SID 'S-1-5-32-544' | Get-LocalGroupMember | Select-Object Name, SID, PrincipalSource }
    Addresses = Read-Section { Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressFamily }
    Routes = Read-Section { Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric }
    DNS = Read-Section { Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses }
    TCP = Read-Section { Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess }
    UDP = Read-Section { Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess }
    Services = Read-Section { Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, StartName, PathName }
    FirewallProfiles = Read-Section { Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules, AllowInboundRules, DisabledInterfaceAliases }
    FirewallRules = Read-Section { Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile, PolicyStoreSourceType }
    FirewallPorts = Read-Section { Get-NetFirewallPortFilter -PolicyStore ActiveStore | Select-Object InstanceID, Protocol, LocalPort, RemotePort }
    FirewallAddresses = Read-Section { Get-NetFirewallAddressFilter -PolicyStore ActiveStore | Select-Object InstanceID, LocalAddress, RemoteAddress }
    RDP = Read-Section { Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections | Select-Object fDenyTSConnections }
    RDPPort = Read-Section { Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber | Select-Object PortNumber }
    Shares = Read-Section { Get-SmbShare | Select-Object Name, Path, Description }
    Defender = Read-Section { Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated }
}
$report | ConvertTo-Json -Depth 8
