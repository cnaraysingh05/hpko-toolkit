# Default is a read-only plan. One active change per machine; rollback before a new apply.
[CmdletBinding(DefaultParameterSetName='Configure', SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory, ParameterSetName='Configure')][string]$Config,
    [Parameter(ParameterSetName='Configure')][switch]$Apply,
    [Parameter(ParameterSetName='Configure')][switch]$ConsoleConfirmed,
    [Parameter(Mandatory, ParameterSetName='Rollback')][switch]$Rollback
)
. "$PSScriptRoot\Common.ps1"

function Assert-Keys($Object, [string[]]$Expected) {
    if ($null -eq $Object) { throw 'Missing config object.' }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -ne (($Expected | Sort-Object) -join ',')) {
        throw "Expected exactly these keys: $($Expected -join ', ')"
    }
}
function Get-Ports($Values) {
    if ($Values -isnot [array] -or $Values.Count -eq 0) { throw 'ports must be a nonempty array.' }
    foreach ($v in $Values) {
        if (($v -isnot [int] -and $v -isnot [long]) -or $v -lt 1 -or $v -gt 65535) {
            throw 'Ports must be integers 1..65535.'
        }
        [int]$v
    }
}
function Get-Sources($Values, [bool]$Management) {
    if ($Values -isnot [array] -or $Values.Count -eq 0) { throw 'sources must be a nonempty array.' }
    foreach ($v in $Values) {
        if ($v -isnot [string] -or $v -match '[%\s]' -or $v -notmatch '^[0-9a-fA-F:.]+(/[0-9]{1,3})?$') {
            throw 'Use literal IPv4/IPv6 addresses or CIDRs.'
        }
        $parts = $v.Split('/')
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { throw "Invalid source: $v" }
        $bits = 128
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            $bits = 32
            if ($parts[0] -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw 'Use full dotted IPv4 addresses.' }
        }
        $prefix = $bits
        if ($parts.Count -eq 2) { $prefix = [int]$parts[1] }
        if ($prefix -lt 0 -or $prefix -gt $bits -or ($Management -and $prefix -eq 0)) {
            throw "Invalid or unrestricted management source: $v"
        }
        # Reject host bits so the operator sees exactly the network being allowed.
        $bytes = $ip.GetAddressBytes()
        for ($bit = $prefix; $bit -lt $bits; $bit++) {
            if (($bytes[[int][Math]::Floor($bit / 8)] -band (1 -shl (7 - ($bit % 8)))) -ne 0) {
                throw "CIDR has host bits set: $v"
            }
        }
        "$($ip.ToString())/$prefix"
    }
}
function Get-Plan([string]$Path) {
    $c = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    Assert-Keys $c @('management','services')
    Assert-Keys $c.management @('sources','tcp_ports')
    [pscustomobject]@{ Label='management'; Protocol='TCP'; Ports=@(Get-Ports $c.management.tcp_ports); Sources=@(Get-Sources $c.management.sources $true) }
    if ($c.services -isnot [array]) { throw 'services must be an array.' }
    foreach ($s in $c.services) {
        Assert-Keys $s @('name','protocol','ports','sources')
        if ($s.name -isnot [string] -or $s.name -cnotmatch '^[A-Za-z0-9_-]{1,40}$') { throw 'Invalid service name.' }
        if ($s.protocol -cnotin @('tcp','udp')) { throw 'Protocol must be tcp or udp.' }
        [pscustomobject]@{ Label=$s.name; Protocol=$s.protocol.ToUpperInvariant(); Ports=@(Get-Ports $s.ports); Sources=@(Get-Sources $s.sources $false) }
    }
}
function Undo-Change($State) {
    if ($State.HostName -ne $env:COMPUTERNAME -or $State.Version -ne 1) { throw 'Wrong host or state version.' }
    # Restore profile defaults first, then remove only the rules in this transaction.
    foreach ($p in $State.Profiles) {
        if ($p.Name -notin @('Domain','Private','Public')) { throw 'Invalid saved profile.' }
        Set-NetFirewallProfile -PolicyStore PersistentStore -Name $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.DefaultInboundAction
    }
    foreach ($name in $State.RuleNames) {
        if ($name -notmatch '^HorsePlinko-[0-9a-f]{32}-[0-9]+$') { throw 'Invalid saved rule name.' }
        # Enumerate with terminating errors; a failed lookup must not masquerade as absence.
        $found = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -eq $name })
        if ($found.Count -gt 0) { $found | Remove-NetFirewallRule }
    }
}

$plan = @()
if (-not $Rollback) {
    $plan = @(Get-Plan $Config)
    # JSON avoids silently truncating long source/port lists in a narrow terminal.
    Write-Host ($plan | ConvertTo-Json -Depth 5)
    Write-Host 'Plan: add listed allows on all profiles; enable firewall; default inbound Block. Preserve all existing rules and outbound policy.'
    if (-not $Apply) { Write-Host 'DRY RUN: no writes.'; return }
    if (-not $ConsoleConfirmed) { throw 'Test out-of-band console access; supply -ConsoleConfirmed.' }
}
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Change Windows Defender Firewall')) { return }
Assert-Administrator
$stateDir = Join-Path $env:ProgramData 'HorsePlinko'
if (Test-Path -LiteralPath $stateDir) {
    if ((Get-Item -LiteralPath $stateDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'State directory may not be a reparse point.'
    }
    # Do not trust a pre-created directory owned by an unprivileged account.
    $owner = (Get-Acl -LiteralPath $stateDir).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'State directory must be owned by SYSTEM or Administrators.' }
} else {
    New-Item -Path $stateDir -ItemType Directory | Out-Null
}
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$adminSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$acl.SetOwner($adminSid)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $stateDir -AclObject $acl
if (@(Get-ChildItem -LiteralPath $stateDir -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
    throw 'State directory must not contain reparse points.'
}
$lock = [IO.File]::Open((Join-Path $stateDir 'lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $journal = Join-Path $stateDir 'active.json'
    if ($Rollback) {
        if (-not (Test-Path -LiteralPath $journal)) { throw 'No active change recorded.' }
        $state = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
        Undo-Change $state
        Remove-Item -LiteralPath $journal
        Write-Host 'Rollback complete; full backup retained.'
        return
    }
    if (Test-Path -LiteralPath $journal) { throw 'An earlier change is active. Roll back before another apply.' }
    $effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if (@($effective | Where-Object { [string]$_.AllowLocalFirewallRules -eq 'False' }).Count -gt 0) {
        throw 'Policy disallows local rules. Coordinate policy changes with the domain owner.'
    }
    if (@($effective | Where-Object { [string]$_.AllowInboundRules -eq 'False' }).Count -gt 0) {
        throw 'A profile ignores inbound allow rules (shields-up mode). Review policy first.'
    }
    if (@($effective | Where-Object {
        @($_.DisabledInterfaceAliases | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0
    }).Count -gt 0) {
        throw 'A profile exempts interfaces from filtering. Review those exemptions first.'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object {
        [pscustomobject]@{ Name=[string]$_.Name; Enabled=[string]$_.Enabled; DefaultInboundAction=[string]$_.DefaultInboundAction }
    })
    if ($profiles.Count -ne 3) { throw 'Expected all three local firewall profiles.' }
    $backup = Join-Path $stateDir ('before-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '.wfw')
    & netsh.exe advfirewall export $backup | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backup)) { throw 'Firewall export failed; no policy changed.' }
    $transaction = [Guid]::NewGuid().ToString('N')
    $names = @(for ($i=0; $i -lt $plan.Count; $i++) { "HorsePlinko-$transaction-$i" })
    $state = [pscustomobject]@{ Version=1; HostName=$env:COMPUTERNAME; Profiles=$profiles; RuleNames=$names; Backup=$backup }
    # Journal every intended rule before mutation so interrupted applies can be rolled back.
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $journal -Encoding UTF8
    try {
        for ($i=0; $i -lt $plan.Count; $i++) {
            $r = $plan[$i]
            New-NetFirewallRule -PolicyStore PersistentStore -Name $names[$i] -DisplayName "Horse Plinko: $($r.Label)" `
                -Group 'Horse Plinko' -Enabled True -Direction Inbound -Action Allow -Profile Any `
                -Protocol $r.Protocol -LocalPort $r.Ports -RemoteAddress $r.Sources | Out-Null
        }
        Set-NetFirewallProfile -PolicyStore PersistentStore -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block
        $after = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
        if (@($after | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -ne 'Block' }).Count -gt 0) {
            throw 'Effective profile settings differ (possibly Group Policy).'
        }
        foreach ($name in $names) {
            $active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name)
            if ($active.Count -ne 1 -or [string]$active[0].Enabled -ne 'True') { throw 'A created rule is not effective.' }
        }
    } catch {
        $originalError = $_
        try { Undo-Change $state; Remove-Item -LiteralPath $journal }
        catch { Write-Warning "Rollback incomplete. Use console and -Rollback. State retained at $journal. $($_.Exception.Message)" }
        throw $originalError
    }
    Write-Host "Applied. Backup and rollback state: $stateDir"
    Write-Host 'Test NEW management and scored-service connections externally now. Existing allow/block rules still affect access.'
    Write-Host 'Rollback: .\windows\Firewall.ps1 -Rollback'
} finally { $lock.Dispose() }
