# Guided wrapper. Individual scripts remain available for experienced operators.
[CmdletBinding()]
param()
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -lt 5) {
    throw 'Use 64-bit Windows PowerShell 5.1.'
}
while ($true) {
    Write-Host "`n1 Collect private baseline reports`n2 Review security settings`n3 Rotate ONE local password`n4 Preview firewall config`n5 Apply firewall config`n6 Roll back toolkit firewall`n7 Handoff checklist`n0 Exit"
    $choice = Read-Host 'Choose a step'
    try {
        switch ($choice) {
            '0' { return }
            '1' {
                $directory = Join-Path $env:ProgramData ('HorsePlinkoReports-' + [Guid]::NewGuid().ToString('N'))
                New-Item -Path $directory -ItemType Directory -ErrorAction Stop | Out-Null
                & icacls.exe $directory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Report directory ACL failed. No reports collected.' }
                Write-Host "Private reports: $directory"
                foreach ($name in @('Recon','Persistence','Review')) {
                    & "$PSScriptRoot\$name.ps1" | Out-File (Join-Path $directory "$name.json") -Encoding utf8
                }
                Write-Host 'Reports collected. Review section errors and findings before making changes.'
            }
            '2' { & "$PSScriptRoot\Review.ps1" }
            '3' {
                $userName = Read-Host 'Exact local account name'
                & "$PSScriptRoot\Credentials.ps1" -User $userName
                if ((Read-Host 'Dependencies reviewed? Type ROTATE to proceed') -ceq 'ROTATE') {
                    & "$PSScriptRoot\Credentials.ps1" -User $userName -Apply -AckServiceImpact
                    Write-Host 'Test a fresh login in another session now; keep this session open.'
                }
            }
            { $_ -in @('4','5') } {
                $configPath = Read-Host 'Path to your edited host JSON config'
                & "$PSScriptRoot\Firewall.ps1" -Config $configPath
                if ($choice -eq '5' -and (Read-Host 'Console tested and service list reviewed? Type APPLY') -ceq 'APPLY') {
                    & "$PSScriptRoot\Firewall.ps1" -Config $configPath -Apply -ConsoleConfirmed
                    Write-Host 'Test NEW remote connections and application functions now. Roll back on regression.'
                }
            }
            '6' {
                if ((Read-Host 'Restore the saved toolkit firewall settings? Type ROLLBACK') -ceq 'ROLLBACK') {
                    & "$PSScriptRoot\Firewall.ps1" -Rollback
                }
            }
            '7' {
                Write-Host 'Before handoff: fresh login tested; required services checked externally; audit findings/errors reviewed; firewall verified; console and rollback ready; open issues recorded; next check assigned. See docs/HANDOFF.md. This menu does not certify the host as secure.'
            }
            default { Write-Host 'Choose a listed step.' }
        }
    } catch { Write-Warning "STOP: $($_.Exception.Message) Do not mark this step complete." }
}
