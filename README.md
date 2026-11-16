# PostEnum

Post-exploitation enumeration scripts for **Windows** and **Linux** servers.

Run them once you have a user-level shell. Each script collects the
situational-awareness and privilege-escalation data you'd normally gather by
hand — users, privileges, services, scheduled tasks, network state, stored
credentials, writable paths and more — and writes it all to a clean Markdown
report.

> **⚠️ Authorized use only.** These tools are for security assessments of
> systems you own or are explicitly permitted to test. Unauthorized use is
> illegal.

## Features

| Area | Windows (`WinEnum.ps1`) | Linux (`LinuxEnum.sh`) |
|---|---|---|
| System | OS/build, domain, BIOS, PowerShell/.NET, **UAC settings** | Kernel, distro, cmdline, AppArmor/SELinux |
| User & privileges | `whoami /all`, token privileges, groups | `id`, groups, `sudo -l`, `sudo`/`doas` |
| Users & groups | Local users, admins, RDP/remote groups, **account policy** | `/etc/passwd`, sudoers, shadow/passwd (+backups) perms |
| Processes & services | Services, unquoted paths, **writable service binaries/dirs**, drivers, features | Running services/processes (incl. root), **deleted binaries**, **kernel modules** |
| Persistence | Scheduled tasks, Run/RunOnce, **StartupApproved**, **AppInit_DLLs**, **Winlogon**, **IFEO**, **WMI startup** | Cron, systemd timers, **at jobs**, **writable units/startup scripts** |
| Software/patching | Installed programs, hotfixes | Package versions, sudo/ssh/openssl |
| Credentials | AutoLogon, AlwaysInstallElevated, cmdkey, PS history, unattend files, **PuTTY**, **VNC**, **wireless keys**, **browser stores**, **certificates** | History files, authorized_keys, private keys, `.env`/backups, **GPG**, **SSH agent** |
| Network | IP, routes, ARP, ports, firewall, shares | Interfaces, routes, sockets, iptables, resolvers |
| Remote access / lateral | **SMB config + shares + sessions**, **RDP config + client history**, **WinRM config** | **VPN configs**, **Samba/NFS exports**, **SSH agent** |
| Sessions & domain | **Logged-on users, Kerberos tickets (local), domain membership, DC/site, applied GPO** — host-local only | **`w`/`who`/`last`/`lastb`, auth logs, journalctl** |
| Filesystem | Writable paths, ACLs, **recent files** | Mounts, world-writable, **root-owned writable files**, **linker config**, PATH hijack |
| Defense / breakout | AV/Defender + **exclusions**, AppLocker, LAPS, secedit | SUID/SGID, capabilities, docker/lxd |
| Cloud / runtime | **WSL distributions** | **Cloud CLI creds (`.aws`/`.gcloud`/`.azure`/`.docker`), IMDS probe, sysctl + kernel mitigations** |
| Sensitive files | Config/web files, password grep, **IIS config, SAM hive backups, WinSCP/FileZilla** | Password grep in `/etc`, DB/config files, mail spool |
| Reporting | **Severity-tagged findings with exploit commands** | **Severity-tagged findings with exploit commands** |

## Report structure

Every run produces one Markdown file with three layers:

1. **Raw enumeration** — everything collected, grouped by topic, in code blocks.
2. **Findings & Exploitation Playbook** — automatically correlated issues, each
   with a severity, the evidence that triggered it, and the exact next-step
   commands. Paths, service names and binaries are filled in from the host,
   for example:

   ````markdown
   ### F3 [HIGH] Unquoted service path with writable directory

   **Evidence**
   ```
   VendorSvc -> drop C:\Program Files\Vendor App\Vendor.exe
   ```

   **Exploit / next steps**
   ```powershell
   copy /y C:\Windows\Temp\payload.exe "C:\Program Files\Vendor App\Vendor.exe"
   sc.exe stop "VendorSvc"; sc.exe start "VendorSvc"
   ```
   ````

   Detected checks include token privileges, writable service binaries and
   directories, unquoted path candidates, AlwaysInstallElevated, AutoLogon,
   stored credentials, wireless PSKs, Defender exclusions, UAC/token filter,
   SMB signing, privileged scheduled tasks, and domain membership/cached
   tickets (host-local only — no domain-wide enumeration), plus cloud
   credentials (Windows); and sudo/GTFOBins, SUID/SGID/capabilities,
   docker/lxd, passwd/shadow, writable sudoers/cron/systemd units,
   `ld.so.preload`, writable root-owned files, PATH, SSH keys/agent, cloud
   credentials/IMDS, NFS `no_root_squash`, GPG and kernel level (Linux).
3. **Wrap-up checklist** — what to review manually and useful reference tooling.

## Requirements

- **Windows:** PowerShell 5.1+ (built into Windows 10 / 11 / Server 2016+).
  No external modules.
- **Linux:** `/bin/bash` plus standard coreutils. Root is *not* required —
  missing privileges simply show up as empty results in the report.

## Usage

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1
powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1 -OutFile C:\Temp\report.md
powershell -ExecutionPolicy Bypass -File .\WinEnum.ps1 -Help
```

### Linux

```bash
chmod +x LinuxEnum.sh
./LinuxEnum.sh
./LinuxEnum.sh -o /tmp/report.md
./LinuxEnum.sh --help
```

Both scripts write a Markdown report named `<platform>_<host>_<timestamp>.md`
into the current directory (or the path you supply).

## Example output

````markdown
# Windows Enumeration Report

> **Authorized security testing only.**

| Field | Value |
|---|---|
| Host | WEB01 |
| User | CORP\jsmith |
| Generated | 11/16/2026 14:22:01 |

## 2. Current User & Privileges

### Token privileges
```
SeImpersonatePrivilege    Impersonate a client after authentication  Enabled
SeChangeNotifyPrivilege   Bypass traverse checking                    Enabled
```
````

Every check lands in its own code block, so the report is easy to skim and
diff against other hosts.

## Non-destructive

The scripts only read system state and write a single report file. They do
not modify the target, drop files (beyond the temporary `secedit` export on
Windows, which is deleted immediately), or establish persistence. The single
network probe is a read-only cloud metadata (IMDS) request with a 3s timeout.

The exploit commands printed in the findings section are **guidance only** —
the scripts never execute them.

## Safety — what the scripts do and do NOT do

**Executed (all read-only):**
- Reads OS, users, services, network, registry/config state and writes one
  Markdown report.
- Windows: `secedit /export` writes a temporary file under `%TEMP%` and
  deletes it immediately after reading it.
- Linux: three read-only HTTP GET requests to cloud metadata endpoints
  (`169.254.169.254`, `metadata.google.internal`) with a 3s timeout — they
  fail harmlessly on non-cloud hosts.

**Never executed (report guidance only):**
- Every "Exploit / next steps" command is plain text. None of it is run.
- No reverse shells, no remote downloads, no privilege-escalation payloads,
  no persistence, no destructive commands.

**No implants:**
- Nothing is installed, scheduled, added to startup, or left running.
- The only artifact is the report file itself (plus the deleted `%TEMP%`
  export on Windows).

> Note: the report *text* names offensive tooling (Mimikatz, Rubeus, nc,
> etc.). If a target scans the report heuristically, those strings can trip
> an AV/EDR alert — but the scripts themselves never execute any of it.

## Notes

- Checks that require elevated rights simply return empty results when run as
  a standard user — that absence is itself useful.
- `WinEnum.ps1` is PowerShell 5.1 compatible; no modules beyond what ships
  with Windows are required.
- On large filesystems the `find /` checks on Linux are the slowest part.

## Contributing

Pull requests are welcome — new checks, better output formatting, and
platform-specific additions are all appreciated.

## License

[MIT](LICENSE)
