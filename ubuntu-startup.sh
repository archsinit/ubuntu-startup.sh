#!/usr/bin/env bash
#
# Personal Ubuntu Docker Host Bootstrap
# Version: 1.0.0
#
# Goal:
# - Fresh Ubuntu server
# - SSH key-only access
# - Non-root admin user
# - Docker Engine installed
# - No Docker Compose
# - UFW protects host SSH only
# - Docker-published ports are treated as intentional public exposure
#
# Run as root:
#   bash personal-docker-host-bootstrap.sh

set -euo pipefail
set +x
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
  echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
  echo -e "${YELLOW}[WARNING] $1${NC}"
}

die() {
  echo -e "${RED}[ERROR] $1${NC}" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run this script as root."
  fi
}

check_ubuntu() {
  if [[ ! -r /etc/os-release ]]; then
    die "Cannot detect OS."
  fi

  . /etc/os-release

  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "This script supports Ubuntu only. Detected: ${ID:-unknown}"
  fi

  case "${VERSION_ID:-}" in
    "22.04"|"24.04"|"25.10"|"26.04")
      log "Detected supported Ubuntu version: ${VERSION_ID}"
      ;;
    *)
      warn "Untested Ubuntu version: ${VERSION_ID:-unknown}"
      read -r -p "Continue anyway? [y/N]: " CONTINUE
      [[ "${CONTINUE}" == "y" || "${CONTINUE}" == "Y" ]] || exit 1
      ;;
  esac
}

prompt_username() {
  while true; do
    read -r -p "Enter admin username to create/use: " NEW_USER

    if [[ "${NEW_USER}" =~ ^[a-z][-a-z0-9_]*$ ]] && [[ "${#NEW_USER}" -le 32 ]]; then
      break
    fi

    echo "Invalid username. Use lowercase letters, numbers, hyphens, underscores. Max 32 chars."
  done
}

prompt_ssh_key() {
  echo
  echo "Paste your SSH public key."
  echo "Expected format: ssh-ed25519 AAAA... comment"
  echo

  while true; do
    read -r -p "SSH public key: " SSH_PUBLIC_KEY

    if [[ "${SSH_PUBLIC_KEY}" =~ ^ssh-ed25519[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]] \
      || [[ "${SSH_PUBLIC_KEY}" =~ ^ecdsa-sha2-nistp[0-9]+[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]] \
      || [[ "${SSH_PUBLIC_KEY}" =~ ^ssh-rsa[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
      break
    fi

    echo "Invalid-looking SSH public key. Paste the full public key line."
  done
}

apt_base_setup() {
  log "Updating packages..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

  log "Installing base packages..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    needrestart \
    git \
    wget \
    htop \
    neovim
}

configure_unattended_upgrades() {
  log "Configuring unattended security upgrades..."

  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  systemctl enable unattended-upgrades >/dev/null 2>&1 || true
  systemctl restart unattended-upgrades >/dev/null 2>&1 || true
}

create_admin_user() {
  if id "${NEW_USER}" >/dev/null 2>&1; then
    warn "User ${NEW_USER} already exists. Reusing."
  else
    log "Creating user ${NEW_USER}..."
    adduser --gecos "" "${NEW_USER}"
  fi

  usermod -aG sudo "${NEW_USER}"
}

install_ssh_key() {
  log "Installing SSH key for ${NEW_USER}..."

  local USER_HOME
  USER_HOME="$(getent passwd "${NEW_USER}" | cut -d: -f6)"

  [[ -n "${USER_HOME}" ]] || die "Could not determine home directory for ${NEW_USER}."

  install -d -m 700 -o "${NEW_USER}" -g "${NEW_USER}" "${USER_HOME}/.ssh"

  touch "${USER_HOME}/.ssh/authorized_keys"
  chown "${NEW_USER}:${NEW_USER}" "${USER_HOME}/.ssh/authorized_keys"
  chmod 600 "${USER_HOME}/.ssh/authorized_keys"

  if ! grep -qxF "${SSH_PUBLIC_KEY}" "${USER_HOME}/.ssh/authorized_keys"; then
    echo "${SSH_PUBLIC_KEY}" >>"${USER_HOME}/.ssh/authorized_keys"
  fi
}

harden_ssh() {
  log "Hardening SSH..."

  local BACKUP
  BACKUP="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
  cp /etc/ssh/sshd_config "${BACKUP}"

  install -d -m 755 /etc/ssh/sshd_config.d

  cat >/etc/ssh/sshd_config.d/99-personal-hardening.conf <<EOF
# Managed by personal Docker host bootstrap

PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no

LoginGraceTime 20
MaxAuthTries 3
MaxSessions 5

AllowUsers ${NEW_USER}

X11Forwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
EOF

  if sshd -t; then
    systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || {
      cp "${BACKUP}" /etc/ssh/sshd_config
      rm -f /etc/ssh/sshd_config.d/99-personal-hardening.conf
      die "Failed to reload SSH. Restored main sshd_config backup."
    }
  else
    cp "${BACKUP}" /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/99-personal-hardening.conf
    die "Invalid SSH config. Restored backup."
  fi
}

configure_ufw() {
  log "Configuring UFW host firewall..."

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  ufw allow 22/tcp comment 'SSH host access'

  ufw --force enable
}

configure_fail2ban() {
  log "Configuring fail2ban..."

  cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 7200
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban
}

install_docker() {
  log "Installing Docker Engine without Docker Compose..."

  for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    apt-get remove -y "${pkg}" >/dev/null 2>&1 || true
  done

  install -m 0755 -d /etc/apt/keyrings

  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  . /etc/os-release

  cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

  apt-get update

  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin

  systemctl enable docker
  systemctl start docker

  usermod -aG docker "${NEW_USER}"

  warn "User ${NEW_USER} is now in the docker group."
  warn "Docker group membership is effectively root-level access."
}

configure_docker_daemon() {
  log "Configuring Docker daemon defaults..."

  install -d -m 755 /etc/docker

  cat >/etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true
}
EOF

  systemctl restart docker
}

create_service_layout() {
  log "Creating service directory layout..."

  install -d -m 750 -o root -g docker /opt/services
  install -d -m 750 -o root -g docker /opt/services/_scripts
  install -d -m 750 -o root -g docker /opt/services/_env
  install -d -m 750 -o root -g docker /opt/services/_secrets
  install -d -m 750 -o root -g docker /opt/services/_volumes

  cat >/opt/services/README.txt <<'EOF'
Personal Docker service layout

/scripts:
  Put docker run scripts here.
  Recommended script header:
    set -euo pipefail
    set +x
    umask 077

_env:
  Non-secret environment files.
  Suggested permissions: 640

_secrets:
  Secret files mounted read-only into containers.
  Suggested permissions: 600

_volumes:
  Bind-mounted app data.
  Back this directory up.

Important Docker exposure rule:
  -p 80:80 exposes publicly on all interfaces.
  -p 127.0.0.1:8080:8080 exposes locally only.
  No -p means no host port exposure.
EOF

  chown root:docker /opt/services/README.txt
  chmod 640 /opt/services/README.txt
}

create_proxy_network() {
  log "Creating Docker network: proxy"

  if docker network inspect proxy >/dev/null 2>&1; then
    log "Docker network proxy already exists."
  else
    docker network create proxy >/dev/null
  fi
}

apply_basic_sysctl() {
  log "Applying modest sysctl hardening..."

  cat >/etc/sysctl.d/99-personal-server.conf <<'EOF'
# Managed by personal Docker host bootstrap

# Spoofing protection
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Redirect hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source routing hardening
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Suspicious packet logging
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Kernel info restrictions
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1

# Filesystem link protections
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

  sysctl --system >/dev/null
}

write_report() {
  local REPORT="/root/hardening-report-$(date +%Y%m%d-%H%M%S).txt"

  {
    echo "Personal Docker Host Bootstrap Report"
    echo "Generated: $(date)"
    echo
    echo "User:"
    echo "  Admin user: ${NEW_USER}"
    echo "  Groups: $(groups "${NEW_USER}")"
    echo
    echo "SSH:"
    sshd -T 2>/dev/null | grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication|allowusers)' || true
    echo
    echo "UFW:"
    ufw status verbose || true
    echo
    echo "Fail2ban:"
    systemctl is-active fail2ban || true
    fail2ban-client status sshd 2>/dev/null || true
    echo
    echo "Docker:"
    docker --version 2>/dev/null || true
    docker buildx version 2>/dev/null || true
    echo
    echo "Docker networks:"
    docker network ls 2>/dev/null || true
    echo
    echo "Published Docker ports:"
    docker ps --format 'table {{.Names}}\t{{.Ports}}' 2>/dev/null || true
    echo
    echo "Listening host ports:"
    ss -tulpen 2>/dev/null || true
    echo
    echo "Reboot required:"
    if [[ -f /var/run/reboot-required ]]; then
      echo "  yes"
      cat /var/run/reboot-required.pkgs 2>/dev/null || true
    else
      echo "  no"
    fi
    echo
    echo "Important notes:"
    echo "  UFW allows SSH only."
    echo "  Docker-published ports may be reachable regardless of normal UFW expectations."
    echo "  Treat every docker run -p 0.0.0.0:HOST:CONTAINER or -p HOST:CONTAINER as public."
    echo "  Use -p 127.0.0.1:HOST:CONTAINER for local-only services."
    echo "  Do not put secrets directly in docker run arguments."
    echo "  Prefer --env-file for config and mounted files for secrets."
    echo "  Back up /opt/services, especially /opt/services/_volumes and /opt/services/_secrets."
  } >"${REPORT}"

  chmod 600 "${REPORT}"

  log "Report written to ${REPORT}"
}

print_final_notes() {
  echo
  echo "============================================================"
  echo "BOOTSTRAP COMPLETE"
  echo "============================================================"
  echo
  echo "Admin user:"
  echo "  ${NEW_USER}"
  echo
  echo "SSH:"
  echo "  Root login disabled"
  echo "  Password login disabled"
  echo "  Key login enabled for ${NEW_USER}"
  echo
  echo "Firewall:"
  echo "  UFW allows host SSH only: 22/tcp"
  echo "  No HTTP/HTTPS UFW rules were added"
  echo
  echo "Docker:"
  echo "  Docker Engine installed"
  echo "  Docker Compose intentionally not installed"
  echo "  Docker log rotation enabled"
  echo "  Docker network created: proxy"
  echo
  echo "Service layout:"
  echo "  /opt/services/_scripts"
  echo "  /opt/services/_env"
  echo "  /opt/services/_secrets"
  echo "  /opt/services/_volumes"
  echo
  echo "Important:"
  echo "  Docker-published ports are intentional exposure."
  echo "  Example public port:"
  echo "    docker run -p 80:80 ..."
  echo
  echo "  Example local-only port:"
  echo "    docker run -p 127.0.0.1:8080:8080 ..."
  echo
  echo "  Avoid secrets in command arguments."
  echo "  Prefer --env-file and mounted secret files."
  echo
  echo "Before closing this root session:"
  echo "  Open a second terminal and test:"
  echo "    ssh ${NEW_USER}@SERVER_IP"
  echo
  if [[ -f /var/run/reboot-required ]]; then
    echo "Reboot required: yes"
  else
    echo "Reboot required: no"
  fi
  echo
  echo "============================================================"
}

main() {
  require_root
  check_ubuntu
  prompt_username
  prompt_ssh_key

  apt_base_setup
  configure_unattended_upgrades

  create_admin_user
  install_ssh_key
  harden_ssh

  configure_ufw
  configure_fail2ban

  install_docker
  configure_docker_daemon
  create_service_layout
  create_proxy_network

  apply_basic_sysctl
  write_report
  print_final_notes
}

main "$@"
