#!/bin/bash
#
# Ubuntu Server Hardening Interactive Script
# Version: 0.2.0 | 2025-07-18
# 
# This script was developed with AI assistance for comprehensive server hardening
# on fresh Ubuntu installations. Based on security best practices from various
# sources including buildplan/du_setup and gtsa/server-setup-linux.
#
# Changelog:
# - Added error handling and logging
# - Improved SSH security configuration
# - Added input validation
# - Enhanced firewall configuration
# - Added system monitoring tools
# - Improved user feedback and verification
#
# Description:
# Hardens a fresh Ubuntu server installation with security best practices.
# Must be run as root on systems with only root user initially configured.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check if running as root (required for fresh install)
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root on a fresh installation."
   error "Please run: sudo bash $0"
   exit 1
fi

log "Starting Ubuntu Server Hardening Script..."

# Update and upgrade system packages
log "Updating and upgrading system packages..."
apt update && apt upgrade -y

log "Installing unattended-upgrades for automatic security updates..."
apt install -y unattended-upgrades apt-listchanges
dpkg-reconfigure --priority=low unattended-upgrades

# Install essential security and monitoring tools
log "Installing essential security and monitoring tools..."
apt install -y \
    fail2ban \
    ufw \
    neovim \
    htop \
    curl \
    wget \
    git \
    tree \
    net-tools \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# Configure fail2ban for SSH protection
log "Configuring fail2ban for SSH protection..."
systemctl enable fail2ban
systemctl start fail2ban

# Create custom fail2ban configuration
tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
bantime = 7200
EOF

systemctl restart fail2ban

# Install Docker and Docker Compose
log "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    
    # Install Docker Compose
    log "Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Create docker-compose symlink for convenience
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
else
    log "Docker is already installed."
fi

# Create non-root user
while true; do
    read -p "Enter the username for the new user: " NEW_USER
    
    # Validate username
    if [[ "$NEW_USER" =~ ^[a-z][-a-z0-9_]*$ ]] && [[ ${#NEW_USER} -le 32 ]]; then
        break
    else
        error "Invalid username. Use lowercase letters, numbers, hyphens, and underscores only (max 32 chars)."
    fi
done

if id "$NEW_USER" &>/dev/null; then
    warning "User $NEW_USER already exists. Skipping creation."
else
    log "Creating user $NEW_USER..."
    adduser --gecos "" $NEW_USER
    usermod -aG sudo $NEW_USER
    
    # Add to docker group if it exists
    if getent group docker > /dev/null 2>&1; then
        usermod -aG docker $NEW_USER
        log "Added $NEW_USER to docker group."
    else
        warning "Docker group does not exist. Skipping docker group assignment."
    fi
fi

# Configure SSH hardening
log "Configuring SSH for enhanced security..."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# Apply SSH hardening configurations
sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
sed -i "s/^#\?LoginGraceTime.*/LoginGraceTime 20/" /etc/ssh/sshd_config
sed -i "s/^#\?MaxAuthTries.*/MaxAuthTries 2/" /etc/ssh/sshd_config
sed -i "s/^#\?MaxSessions.*/MaxSessions 5/" /etc/ssh/sshd_config
sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config
sed -i "s/^#\?Protocol.*/Protocol 2/" /etc/ssh/sshd_config
sed -i "s/^#\?X11Forwarding.*/X11Forwarding no/" /etc/ssh/sshd_config

# Remove any existing AllowUsers lines and add new one
sed -i "/^AllowUsers/d" /etc/ssh/sshd_config
echo "AllowUsers $NEW_USER" | tee -a /etc/ssh/sshd_config > /dev/null

# Add additional security settings
cat << 'EOF' | tee -a /etc/ssh/sshd_config > /dev/null

# Additional security settings
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
PermitUserEnvironment no
Compression no
TCPKeepAlive no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
EOF

# Test SSH configuration
if sshd -t; then
    log "SSH configuration is valid. Restarting SSH service..."
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
else
    error "SSH configuration is invalid. Restoring backup..."
    cp /etc/ssh/sshd_config.backup.* /etc/ssh/sshd_config
    exit 1
fi

# Configure UFW firewall
log "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow essential services
ufw allow 22/tcp comment 'SSH'

# Enable firewall
ufw --force enable

# Secure shared memory (prevents execution of code from shared memory)
# This prevents malicious programs from accessing shared memory segments
# that could contain sensitive data from other processes
log "Securing shared memory..."
if ! grep -q "tmpfs /run/shm" /etc/fstab; then
    echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' | tee -a /etc/fstab > /dev/null
    log "Added secure shared memory mount to /etc/fstab"
fi

# Disable unnecessary services that could be attack vectors
# These services are often not needed on servers
log "Checking for unnecessary services to disable..."
services_to_disable=("avahi-daemon" "cups" "isc-dhcp-server" "isc-dhcp-server6" "rpcbind" "nfs-server")
for service in "${services_to_disable[@]}"; do
    if systemctl is-enabled "$service" &>/dev/null; then
        systemctl disable "$service" && log "Disabled $service"
    fi
done

# Apply kernel security parameters to harden network stack
# These settings protect against various network-based attacks
log "Applying kernel security parameters..."
tee /etc/sysctl.d/99-security.conf > /dev/null <<EOF
# IP Spoofing protection - prevents attackers from pretending to be other IPs
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore ICMP redirects - prevents network redirection attacks
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects - prevents this server from being used in redirection attacks
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing - prevents routing manipulation attacks
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log suspicious packets (Martians) - helps detect network attacks
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests - makes server less discoverable
net.ipv4.icmp_echo_ignore_all = 1

# Ignore broadcast pings - prevents participation in smurf attacks
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6 if not needed - reduces attack surface
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Enable TCP SYN cookies - helps prevent SYN flood attacks
net.ipv4.tcp_syncookies = 1

# Increase system security - enables additional protections
kernel.randomize_va_space = 2
EOF

sysctl -p /etc/sysctl.d/99-security.conf

# Verification and summary
echo
echo "=================================================="
echo "UBUNTU SERVER HARDENING COMPLETED"
echo "=================================================="
echo
echo "Verification Summary:"
echo "--------------------"

# Docker verification
if command -v docker &> /dev/null; then
    echo "Docker version: $(docker --version)"
fi

if command -v docker-compose &> /dev/null; then
    echo "Docker Compose version: $(docker-compose --version)"
fi

# SSH service verification
echo "SSH service status:"
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
    echo "   SSH service is running"
else
    echo "   SSH service is not running"
fi

# Firewall verification
echo "UFW status:"
ufw status | head -n 10

# Fail2ban verification
echo "Fail2ban status:"
if systemctl is-active --quiet fail2ban; then
    echo "   Fail2ban is running"
    fail2ban-client status sshd | head -n 5
else
    echo "   Fail2ban is not running"
fi

# User verification
echo "User $NEW_USER groups: $(groups $NEW_USER)"

echo
echo "=================================================="
echo "SSH KEY-BASED AUTHENTICATION SETUP"
echo "=================================================="
echo
echo "IMPORTANT: Password authentication is now DISABLED!"
echo "You MUST set up SSH key authentication before logging out."
echo
echo "Instructions:"
echo "1. On your LOCAL machine, generate an SSH key pair if you don't have one:"
echo "   ssh-keygen -t ed25519 -C \"your_email@example.com\""
echo
echo "2. Display your public key on your local machine:"
echo "   cat ~/.ssh/id_ed25519.pub"
echo
echo "3. Copy the ENTIRE output from step 2."
echo
echo "4. On THIS SERVER, while still logged in as root, run:"
echo "   mkdir -p /home/$NEW_USER/.ssh"
echo "   chmod 700 /home/$NEW_USER/.ssh"
echo "   nano /home/$NEW_USER/.ssh/authorized_keys"
echo
echo "5. Paste your public key into the file and save (Ctrl+X, Y, Enter)."
echo
echo "6. Set proper permissions:"
echo "   chmod 600 /home/$NEW_USER/.ssh/authorized_keys"
echo "   chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh"
echo
echo "7. Test SSH connection from your local machine:"
echo "   ssh $NEW_USER@$(hostname -I | awk '{print $1}')"
echo
echo "8. Only after confirming SSH key login works, you can logout safely."
echo
echo "=================================================="
echo "ADDITIONAL SECURITY RECOMMENDATIONS"
echo "=================================================="
echo "- Regularly update your system: apt update && apt upgrade"
echo "- Monitor logs: journalctl -f"
echo "- Check fail2ban status: fail2ban-client status"
echo "- Review UFW rules: ufw status verbose"
echo "- Consider setting up automated backups"
echo "- Enable 2FA where possible"
echo "- Use strong, unique passwords"
echo "- Regularly audit user accounts and permissions"
echo
echo "Server hardening complete."
echo "=================================================="
