#!/bin/bash
#
# Ubuntu Server Hardening Interactive Script
# Version: 0.1.0 | 2025-07-14
# Changelog:
#
# Description:
# This script is based on https://github.com/buildplan/du_setup/
# and https://github.com/gtsa/server-setup-linux/.
# It is intended to be used on a fresh Ubuntu installation.

# --- UPGRADE SYSTEM ---
sudo apt update && sudo apt upgrade -y
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades

# --- INSTALL DOCKER AND DOCKER COMPOSE ---
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# --- CREATE NON-ROOT USER ---
read -p "Enter the username for the new user: " NEW_USER
DOCKER_GROUP=true

if id "$NEW_USER" &>/dev/null; then
  echo "User $NEW_USER already exists. Skipping creation."
else
  sudo adduser $NEW_USER
  sudo usermod -aG sudo $NEW_USER
  if $DOCKER_GROUP && grep -q "^docker:" /etc/group; then
    sudo usermod -aG docker $NEW_USER
  elif $DOCKER_GROUP; then
    echo "Docker group does not exist. Skipping docker group assignment."
  fi
fi

# --- CONFIGURE SSH ---
sudo sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?LoginGraceTime.*/LoginGraceTime 20/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?MaxAuthTries.*/MaxAuthTries 2/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?MaxSessions.*/MaxSessions 10/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
sudo sed -i "/^AuthenticationMethods/d" /etc/ssh/sshd_config
if ! grep -q "^AllowUsers $NEW_USER" /etc/ssh/sshd_config; then
  echo "AllowUsers $NEW_USER" | sudo tee -a /etc/ssh/sshd_config > /dev/null
fi
sudo systemctl restart ssh || sudo systemctl restart sshd

# --- INSTALL ESSENTIAL TOOLS ---
sudo apt install -y git neovim

# --- CONFIGURE FIREWALL
sudo apt install -y ufw
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

echo "--------------------------------------------------"
echo "Verification Summary:"
echo "Docker version:"; docker version
echo "Docker Compose version:"; docker-compose version
echo "SSH service status:"; (sudo systemctl status ssh --no-pager || sudo systemctl status sshd --no-pager) | head -n 5
echo "UFW status:"; sudo ufw status
echo "--------------------------------------------------"

echo "--------------------------------------------------"
echo "SSH Key-Based Authentication Setup Instructions:"
echo "1. On your local machine, display your public key (e.g., run: cat ~/.ssh/id_ed25519.pub)"
echo "2. Copy the entire output."
echo "3. On the server, log in as the new user:"
echo "   ssh $NEW_USER@your_server_ip"
echo "4. Then run:"
echo "   mkdir -p ~/.ssh && chmod 700 ~/.ssh"
echo "   nano ~/.ssh/authorized_keys"
echo "5. Paste your public key into the file and save."
echo "6. Finally, run: chmod 600 ~/.ssh/authorized_keys"
echo "--------------------------------------------------"

echo "Setup complete!"
