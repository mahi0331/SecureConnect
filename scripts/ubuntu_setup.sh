#!/bin/bash

# SecureConnect VPN - Ubuntu One-Click Setup
# This script sets up everything needed for Ubuntu systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  SecureConnect VPN - Ubuntu Setup${NC}"
echo -e "${BLUE}=================================================${NC}"
echo

# Check if running on Ubuntu
if ! grep -q "Ubuntu" /etc/os-release; then
    echo -e "${YELLOW}Warning: This script is optimized for Ubuntu.${NC}"
    echo -e "${YELLOW}It may work on other Debian-based systems.${NC}"
    echo
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}Error: Please run this script with sudo, not as root user${NC}"
    echo "Usage: sudo ./ubuntu_setup.sh"
    exit 1
fi

# Check if sudo is available
if ! sudo -n true 2>/dev/null; then
    echo -e "${RED}Error: This script requires sudo privileges${NC}"
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo -e "${BLUE}Project directory: $PROJECT_ROOT${NC}"
echo

# Step 1: Update system
echo -e "${YELLOW}📦 Step 1: Updating Ubuntu system...${NC}"
sudo apt update
sudo apt upgrade -y
echo -e "${GREEN}✅ System updated${NC}"
echo

# Step 2: Install required packages
echo -e "${YELLOW}📦 Step 2: Installing required packages...${NC}"
sudo apt install -y \
    strongswan \
    strongswan-pki \
    libcharon-extra-plugins \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    openssl \
    iptables \
    iptables-persistent \
    net-tools \
    tcpdump \
    sqlite3 \
    git \
    tree
echo -e "${GREEN}✅ Packages installed${NC}"
echo

# Step 3: Setup Python environment
echo -e "${YELLOW}🐍 Step 3: Setting up Python environment...${NC}"
cd "$PROJECT_ROOT"

# Remove existing venv if it exists
if [ -d "venv" ]; then
    rm -rf venv
fi

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip

# Install Python requirements
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    # Install basic requirements manually
    pip install pyotp qrcode[pil] flask flask-cors cryptography pyyaml python-dotenv psutil
fi
echo -e "${GREEN}✅ Python environment ready${NC}"
echo

# Step 4: Enable IP forwarding
echo -e "${YELLOW}🌐 Step 4: Configuring network settings...${NC}"
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
echo -e "${GREEN}✅ IP forwarding enabled${NC}"
echo

# Step 5: Generate certificates
echo -e "${YELLOW}🔐 Step 5: Generating SSL certificates...${NC}"
sudo mkdir -p /etc/ipsec.d/{private,certs,cacerts}

cd "$PROJECT_ROOT/server/strongswan"

# Generate CA key
sudo ipsec pki --gen --type rsa --size 4096 --outform pem > ca-key.pem

# Generate CA certificate
sudo ipsec pki --self --ca --lifetime 3650 --in ca-key.pem \
    --type rsa --dn "CN=SecureConnect VPN CA" \
    --outform pem > ca-cert.pem

# Generate server key
sudo ipsec pki --gen --type rsa --size 4096 --outform pem > server-key.pem

# Generate server certificate
sudo ipsec pki --pub --in server-key.pem --type rsa | \
sudo ipsec pki --issue --lifetime 1825 --cacert ca-cert.pem \
    --cakey ca-key.pem --dn "CN=secureconnect.vpn" \
    --san "secureconnect.vpn" --flag serverAuth \
    --flag ikeIntermediate --outform pem > server-cert.pem

# Install certificates
sudo cp ca-cert.pem /etc/ipsec.d/cacerts/
sudo cp server-cert.pem /etc/ipsec.d/certs/
sudo cp server-key.pem /etc/ipsec.d/private/
sudo chmod 600 /etc/ipsec.d/private/server-key.pem

echo -e "${GREEN}✅ Certificates generated and installed${NC}"
echo

# Step 6: Configure StrongSwan
echo -e "${YELLOW}⚙️  Step 6: Configuring StrongSwan VPN...${NC}"

# Backup original configs
sudo cp /etc/ipsec.conf /etc/ipsec.conf.backup 2>/dev/null || true
sudo cp /etc/ipsec.secrets /etc/ipsec.secrets.backup 2>/dev/null || true

# Copy our configurations
sudo cp ipsec.conf /etc/ipsec.conf
sudo cp ipsec.secrets /etc/ipsec.secrets
sudo cp strongswan.conf /etc/strongswan.d/charon.conf

# Set permissions
sudo chmod 644 /etc/ipsec.conf
sudo chmod 600 /etc/ipsec.secrets

echo -e "${GREEN}✅ StrongSwan configured${NC}"
echo

# Step 7: Configure firewall
echo -e "${YELLOW}🔥 Step 7: Configuring firewall...${NC}"

# Allow SSH (important!)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow VPN ports
sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
sudo iptables -A INPUT -p esp -j ACCEPT

# Allow web dashboard
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

# Allow forwarding for VPN
sudo iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT

# NAT for VPN clients
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o $(ip route | grep default | awk '{print $5}' | head -1) -j MASQUERADE

# Save rules
sudo mkdir -p /etc/iptables
sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null

echo -e "${GREEN}✅ Firewall configured${NC}"
echo

# Step 8: Setup directories and permissions
echo -e "${YELLOW}📁 Step 8: Setting up directories...${NC}"
cd "$PROJECT_ROOT"

mkdir -p server/logs
chmod 755 server/logs

chmod +x scripts/*.sh
chmod +x client/scripts/*.sh

echo -e "${GREEN}✅ Directories and permissions set${NC}"
echo

# Step 9: Initialize OTP database
echo -e "${YELLOW}🗄️  Step 9: Initializing authentication system...${NC}"
cd "$PROJECT_ROOT/server/otp_auth"
source "$PROJECT_ROOT/venv/bin/activate"

python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
print('✅ OTP authentication database initialized')
"

echo -e "${GREEN}✅ Authentication system ready${NC}"
echo

# Step 10: Enable services
echo -e "${YELLOW}🚀 Step 10: Enabling services...${NC}"
sudo systemctl enable strongswan

# Create systemd service for dashboard
sudo tee /etc/systemd/system/secureconnect-dashboard.service > /dev/null << EOF
[Unit]
Description=SecureConnect VPN Dashboard
After=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_ROOT/web_dashboard
Environment=PATH=$PROJECT_ROOT/venv/bin
ExecStart=$PROJECT_ROOT/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable secureconnect-dashboard

echo -e "${GREEN}✅ Services configured${NC}"
echo

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

# Success message
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}  ✅ SecureConnect VPN Setup Complete!${NC}"
echo -e "${GREEN}=================================================${NC}"
echo
echo -e "${BLUE}🎉 Installation Summary:${NC}"
echo "  ✅ Ubuntu system updated"
echo "  ✅ StrongSwan VPN server installed"
echo "  ✅ Python environment configured"
echo "  ✅ SSL certificates generated"
echo "  ✅ Firewall rules applied"
echo "  ✅ Authentication system initialized"
echo "  ✅ Services configured"
echo
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo "  1. Start the VPN server:"
echo "     ${YELLOW}sudo ./scripts/start_server.sh${NC}"
echo
echo "  2. Access the web dashboard:"
echo "     ${YELLOW}http://$SERVER_IP:5000${NC}"
echo "     Login: admin / admin123"
echo
echo "  3. Create your first VPN user:"
echo "     ${YELLOW}cd server/otp_auth${NC}"
echo "     ${YELLOW}source ../../venv/bin/activate${NC}"
echo "     ${YELLOW}python3 otp_cli.py${NC}"
echo
echo "  4. Connect clients:"
echo "     ${YELLOW}./client/scripts/connect.sh connect${NC}"
echo
echo -e "${BLUE}📖 Documentation:${NC}"
echo "  • Quick Start Guide: QUICK_START.md"
echo "  • User Guide: docs/USER_GUIDE.md"
echo "  • Troubleshooting: docs/TROUBLESHOOTING.md"
echo
echo -e "${YELLOW}🔒 Security Reminder:${NC}"
echo "  • Change default dashboard password (admin/admin123)"
echo "  • Update PSK in /etc/ipsec.secrets"
echo "  • Monitor logs regularly"
echo
echo -e "${GREEN}Ready to start your VPN server!${NC}"
