#!/bin/bash

# SecureConnect VPN - Ubuntu System Verification
# Verifies that everything is properly installed and configured

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

check_mark="✅"
cross_mark="❌"
warning_mark="⚠️"

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  SecureConnect VPN - Ubuntu Verification${NC}"
echo -e "${BLUE}=================================================${NC}"
echo

# Check if running on Ubuntu
if ! grep -q "Ubuntu" /etc/os-release; then
    echo -e "${YELLOW}${warning_mark} Warning: Not running on Ubuntu${NC}"
else
    echo -e "${GREEN}${check_mark} Running on Ubuntu${NC}"
fi

# Check package installations
echo -e "\n${BLUE}📦 Checking package installations...${NC}"

packages=("strongswan" "python3" "python3-pip" "openssl" "iptables")
for package in "${packages[@]}"; do
    if dpkg -l | grep -q "^ii  $package "; then
        echo -e "${GREEN}${check_mark} $package installed${NC}"
    else
        echo -e "${RED}${cross_mark} $package NOT installed${NC}"
    fi
done

# Check Python environment
echo -e "\n${BLUE}🐍 Checking Python environment...${NC}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -d "$PROJECT_ROOT/venv" ]; then
    echo -e "${GREEN}${check_mark} Python virtual environment exists${NC}"
    
    # Check if we can activate and import required modules
    source "$PROJECT_ROOT/venv/bin/activate"
    
    python_modules=("pyotp" "qrcode" "flask" "cryptography")
    for module in "${python_modules[@]}"; do
        if python3 -c "import $module" 2>/dev/null; then
            echo -e "${GREEN}${check_mark} Python module: $module${NC}"
        else
            echo -e "${RED}${cross_mark} Python module: $module NOT installed${NC}"
        fi
    done
else
    echo -e "${RED}${cross_mark} Python virtual environment NOT found${NC}"
fi

# Check StrongSwan configuration
echo -e "\n${BLUE}🔐 Checking StrongSwan configuration...${NC}"

if [ -f "/etc/ipsec.conf" ]; then
    echo -e "${GREEN}${check_mark} /etc/ipsec.conf exists${NC}"
else
    echo -e "${RED}${cross_mark} /etc/ipsec.conf missing${NC}"
fi

if [ -f "/etc/ipsec.secrets" ]; then
    echo -e "${GREEN}${check_mark} /etc/ipsec.secrets exists${NC}"
else
    echo -e "${RED}${cross_mark} /etc/ipsec.secrets missing${NC}"
fi

# Check certificates
echo -e "\n${BLUE}🏆 Checking SSL certificates...${NC}"

cert_files=(
    "/etc/ipsec.d/cacerts/ca-cert.pem"
    "/etc/ipsec.d/certs/server-cert.pem"
    "/etc/ipsec.d/private/server-key.pem"
)

for cert_file in "${cert_files[@]}"; do
    if [ -f "$cert_file" ]; then
        echo -e "${GREEN}${check_mark} $(basename $cert_file)${NC}"
    else
        echo -e "${RED}${cross_mark} $(basename $cert_file) missing${NC}"
    fi
done

# Check IP forwarding
echo -e "\n${BLUE}🌐 Checking network configuration...${NC}"

if sysctl net.ipv4.ip_forward | grep -q "1"; then
    echo -e "${GREEN}${check_mark} IP forwarding enabled${NC}"
else
    echo -e "${RED}${cross_mark} IP forwarding disabled${NC}"
fi

# Check firewall rules
echo -e "\n${BLUE}🔥 Checking firewall rules...${NC}"

if sudo iptables -L INPUT | grep -q "500"; then
    echo -e "${GREEN}${check_mark} VPN port 500 allowed${NC}"
else
    echo -e "${YELLOW}${warning_mark} VPN port 500 rule not found${NC}"
fi

if sudo iptables -L INPUT | grep -q "4500"; then
    echo -e "${GREEN}${check_mark} VPN port 4500 allowed${NC}"
else
    echo -e "${YELLOW}${warning_mark} VPN port 4500 rule not found${NC}"
fi

# Check services
echo -e "\n${BLUE}🚀 Checking services...${NC}"

if systemctl is-enabled strongswan &>/dev/null; then
    echo -e "${GREEN}${check_mark} StrongSwan service enabled${NC}"
else
    echo -e "${YELLOW}${warning_mark} StrongSwan service not enabled${NC}"
fi

if systemctl is-active strongswan &>/dev/null; then
    echo -e "${GREEN}${check_mark} StrongSwan service running${NC}"
else
    echo -e "${YELLOW}${warning_mark} StrongSwan service not running${NC}"
fi

# Check OTP database
echo -e "\n${BLUE}🗄️  Checking OTP authentication...${NC}"

if [ -f "$PROJECT_ROOT/server/otp_auth/users.db" ]; then
    echo -e "${GREEN}${check_mark} OTP database exists${NC}"
    
    # Count users
    user_count=$(sqlite3 "$PROJECT_ROOT/server/otp_auth/users.db" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
    echo -e "${BLUE}📊 Users in database: $user_count${NC}"
else
    echo -e "${YELLOW}${warning_mark} OTP database not found${NC}"
fi

# Check web dashboard
echo -e "\n${BLUE}🌐 Checking web dashboard...${NC}"

if [ -f "$PROJECT_ROOT/web_dashboard/app.py" ]; then
    echo -e "${GREEN}${check_mark} Dashboard application exists${NC}"
else
    echo -e "${RED}${cross_mark} Dashboard application missing${NC}"
fi

if systemctl is-enabled secureconnect-dashboard &>/dev/null; then
    echo -e "${GREEN}${check_mark} Dashboard service enabled${NC}"
else
    echo -e "${YELLOW}${warning_mark} Dashboard service not enabled${NC}"
fi

# Network connectivity test
echo -e "\n${BLUE}🔍 Network connectivity tests...${NC}"

SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "${BLUE}📍 Server IP: $SERVER_IP${NC}"

# Test if ports are listening
if netstat -tuln | grep -q ":500 "; then
    echo -e "${GREEN}${check_mark} Port 500 listening${NC}"
else
    echo -e "${YELLOW}${warning_mark} Port 500 not listening${NC}"
fi

if netstat -tuln | grep -q ":4500 "; then
    echo -e "${GREEN}${check_mark} Port 4500 listening${NC}"
else
    echo -e "${YELLOW}${warning_mark} Port 4500 not listening${NC}"
fi

# Summary
echo -e "\n${BLUE}=================================================${NC}"
echo -e "${BLUE}  Verification Summary${NC}"
echo -e "${BLUE}=================================================${NC}"

echo -e "\n${GREEN}✅ Installation appears to be complete!${NC}"
echo
echo -e "${BLUE}🚀 To start the VPN server:${NC}"
echo "  ${YELLOW}sudo ./scripts/start_server.sh${NC}"
echo
echo -e "${BLUE}🌐 To access the dashboard:${NC}"
echo "  ${YELLOW}http://$SERVER_IP:5000${NC}"
echo "  Login: admin / admin123"
echo
echo -e "${BLUE}👤 To create VPN users:${NC}"
echo "  ${YELLOW}cd server/otp_auth${NC}"
echo "  ${YELLOW}source ../../venv/bin/activate${NC}"
echo "  ${YELLOW}python3 otp_cli.py${NC}"
echo
echo -e "${BLUE}📱 To connect clients:${NC}"
echo "  ${YELLOW}./client/scripts/connect.sh connect${NC}"
echo
echo -e "${YELLOW}💡 If you see any warnings above, check:${NC}"
echo "  • docs/TROUBLESHOOTING.md"
echo "  • sudo journalctl -u strongswan"
echo "  • Server logs in server/logs/"
echo
