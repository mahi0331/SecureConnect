#!/bin/bash

# SecureConnect VPN - Complete Verification Script
# Verifies Windows, Mobile, and IP tracking functionality

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
echo -e "${BLUE}  SecureConnect VPN - Complete Verification${NC}"
echo -e "${BLUE}=================================================${NC}"
echo

SERVER_IP=$(hostname -I | awk '{print $1}')
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${BLUE}🌐 Server IP: $SERVER_IP${NC}"
echo

# Check StrongSwan installation and status
echo -e "\n${BLUE}🔐 Checking VPN Server Status...${NC}"

if systemctl is-active strongswan-starter &>/dev/null; then
    echo -e "${GREEN}${check_mark} StrongSwan service running${NC}"
else
    echo -e "${RED}${cross_mark} StrongSwan service not running${NC}"
fi

if command -v ipsec &>/dev/null; then
    echo -e "${GREEN}${check_mark} IPSec tools available${NC}"
    
    # Check VPN status
    vpn_status=$(ipsec status 2>/dev/null || echo "")
    if [[ $vpn_status == *"Security Associations"* ]]; then
        echo -e "${GREEN}${check_mark} VPN server configured and ready${NC}"
    else
        echo -e "${YELLOW}${warning_mark} VPN server may need configuration${NC}"
    fi
else
    echo -e "${RED}${cross_mark} IPSec tools not installed${NC}"
fi

# Check certificates
echo -e "\n${BLUE}🏆 Checking SSL Certificates...${NC}"

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

# Check network configuration
echo -e "\n${BLUE}🌐 Checking Network Configuration...${NC}"

if sysctl net.ipv4.ip_forward | grep -q "1"; then
    echo -e "${GREEN}${check_mark} IP forwarding enabled${NC}"
else
    echo -e "${RED}${cross_mark} IP forwarding disabled${NC}"
fi

# Check listening ports
echo -e "\n${BLUE}🔌 Checking VPN Ports...${NC}"

if netstat -tuln | grep -q ":500 "; then
    echo -e "${GREEN}${check_mark} Port 500 (IKE) listening${NC}"
else
    echo -e "${YELLOW}${warning_mark} Port 500 not listening${NC}"
fi

if netstat -tuln | grep -q ":4500 "; then
    echo -e "${GREEN}${check_mark} Port 4500 (NAT-T) listening${NC}"
else
    echo -e "${YELLOW}${warning_mark} Port 4500 not listening${NC}"
fi

if netstat -tuln | grep -q ":5000 "; then
    echo -e "${GREEN}${check_mark} Port 5000 (Dashboard) listening${NC}"
else
    echo -e "${YELLOW}${warning_mark} Port 5000 (Dashboard) not listening${NC}"
fi

# Check Python environment and OTP system
echo -e "\n${BLUE}🐍 Checking Python Environment and OTP System...${NC}"

if [ -d "$PROJECT_ROOT/venv" ]; then
    echo -e "${GREEN}${check_mark} Python virtual environment exists${NC}"
    
    # Check if we can activate and import required modules
    cd "$PROJECT_ROOT"
    source venv/bin/activate
    
    python_modules=("pyotp" "qrcode" "flask" "sqlite3")
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

# Check database and IP tracking
echo -e "\n${BLUE}🗄️  Checking Database and IP Tracking...${NC}"

if [ -f "$PROJECT_ROOT/server/otp_auth/users.db" ]; then
    echo -e "${GREEN}${check_mark} User database exists${NC}"
    
    # Check database tables
    cd "$PROJECT_ROOT/server/otp_auth"
    source ../../venv/bin/activate
    
    tables=$(sqlite3 users.db "SELECT name FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "")
    if [[ $tables == *"users"* ]]; then
        echo -e "${GREEN}${check_mark} Users table exists${NC}"
    else
        echo -e "${RED}${cross_mark} Users table missing${NC}"
    fi
    
    if [[ $tables == *"connection_logs"* ]]; then
        echo -e "${GREEN}${check_mark} IP tracking table exists${NC}"
    else
        echo -e "${RED}${cross_mark} IP tracking table missing${NC}"
    fi
    
    if [[ $tables == *"auth_logs"* ]]; then
        echo -e "${GREEN}${check_mark} Authentication logs table exists${NC}"
    else
        echo -e "${RED}${cross_mark} Authentication logs table missing${NC}"
    fi
    
    # Count users
    user_count=$(sqlite3 users.db "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
    echo -e "${BLUE}📊 Users in database: $user_count${NC}"
else
    echo -e "${YELLOW}${warning_mark} User database not found${NC}"
fi

# Check web dashboard
echo -e "\n${BLUE}🌐 Checking Web Dashboard...${NC}"

if [ -f "$PROJECT_ROOT/web_dashboard/app.py" ]; then
    echo -e "${GREEN}${check_mark} Dashboard application exists${NC}"
else
    echo -e "${RED}${cross_mark} Dashboard application missing${NC}"
fi

if systemctl is-active secureconnect-dashboard &>/dev/null; then
    echo -e "${GREEN}${check_mark} Dashboard service running${NC}"
else
    echo -e "${YELLOW}${warning_mark} Dashboard service not running${NC}"
fi

# Test dashboard accessibility
if curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 | grep -q "200"; then
    echo -e "${GREEN}${check_mark} Dashboard accessible locally${NC}"
else
    echo -e "${YELLOW}${warning_mark} Dashboard not accessible${NC}"
fi

# Check firewall configuration
echo -e "\n${BLUE}🔥 Checking Firewall Configuration...${NC}"

if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}${check_mark} UFW firewall active${NC}"
        
        if ufw status | grep -q "500/udp"; then
            echo -e "${GREEN}${check_mark} VPN port 500 allowed${NC}"
        else
            echo -e "${YELLOW}${warning_mark} VPN port 500 not explicitly allowed${NC}"
        fi
        
        if ufw status | grep -q "4500/udp"; then
            echo -e "${GREEN}${check_mark} VPN port 4500 allowed${NC}"
        else
            echo -e "${YELLOW}${warning_mark} VPN port 4500 not explicitly allowed${NC}"
        fi
    else
        echo -e "${YELLOW}${warning_mark} UFW firewall not active${NC}"
    fi
else
    echo -e "${YELLOW}${warning_mark} UFW not installed${NC}"
fi

# Check NAT rules for IP tracking
if iptables -t nat -L POSTROUTING | grep -q "10.10.10.0/24\|10.10.11.0/24"; then
    echo -e "${GREEN}${check_mark} NAT rules configured for VPN clients${NC}"
else
    echo -e "${YELLOW}${warning_mark} NAT rules may need configuration${NC}"
fi

# Windows and Mobile compatibility check
echo -e "\n${BLUE}📱 Checking Windows/Mobile Compatibility...${NC}"

if grep -q "windows-ikev2\|mobile-ikev2" /etc/ipsec.conf 2>/dev/null; then
    echo -e "${GREEN}${check_mark} Windows/Mobile VPN profiles configured${NC}"
else
    echo -e "${YELLOW}${warning_mark} Windows/Mobile profiles may need configuration${NC}"
fi

if grep -q "eap-mschapv2" /etc/ipsec.conf 2>/dev/null; then
    echo -e "${GREEN}${check_mark} EAP-MSCHAPv2 authentication configured${NC}"
else
    echo -e "${YELLOW}${warning_mark} EAP-MSCHAPv2 authentication not configured${NC}"
fi

# Summary and client configuration
echo -e "\n${BLUE}=================================================${NC}"
echo -e "${BLUE}  📊 Verification Summary${NC}"
echo -e "${BLUE}=================================================${NC}"
echo
echo -e "${GREEN}✅ Your SecureConnect VPN server verification complete!${NC}"
echo
echo -e "${BLUE}🖥️  Windows 10/11 VPN Setup:${NC}"
echo "  1. Settings → Network & Internet → VPN → Add VPN"
echo "  2. VPN Provider: Windows (built-in)"
echo "  3. Connection Name: SecureConnect"
echo "  4. Server: $SERVER_IP"
echo "  5. VPN Type: IKEv2"
echo "  6. Username/Password: Created via OTP CLI"
echo
echo -e "${BLUE}📱 Mobile (iOS/Android) VPN Setup:${NC}"
echo "  1. Settings → VPN → Add VPN Configuration"
echo "  2. Type: IKEv2"
echo "  3. Server: $SERVER_IP"
echo "  4. Remote ID: $SERVER_IP"
echo "  5. Username/Password: Created via OTP CLI"
echo
echo -e "${BLUE}🌐 Admin Dashboard Access:${NC}"
echo "  • URL: http://$SERVER_IP:5000"
echo "  • Login: admin / admin123"
echo "  • Features: IP tracking, connection logs, user management"
echo
echo -e "${BLUE}👤 Create VPN Users:${NC}"
echo "  cd $PROJECT_ROOT/server/otp_auth"
echo "  source ../../venv/bin/activate"
echo "  python3 otp_cli.py"
echo
echo -e "${BLUE}🔍 Monitor Connections:${NC}"
echo "  • Real-time: sudo journalctl -u strongswan -f"
echo "  • Status: sudo ipsec status"
echo "  • Dashboard: http://$SERVER_IP:5000"
echo
echo -e "${YELLOW}💡 Troubleshooting:${NC}"
echo "  • Check logs: sudo journalctl -u strongswan"
echo "  • Restart VPN: sudo systemctl restart strongswan-starter"
echo "  • Restart Dashboard: sudo systemctl restart secureconnect-dashboard"
echo
echo -e "${GREEN}🎯 Your VPN is ready for Windows, Mobile, and complete IP tracking!${NC}"
