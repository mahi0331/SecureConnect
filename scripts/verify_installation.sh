#!/bin/bash

# SecureConnect VPN - Installation Verification Script
# This script checks if the VPN system is properly installed and running

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Status tracking
TESTS_PASSED=0
TESTS_TOTAL=0

# Test function
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✅ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "  ${RED}❌ FAIL${NC}"
        return 1
    fi
}

# Header
clear
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  SecureConnect VPN - Installation Verification${NC}"
echo -e "${BLUE}=================================================${NC}"
echo

# System Requirements Tests
echo -e "${YELLOW}🔍 System Requirements${NC}"
echo "─────────────────────────────────"

run_test "Linux distribution check" "[ -f /etc/os-release ]"
run_test "Root/sudo access" "sudo -n true"
run_test "Python 3.8+ installed" "python3 -c 'import sys; exit(0 if sys.version_info >= (3,8) else 1)'"
run_test "StrongSwan installed" "command -v ipsec"
run_test "SQLite installed" "command -v sqlite3"

echo

# Network Configuration Tests
echo -e "${YELLOW}🌐 Network Configuration${NC}"
echo "─────────────────────────────────"

run_test "IP forwarding enabled" "[ \$(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]"
run_test "IKE port (500) accessible" "sudo netstat -tulpn | grep ':500 '"
run_test "NAT-T port (4500) accessible" "sudo netstat -tulpn | grep ':4500 '"

echo

# StrongSwan Configuration Tests
echo -e "${YELLOW}🔐 StrongSwan Configuration${NC}"
echo "─────────────────────────────────"

run_test "StrongSwan service active" "systemctl is-active strongswan"
run_test "IPSec configuration exists" "[ -f /etc/ipsec.conf ]"
run_test "IPSec secrets exists" "[ -f /etc/ipsec.secrets ]"
run_test "Server certificate exists" "[ -f /etc/ipsec.d/certs/server-cert.pem ]"
run_test "Server private key exists" "[ -f /etc/ipsec.d/private/server-key.pem ]"
run_test "CA certificate exists" "[ -f /etc/ipsec.d/cacerts/ca-cert.pem ]"

echo

# Python Environment Tests
echo -e "${YELLOW}🐍 Python Environment${NC}"
echo "─────────────────────────────────"

run_test "Virtual environment exists" "[ -d $PROJECT_ROOT/venv ]"
run_test "OTP server module exists" "[ -f $PROJECT_ROOT/server/otp_auth/otp_server.py ]"

if [ -d "$PROJECT_ROOT/venv" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
    run_test "PyOTP library installed" "python -c 'import pyotp'"
    run_test "QRCode library installed" "python -c 'import qrcode'"
    run_test "Flask library installed" "python -c 'import flask'"
fi

echo

# Database Tests
echo -e "${YELLOW}🗄️  Database Configuration${NC}"
echo "─────────────────────────────────"

run_test "OTP auth directory exists" "[ -d $PROJECT_ROOT/server/otp_auth ]"
run_test "Log directory exists" "[ -d $PROJECT_ROOT/server/logs ]"

# Test database creation
if [ -d "$PROJECT_ROOT/venv" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
    cd "$PROJECT_ROOT/server/otp_auth"
    
    python3 -c "
from otp_server import OTPAuthenticator
import sqlite3
try:
    auth = OTPAuthenticator(db_path='test_db.db')
    conn = sqlite3.connect('test_db.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM sqlite_master WHERE type=\"table\"')
    tables = cursor.fetchall()
    conn.close()
    import os
    os.remove('test_db.db')
    exit(0 if len(tables) >= 2 else 1)
except Exception as e:
    exit(1)
" >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} Database schema creation"
        echo -e "  ${GREEN}✅ PASS${NC}"
    else
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} Database schema creation"
        echo -e "  ${RED}❌ FAIL${NC}"
    fi
fi

echo

# Web Dashboard Tests
echo -e "${YELLOW}🌐 Web Dashboard${NC}"
echo "─────────────────────────────────"

run_test "Dashboard directory exists" "[ -d $PROJECT_ROOT/web_dashboard ]"
run_test "Flask app exists" "[ -f $PROJECT_ROOT/web_dashboard/app.py ]"

# Test if dashboard service is configured
if [ -f /etc/systemd/system/secureconnect-dashboard.service ]; then
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} Dashboard systemd service configured"
    echo -e "  ${GREEN}✅ PASS${NC}"
else
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} Dashboard systemd service configured"
    echo -e "  ${YELLOW}⚠️  OPTIONAL${NC} (can run manually)"
fi

echo

# Client Scripts Tests
echo -e "${YELLOW}📱 Client Scripts${NC}"
echo "─────────────────────────────────"

run_test "Linux client script exists" "[ -f $PROJECT_ROOT/client/scripts/connect.sh ]"
run_test "Windows client script exists" "[ -f $PROJECT_ROOT/client/scripts/connect.bat ]"
run_test "Linux script is executable" "[ -x $PROJECT_ROOT/client/scripts/connect.sh ]"

echo

# Security Tests
echo -e "${YELLOW}🛡️  Security Configuration${NC}"
echo "─────────────────────────────────"

run_test "IPSec secrets proper permissions" "[ \$(stat -c %a /etc/ipsec.secrets) = '600' ]"
run_test "Server key proper permissions" "[ \$(stat -c %a /etc/ipsec.d/private/server-key.pem) = '600' ]"

# Check firewall rules
if iptables -L | grep -q "500"; then
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} Firewall rules configured"
    echo -e "  ${GREEN}✅ PASS${NC}"
else
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} Firewall rules configured"
    echo -e "  ${YELLOW}⚠️  WARNING${NC} (firewall may need configuration)"
fi

echo

# Final Results
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  Verification Results${NC}"
echo -e "${BLUE}=================================================${NC}"
echo
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC} / $TESTS_TOTAL"
echo

if [ $TESTS_PASSED -eq $TESTS_TOTAL ]; then
    echo -e "${GREEN}🎉 All tests passed! Your SecureConnect VPN is ready to use.${NC}"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Create VPN users: cd server/otp_auth && python3 otp_cli.py"
    echo "2. Start dashboard: python3 web_dashboard/app.py"
    echo "3. Connect clients: ./client/scripts/connect.sh"
    echo
elif [ $TESTS_PASSED -gt $((TESTS_TOTAL * 2 / 3)) ]; then
    echo -e "${YELLOW}⚠️  Most tests passed, but some issues were found.${NC}"
    echo -e "${YELLOW}Your VPN may work but could have some limitations.${NC}"
    echo
    echo -e "${BLUE}Recommendations:${NC}"
    echo "1. Review failed tests above"
    echo "2. Check the setup guide: docs/SETUP.md"
    echo "3. Run: sudo ./scripts/setup.sh"
    echo
else
    echo -e "${RED}❌ Multiple tests failed. Setup is incomplete.${NC}"
    echo
    echo -e "${BLUE}Recommended actions:${NC}"
    echo "1. Run the setup script: sudo ./scripts/setup.sh"
    echo "2. Check system requirements"
    echo "3. Review the setup guide: docs/SETUP.md"
    echo "4. Check logs for errors"
    echo
fi

# Show system information
echo -e "${BLUE}System Information:${NC}"
echo "─────────────────────"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
echo "Kernel: $(uname -r)"
echo "Python: $(python3 --version)"

if command -v ipsec >/dev/null 2>&1; then
    echo "StrongSwan: $(ipsec --version | head -1)"
fi

echo "Server IP: $(hostname -I | awk '{print $1}')"
echo

if [ $TESTS_PASSED -eq $TESTS_TOTAL ]; then
    echo -e "${GREEN}Your VPN server is accessible at: http://$(hostname -I | awk '{print $1}'):5000${NC}"
    echo -e "${GREEN}Default dashboard login: admin / admin123${NC}"
    echo -e "${YELLOW}Remember to change the default password!${NC}"
fi

echo
echo "For detailed setup instructions, see: QUICK_START.md"
echo "For troubleshooting help, see: docs/SETUP.md"
