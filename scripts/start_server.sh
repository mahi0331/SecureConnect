#!/bin/bash

# SecureConnect VPN Server Start Script
# This script starts all VPN server components

set -e

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$PROJECT_ROOT/server/logs/server.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    echo -e "${BLUE}[INFO]${NC} $1"
}

error_exit() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check if StrongSwan is installed
    if ! command -v ipsec &> /dev/null; then
        error_exit "StrongSwan is not installed. Run setup.sh first."
    fi
    
    # Check if Python virtual environment exists
    if [[ ! -d "$PROJECT_ROOT/venv" ]]; then
        error_exit "Python virtual environment not found. Run setup.sh first."
    fi
    
    # Check if configuration files exist
    if [[ ! -f "/etc/ipsec.conf" ]]; then
        error_exit "StrongSwan configuration not found. Run setup.sh first."
    fi
    
    # Check if certificates exist
    if [[ ! -f "/etc/ipsec.d/certs/server-cert.pem" ]]; then
        error_exit "Server certificates not found. Run setup.sh first."
    fi
    
    success "System requirements check passed"
}

# Start StrongSwan service
start_strongswan() {
    log "Starting StrongSwan IPSec service..."
    
    # Enable IP forwarding (in case it's not enabled)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Start StrongSwan
    systemctl start strongswan
    
    # Check if service started successfully
    if systemctl is-active --quiet strongswan; then
        success "StrongSwan service started successfully"
    else
        error_exit "Failed to start StrongSwan service"
    fi
    
    # Load connection configurations
    ipsec reload
    
    # Show status
    log "StrongSwan status:"
    ipsec status
}

# Start web dashboard
start_dashboard() {
    log "Starting web dashboard..."
    
    # Start the dashboard service
    systemctl start secureconnect-dashboard
    
    # Check if service started successfully
    sleep 3
    if systemctl is-active --quiet secureconnect-dashboard; then
        success "Web dashboard started successfully"
        
        # Get server IP address
        local server_ip=$(hostname -I | awk '{print $1}')
        echo
        echo "🌐 Dashboard URL: http://$server_ip:5000"
        echo "🔑 Default credentials: admin / admin123"
        echo
    else
        warning "Web dashboard failed to start. Check logs:"
        journalctl -u secureconnect-dashboard --no-pager -n 20
    fi
}

# Configure firewall rules
configure_firewall() {
    log "Configuring firewall rules..."
    
    # Check if iptables rules are already configured
    if iptables -L | grep -q "500"; then
        log "Firewall rules appear to be already configured"
        return 0
    fi
    
    # Apply firewall rules
    "$PROJECT_ROOT/scripts/configure_firewall.sh"
    
    success "Firewall rules configured"
}

# Create initial admin user
create_admin_user() {
    log "Checking for admin user..."
    
    cd "$PROJECT_ROOT/server/otp_auth"
    source "$PROJECT_ROOT/venv/bin/activate"
    
    # Check if admin user already exists
    if python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
import sqlite3
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('SELECT username FROM users WHERE username = ?', ('admin',))
exists = cursor.fetchone() is not None
conn.close()
print('EXISTS' if exists else 'NOT_EXISTS')
" | grep -q "EXISTS"; then
        log "Admin user already exists"
        return 0
    fi
    
    # Create admin user
    log "Creating default admin user..."
    python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
success, result = auth.create_user('admin', 'admin@secureconnect.vpn', 'SecureAdmin2024!')
if success:
    print(f'Admin user created successfully')
    print(f'TOTP Secret: {result}')
    
    # Generate QR code
    qr_code = auth.generate_qr_code('admin', result)
    if qr_code:
        import base64
        with open('admin_qr.png', 'wb') as f:
            f.write(base64.b64decode(qr_code))
        print('QR code saved as admin_qr.png')
else:
    print(f'Failed to create admin user: {result}')
"
    
    success "Admin user created. Check admin_qr.png for TOTP setup."
}

# Monitor services
monitor_services() {
    log "Monitoring service status..."
    
    echo
    echo "=== Service Status ==="
    
    # StrongSwan status
    echo "StrongSwan:"
    if systemctl is-active --quiet strongswan; then
        echo "  ✅ Running"
        ipsec status | head -5
    else
        echo "  ❌ Stopped"
    fi
    
    echo
    
    # Dashboard status
    echo "Web Dashboard:"
    if systemctl is-active --quiet secureconnect-dashboard; then
        echo "  ✅ Running"
        local server_ip=$(hostname -I | awk '{print $1}')
        echo "  🌐 URL: http://$server_ip:5000"
    else
        echo "  ❌ Stopped"
    fi
    
    echo
    
    # Network interfaces
    echo "Network Interfaces:"
    ip addr show | grep -E "inet [0-9]" | awk '{print "  " $NF ": " $2}'
    
    echo
    
    # Active connections
    echo "Active VPN Connections:"
    if ipsec status | grep -q "ESTABLISHED"; then
        ipsec status | grep "ESTABLISHED"
    else
        echo "  No active connections"
    fi
    
    echo
}

# Show server information
show_server_info() {
    local server_ip=$(hostname -I | awk '{print $1}')
    
    echo
    echo "================================================="
    echo "  SecureConnect VPN Server Started"
    echo "================================================="
    echo
    echo "🖥️  Server Information:"
    echo "  • Server IP: $server_ip"
    echo "  • VPN Client Pool: 10.10.10.0/24"
    echo "  • IKE Port: 500/udp"
    echo "  • NAT-T Port: 4500/udp"
    echo
    echo "🌐 Web Dashboard:"
    echo "  • URL: http://$server_ip:5000"
    echo "  • Username: admin"
    echo "  • Password: admin123 (CHANGE THIS!)"
    echo
    echo "📱 Client Configuration:"
    echo "  • Server: $server_ip"
    echo "  • Auth Method: PSK + OTP"
    echo "  • Encryption: AES-256"
    echo
    echo "🔧 Management Commands:"
    echo "  • Create user: cd $PROJECT_ROOT/server/otp_auth && python3 otp_cli.py"
    echo "  • View logs: tail -f $PROJECT_ROOT/server/logs/server.log"
    echo "  • Stop server: sudo systemctl stop strongswan secureconnect-dashboard"
    echo
    echo "📊 Monitor Status:"
    echo "  • Server status: sudo $PROJECT_ROOT/scripts/server_status.sh"
    echo "  • Connection logs: sudo journalctl -u strongswan -f"
    echo
}

# Main function
main() {
    echo "================================================="
    echo "  SecureConnect VPN Server Startup"
    echo "================================================="
    echo
    
    check_root
    check_requirements
    
    log "Starting SecureConnect VPN server components..."
    
    # Start services
    configure_firewall
    start_strongswan
    start_dashboard
    create_admin_user
    
    # Show status
    monitor_services
    show_server_info
    
    success "SecureConnect VPN server started successfully!"
    
    echo "Press Ctrl+C to stop monitoring, or run:"
    echo "  sudo $0 monitor"
    echo
    
    # If monitor argument provided, keep monitoring
    if [[ "$1" == "monitor" ]]; then
        log "Entering monitoring mode..."
        while true; do
            sleep 30
            monitor_services
        done
    fi
}

# Handle script interruption
trap 'echo; log "Server startup script terminated"; exit 0' INT

# Run main function
main "$@"
