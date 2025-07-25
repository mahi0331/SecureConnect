#!/bin/bash

# SecureConnect VPN Setup Script
# This script sets up the complete VPN environment on Ubuntu/Debian systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="/var/log/secureconnect-setup.log"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | sudo tee -a "$LOG_FILE"
    echo -e "${BLUE}[INFO]${NC} $1"
}

error_exit() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" | sudo tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: $1" | sudo tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: $1" | sudo tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        error_exit "Cannot detect Linux distribution"
    fi
    
    log "Detected distribution: $DISTRO $VERSION"
}

# Update system packages
update_system() {
    log "Updating system packages..."
    
    case $DISTRO in
        ubuntu|debian)
            apt update && apt upgrade -y
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf update -y
            else
                yum update -y
            fi
            ;;
        *)
            warning "Unsupported distribution: $DISTRO"
            ;;
    esac
    
    success "System packages updated"
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    
    local packages
    case $DISTRO in
        ubuntu|debian)
            packages=(
                "strongswan"
                "strongswan-pki"
                "libcharon-extra-plugins"
                "python3"
                "python3-pip"
                "python3-venv"
                "curl"
                "wget"
                "openssl"
                "iptables"
                "iptables-persistent"
                "net-tools"
                "tcpdump"
                "wireshark-common"
                "sqlite3"
            )
            
            apt install -y "${packages[@]}"
            ;;
            
        centos|rhel|fedora)
            packages=(
                "strongswan"
                "python3"
                "python3-pip"
                "curl"
                "wget"
                "openssl"
                "iptables"
                "net-tools"
                "tcpdump"
                "wireshark"
                "sqlite"
            )
            
            if command -v dnf &> /dev/null; then
                dnf install -y "${packages[@]}"
            else
                yum install -y "${packages[@]}"
            fi
            ;;
            
        *)
            error_exit "Unsupported distribution for automatic package installation"
            ;;
    esac
    
    success "Required packages installed"
}

# Setup Python virtual environment
setup_python_env() {
    log "Setting up Python virtual environment..."
    
    local venv_dir="$PROJECT_ROOT/venv"
    
    # Create virtual environment
    python3 -m venv "$venv_dir"
    
    # Activate virtual environment
    source "$venv_dir/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python requirements
    if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
        pip install -r "$PROJECT_ROOT/requirements.txt"
    else
        # Install basic requirements manually
        pip install pyotp qrcode[pil] flask flask-cors cryptography pyyaml python-dotenv psutil
    fi
    
    success "Python environment configured"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall rules..."
    
    # Allow SSH (important!)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow IKE (port 500)
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    
    # Allow NAT-T (port 4500)
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    
    # Allow ESP
    iptables -A INPUT -p esp -j ACCEPT
    
    # Allow web dashboard (port 5000)
    iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
    
    # Allow forwarding for VPN traffic
    iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
    iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT
    
    # NAT for VPN clients
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4
    fi
    
    success "Firewall configured"
}

# Enable IP forwarding
enable_ip_forwarding() {
    log "Enabling IP forwarding..."
    
    # Enable in current session
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Make permanent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    sysctl -p
    
    success "IP forwarding enabled"
}

# Generate certificates
generate_certificates() {
    log "Generating PKI certificates..."
    
    local pki_dir="$PROJECT_ROOT/server/strongswan/pki"
    mkdir -p "$pki_dir"
    cd "$pki_dir"
    
    # Generate CA private key
    ipsec pki --gen --type rsa --size 4096 --outform pem > ca-key.pem
    
    # Generate CA certificate
    ipsec pki --self --ca --lifetime 3650 --in ca-key.pem \
        --type rsa --dn "CN=SecureConnect VPN CA" \
        --outform pem > ca-cert.pem
    
    # Generate server private key
    ipsec pki --gen --type rsa --size 4096 --outform pem > server-key.pem
    
    # Generate server certificate
    ipsec pki --pub --in server-key.pem --type rsa | \
    ipsec pki --issue --lifetime 1825 --cacert ca-cert.pem \
        --cakey ca-key.pem --dn "CN=secureconnect.vpn" \
        --san "secureconnect.vpn" --flag serverAuth \
        --flag ikeIntermediate --outform pem > server-cert.pem
    
    # Set proper permissions
    chmod 600 *-key.pem
    chmod 644 *-cert.pem
    
    # Copy certificates to system location
    cp ca-cert.pem /etc/ipsec.d/cacerts/
    cp server-cert.pem /etc/ipsec.d/certs/
    cp server-key.pem /etc/ipsec.d/private/
    
    success "PKI certificates generated"
}

# Configure StrongSwan
configure_strongswan() {
    log "Configuring StrongSwan..."
    
    # Backup original configurations
    cp /etc/ipsec.conf /etc/ipsec.conf.backup 2>/dev/null || true
    cp /etc/ipsec.secrets /etc/ipsec.secrets.backup 2>/dev/null || true
    
    # Copy our configurations
    cp "$PROJECT_ROOT/server/strongswan/ipsec.conf" /etc/ipsec.conf
    cp "$PROJECT_ROOT/server/strongswan/ipsec.secrets" /etc/ipsec.secrets
    cp "$PROJECT_ROOT/server/strongswan/strongswan.conf" /etc/strongswan.d/charon.conf
    
    # Set proper permissions
    chmod 644 /etc/ipsec.conf
    chmod 600 /etc/ipsec.secrets
    chmod 644 /etc/strongswan.d/charon.conf
    
    # Enable and restart StrongSwan
    systemctl enable strongswan
    systemctl restart strongswan
    
    success "StrongSwan configured and started"
}

# Create system users and directories
setup_directories() {
    log "Setting up directories and permissions..."
    
    # Create log directory
    mkdir -p "$PROJECT_ROOT/server/logs"
    chmod 755 "$PROJECT_ROOT/server/logs"
    
    # Create database directory
    mkdir -p "$PROJECT_ROOT/server/otp_auth"
    chmod 755 "$PROJECT_ROOT/server/otp_auth"
    
    # Create client config directory
    mkdir -p "$PROJECT_ROOT/client/configs"
    chmod 755 "$PROJECT_ROOT/client/configs"
    
    # Make scripts executable
    chmod +x "$PROJECT_ROOT"/scripts/*.sh
    chmod +x "$PROJECT_ROOT"/client/scripts/*.sh
    
    success "Directories and permissions configured"
}

# Create systemd service for web dashboard
create_dashboard_service() {
    log "Creating systemd service for web dashboard..."
    
    cat > /etc/systemd/system/secureconnect-dashboard.service << EOF
[Unit]
Description=SecureConnect VPN Dashboard
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=$PROJECT_ROOT/web_dashboard
Environment=PATH=$PROJECT_ROOT/venv/bin
ExecStart=$PROJECT_ROOT/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Enable the service
    systemctl daemon-reload
    systemctl enable secureconnect-dashboard
    
    success "Dashboard service created"
}

# Initialize OTP database
initialize_otp_database() {
    log "Initializing OTP authentication database..."
    
    cd "$PROJECT_ROOT/server/otp_auth"
    
    # Activate virtual environment
    source "$PROJECT_ROOT/venv/bin/activate"
    
    # Initialize database by running the OTP server
    python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
print('Database initialized successfully')
"
    
    success "OTP database initialized"
}

# Display setup completion information
show_completion_info() {
    echo
    echo "================================================="
    echo "  SecureConnect VPN Setup Complete!"
    echo "================================================="
    echo
    echo "🎉 Installation Summary:"
    echo "  ✅ StrongSwan IPSec VPN server installed and configured"
    echo "  ✅ OTP authentication system set up"
    echo "  ✅ Web dashboard configured"
    echo "  ✅ Firewall rules applied"
    echo "  ✅ PKI certificates generated"
    echo
    echo "🔧 Next Steps:"
    echo "  1. Start the dashboard: systemctl start secureconnect-dashboard"
    echo "  2. Access dashboard: http://$(hostname -I | awk '{print $1}'):5000"
    echo "  3. Create VPN users: cd $PROJECT_ROOT/server/otp_auth && python3 otp_cli.py"
    echo "  4. Configure clients using the generated certificates"
    echo
    echo "📁 Important Files:"
    echo "  • Server config: /etc/ipsec.conf"
    echo "  • Certificates: $PROJECT_ROOT/server/strongswan/pki/"
    echo "  • Logs: $PROJECT_ROOT/server/logs/"
    echo "  • User database: $PROJECT_ROOT/server/otp_auth/users.db"
    echo
    echo "🔐 Security Notes:"
    echo "  • Change default dashboard password (admin/admin123)"
    echo "  • Update PSK in /etc/ipsec.secrets"
    echo "  • Regularly monitor logs for security events"
    echo "  • Consider certificate-based authentication for production"
    echo
    echo "📖 Documentation:"
    echo "  • Setup guide: $PROJECT_ROOT/docs/SETUP.md"
    echo "  • User manual: $PROJECT_ROOT/docs/USER_GUIDE.md"
    echo
}

# Main installation function
main() {
    echo "================================================="
    echo "  SecureConnect VPN Setup Script"
    echo "  Educational IPSec VPN with OTP Authentication"
    echo "================================================="
    echo
    
    check_root
    detect_distro
    
    log "Starting SecureConnect VPN installation..."
    
    # Installation steps
    update_system
    install_packages
    setup_python_env
    enable_ip_forwarding
    configure_firewall
    generate_certificates
    configure_strongswan
    setup_directories
    create_dashboard_service
    initialize_otp_database
    
    success "SecureConnect VPN installation completed successfully!"
    show_completion_info
}

# Handle script interruption
trap 'echo; error_exit "Installation interrupted"' INT

# Run main function
main "$@"
