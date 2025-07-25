#!/bin/bash

# SecureConnect VPN Client Connection Script
# This script handles the complete VPN connection process including OTP authentication

set -e  # Exit on any error

# Configuration
VPN_SERVER="your-vpn-server.com"          # Replace with your server address
VPN_USER=""                               # Will be prompted
CONFIG_DIR="$HOME/.secureconnect"
LOG_FILE="$CONFIG_DIR/client.log"
PID_FILE="$CONFIG_DIR/strongswan.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    log "ERROR: $1"
    exit 1
}

# Success message
success() {
    echo -e "${GREEN}✅ $1${NC}"
    log "SUCCESS: $1"
}

# Warning message
warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
    log "WARNING: $1"
}

# Info message
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
    log "INFO: $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error_exit "This script should not be run as root for security reasons"
    fi
}

# Check dependencies
check_dependencies() {
    local deps=("strongswan" "python3" "curl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error_exit "Missing dependencies: ${missing[*]}. Please install them first."
    fi
}

# Setup configuration directory
setup_config_dir() {
    if [[ ! -d "$CONFIG_DIR" ]]; then
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        info "Created configuration directory: $CONFIG_DIR"
    fi
}

# Get user credentials
get_credentials() {
    if [[ -z "$VPN_USER" ]]; then
        read -p "Enter your VPN username: " VPN_USER
    fi
    
    if [[ -z "$VPN_USER" ]]; then
        error_exit "Username cannot be empty"
    fi
    
    # Get password securely
    read -s -p "Enter your password: " VPN_PASSWORD
    echo
    
    if [[ -z "$VPN_PASSWORD" ]]; then
        error_exit "Password cannot be empty"
    fi
}

# Get OTP code
get_otp() {
    echo
    info "Two-factor authentication required"
    read -p "Enter your 6-digit OTP code: " OTP_CODE
    
    if [[ ! "$OTP_CODE" =~ ^[0-9]{6}$ ]]; then
        error_exit "OTP code must be exactly 6 digits"
    fi
}

# Authenticate with OTP server
authenticate_otp() {
    info "Authenticating with OTP server..."
    
    # Create authentication request
    local auth_data=$(cat <<EOF
{
    "username": "$VPN_USER",
    "password": "$VPN_PASSWORD",
    "otp_code": "$OTP_CODE"
}
EOF
)
    
    # Send authentication request to OTP server
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$auth_data" \
        "http://$VPN_SERVER:5000/api/authenticate" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        error_exit "Failed to connect to authentication server"
    fi
    
    # Parse response (simple check for success)
    if echo "$response" | grep -q '"success":true'; then
        success "OTP authentication successful"
        return 0
    else
        local error_msg=$(echo "$response" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
        error_exit "Authentication failed: ${error_msg:-Unknown error}"
    fi
}

# Generate StrongSwan client configuration
generate_client_config() {
    local config_file="$CONFIG_DIR/ipsec.conf"
    
    cat > "$config_file" << EOF
# StrongSwan client configuration for SecureConnect VPN
config setup
    strictcrlpolicy=no
    uniqueids=yes

conn secureconnect
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    
    # Server configuration
    right=$VPN_SERVER
    rightid=@secureconnect.vpn
    rightsubnet=0.0.0.0/0
    
    # Client configuration
    left=%defaultroute
    leftid=$VPN_USER@secureconnect.vpn
    leftsourceip=%config
    
    # Authentication
    authby=psk
    
    # Encryption
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256-modp2048!
    
    # Connection behavior
    auto=start
    closeaction=restart
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    
    # Rekeying
    keylife=1h
    rekeymargin=3m
    keyingtries=3
EOF
    
    chmod 600 "$config_file"
    info "Generated client configuration: $config_file"
}

# Generate secrets file
generate_secrets() {
    local secrets_file="$CONFIG_DIR/ipsec.secrets"
    
    cat > "$secrets_file" << EOF
# SecureConnect VPN client secrets
$VPN_USER@secureconnect.vpn %any : PSK "SecureConnect2024!TestKey"
EOF
    
    chmod 600 "$secrets_file"
    info "Generated secrets file: $secrets_file"
}

# Start VPN connection
start_vpn() {
    info "Starting VPN connection..."
    
    # Copy configuration to system location (requires sudo)
    sudo cp "$CONFIG_DIR/ipsec.conf" /etc/ipsec.conf
    sudo cp "$CONFIG_DIR/ipsec.secrets" /etc/ipsec.secrets
    sudo chmod 644 /etc/ipsec.conf
    sudo chmod 600 /etc/ipsec.secrets
    
    # Start StrongSwan
    sudo systemctl start strongswan
    
    # Wait a moment for connection to establish
    sleep 5
    
    # Check connection status
    if sudo ipsec status | grep -q "ESTABLISHED"; then
        success "VPN connection established successfully!"
        
        # Get assigned IP
        local vpn_ip=$(ip addr show | grep -E '10\.10\.10\.' | awk '{print $2}' | cut -d'/' -f1)
        if [[ -n "$vpn_ip" ]]; then
            success "Assigned VPN IP: $vpn_ip"
        fi
        
        # Test connectivity
        info "Testing connectivity..."
        if ping -c 3 8.8.8.8 &>/dev/null; then
            success "Internet connectivity confirmed"
        else
            warning "Internet connectivity test failed"
        fi
        
        # Store PID for later cleanup
        echo $$ > "$PID_FILE"
        
    else
        error_exit "Failed to establish VPN connection"
    fi
}

# Check connection status
check_status() {
    if sudo ipsec status | grep -q "ESTABLISHED"; then
        success "VPN is connected"
        
        # Show detailed status
        echo
        info "Connection details:"
        sudo ipsec status
        
        # Show assigned IP
        local vpn_ip=$(ip addr show | grep -E '10\.10\.10\.' | awk '{print $2}' | cut -d'/' -f1)
        if [[ -n "$vpn_ip" ]]; then
            echo "VPN IP: $vpn_ip"
        fi
        
        return 0
    else
        warning "VPN is not connected"
        return 1
    fi
}

# Disconnect VPN
disconnect_vpn() {
    info "Disconnecting VPN..."
    
    # Stop StrongSwan
    sudo systemctl stop strongswan
    
    # Clean up routes (optional)
    sudo ip route del default 2>/dev/null || true
    
    # Remove PID file
    rm -f "$PID_FILE"
    
    success "VPN disconnected"
}

# Show help
show_help() {
    echo "SecureConnect VPN Client"
    echo
    echo "Usage: $0 [command]"
    echo
    echo "Commands:"
    echo "  connect     Connect to VPN (default)"
    echo "  disconnect  Disconnect from VPN"
    echo "  status      Show connection status"
    echo "  help        Show this help message"
    echo
    echo "Environment variables:"
    echo "  VPN_SERVER  VPN server address (default: your-vpn-server.com)"
    echo "  VPN_USER    VPN username (will be prompted if not set)"
}

# Main function
main() {
    local command="${1:-connect}"
    
    case "$command" in
        "connect")
            check_root
            check_dependencies
            setup_config_dir
            
            echo "=== SecureConnect VPN Client ==="
            echo
            
            get_credentials
            get_otp
            authenticate_otp
            
            generate_client_config
            generate_secrets
            start_vpn
            ;;
            
        "disconnect")
            disconnect_vpn
            ;;
            
        "status")
            check_status
            ;;
            
        "help"|"-h"|"--help")
            show_help
            ;;
            
        *)
            error_exit "Unknown command: $command. Use 'help' for usage information."
            ;;
    esac
}

# Handle script interruption
trap 'echo; warning "Script interrupted"; exit 1' INT

# Run main function
main "$@"
