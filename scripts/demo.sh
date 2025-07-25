#!/bin/bash

# SecureConnect VPN - Project Demonstration Script
# This script demonstrates the key features of the SecureConnect VPN project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_LOG="$PROJECT_ROOT/demo.log"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$DEMO_LOG"
}

# Display functions
title() {
    echo -e "${PURPLE}=================================================${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}=================================================${NC}"
    echo
    log "DEMO: $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log "INFO: $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log "SUCCESS: $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "WARNING: $1"
}

demo_step() {
    echo -e "${CYAN}>>> $1${NC}"
    log "STEP: $1"
}

press_enter() {
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read
}

# Introduction
show_introduction() {
    clear
    title "SecureConnect VPN - Educational Project Demonstration"
    
    cat << EOF
🎓 Welcome to SecureConnect VPN!
   An educational VPN project demonstrating:
   
   🔐 IPSec VPN with StrongSwan
   🔑 Two-Factor Authentication (OTP)
   🌐 Web-based Management Dashboard
   📊 Real-time Monitoring and Logging
   🛡️  Security Best Practices

📚 This demonstration covers:
   1. Project Architecture Overview
   2. OTP Authentication System
   3. VPN Server Configuration
   4. Client Connection Demo
   5. Web Dashboard Features
   6. Security Monitoring
   7. Educational Value

EOF
    press_enter
}

# Project overview
show_project_overview() {
    title "Project Architecture Overview"
    
    cat << 'EOF'
   Network Architecture:
   
   ┌─────────────┐         ┌──────────────────────┐
   │             │  IPSec  │                      │
   │   Client    ├────────►│    VPN Gateway       │
   │  (Laptop)   │ Tunnel  │  (Linux + StrongSwan)│
   │             │         │                      │
   └─────────────┘         └──────────────────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │  OTP Auth System     │
                           │  (Python + SQLite)   │
                           └──────────────────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │  Web Dashboard       │
                           │  (Flask + HTML/JS)   │
                           └──────────────────────┘

EOF

    info "Key Components:"
    echo "  • StrongSwan IPSec VPN Server"
    echo "  • Python-based OTP Authentication"
    echo "  • SQLite User Database"
    echo "  • Flask Web Dashboard"
    echo "  • Client Scripts (Linux/Windows)"
    echo "  • PKI Certificate Infrastructure"
    echo
    
    press_enter
}

# Demonstrate OTP system
demo_otp_system() {
    title "OTP Authentication System Demonstration"
    
    info "The OTP system provides two-factor authentication using TOTP (Time-based One-Time Passwords)"
    echo
    
    # Check if virtual environment exists
    if [[ ! -d "$PROJECT_ROOT/venv" ]]; then
        warning "Python virtual environment not found. Setting up demo environment..."
        python3 -m venv "$PROJECT_ROOT/demo_venv"
        source "$PROJECT_ROOT/demo_venv/bin/activate"
        pip install pyotp qrcode[pil] >/dev/null 2>&1
    else
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    demo_step "1. Creating a demo user account"
    
    cd "$PROJECT_ROOT/server/otp_auth"
    
    # Create demo user
    python3 << 'EOF'
import sys
import os
sys.path.append('.')

try:
    from otp_server import OTPAuthenticator
    import pyotp
    import base64
    
    print("Initializing OTP authenticator...")
    auth = OTPAuthenticator(db_path="demo_users.db")
    
    # Create demo user
    username = "demo_user"
    email = "demo@secureconnect.vpn"
    password = "SecureDemo123!"
    
    print(f"Creating user: {username}")
    success, result = auth.create_user(username, email, password)
    
    if success:
        print(f"✅ User created successfully!")
        print(f"   Username: {username}")
        print(f"   Email: {email}")
        print(f"   TOTP Secret: {result}")
        
        # Generate current OTP
        totp = pyotp.TOTP(result)
        current_otp = totp.now()
        print(f"   Current OTP: {current_otp}")
        
        # Generate QR code
        qr_code = auth.generate_qr_code(username, result)
        if qr_code:
            with open("demo_qr.png", "wb") as f:
                f.write(base64.b64decode(qr_code))
            print(f"   QR Code saved: demo_qr.png")
        
        print("\n🔐 Testing OTP verification...")
        verified, message = auth.verify_otp(username, current_otp, password)
        print(f"   Verification result: {verified} - {message}")
        
    else:
        print(f"❌ Failed to create user: {result}")
        
except ImportError as e:
    print(f"Import error: {e}")
    print("Installing required packages...")
    os.system("pip install pyotp qrcode[pil]")
    print("Please run the demo again.")
EOF
    
    echo
    press_enter
}

# Demonstrate configuration
demo_configuration() {
    title "VPN Server Configuration"
    
    info "Showing key configuration files and their purposes"
    echo
    
    demo_step "1. StrongSwan main configuration (ipsec.conf)"
    echo "Location: /etc/ipsec.conf"
    echo "Purpose: Defines VPN connection parameters"
    echo
    cat "$PROJECT_ROOT/server/strongswan/ipsec.conf" | head -20
    echo "... (truncated for demo)"
    echo
    
    demo_step "2. Authentication secrets (ipsec.secrets)"
    echo "Location: /etc/ipsec.secrets"
    echo "Purpose: Contains authentication credentials"
    echo "⚠️  This file contains sensitive information and should be protected"
    echo
    
    demo_step "3. Firewall configuration"
    echo "Required ports:"
    echo "  • 500/UDP  - IKE (Internet Key Exchange)"
    echo "  • 4500/UDP - NAT-T (NAT Traversal)"
    echo "  • 5000/TCP - Web Dashboard (optional)"
    echo
    
    press_enter
}

# Demonstrate web dashboard
demo_web_dashboard() {
    title "Web Dashboard Features"
    
    info "The web dashboard provides real-time monitoring and management"
    echo
    
    demo_step "1. Dashboard Features"
    echo "  • Real-time connection monitoring"
    echo "  • User authentication logs"
    echo "  • System statistics"
    echo "  • User management interface"
    echo "  • Security event tracking"
    echo
    
    demo_step "2. Starting the dashboard (simulation)"
    echo "Command: python3 web_dashboard/app.py"
    echo "Access URL: http://localhost:5000"
    echo "Default login: admin / admin123"
    echo
    
    demo_step "3. API Endpoints"
    echo "  • GET  /api/stats    - Get system statistics"
    echo "  • GET  /api/logs     - Get authentication logs"
    echo "  • GET  /api/users    - Get user information"
    echo "  • POST /api/authenticate - VPN client authentication"
    echo
    
    press_enter
}

# Demonstrate security features
demo_security_features() {
    title "Security Features and Best Practices"
    
    info "SecureConnect implements multiple layers of security"
    echo
    
    demo_step "1. Encryption"
    echo "  • AES-256 encryption for data"
    echo "  • SHA-256 for integrity"
    echo "  • Diffie-Hellman key exchange"
    echo "  • Perfect Forward Secrecy"
    echo
    
    demo_step "2. Authentication"
    echo "  • Multi-factor authentication (password + OTP)"
    echo "  • Certificate-based authentication option"
    echo "  • Account lockout after failed attempts"
    echo "  • Session timeout controls"
    echo
    
    demo_step "3. Monitoring and Logging"
    echo "  • Comprehensive authentication logging"
    echo "  • Connection attempt tracking"
    echo "  • Failed login detection"
    echo "  • Real-time security alerts"
    echo
    
    demo_step "4. Network Security"
    echo "  • Firewall rule templates"
    echo "  • NAT traversal support"
    echo "  • Dead peer detection"
    echo "  • IP forwarding controls"
    echo
    
    press_enter
}

# Show educational value
show_educational_value() {
    title "Educational Value and Learning Objectives"
    
    info "This project teaches fundamental network security concepts"
    echo
    
    demo_step "1. Core Technologies Learned"
    echo "  🔐 IPSec Protocol Suite"
    echo "     - Internet Key Exchange (IKE)"
    echo "     - Encapsulating Security Payload (ESP)"
    echo "     - Security Associations (SA)"
    echo
    echo "  🔑 Cryptographic Concepts"
    echo "     - Symmetric and asymmetric encryption"
    echo "     - Digital certificates and PKI"
    echo "     - Hash functions and integrity"
    echo
    echo "  📱 Two-Factor Authentication"
    echo "     - Time-based One-Time Passwords (TOTP)"
    echo "     - RFC 6238 implementation"
    echo "     - QR code generation"
    echo
    echo "  🌐 Network Security"
    echo "     - Virtual Private Networks"
    echo "     - NAT traversal techniques"
    echo "     - Firewall configuration"
    echo
    
    demo_step "2. Practical Skills Developed"
    echo "  • Linux system administration"
    echo "  • Python security programming"
    echo "  • Database design and management"
    echo "  • Web application development"
    echo "  • Network troubleshooting"
    echo "  • Security best practices"
    echo
    
    demo_step "3. Real-World Applications"
    echo "  • Enterprise VPN solutions"
    echo "  • Remote access security"
    echo "  • Identity and access management"
    echo "  • Security operations centers"
    echo "  • Penetration testing"
    echo
    
    press_enter
}

# Demonstrate client connection
demo_client_connection() {
    title "Client Connection Process"
    
    info "Demonstrating how clients connect to the VPN"
    echo
    
    demo_step "1. Client Authentication Flow"
    cat << 'EOF'
   Authentication Sequence:
   
   Client                    VPN Server              OTP Server
     │                          │                        │
     ├─── IKE_SA_INIT ─────────►│                        │
     │◄──── IKE_SA_INIT ────────┤                        │
     │                          │                        │
     ├─── IKE_AUTH ────────────►│                        │
     │    (Username + Password)  │─── Verify OTP ───────►│
     │                          │◄─── OTP Result ──────┤
     │◄──── IKE_AUTH ───────────┤                        │
     │    (Success/Failure)      │                        │
     │                          │                        │
     ├─── CREATE_CHILD_SA ─────►│                        │
     │◄──── CREATE_CHILD_SA ────┤                        │
     │                          │                        │
     │◄═══ Encrypted Tunnel ═══►│                        │

EOF
    
    demo_step "2. Client Scripts"
    echo "Linux/macOS: client/scripts/connect.sh"
    echo "Windows:     client/scripts/connect.bat"
    echo
    echo "Example usage:"
    echo "  ./connect.sh connect    # Connect to VPN"
    echo "  ./connect.sh status     # Check connection status"
    echo "  ./connect.sh disconnect # Disconnect from VPN"
    echo
    
    demo_step "3. Mobile Client Support"
    echo "Android: StrongSwan VPN Client"
    echo "iOS:     Built-in IKEv2 VPN"
    echo "Configuration: Server IP + Username + Password+OTP"
    echo
    
    press_enter
}

# Show project structure
show_project_structure() {
    title "Project Structure and Organization"
    
    info "Well-organized codebase for easy understanding and modification"
    echo
    
    tree "$PROJECT_ROOT" -I "venv|__pycache__|*.pyc|*.log|*.db" 2>/dev/null || {
        echo "Project structure:"
        find "$PROJECT_ROOT" -type f -name "*.py" -o -name "*.sh" -o -name "*.conf" -o -name "*.md" | \
        grep -E -v "(venv|__pycache__|\.pyc|\.log|\.db)" | \
        sort | sed 's|^'"$PROJECT_ROOT"'||' | sed 's|^/||'
    }
    
    echo
    demo_step "Key Directories"
    echo "  📁 server/          - Server-side components"
    echo "     ├── strongswan/  - VPN server configuration"
    echo "     ├── otp_auth/    - Authentication system"
    echo "     └── logs/        - Server log files"
    echo
    echo "  📁 client/          - Client-side tools"
    echo "     ├── scripts/     - Connection scripts"
    echo "     └── configs/     - Client configurations"
    echo
    echo "  📁 web_dashboard/   - Web management interface"
    echo "  📁 docs/           - Comprehensive documentation"
    echo "  📁 scripts/        - Setup and utility scripts"
    echo
    
    press_enter
}

# Performance and scalability
demo_performance() {
    title "Performance and Scalability Features"
    
    info "Designed for educational use but scalable for production"
    echo
    
    demo_step "1. Performance Optimizations"
    echo "  • Multi-threaded StrongSwan configuration"
    echo "  • Efficient database queries with indexing"
    echo "  • Connection pooling and caching"
    echo "  • Hardware acceleration support (AES-NI)"
    echo
    
    demo_step "2. Scalability Considerations"
    echo "  • Configurable client IP pools"
    echo "  • Load balancing support"
    echo "  • Database optimization options"
    echo "  • Horizontal scaling patterns"
    echo
    
    demo_step "3. Monitoring Capabilities"
    echo "  • Real-time connection statistics"
    echo "  • Performance metrics collection"
    echo "  • Resource usage monitoring"
    echo "  • Alert system for anomalies"
    echo
    
    press_enter
}

# Future enhancements
show_future_enhancements() {
    title "Future Enhancements and Extensions"
    
    info "Opportunities for further development and learning"
    echo
    
    demo_step "1. Advanced Features"
    echo "  🔧 Split tunneling support"
    echo "  🌍 Geographic load balancing"
    echo "  📊 Advanced analytics dashboard"
    echo "  🔐 Hardware security module integration"
    echo "  📱 Dedicated mobile applications"
    echo
    
    demo_step "2. Integration Possibilities"
    echo "  🏢 LDAP/Active Directory integration"
    echo "  ☁️  Cloud deployment automation"
    echo "  📡 RADIUS authentication"
    echo "  🛡️  SIEM system integration"
    echo "  🔄 Container orchestration (Docker/K8s)"
    echo
    
    demo_step "3. Educational Extensions"
    echo "  📚 Additional protocol support (OpenVPN, WireGuard)"
    echo "  🎓 Security analysis and penetration testing modules"
    echo "  📊 Traffic analysis and forensics tools"
    echo "  🏗️  Network simulation environments"
    echo
    
    press_enter
}

# Conclusion
show_conclusion() {
    title "Demonstration Complete"
    
    success "SecureConnect VPN Project Summary"
    echo
    echo "🎯 Project Achievements:"
    echo "  ✅ Fully functional IPSec VPN server"
    echo "  ✅ Secure two-factor authentication"
    echo "  ✅ Web-based management interface"
    echo "  ✅ Comprehensive documentation"
    echo "  ✅ Cross-platform client support"
    echo "  ✅ Security best practices implementation"
    echo
    
    echo "🎓 Educational Value:"
    echo "  • Hands-on experience with VPN technologies"
    echo "  • Understanding of cryptographic protocols"
    echo "  • Network security fundamentals"
    echo "  • System administration skills"
    echo "  • Software development practices"
    echo
    
    echo "🚀 Next Steps:"
    echo "  1. Run ./scripts/setup.sh to install the system"
    echo "  2. Follow docs/SETUP.md for detailed instructions"
    echo "  3. Explore docs/USER_GUIDE.md for usage examples"
    echo "  4. Review docs/SECURITY.md for best practices"
    echo "  5. Experiment with configurations and enhancements"
    echo
    
    echo "📞 Support and Resources:"
    echo "  • Documentation: ./docs/"
    echo "  • Issue tracking: GitHub repository"
    echo "  • Community: Educational forums and groups"
    echo
    
    success "Thank you for exploring SecureConnect VPN!"
    log "Demo completed successfully"
}

# Main menu
show_menu() {
    while true; do
        clear
        title "SecureConnect VPN - Interactive Demo Menu"
        
        echo "Choose a demonstration topic:"
        echo
        echo "  1) Project Overview and Architecture"
        echo "  2) OTP Authentication System"
        echo "  3) VPN Server Configuration"
        echo "  4) Web Dashboard Features"
        echo "  5) Client Connection Process"
        echo "  6) Security Features"
        echo "  7) Project Structure"
        echo "  8) Performance and Scalability"
        echo "  9) Educational Value"
        echo " 10) Future Enhancements"
        echo " 11) Run Full Demonstration"
        echo "  0) Exit"
        echo
        echo -n "Enter your choice (0-11): "
        read choice
        
        case $choice in
            1) show_project_overview ;;
            2) demo_otp_system ;;
            3) demo_configuration ;;
            4) demo_web_dashboard ;;
            5) demo_client_connection ;;
            6) demo_security_features ;;
            7) show_project_structure ;;
            8) demo_performance ;;
            9) show_educational_value ;;
            10) show_future_enhancements ;;
            11) run_full_demo ;;
            0) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice. Please try again."; sleep 2 ;;
        esac
    done
}

# Full demonstration
run_full_demo() {
    show_introduction
    show_project_overview
    demo_otp_system
    demo_configuration
    demo_web_dashboard
    demo_client_connection
    demo_security_features
    show_project_structure
    demo_performance
    show_educational_value
    show_future_enhancements
    show_conclusion
}

# Main execution
main() {
    # Create log file
    touch "$DEMO_LOG"
    log "Demo started"
    
    # Check if running in interactive mode
    if [[ "$1" == "--interactive" || "$1" == "-i" ]]; then
        show_menu
    elif [[ "$1" == "--full" || "$1" == "-f" ]]; then
        run_full_demo
    else
        echo "SecureConnect VPN - Project Demonstration"
        echo
        echo "Usage:"
        echo "  $0 --interactive    Interactive menu"
        echo "  $0 --full          Full demonstration"
        echo "  $0 --help          Show this help"
        echo
        echo "Quick start: $0 --interactive"
    fi
}

# Handle script interruption
trap 'echo; echo "Demo interrupted"; exit 0' INT

# Run main function
main "$@"
