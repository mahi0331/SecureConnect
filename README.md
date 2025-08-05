# SecureConnect VPN - Complete Enterprise Solution

A comprehensive VPN solution with StrongSwan IPSec, OTP authentication, real-time IP tracking, and full cross-platform support for Windows, mobile, and enterprise environments.

## 🚀 Key Features

### 🔐 **Enterprise Security**
- **Military-Grade Encryption**: IPSec/IKEv2 with AES-256-GCM encryption
- **Multi-Factor Authentication**: Time-based OTP (TOTP) with QR code generation
- **Certificate-based PKI**: Automated CA and client certificate management
- **Perfect Forward Secrecy**: New encryption keys for each session

### 🌐 **Universal Client Support**
- **Windows 10/11**: Native IKEv2 client with built-in support
- **Mobile Devices**: iOS and Android with optimized mobile configurations
- **Linux Desktop**: NetworkManager and command-line client support
- **Cross-Platform**: Seamless roaming between all device types

### 📊 **Advanced Monitoring & Analytics**
- **Real-Time IP Tracking**: Monitor all client connections and IP addresses
- **Connection Analytics**: Bandwidth usage, session duration, and connection quality
- **Authentication Logs**: Complete audit trail of all login attempts
- **Device Identification**: Track connections by device type and user

### 🎯 **Zero-Configuration Setup**
- **Automated Installation**: One-command complete server deployment
- **Intelligent Configuration**: Automatic detection and optimization for your environment
- **Client Auto-Discovery**: Automatic client configuration generation
- **Self-Healing**: Automatic service recovery and network optimization

## 🖼️ Enterprise Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────┐
│   Windows PC    │    │   Mobile Device  │    │                         │
│   (Native VPN)  │◄──►│  (iOS/Android)   │◄──►│    SecureConnect VPN    │
└─────────────────┘    └──────────────────┘    │         Server          │
                                               │                         │
┌─────────────────┐    ┌──────────────────┐    │  ┌─────────────────────┐ │
│   Linux Client  │    │  Enterprise App  │    │  │   StrongSwan VPN    │ │
│ (NetworkManager)│◄──►│   Integration    │◄──►│  │   IKEv2 Gateway     │ │
└─────────────────┘    └──────────────────┘    │  └─────────────────────┘ │
                                               │  ┌─────────────────────┐ │
         ┌─────────────────────────────────────┤  │  OTP Authentication │ │
         │          Admin Dashboard             │  │   TOTP + Database   │ │
         │      Real-time Monitoring           │  └─────────────────────┘ │
         │    IP Tracking • Analytics          │  ┌─────────────────────┐ │
         └─────────────────────────────────────┤  │   Web Dashboard     │ │
                                               │  │  Flask + Bootstrap  │ │
                                               │  └─────────────────────┘ │
                                               └─────────────────────────┘
```

## 🛠️ Complete Tech Stack
- **VPN Core**: StrongSwan 5.9+ with IKEv2/IPSec
- **Authentication**: TOTP with pyotp, qrcode generation
- **Database**: SQLite with connection logging and IP tracking
- **Web Interface**: Flask with real-time monitoring
- **Encryption**: AES-256-GCM, DH Group 19, HMAC-SHA256
- **Platform**: Ubuntu 20.04+ (optimized for cloud deployment)
- **Monitoring**: Real-time connection analytics and device tracking

## 📁 Complete Project Structure
```
SecureConnect/
├── 🚀 QUICK START
│   ├── scripts/complete_setup.sh     # One-command installation
│   ├── scripts/verify_complete.sh    # Complete system verification
│   └── UBUNTU_README.md             # Main setup documentation
│
├── 💻 CLIENT SETUP GUIDES
│   ├── WINDOWS_SETUP.md             # Windows 10/11 configuration
│   ├── MOBILE_SETUP.md              # iOS/Android setup
│   └── client/configs/              # Auto-generated client configs
│
├── 🖥️ SERVER COMPONENTS
│   ├── server/strongswan/           # StrongSwan VPN configuration
│   ├── server/otp_auth/             # OTP authentication system
│   │   ├── otp_server.py           # Core OTP functionality
│   │   ├── otp_cli.py              # User management CLI
│   │   └── users.db                # User database with IP tracking
│   └── server/logs/                # Detailed connection logs
│
├── 📊 WEB DASHBOARD
│   ├── web_dashboard/app.py         # Flask monitoring interface
│   ├── web_dashboard/templates/     # Dashboard UI templates
│   └── web_dashboard/static/        # CSS/JS assets
│
├── 🔧 SCRIPTS & UTILITIES
│   ├── scripts/complete_setup.sh    # Complete automated installation
│   └── scripts/verify_complete.sh   # System verification script
│
└── 📚 DOCUMENTATION
    ├── docs/troubleshooting.md      # Common issues and solutions
    ├── docs/security.md             # Security best practices
    └── docs/enterprise.md           # Enterprise deployment guide
```

## 🚀 Quick Start (Complete Setup)

### Method 1: Automated Installation (Recommended)
```bash
# Clone repository
git clone https://github.com/yourusername/SecureConnect.git
cd SecureConnect

# Run complete setup
sudo chmod +x scripts/complete_setup.sh
sudo ./scripts/complete_setup.sh

# Verify installation
sudo ./scripts/verify_complete.sh

# Create your first VPN user
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py
```

### Method 2: Direct Download
```bash
# Download and run complete setup
wget https://github.com/yourusername/SecureConnect/raw/main/scripts/complete_setup.sh
chmod +x complete_setup.sh
sudo ./complete_setup.sh

# Verify installation
./scripts/verify_complete.sh
```

## 🌟 What You Get After Setup

### ✅ **VPN Server Ready**
- StrongSwan VPN running on ports 500/4500
- Support for Windows, iOS, Android, Linux clients
- AES-256 encryption with perfect forward secrecy
- Automatic certificate generation and management

### ✅ **User Management System**
- OTP-based authentication with QR codes
- CLI tool for creating/managing users
- SQLite database with user profiles
- Automatic password generation and email delivery

### ✅ **Real-time Monitoring Dashboard**
- Web interface at `http://YOUR-SERVER-IP:5000`
- Live connection monitoring with IP tracking
- User activity logs and connection analytics
- Device identification and bandwidth monitoring

### ✅ **Client Configuration**
- Windows: Native IKEv2 setup guide
- Mobile: iOS and Android configuration profiles
- Linux: NetworkManager integration
- Automatic client configuration generation

## 🚀 Quick Setup (2 Commands)

### Step 1: Run Automated Setup
```bash
# Make scripts executable and run complete installation
sudo chmod +x scripts/complete_setup.sh
sudo ./scripts/complete_setup.sh
```

### Step 2: Verify and Create Users
```bash
# Verify everything works
sudo ./scripts/verify_complete.sh

# Create VPN users with OTP
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py
```

### 🌐 Access Services
```bash
# Web Dashboard: http://YOUR_SERVER_IP:5000
# Default login: admin / admin123
# VPN Server: Ready on ports 500/4500
```

### ✅ System Requirements
- **OS**: Ubuntu 20.04+ or Debian 11+ (recommended)
- **RAM**: 2GB minimum, 4GB recommended
- **Python**: 3.8+
- **Network**: Public IP or port forwarding (ports 500, 4500, 5000)
- **Privileges**: Root/sudo access for installation

## 📚 Educational Value
This project teaches:
- IPSec protocol fundamentals
- Public Key Infrastructure (PKI)
- Two-factor authentication implementation
- Network security best practices
- Linux system administration
- Python security scripting

## 🎯 Learning Objectives
- Understand VPN technologies and use cases
- Implement secure authentication mechanisms
- Configure network security tools
- Analyze encrypted network traffic
- Develop security-focused applications

## 📖 Documentation
- [Complete Setup Guide](UBUNTU_README.md) - Main installation guide
- [Windows Setup](WINDOWS_SETUP.md) - Windows client configuration
- [Mobile Setup](MOBILE_SETUP.md) - iOS/Android configuration
- [Complete Solution Summary](COMPLETE_SOLUTION.md) - Project overview
- [Configuration Reference](docs/CONFIGURATION.md) - Advanced settings
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues
- [User Guide](docs/USER_GUIDE.md) - How to use the VPN

## 🔧 Optional Enhancements
- Mobile client support
- Advanced firewall rules
- Load balancing for multiple clients
- Integration with LDAP/Active Directory
- Advanced logging and monitoring

## 📝 License
This project is for educational purposes. See LICENSE file for details.

## 🤝 Contributing
This is an educational project. Suggestions and improvements are welcome!
