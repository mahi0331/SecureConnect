# SecureConnect: A Basic VPN with IPSec and OTP-Based Authentication

## 🔍 Project Overview
SecureConnect is an educational VPN solution that demonstrates secure remote access using IPSec tunneling and Two-Factor Authentication (2FA) with OTP. This project is designed to teach students the fundamentals of:
- VPN technology and IPSec protocols
- Two-factor authentication systems
- Network security principles
- Python scripting for security applications

## 🧩 Key Features
- **🔐 IPSec Tunnel**: Secure communication using StrongSwan
- **🧾 OTP Authentication (2FA)**: Email-based or TOTP authentication
- **📄 Basic Logging**: Comprehensive logging of connections and authentication attempts
- **🖥️ Command-Line Interface**: Simple scripts for VPN management
- **🌐 Web Dashboard**: Optional Flask-based monitoring interface

## 🖼️ Architecture
```
+-------------------+         +------------------------+
|                   |         |                        |
|  Client Device    +--------->  VPN Gateway (Linux)   |
| (Laptop/PC)       |  IPSec  |  StrongSwan + OTP Auth |
|                   | Tunnel  |                        |
+-------------------+         +------------------------+
```

## 🛠️ Tech Stack
- **VPN**: StrongSwan (IPSec implementation)
- **OTP**: Python with pyotp, qrcode libraries
- **Web Interface**: Flask (optional)
- **Platform**: Linux (Ubuntu/Debian recommended)
- **Testing**: Wireshark for traffic analysis

## 📁 Project Structure
```
SecureConnect/
├── server/                 # VPN Server components
│   ├── strongswan/         # StrongSwan configuration
│   ├── otp_auth/          # OTP authentication system
│   └── logs/              # Server logs
├── client/                # Client-side tools
│   ├── scripts/           # Connection scripts
│   └── configs/           # Client configurations
├── web_dashboard/         # Optional web interface
├── docs/                  # Documentation
└── scripts/               # Setup and utility scripts
```

## 🚀 How to Run and Setup

### ⚡ Quick Setup (3 Commands)
```bash
# 1. Make scripts executable
chmod +x scripts/*.sh client/scripts/*.sh

# 2. Run automated setup (installs everything)
sudo ./scripts/setup.sh

# 3. Start the VPN server
sudo ./scripts/start_server.sh
```

### 🌐 Access Web Dashboard
```bash
# Open in browser: http://YOUR_SERVER_IP:5000
# Default login: admin / admin123
```

### 👥 Create VPN Users
```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py
# Choose option 1 to create new user
# Scan the generated QR code with Google Authenticator
```

### 📱 Connect Clients
```bash
# Linux/macOS:
./client/scripts/connect.sh connect

# Windows (run as admin):
client\scripts\connect.bat connect
```

### ✅ Verify Installation
```bash
# Check if everything is properly installed and configured
sudo ./scripts/verify_installation.sh
```

### 📖 Detailed Instructions
For complete step-by-step instructions, troubleshooting, and advanced configuration:
- **[📋 Complete Setup Guide](QUICK_START.md)** - Detailed installation and configuration
- **[👥 User Guide](docs/USER_GUIDE.md)** - How to use and manage the VPN
- **[🔧 Configuration](docs/CONFIGURATION.md)** - Advanced settings and customization

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
- [Setup Guide](docs/SETUP.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Security Considerations](docs/SECURITY.md)

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
