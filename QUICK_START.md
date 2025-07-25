# SecureConnect VPN - Quick Setup and Run Guide

## 🐧 Ubuntu Quick Start (New Ubuntu Installation)

If you've just installed Ubuntu and want to get the VPN running quickly:

### Ubuntu-Optimized Setup (Recommended)
```bash
# 1. Update your fresh Ubuntu system
sudo apt update && sudo apt upgrade -y

# 2. Navigate to project directory
cd ~/Desktop/Wifisec  # Standard Ubuntu Desktop location

# 3. Ubuntu-specific one-command setup
sudo ./scripts/ubuntu_setup.sh

# 4. Verify everything is working
./scripts/ubuntu_verify.sh
```

### Standard Setup (Alternative)
```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Navigate to project
cd ~/Desktop/Wifisec

# 3. Make scripts executable and run setup
chmod +x scripts/*.sh
sudo ./scripts/setup.sh

# 4. Start services and verify
sudo ./scripts/start_server.sh
sudo ./scripts/verify_installation.sh
```

**The Ubuntu-optimized setup provides:**
- Better Ubuntu package integration
- Systemd service configuration
- Enhanced security settings
- Automatic dependency resolution

---ecureConnect VPN - Quick Setup and Run Guide

## � Ubuntu Quick Start (Recommended)

### Step 1: Download and Prepare
```bash
# First, update your Ubuntu system
sudo apt update && sudo apt upgrade -y

# Navigate to your project directory (adjust path as needed)
cd ~/Desktop/Wifisec
# OR wherever you extracted/cloned the project

# Make scripts executable
chmod +x scripts/*.sh
chmod +x client/scripts/*.sh
```

### Step 2: One-Command Installation
```bash
# This single command installs EVERYTHING automatically:
# - StrongSwan VPN server
# - Python environment and dependencies  
# - OTP authentication system
# - Web dashboard
# - Firewall configuration
# - Certificates and security setup

sudo ./scripts/setup.sh
```

### Step 3: Start the VPN Server
```bash
# Start all VPN services
sudo ./scripts/start_server.sh
```

### Step 4: Verify Installation (Optional but Recommended)
```bash
# Check if everything is working correctly
sudo ./scripts/verify_installation.sh
```

## 🚀 Quick Setup (Automated)

### Step 2: Install Everything Automatically
```bash
# Run the automated setup script (this installs everything)
sudo ./scripts/setup.sh
```

### Step 3: Start the VPN Server
```bash
# Start all VPN services
sudo ./scripts/start_server.sh
```

### Step 4: Access the Web Dashboard
```bash
# Open your browser and go to:
http://YOUR_SERVER_IP:5000

# Default login credentials:
Username: admin
Password: admin123
```

### Step 5: Create Your First VPN User
```bash
# Navigate to the OTP authentication directory
cd server/otp_auth

# Activate Python environment
source ../../venv/bin/activate

# Run the user management CLI
python3 otp_cli.py

# Choose option 1 to create a new user
# Follow the prompts to create username, email, and password
# Save the QR code for setting up 2FA on your phone
```

### Step 6: Connect a Client
```bash
# For Linux/macOS clients:
cd client/scripts
./connect.sh connect

# For Windows clients:
# Run connect.bat as administrator
```

## 🔧 Manual Setup (Step by Step)

### Prerequisites
```bash
# Update your system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y strongswan strongswan-pki libcharon-extra-plugins \
    python3 python3-pip python3-venv curl wget openssl iptables \
    iptables-persistent net-tools tcpdump sqlite3
```

### Step 1: Setup Python Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Configure IP Forwarding
```bash
# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Step 3: Generate Certificates
```bash
# Create certificate directory
sudo mkdir -p /etc/ipsec.d/{private,certs,cacerts}

# Navigate to strongswan directory
cd server/strongswan

# Generate CA private key
sudo ipsec pki --gen --type rsa --size 4096 --outform pem > ca-key.pem

# Generate CA certificate
sudo ipsec pki --self --ca --lifetime 3650 --in ca-key.pem \
    --type rsa --dn "CN=SecureConnect VPN CA" \
    --outform pem > ca-cert.pem

# Generate server private key
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
```

### Step 4: Configure StrongSwan
```bash
# Backup original configurations
sudo cp /etc/ipsec.conf /etc/ipsec.conf.backup
sudo cp /etc/ipsec.secrets /etc/ipsec.secrets.backup

# Copy our configurations
sudo cp server/strongswan/ipsec.conf /etc/ipsec.conf
sudo cp server/strongswan/ipsec.secrets /etc/ipsec.secrets
sudo cp server/strongswan/strongswan.conf /etc/strongswan.d/charon.conf

# Set proper permissions
sudo chmod 644 /etc/ipsec.conf
sudo chmod 600 /etc/ipsec.secrets
```

### Step 5: Configure Firewall
```bash
# Allow VPN traffic
sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
sudo iptables -A INPUT -p esp -j ACCEPT

# Allow VPN subnet forwarding
sudo iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT

# NAT for VPN clients
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE

# Allow web dashboard (optional)
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Step 6: Start Services
```bash
# Enable and start StrongSwan
sudo systemctl enable strongswan
sudo systemctl start strongswan

# Check StrongSwan status
sudo systemctl status strongswan
sudo ipsec status
```

### Step 7: Initialize OTP Database
```bash
# Navigate to OTP auth directory
cd server/otp_auth

# Activate virtual environment
source ../../venv/bin/activate

# Initialize the database
python3 -c "from otp_server import OTPAuthenticator; auth = OTPAuthenticator(); print('Database initialized')"
```

### Step 8: Start Web Dashboard
```bash
# Navigate to web dashboard directory
cd ../../web_dashboard

# Start the Flask application
python3 app.py

# Or run as a service (recommended for production)
sudo systemctl start secureconnect-dashboard
```

## 📱 Creating and Managing Users

### Using the Command Line Interface
```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py

# Menu options:
# 1. Create new user
# 2. Verify OTP code
# 3. Show user information
# 4. Show authentication logs
# 5. Generate test OTP
```

### Using the Web Dashboard
1. Open http://YOUR_SERVER_IP:5000
2. Login with admin/admin123
3. Navigate to user management
4. Add new users and manage existing ones

### Creating a User Programmatically
```bash
cd server/otp_auth
source ../../venv/bin/activate

python3 -c "
from otp_server import OTPAuthenticator
import base64

auth = OTPAuthenticator()
success, secret = auth.create_user('testuser', 'test@example.com', 'password123')

if success:
    print(f'User created successfully!')
    print(f'Username: testuser')
    print(f'TOTP Secret: {secret}')
    
    # Generate QR code
    qr_code = auth.generate_qr_code('testuser', secret)
    with open('testuser_qr.png', 'wb') as f:
        f.write(base64.b64decode(qr_code))
    print('QR code saved as testuser_qr.png')
    print('Scan this with Google Authenticator or similar app')
"
```

## 🔌 Connecting Clients

### Linux/macOS Clients
```bash
# Navigate to client scripts
cd client/scripts

# Make script executable
chmod +x connect.sh

# Connect to VPN
./connect.sh connect

# Check connection status
./connect.sh status

# Disconnect from VPN
./connect.sh disconnect
```

### Windows Clients
```cmd
REM Navigate to client scripts directory
cd client\scripts

REM Run as administrator
connect.bat connect

REM Check status
connect.bat status

REM Disconnect
connect.bat disconnect
```

### Mobile Clients (Android/iOS)

#### Android (using StrongSwan app):
1. Install "strongSwan VPN Client" from Google Play
2. Add VPN Profile:
   - Server: YOUR_SERVER_IP
   - VPN Type: IKEv2 EAP
   - Username: your_username
   - Password: your_password + current_otp_code

#### iOS (built-in VPN):
1. Settings > VPN > Add VPN Configuration
2. Type: IKEv2
3. Server: YOUR_SERVER_IP
4. Remote ID: secureconnect.vpn
5. Local ID: your_username@secureconnect.vpn
6. Username: your_username
7. Password: your_password + current_otp_code

## 🔍 Verification and Testing

### Check VPN Server Status
```bash
# Check StrongSwan service
sudo systemctl status strongswan

# Check active connections
sudo ipsec status

# View real-time logs
sudo journalctl -u strongswan -f

# Check listening ports
sudo netstat -tulpn | grep -E '(500|4500)'
```

### Test VPN Configuration
```bash
# Verify StrongSwan configuration
sudo ipsec verify

# Test configuration syntax
sudo ipsec reload

# Check certificates
sudo ipsec listcerts
```

### Monitor Authentication
```bash
# Watch authentication logs
tail -f server/logs/otp_auth.log

# Check recent authentication attempts
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py
# Choose option 4 to show logs
```

### Test Client Connection
```bash
# After connecting, verify your VPN IP
curl ifconfig.me

# Test DNS resolution
nslookup google.com

# Check routing table
ip route show

# Test connectivity
ping 8.8.8.8
```

## 🛠️ Troubleshooting Common Issues

### StrongSwan Won't Start
```bash
# Check configuration syntax
sudo ipsec verify

# Check logs for errors
sudo journalctl -u strongswan --no-pager

# Restart service
sudo systemctl restart strongswan
```

### Authentication Failures
```bash
# Check OTP server logs
tail -f server/logs/otp_auth.log

# Verify user exists
cd server/otp_auth
python3 otp_cli.py
# Choose option 3 to check user info

# Test OTP generation
python3 otp_cli.py
# Choose option 5 to generate test OTP
```

### Connection Timeouts
```bash
# Check firewall rules
sudo iptables -L | grep -E '(500|4500)'

# Test server reachability
telnet YOUR_SERVER_IP 500

# Check NAT traversal
sudo tcpdump -i any port 4500
```

### No Internet After VPN Connection
```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# Check NAT rules
sudo iptables -t nat -L POSTROUTING

# Verify DNS settings
cat /etc/resolv.conf
```

## 🔧 Useful Commands

### Server Management
```bash
# Start/stop VPN server
sudo ./scripts/start_server.sh
sudo systemctl stop strongswan secureconnect-dashboard

# View server status
sudo ./scripts/server_status.sh  # If available

# Backup configuration
sudo ./scripts/backup_config.sh  # If available
```

### Log Management
```bash
# View all VPN-related logs
sudo journalctl -u strongswan --since "1 hour ago"

# Monitor real-time connections
sudo ipsec status
watch -n 5 'sudo ipsec status'

# Analyze traffic
sudo tcpdump -i any port 500 or port 4500
```

### User Management
```bash
# List all users
cd server/otp_auth
sqlite3 users.db "SELECT username, email, is_active, last_login FROM users;"

# Disable a user
sqlite3 users.db "UPDATE users SET is_active = 0 WHERE username = 'username';"

# View authentication stats
sqlite3 users.db "SELECT action, success, COUNT(*) FROM auth_logs GROUP BY action, success;"
```

## 🎯 Next Steps

1. **Secure Your Installation**:
   - Change default passwords
   - Update firewall rules for your network
   - Configure proper SSL certificates for web dashboard

2. **Add More Users**:
   - Create accounts for team members
   - Set up email notifications
   - Configure user groups and permissions

3. **Monitor and Maintain**:
   - Set up log rotation
   - Monitor system resources
   - Regular security updates

4. **Enhance Features**:
   - Add mobile client support
   - Implement advanced logging
   - Set up automatic backups

For detailed documentation, see:
- [Complete Setup Guide](docs/SETUP.md)
- [User Guide](docs/USER_GUIDE.md)
- [Configuration Reference](docs/CONFIGURATION.md)
