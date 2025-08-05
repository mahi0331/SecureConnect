# SecureConnect VPN - Troubleshooting Guide

## 🚨 Common Setup Issues and Solutions

### ❌ **Setup Script Fails**

#### Problem: Permission denied errors
```bash
# Solution: Make scripts executable
chmod +x scripts/*.sh
chmod +x client/scripts/*.sh

# Run with proper permissions
sudo ./scripts/complete_setup.sh
```

#### Problem: Package installation fails
```bash
# Update package lists first
sudo apt update

# Fix broken dependencies
sudo apt --fix-broken install

# Try manual installation
sudo apt install strongswan strongswan-pki python3 python3-pip
```

#### Problem: Python virtual environment issues
```bash
# Install venv module
sudo apt install python3-venv

# Create virtual environment manually
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### ❌ **StrongSwan Won't Start**

#### Problem: Configuration syntax errors
```bash
# Check configuration
sudo ipsec verify

# Test configuration syntax
sudo ipsec reload

# Check for errors in logs
sudo journalctl -u strongswan --no-pager -n 50
```

#### Problem: Certificate issues
```bash
# Regenerate certificates
cd server/strongswan
sudo rm -rf /etc/ipsec.d/certs/* /etc/ipsec.d/private/* /etc/ipsec.d/cacerts/*

# Run certificate generation again
sudo ipsec pki --gen --type rsa --size 4096 --outform pem > ca-key.pem
sudo ipsec pki --self --ca --lifetime 3650 --in ca-key.pem \
    --type rsa --dn "CN=SecureConnect VPN CA" --outform pem > ca-cert.pem

# Install certificates
sudo cp ca-cert.pem /etc/ipsec.d/cacerts/
sudo cp server-cert.pem /etc/ipsec.d/certs/
sudo cp server-key.pem /etc/ipsec.d/private/
sudo chmod 600 /etc/ipsec.d/private/server-key.pem
```

#### Problem: Service won't start
```bash
# Check service status
sudo systemctl status strongswan

# Enable service
sudo systemctl enable strongswan

# Reset and start service
sudo systemctl stop strongswan
sudo systemctl start strongswan
```

### ❌ **Firewall Issues**

#### Problem: VPN ports blocked
```bash
# Check if ports are open
sudo netstat -tulpn | grep -E '(500|4500)'

# Add firewall rules manually
sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
sudo iptables -A INPUT -p esp -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

#### Problem: UFW blocking connections
```bash
# Allow VPN ports through UFW
sudo ufw allow 500/udp
sudo ufw allow 4500/udp
sudo ufw allow 5000/tcp

# Check UFW status
sudo ufw status verbose
```

### ❌ **OTP Authentication Issues**

#### Problem: Database not initialized
```bash
cd server/otp_auth
source ../../venv/bin/activate

# Initialize database manually
python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
print('Database initialized successfully')
"
```

#### Problem: Python module import errors
```bash
# Reinstall requirements
source venv/bin/activate
pip install --force-reinstall -r requirements.txt

# Install specific modules
pip install pyotp qrcode[pil] flask sqlite3
```

#### Problem: QR code generation fails
```bash
# Install PIL/Pillow
pip install Pillow

# Install qrcode with pillow support
pip install qrcode[pil]
```

### ❌ **Web Dashboard Issues**

#### Problem: Dashboard won't start
```bash
cd web_dashboard
source ../venv/bin/activate

# Check for import errors
python3 -c "import flask; print('Flask OK')"

# Run with debug mode
python3 app.py

# Check if port 5000 is available
sudo netstat -tulpn | grep :5000
```

#### Problem: Can't access dashboard from other machines
```bash
# Modify app.py to bind to all interfaces
# Change: app.run(host='localhost', port=5000)
# To: app.run(host='0.0.0.0', port=5000)

# Or specify host when running
python3 app.py --host=0.0.0.0
```

### ❌ **Client Connection Issues**

#### Problem: Authentication fails
```bash
# Check if user exists
cd server/otp_auth
python3 otp_cli.py
# Choose option 3 to check user info

# Verify OTP generation
python3 otp_cli.py
# Choose option 5 to generate test OTP

# Check authentication logs
tail -f ../logs/otp_auth.log
```

#### Problem: Connection timeout
```bash
# Test server reachability
ping YOUR_SERVER_IP

# Test VPN ports
telnet YOUR_SERVER_IP 500
nc -u YOUR_SERVER_IP 500

# Check server logs during connection attempt
sudo journalctl -u strongswan -f
```

#### Problem: Windows client script issues
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Check if curl is available
curl --version

# Install curl if missing (Windows 10 1803+)
# Or use alternative HTTP client
```

### ❌ **Network Issues**

#### Problem: No internet after VPN connection
```bash
# Check IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Check NAT rules
sudo iptables -t nat -L POSTROUTING

# Add NAT rule if missing
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE

# Check DNS settings
cat /etc/resolv.conf
```

#### Problem: Can't reach VPN clients from server
```bash
# Check forwarding rules
sudo iptables -L FORWARD

# Add forwarding rules
sudo iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT
```

## 🛠️ **Diagnostic Commands**

### System Information
```bash
# Check OS version
cat /etc/os-release

# Check kernel version
uname -a

# Check available memory
free -h

# Check disk space
df -h
```

### Network Diagnostics
```bash
# Show network interfaces
ip addr show

# Show routing table
ip route show

# Check listening ports
sudo netstat -tulpn

# Test connectivity
ping 8.8.8.8
```

### VPN Specific Diagnostics
```bash
# StrongSwan status
sudo ipsec status
sudo ipsec statusall

# Configuration verification
sudo ipsec verify

# Certificate information
sudo ipsec listcerts

# Live connection monitoring
sudo tcpdump -i any port 500 or port 4500
```

### Log Analysis
```bash
# StrongSwan logs
sudo journalctl -u strongswan --since "1 hour ago"

# System logs
sudo journalctl --since "1 hour ago" | grep -i vpn

# Authentication logs
tail -f server/logs/otp_auth.log

# Web dashboard logs
tail -f server/logs/dashboard.log
```

## 🔧 **Quick Fixes**

### Reset Everything
```bash
# Stop all services
sudo systemctl stop strongswan secureconnect-dashboard

# Reset firewall rules
sudo iptables -F
sudo iptables -t nat -F

# Remove and recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run setup script again
sudo ./scripts/complete_setup.sh
```

### Minimal Working Configuration
```bash
# Basic ipsec.conf
sudo tee /etc/ipsec.conf << EOF
config setup
    strictcrlpolicy=no
    uniqueids=yes

conn secureconnect
    type=tunnel
    keyexchange=ikev2
    left=%any
    leftid=@secureconnect.vpn
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    authby=psk
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256-modp2048!
    auto=add
EOF

# Basic ipsec.secrets
sudo tee /etc/ipsec.secrets << EOF
%any %any : PSK "SecureConnect2024!TestKey"
EOF

sudo chmod 600 /etc/ipsec.secrets
sudo systemctl restart strongswan
```

## 📞 **Getting Help**

### Check Documentation
- [Complete Setup Guide](../UBUNTU_README.md)
- [User Guide](USER_GUIDE.md)
- [Configuration Reference](CONFIGURATION.md)

### Run Verification Script
```bash
# Check installation status
sudo ./scripts/verify_complete.sh
```

### Collect Debug Information
```bash
# Create debug report
sudo ipsec verify > debug_report.txt
sudo systemctl status strongswan >> debug_report.txt
sudo journalctl -u strongswan --no-pager >> debug_report.txt
ip addr show >> debug_report.txt
sudo iptables -L >> debug_report.txt
```

### Community Support
- Check project documentation
- Search for similar issues
- Create detailed bug reports with:
  - Operating system version
  - Error messages
  - Log excerpts
  - Steps to reproduce

Remember: Most issues are related to permissions, firewall settings, or missing dependencies. The verification script can help identify the specific problem.
