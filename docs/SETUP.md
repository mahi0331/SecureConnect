# SecureConnect VPN - Setup Guide

This guide will walk you through setting up SecureConnect, an educational VPN system with IPSec and OTP-based authentication.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Ubuntu 20.04+ or Debian 11+ (recommended)
- **RAM**: Minimum 2GB, Recommended 4GB
- **Storage**: At least 10GB free space
- **Network**: Public IP address or port forwarding capability
- **Privileges**: Root/sudo access

### Network Requirements
- **Ports to open**:
  - 500/UDP (IKE - Internet Key Exchange)
  - 4500/UDP (NAT-T - NAT Traversal)
  - 5000/TCP (Web Dashboard, optional)
  - 22/TCP (SSH for management)

## 🚀 Quick Installation

### Option 1: Automated Setup (Recommended)

1. **Download the project**:
   ```bash
   git clone https://github.com/your-repo/SecureConnect.git
   cd SecureConnect
   ```

2. **Run the setup script**:
   ```bash
   sudo ./scripts/complete_setup.sh
   ```

3. **Verify the installation**:
   ```bash
   sudo ./scripts/verify_complete.sh
   ```

4. **Access the dashboard**:
   - Open http://YOUR_SERVER_IP:5000
   - Login with admin/admin123
   - **IMPORTANT**: Change the default password immediately!

### Option 2: Manual Installation

If you prefer to understand each step or the automated setup fails:

#### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Dependencies
```bash
sudo apt install -y strongswan strongswan-pki libcharon-extra-plugins \
    python3 python3-pip python3-venv curl wget openssl \
    iptables iptables-persistent net-tools tcpdump sqlite3
```

#### Step 3: Setup Python Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Step 4: Configure IP Forwarding
```bash
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### Step 5: Generate Certificates
```bash
cd server/strongswan
sudo mkdir -p /etc/ipsec.d/private /etc/ipsec.d/certs /etc/ipsec.d/cacerts

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

#### Step 6: Configure StrongSwan
```bash
# Backup original configuration
sudo cp /etc/ipsec.conf /etc/ipsec.conf.backup
sudo cp /etc/ipsec.secrets /etc/ipsec.secrets.backup

# Copy our configuration
sudo cp server/strongswan/ipsec.conf /etc/ipsec.conf
sudo cp server/strongswan/ipsec.secrets /etc/ipsec.secrets
sudo cp server/strongswan/strongswan.conf /etc/strongswan.d/charon.conf

# Set permissions
sudo chmod 644 /etc/ipsec.conf
sudo chmod 600 /etc/ipsec.secrets
```

#### Step 7: Configure Firewall
```bash
# Allow VPN traffic
sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
sudo iptables -A INPUT -p esp -j ACCEPT

# Allow VPN subnet
sudo iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT

# NAT for VPN clients
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

#### Step 8: Start Services
```bash
# Start StrongSwan
sudo systemctl enable strongswan
sudo systemctl start strongswan

# Initialize OTP database
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_server.py

# Start web dashboard
cd ../../web_dashboard
python3 app.py
```

## 👥 User Management

### Creating VPN Users

1. **Using the CLI tool**:
   ```bash
   cd server/otp_auth
   source ../../venv/bin/activate
   python3 otp_cli.py
   ```

2. **Using the web dashboard**:
   - Access http://YOUR_SERVER_IP:5000
   - Navigate to User Management
   - Click "Add New User"

### Example: Creating a Test User
```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
success, secret = auth.create_user('testuser', 'test@example.com', 'password123')
if success:
    print(f'User created! TOTP Secret: {secret}')
    qr = auth.generate_qr_code('testuser', secret)
    import base64
    with open('testuser_qr.png', 'wb') as f:
        f.write(base64.b64decode(qr))
    print('QR code saved as testuser_qr.png')
"
```

## 📱 Client Setup

### For Linux Clients

1. **Install StrongSwan client**:
   ```bash
   sudo apt install strongswan
   ```

2. **Use the connection script**:
   ```bash
   cd client/scripts
   chmod +x connect.sh
   ./connect.sh connect
   ```

### For Windows Clients

1. **Use the batch script**:
   ```cmd
   cd client\scripts
   connect.bat connect
   ```

2. **Or configure manually**:
   - Open Network settings
   - Add VPN connection
   - Choose IKEv2
   - Server: YOUR_SERVER_IP
   - Authentication: Username and password + OTP

### For Mobile Clients

#### Android (StrongSwan app):
1. Install StrongSwan from Google Play
2. Import CA certificate
3. Create new profile:
   - Server: YOUR_SERVER_IP
   - Type: IKEv2 EAP
   - Username: your_username
   - Password: your_password + current_otp

#### iOS:
1. Go to Settings > VPN
2. Add VPN Configuration
3. Type: IKEv2
4. Server: YOUR_SERVER_IP
5. Username/Password + OTP

## 🔧 Configuration

### Server Configuration

#### Main configuration files:
- `/etc/ipsec.conf` - StrongSwan connection definitions
- `/etc/ipsec.secrets` - Authentication secrets
- `/etc/strongswan.d/charon.conf` - Daemon configuration

#### Key settings to customize:
```bash
# In /etc/ipsec.conf
rightsourceip=10.10.10.0/24    # VPN client IP pool
rightdns=8.8.8.8,8.8.4.4       # DNS servers for clients

# In /etc/ipsec.secrets
%any %any : PSK "YourSecretPSK"  # Change this!
```

### OTP Configuration

#### Email settings (for email-based OTP):
```python
# In server/otp_auth/config.py
SMTP_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'from_email': 'your-email@gmail.com',
    'password': 'your-app-password'
}
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Connection fails immediately
```bash
# Check StrongSwan status
sudo systemctl status strongswan
sudo ipsec status

# Check logs
sudo journalctl -u strongswan -f
tail -f /var/log/strongswan.log
```

#### 2. Authentication fails
```bash
# Check OTP logs
tail -f server/logs/otp_auth.log

# Test OTP verification
cd server/otp_auth
python3 otp_cli.py
# Select option 2 to test OTP verification
```

#### 3. No internet through VPN
```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should show 1

# Check NAT rules
sudo iptables -t nat -L POSTROUTING
```

#### 4. Firewall blocks connection
```bash
# Check if ports are open
sudo netstat -tulpn | grep -E '(500|4500)'
sudo iptables -L | grep -E '(500|4500)'

# Temporarily disable firewall for testing
sudo ufw disable  # if using UFW
```

### Log Files Locations
- StrongSwan: `/var/log/strongswan.log`
- System logs: `journalctl -u strongswan`
- OTP logs: `server/logs/otp_auth.log`
- Dashboard logs: `server/logs/dashboard.log`

### Testing Connectivity

#### Server-side tests:
```bash
# Test StrongSwan configuration
sudo ipsec verify

# Check listening ports
sudo netstat -tulpn | grep -E '(500|4500|5000)'

# Monitor real-time connections
sudo tcpdump -i any port 500 or port 4500
```

#### Client-side tests:
```bash
# Test server reachability
ping YOUR_SERVER_IP
telnet YOUR_SERVER_IP 500

# Test DNS resolution
nslookup google.com

# Check routing table
ip route show
```

## 🔒 Security Best Practices

### Essential Security Steps

1. **Change default passwords**:
   ```bash
   # Dashboard admin password
   # Edit web_dashboard/app.py and change DASHBOARD_CONFIG
   
   # Database encryption
   # Use strong PSK in /etc/ipsec.secrets
   ```

2. **Regular updates**:
   ```bash
   sudo apt update && sudo apt upgrade
   pip install --upgrade -r requirements.txt
   ```

3. **Monitor logs**:
   ```bash
   # Set up log monitoring
   sudo apt install logwatch
   
   # Or use journalctl
   sudo journalctl -u strongswan --since "1 hour ago"
   ```

4. **Certificate management**:
   - Regularly rotate certificates (every 1-2 years)
   - Use strong key sizes (4096-bit RSA minimum)
   - Consider ECDSA for better performance

### Production Recommendations

1. **Use certificate-based authentication** instead of PSK
2. **Enable fail2ban** to prevent brute force attacks
3. **Set up proper logging and monitoring**
4. **Use a hardware security module (HSM)** for key storage
5. **Implement network segmentation**
6. **Regular security audits and penetration testing**

## 📈 Performance Tuning

### For High Load

1. **Increase connection limits**:
   ```bash
   # In /etc/strongswan.d/charon.conf
   threads = 32
   keep_alive = 20
   ```

2. **Optimize network settings**:
   ```bash
   # In /etc/sysctl.conf
   net.core.rmem_max = 16777216
   net.core.wmem_max = 16777216
   net.ipv4.tcp_congestion_control = bbr
   ```

3. **Use hardware acceleration**:
   - Enable AES-NI if available
   - Consider dedicated VPN hardware

## 🆘 Support

### Getting Help

1. **Check documentation**: All docs are in the `docs/` directory
2. **Review logs**: Most issues can be diagnosed from log files
3. **Test step by step**: Use the troubleshooting section
4. **Community support**: GitHub issues or relevant forums

### Reporting Issues

When reporting issues, please include:
- Operating system and version
- StrongSwan version (`ipsec --version`)
- Relevant log excerpts
- Configuration files (remove sensitive information)
- Steps to reproduce the issue

## 📚 Additional Resources

- [StrongSwan Documentation](https://wiki.strongswan.org/)
- [IPSec RFC Documents](https://tools.ietf.org/rfc/)
- [Linux VPN HOWTO](https://www.kernel.org/doc/Documentation/networking/l2tp.txt)
- [TOTP RFC 6238](https://tools.ietf.org/html/rfc6238)

---

**Next Steps**: Once setup is complete, proceed to the [User Guide](USER_GUIDE.md) for daily operations and the [Security Guide](SECURITY.md) for hardening your installation.
