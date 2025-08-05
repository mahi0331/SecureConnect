# SecureConnect VPN - Complete Setup Guide

Welcome to SecureConnect VPN! This comprehensive guide will help you set up a fully functional VPN server with Windows, mobile, and IP tracking support.

## 🎯 What You'll Get After Setup

✅ **Working VPN on Windows** - Native Windows 10/11 VPN client support  
✅ **Working VPN on Mobile** - iOS and Android compatibility  
✅ **IP Address Tracking** - Admin dashboard shows all connected device IPs  
✅ **Real-time Monitoring** - See who's connected and when  
✅ **Two-Factor Authentication** - Secure OTP-based login  

## 🚀 Complete Ubuntu Setup (All-in-One)

### Method 1: Complete Automated Setup (Recommended) ⭐
```bash
# Step 1: Update your Ubuntu system
sudo apt update && sudo apt upgrade -y

# Step 2: Navigate to the project directory
cd ~/Desktop/Wifisec  # Or wherever you have the project

# Step 3: Make all scripts executable
chmod +x scripts/*.sh client/scripts/*.sh

# Step 4: Run the complete setup (this installs everything)
sudo ./scripts/complete_setup.sh

# Step 5: Verify everything works
./scripts/verify_complete.sh

# Step 6: Get your server IP for clients
hostname -I
```

**What this installs:**
- ✅ StrongSwan VPN with proper Windows/Mobile support
- ✅ Python OTP system with enhanced security
- ✅ Flask dashboard with IP tracking
- ✅ Automatic certificate generation
- ✅ Firewall configuration
- ✅ User management system

### Method 2: Standard Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Navigate to project
cd ~/OneDrive/Desktop/Wifisec

# Make scripts executable
chmod +x scripts/*.sh

# Run complete setup
sudo ./scripts/complete_setup.sh

# Verify installation
sudo ./scripts/verify_complete.sh
```

### Method 3: One-Liner (Future Release)
```bash
# This will be available when project is on GitHub
curl -sSL https://raw.githubusercontent.com/user/secureconnect/main/scripts/complete_setup.sh | sudo bash
```

## 🎯 What Gets Installed

The Ubuntu setup installs and configures:

✅ **StrongSwan VPN Server** - Industry-standard IPSec/IKEv2 VPN  
✅ **Python OTP Authentication** - Time-based one-time passwords  
✅ **Web Dashboard** - Monitor connections and manage users  
✅ **SSL Certificates** - Secure communication  
✅ **Firewall Rules** - Secure network configuration  
✅ **Systemd Services** - Auto-start on boot  

## 🔧 After Installation

### 1. Start the VPN Server
```bash
sudo ./scripts/start_server.sh
```

### 2. Access Web Dashboard
Open your browser and go to:
```
http://YOUR_SERVER_IP:5000
```
**Default Login:** admin / admin123 ⚠️ **Change this!**

### 3. Create Your First VPN User
```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py
```

Follow the prompts to:
- Create username and password
- Generate QR code for mobile authenticator
- Set up two-factor authentication

### 4. Connect Clients

**Linux/Mac:**
```bash
cd client/scripts
./connect.sh connect
```

**Windows:**
```bash
# Run as administrator
connect.bat
```

**Mobile (iOS/Android):**
Use built-in VPN settings with the server configuration

## 🔍 Verification Commands

Check if everything is running:

```bash
# Check VPN service
sudo systemctl status strongswan

# Check dashboard service  
sudo systemctl status secureconnect-dashboard

# Check open ports
sudo netstat -tuln | grep -E "(500|4500|5000)"

# Check VPN logs
sudo journalctl -u strongswan -f

# Run full verification
./scripts/ubuntu_verify.sh
```

## 📱 Mobile Setup

1. **Install authenticator app** (Google Authenticator, Authy, etc.)
2. **Scan QR code** generated when creating user
3. **Configure VPN on device:**
   - Server: `YOUR_SERVER_IP`
   - Type: `IKEv2`
   - Username: `your_username`
   - Password: `your_password`

## 🔒 Security Best Practices

After installation:

1. **Change default passwords:**
   ```bash
   # Web dashboard: http://YOUR_SERVER_IP:5000/settings
   # Update admin password
   ```

2. **Update PSK (Pre-Shared Key):**
   ```bash
   sudo nano /etc/ipsec.secrets
   # Change the PSK value
   sudo systemctl restart strongswan
   ```

3. **Monitor connections:**
   ```bash
   # Check active connections
   sudo ipsec status
   
   # Monitor logs
   sudo tail -f /var/log/auth.log
   ```

4. **Regular updates:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

## 🐛 Troubleshooting

**VPN won't start:**
```bash
sudo systemctl restart strongswan
sudo journalctl -u strongswan --no-pager
```

**Can't connect:**
```bash
# Check firewall
sudo iptables -L -n

# Check certificates
sudo ipsec listcacerts
sudo ipsec listcerts
```

**Dashboard not working:**
```bash
sudo systemctl restart secureconnect-dashboard
sudo journalctl -u secureconnect-dashboard --no-pager
```

**Port issues:**
```bash
# Check what's using the ports
sudo lsof -i :500
sudo lsof -i :4500
sudo lsof -i :5000
```

## 📖 More Documentation

- **Full Documentation:** `docs/`
- **User Guide:** `docs/USER_GUIDE.md`
- **Troubleshooting:** `docs/TROUBLESHOOTING.md`
- **Configuration:** `docs/CONFIGURATION.md`

## 🆘 Need Help?

1. Check `docs/TROUBLESHOOTING.md`
2. Run the verification script: `./scripts/ubuntu_verify.sh`
3. Check system logs: `sudo journalctl -xe`
4. Review VPN logs: `sudo journalctl -u strongswan`

---

## 🎉 Success!

Once everything is running, you'll have:

- **Secure VPN server** accessible from anywhere
- **Web dashboard** for monitoring and management  
- **Mobile-ready** OTP authentication
- **Enterprise-grade** IPSec encryption
- **Professional setup** ready for production

**Your VPN server is now ready to secure your internet traffic!** 🔐

---

*Made with ❤️ for educational purposes. SecureConnect VPN demonstrates modern VPN technologies and security practices.*
