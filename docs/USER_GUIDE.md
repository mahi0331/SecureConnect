# SecureConnect VPN - User Guide

This guide explains how to use SecureConnect VPN for both administrators and end users.

## 👥 For Administrators

### Daily Operations

#### Starting/Stopping the VPN Server

```bash
# Start all services
sudo ./scripts/start_server.sh

# Stop all services
sudo systemctl stop strongswan secureconnect-dashboard

# Restart services
sudo systemctl restart strongswan secureconnect-dashboard

# Check service status
sudo systemctl status strongswan secureconnect-dashboard
```

#### Managing Users

##### Creating New Users

**Method 1: Using the CLI tool**
```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py
```

**Method 2: Using the Web Dashboard**
1. Access http://YOUR_SERVER_IP:5000
2. Login with admin credentials
3. Navigate to "User Management"
4. Click "Add New User"
5. Fill in user details
6. Generate QR code for user

**Method 3: Programmatically**
```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
success, secret = auth.create_user('username', 'email@domain.com', 'password')
if success:
    print(f'User created! Secret: {secret}')
    # Generate QR code
    qr = auth.generate_qr_code('username', secret)
    import base64
    with open('user_qr.png', 'wb') as f:
        f.write(base64.b64decode(qr))
    print('QR code saved as user_qr.png')
"
```

##### Disabling/Enabling Users

```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 -c "
from otp_server import OTPAuthenticator
import sqlite3

auth = OTPAuthenticator()
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Disable user
cursor.execute('UPDATE users SET is_active = 0 WHERE username = ?', ('username',))

# Enable user
cursor.execute('UPDATE users SET is_active = 1 WHERE username = ?', ('username',))

conn.commit()
conn.close()
print('User status updated')
"
```

##### Viewing User Activity

```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 otp_cli.py
# Choose option 3: Show user information
```

#### Monitoring Connections

##### Real-time Connection Monitoring

```bash
# View active connections
sudo ipsec status

# Monitor connection attempts
sudo journalctl -u strongswan -f

# Watch authentication logs
tail -f server/logs/otp_auth.log

# Monitor network traffic
sudo tcpdump -i any port 500 or port 4500
```

##### Web Dashboard Monitoring

1. Access http://YOUR_SERVER_IP:5000
2. View real-time statistics:
   - Total authentication attempts
   - Success/failure rates
   - Active connections
   - User activity logs

#### Log Management

##### Important Log Files

```bash
# StrongSwan logs
sudo journalctl -u strongswan --since "1 hour ago"
tail -f /var/log/strongswan.log

# OTP authentication logs
tail -f server/logs/otp_auth.log

# Dashboard logs
tail -f server/logs/dashboard.log

# System logs
sudo journalctl --since "1 hour ago" | grep -i vpn
```

##### Log Rotation

```bash
# Configure logrotate for VPN logs
sudo cat > /etc/logrotate.d/secureconnect << EOF
/var/log/strongswan.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        /bin/systemctl reload strongswan > /dev/null 2>&1 || true
    endscript
}
EOF
```

#### Backup and Recovery

##### Backing Up Configuration

```bash
#!/bin/bash
# backup_vpn.sh

BACKUP_DIR="/backup/secureconnect-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup StrongSwan configuration
cp /etc/ipsec.conf "$BACKUP_DIR/"
cp /etc/ipsec.secrets "$BACKUP_DIR/"
cp -r /etc/ipsec.d/ "$BACKUP_DIR/"
cp /etc/strongswan.d/charon.conf "$BACKUP_DIR/"

# Backup user database
cp server/otp_auth/users.db "$BACKUP_DIR/"

# Backup certificates
cp -r server/strongswan/pki/ "$BACKUP_DIR/"

# Create archive
tar -czf "secureconnect-backup-$(date +%Y%m%d).tar.gz" -C /backup "secureconnect-$(date +%Y%m%d)"

echo "Backup created: secureconnect-backup-$(date +%Y%m%d).tar.gz"
```

##### Restoring from Backup

```bash
#!/bin/bash
# restore_vpn.sh

BACKUP_FILE="$1"
if [[ -z "$BACKUP_FILE" ]]; then
    echo "Usage: $0 <backup-file.tar.gz>"
    exit 1
fi

# Extract backup
tar -xzf "$BACKUP_FILE" -C /tmp/

BACKUP_DIR="/tmp/secureconnect-*"

# Stop services
sudo systemctl stop strongswan secureconnect-dashboard

# Restore configuration
sudo cp "$BACKUP_DIR"/ipsec.conf /etc/
sudo cp "$BACKUP_DIR"/ipsec.secrets /etc/
sudo cp -r "$BACKUP_DIR"/ipsec.d/ /etc/
sudo cp "$BACKUP_DIR"/charon.conf /etc/strongswan.d/

# Restore user database
cp "$BACKUP_DIR"/users.db server/otp_auth/

# Restore certificates
cp -r "$BACKUP_DIR"/pki/ server/strongswan/

# Set permissions
sudo chmod 644 /etc/ipsec.conf
sudo chmod 600 /etc/ipsec.secrets
sudo chmod -R 600 /etc/ipsec.d/private/

# Start services
sudo systemctl start strongswan secureconnect-dashboard

echo "Restore completed"
```

### Security Management

#### Certificate Management

##### Checking Certificate Expiry

```bash
# Check server certificate
openssl x509 -in /etc/ipsec.d/certs/server-cert.pem -text -noout | grep -A2 "Validity"

# Check CA certificate
openssl x509 -in /etc/ipsec.d/cacerts/ca-cert.pem -text -noout | grep -A2 "Validity"
```

##### Renewing Certificates

```bash
cd server/strongswan/pki

# Generate new server certificate
sudo ipsec pki --gen --type rsa --size 4096 --outform pem > server-key-new.pem

sudo ipsec pki --pub --in server-key-new.pem --type rsa | \
sudo ipsec pki --issue --lifetime 1825 --cacert ca-cert.pem \
    --cakey ca-key.pem --dn "CN=secureconnect.vpn" \
    --san "secureconnect.vpn" --flag serverAuth \
    --flag ikeIntermediate --outform pem > server-cert-new.pem

# Backup old certificates
sudo cp /etc/ipsec.d/certs/server-cert.pem /etc/ipsec.d/certs/server-cert.pem.bak
sudo cp /etc/ipsec.d/private/server-key.pem /etc/ipsec.d/private/server-key.pem.bak

# Install new certificates
sudo cp server-cert-new.pem /etc/ipsec.d/certs/server-cert.pem
sudo cp server-key-new.pem /etc/ipsec.d/private/server-key.pem
sudo chmod 600 /etc/ipsec.d/private/server-key.pem

# Restart StrongSwan
sudo systemctl restart strongswan
```

#### Security Auditing

##### Failed Login Attempts

```bash
cd server/otp_auth
source ../../venv/bin/activate
python3 -c "
from otp_server import OTPAuthenticator
auth = OTPAuthenticator()
logs = auth.get_auth_logs(limit=100)
failed = [log for log in logs if not log['success']]
print(f'Failed attempts in last 100 logs: {len(failed)}')
for log in failed[-10:]:  # Show last 10 failures
    print(f'{log[\"timestamp\"]} - {log[\"username\"]} from {log[\"ip_address\"]}: {log[\"details\"]}')
"
```

##### Suspicious Activity Detection

```bash
# Check for multiple failed attempts from same IP
sudo journalctl -u strongswan --since "1 day ago" | grep -i "authentication failed" | awk '{print $7}' | sort | uniq -c | sort -nr

# Check for login attempts outside business hours
grep "$(date '+%Y-%m-%d')" server/logs/otp_auth.log | grep -E "(0[0-7]|2[0-3]):" | grep "login"
```

## 👤 For End Users

### Setting Up Your VPN Connection

#### Step 1: Get Your Credentials

Your administrator will provide:
1. **Username and password**
2. **Server address** (IP or domain name)
3. **QR code** for two-factor authentication setup

#### Step 2: Set Up Two-Factor Authentication

##### Using Google Authenticator (Recommended)

1. Install Google Authenticator on your phone:
   - [Android](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
   - [iPhone](https://apps.apple.com/app/google-authenticator/id388497605)

2. Open the app and scan the QR code provided by your administrator

3. The app will now generate 6-digit codes every 30 seconds

##### Using Other TOTP Apps

Compatible apps include:
- Authy
- Microsoft Authenticator
- 1Password
- Bitwarden

### Connecting to the VPN

#### Windows 10/11

##### Method 1: Using the provided script
1. Download the `connect.bat` file from your administrator
2. Right-click and "Run as administrator"
3. Follow the prompts to enter your credentials and OTP

##### Method 2: Manual setup
1. Open **Settings** > **Network & Internet** > **VPN**
2. Click **Add a VPN connection**
3. Fill in the details:
   - **VPN provider**: Windows (built-in)
   - **Connection name**: SecureConnect VPN
   - **Server name or address**: [provided by admin]
   - **VPN type**: IKEv2
   - **Type of sign-in info**: User name and password
   - **User name**: [your username]
   - **Password**: [your password + current OTP code]

4. Click **Save**
5. Click **Connect**

#### macOS

1. Open **System Preferences** > **Network**
2. Click the **+** button to add a new connection
3. Choose:
   - **Interface**: VPN
   - **VPN Type**: IKEv2
   - **Service Name**: SecureConnect VPN
4. Fill in:
   - **Server Address**: [provided by admin]
   - **Remote ID**: secureconnect.vpn
   - **Local ID**: [your username]@secureconnect.vpn
5. Click **Authentication Settings**
6. Choose **Username** and enter:
   - **Username**: [your username]
   - **Password**: [your password + current OTP code]
7. Click **OK** and then **Connect**

#### Linux (Ubuntu/Debian)

##### Using the provided script
```bash
cd client/scripts
chmod +x connect.sh
./connect.sh connect
```

##### Manual setup using NetworkManager
```bash
# Install NetworkManager StrongSwan plugin
sudo apt install network-manager-strongswan

# Use GUI to configure:
# Settings > Network > VPN > Add > IPSec/IKEv2 (strongswan)
```

#### Android

1. Install **strongSwan VPN Client** from Google Play Store
2. Open the app and tap **ADD VPN PROFILE**
3. Enter:
   - **Server**: [provided by admin]
   - **VPN Type**: IKEv2 EAP (Username/Password)
   - **Username**: [your username]
   - **Password**: [your password + current OTP code]
4. Tap **SAVE**
5. Tap the profile to connect

#### iOS

1. Go to **Settings** > **General** > **VPN & Device Management** > **VPN**
2. Tap **Add VPN Configuration**
3. Choose **IKEv2**
4. Enter:
   - **Description**: SecureConnect VPN
   - **Server**: [provided by admin]
   - **Remote ID**: secureconnect.vpn
   - **Local ID**: [your username]@secureconnect.vpn
   - **User Authentication**: Username
   - **Username**: [your username]
   - **Password**: [your password + current OTP code]
5. Tap **Done**
6. Toggle the VPN switch to connect

### Using the VPN

#### Connecting

1. **Get your current OTP code** from your authenticator app
2. **Combine your password with the OTP**: 
   - If your password is "mypass123" and OTP is "456789"
   - Enter "mypass123456789" as the password
3. **Connect using your preferred method** (see platform-specific instructions above)

#### Verifying Connection

Once connected, verify your VPN is working:

1. **Check your IP address**:
   - Visit [whatismyipaddress.com](https://whatismyipaddress.com)
   - Your IP should show the VPN server's location

2. **Test DNS resolution**:
   ```bash
   nslookup google.com
   ```

3. **Check for IP leaks**:
   - Visit [ipleak.net](https://ipleak.net)
   - Ensure no DNS or IP leaks are detected

#### Disconnecting

- **Windows**: Settings > Network & Internet > VPN > Disconnect
- **macOS**: System Preferences > Network > Disconnect
- **Linux**: `./connect.sh disconnect` or NetworkManager GUI
- **Android/iOS**: VPN settings > Toggle off

### Troubleshooting

#### Common Issues

##### Authentication Failures

**Problem**: "Authentication failed" error
**Solutions**:
1. Verify your username and password are correct
2. Ensure you're using the current OTP code (codes change every 30 seconds)
3. Try combining password and OTP without spaces
4. Check that your device's time is synchronized (OTP is time-sensitive)

##### Connection Timeouts

**Problem**: Connection times out or fails to establish
**Solutions**:
1. Check your internet connection
2. Verify the server address is correct
3. Ensure ports 500 and 4500 are not blocked by your firewall
4. Try connecting from a different network

##### No Internet After Connecting

**Problem**: VPN connects but no internet access
**Solutions**:
1. Check your VPN client's DNS settings
2. Try different DNS servers (8.8.8.8, 1.1.1.1)
3. Restart your network adapter
4. Contact your administrator

##### OTP Code Not Working

**Problem**: OTP codes are consistently rejected
**Solutions**:
1. Check your device's time is correct (Settings > Date & Time > Automatic)
2. Re-scan the QR code if you recently changed devices
3. Contact your administrator for a new secret key

#### Getting Help

If you continue having issues:

1. **Check with your administrator** - they can see connection logs
2. **Try from a different location** - your current network might block VPN
3. **Test with mobile data** - to rule out Wi-Fi issues
4. **Restart your device** - solves many networking issues

### Best Practices

#### Security

1. **Never share your credentials** - your username, password, and OTP secret are personal
2. **Use strong passwords** - at least 12 characters with mixed case, numbers, and symbols
3. **Keep your devices updated** - install security updates promptly
4. **Don't save passwords** in browsers when using public computers
5. **Disconnect when done** - don't leave VPN connections open unnecessarily

#### Performance

1. **Choose nearby servers** - closer servers typically offer better performance
2. **Use wired connections** when possible - more stable than Wi-Fi
3. **Close unnecessary applications** - reduces bandwidth usage
4. **Monitor data usage** - some VPN usage may count against data caps

#### Privacy

1. **Understand the logs** - ask your administrator what is logged
2. **Use HTTPS websites** - VPN encrypts transport, but websites can still track you
3. **Consider additional privacy tools** - VPN is one layer of privacy protection
4. **Read the privacy policy** - understand how your data is handled

### Frequently Asked Questions

**Q: Can I use the VPN on multiple devices?**
A: Yes, but you'll need to set up the OTP authenticator on each device or use the same secret on multiple authenticator apps.

**Q: What happens if I lose my phone with the authenticator app?**
A: Contact your administrator immediately. They can disable your account and provide new credentials.

**Q: Can I connect from any country?**
A: Generally yes, unless your administrator has implemented geo-blocking.

**Q: Is there a data usage limit?**
A: This depends on your administrator's policies. Check with them for any limitations.

**Q: Can I use this for torrenting or streaming?**
A: Check your organization's acceptable use policy. Some activities may be restricted.

**Q: Why do I need to enter a new code every time?**
A: The OTP (One-Time Password) changes every 30 seconds for security. You always need the current code.

**Q: Can I save my password with the OTP included?**
A: No, because the OTP changes frequently. Always enter password + current OTP code manually.

---

For technical issues not covered here, contact your system administrator or refer to the [Troubleshooting Guide](TROUBLESHOOTING.md).
