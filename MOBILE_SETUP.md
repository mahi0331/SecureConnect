# Mobile VPN Client Setup Guide
# SecureConnect VPN - iOS and Android Configuration

## Prerequisites
✅ SecureConnect VPN server running (use verify_complete.sh to check)
✅ VPN user account created (using OTP CLI tool)
✅ Server IP address noted
✅ iOS 12+ or Android 7+

## iOS Setup (iPhone/iPad)

### Method 1: iOS Settings (Native IKEv2)

1. **Open VPN Settings**
   - Settings → General → VPN & Device Management → VPN
   - Tap "Add VPN Configuration..."

2. **Configure IKEv2 Connection**
   ```
   Type: IKEv2
   Description: SecureConnect VPN
   Server: [YOUR_SERVER_IP]
   Remote ID: [YOUR_SERVER_IP]
   Local ID: [Leave empty]
   User Authentication: Username
   Username: [Created via OTP CLI]
   Password: [Set during user creation]
   ```

3. **Advanced Settings (Optional)**
   - Use Certificate: Off
   - Send All Traffic: On (for full VPN)
   - Proxy: Off

4. **Save and Connect**
   - Tap "Done"
   - Toggle VPN switch to connect
   - Enter password when prompted

### Method 2: iOS Shortcuts (Auto-Connect)

1. **Create Shortcut**
   - Open Shortcuts app
   - Create new shortcut
   - Add "Set VPN" action
   - Configure SecureConnect connection

2. **Add to Home Screen**
   - Name: "Connect VPN"
   - Add to Home Screen for quick access

## Android Setup

### Method 1: Android Settings (Native IKEv2)

1. **Open VPN Settings**
   - Settings → Network & Internet → Advanced → VPN
   - Tap "+" or "Add VPN"

2. **Configure IKEv2 Connection**
   ```
   Name: SecureConnect VPN
   Type: IKEv2/IPSec PSK or IKEv2/IPSec RSA
   Server Address: [YOUR_SERVER_IP]
   IPSec Identifier: [YOUR_SERVER_IP]
   Username: [Created via OTP CLI]
   Password: [Set during user creation]
   ```

3. **Advanced Options**
   - DNS Search Domains: [Leave empty]
   - DNS Servers: 8.8.8.8,1.1.1.1 (optional)
   - Forwarding Routes: 0.0.0.0/0 (for all traffic)

4. **Save and Connect**
   - Tap "Save"
   - Tap connection name to connect
   - Enter credentials when prompted

### Method 2: Third-Party Apps

#### StrongSwan VPN Client (Recommended)
1. **Install from Play Store**
   - Download "strongSwan VPN Client"
   - Open app

2. **Add Profile**
   - Tap "+" to add profile
   - Select "Import Profile"

3. **Manual Configuration**
   ```
   Gateway: [YOUR_SERVER_IP]
   Type: IKEv2 EAP
   Username: [Your username]
   Password: [Your password]
   ```

4. **Certificate Installation**
   - Download CA certificate from server
   - Install in "CA certificates" section

## Mobile Configuration Files

### iOS Configuration Profile (.mobileconfig)
Create and email this file to iOS devices:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDisplayName</key>
            <string>SecureConnect VPN</string>
            <key>PayloadIdentifier</key>
            <string>com.secureconnect.vpn</string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>VPN-UUID-HERE</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>UserDefinedName</key>
            <string>SecureConnect VPN</string>
            <key>VPNType</key>
            <string>IKEv2</string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>[YOUR_SERVER_IP]</string>
                <key>RemoteIdentifier</key>
                <string>[YOUR_SERVER_IP]</string>
                <key>AuthenticationMethod</key>
                <string>None</string>
                <key>ExtendedAuthEnabled</key>
                <integer>1</integer>
                <key>AuthName</key>
                <string>[USERNAME]</string>
                <key>AuthPassword</key>
                <string>[PASSWORD]</string>
            </dict>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>SecureConnect VPN Profile</string>
    <key>PayloadIdentifier</key>
    <string>com.secureconnect.profile</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>PROFILE-UUID-HERE</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

## Verification Steps

### 1. Check Connection Status

#### iOS
- Settings → VPN (shows connected status)
- Status bar shows VPN icon

#### Android
- Notification panel shows VPN active
- Settings → Network shows VPN connected

### 2. Verify IP Address
- Open browser and visit: https://whatismyip.com
- Should show server IP, not your mobile IP

### 3. Test Connectivity
```bash
# Use network testing apps or browser
ping 8.8.8.8
nslookup google.com
```

## Troubleshooting Common Issues

### iOS Issues

#### "The VPN server did not respond"
**Solutions:**
1. Check server IP is correct
2. Verify server is running
3. Try connecting from WiFi vs cellular
4. Reset network settings (last resort)

#### "Authentication failed"
**Solutions:**
1. Verify username/password
2. Check if account is active on server
3. Try recreating user account

#### "Unable to establish a secure connection"
**Solutions:**
1. Check iOS version compatibility
2. Verify certificate installation
3. Try different VPN type (L2TP as fallback)

### Android Issues

#### "Connection unsuccessful"
**Solutions:**
1. Check VPN type setting (IKEv2/IPSec)
2. Verify server address format
3. Clear VPN app data and reconfigure

#### "Authentication failed"
**Solutions:**
1. Double-check credentials
2. Try different authentication method
3. Check server-side user configuration

#### "No internet after connecting"
**Solutions:**
1. Check DNS settings
2. Verify routing configuration
3. Try different DNS servers (8.8.8.8, 1.1.1.1)

## Advanced Mobile Features

### Auto-Connect on Untrusted Networks

#### iOS Shortcuts Automation
1. **Create Automation**
   - Shortcuts app → Automation → Create Personal Automation
   - Wi-Fi: When joining any network
   - Add action: Connect to VPN

2. **Trusted Networks Exception**
   - Create separate automation for home/work WiFi
   - Action: Disconnect VPN

#### Android Tasker Integration
```
Profile: WiFi Connected (not home/work)
Task: Connect SecureConnect VPN
```

### Kill Switch Configuration

#### iOS
- Settings → VPN → Connect On Demand
- Add trusted WiFi networks
- Enable "Connect On Demand" for untrusted networks

#### Android
- Many VPN apps have built-in kill switch
- StrongSwan: Enable "Block connections without VPN"

## Battery Optimization

### iOS Battery Saving
1. **Optimize for Battery**
   - Settings → Battery → Low Power Mode compatibility
   - VPN connections maintained in low power mode

2. **Background App Refresh**
   - Keep VPN apps enabled for background refresh

### Android Battery Optimization
1. **Disable Battery Optimization**
   - Settings → Apps → VPN App → Battery → Not optimized

2. **Auto-Start Management**
   - Allow VPN app to auto-start
   - Add to protected apps list

## Monitoring and Logs

### iOS Logs
- Settings → Privacy & Security → Analytics & Improvements
- Share with App Developers → Analytics Data
- Search for VPN-related entries

### Android Logs
- Developer Options → Bug Reports
- VPN app logs (if available)
- System logs via ADB

## Mobile Hotspot Sharing

### iOS Personal Hotspot
1. **Enable with VPN**
   - Connect to VPN first
   - Settings → Personal Hotspot → Allow Others to Join
   - Connected devices will use VPN connection

2. **Configuration**
   - Set strong hotspot password
   - Monitor connected devices

### Android Hotspot
1. **Mobile Hotspot with VPN**
   - Connect to VPN
   - Settings → Network → Hotspot & Tethering
   - Enable Mobile Hotspot
   - All connected devices route through VPN

## Performance Optimization

### Connection Speed Tips
1. **Choose Optimal Server Protocol**
   - IKEv2 generally fastest on mobile
   - Test different encryption levels

2. **Network Selection**
   - 5GHz WiFi typically faster than 2.4GHz
   - LTE often faster than WiFi in crowded areas

### Data Usage Monitoring
- iOS: Settings → Cellular → VPN Data Usage
- Android: Settings → Network → Data Usage → VPN

## Security Best Practices

### 1. Regular Updates
- Keep mobile OS updated
- Update VPN credentials monthly
- Monitor connection logs on dashboard

### 2. Secure Credential Storage
- Use built-in keychain/keystore
- Avoid saving passwords in plain text
- Enable device lock screen

### 3. Network Hygiene
- Avoid public WiFi for sensitive activities
- Always connect VPN before browsing
- Use HTTPS websites whenever possible

## Dashboard Integration

### View Mobile Connections
- Open browser: http://[SERVER_IP]:5000
- Login: admin / admin123
- Mobile connections show:
  - Device type (iOS/Android)
  - Mobile carrier IP
  - Connection duration
  - Data usage statistics

### Real-time Mobile Monitoring
Your mobile connection appears in dashboard with:
- Device identification
- Original mobile IP address
- VPN tunnel IP (10.10.11.x range)
- Connection quality metrics
- Bandwidth utilization

## Quick Setup Summary

### iOS Quick Steps
1. Settings → VPN → Add VPN
2. Type: IKEv2, Server: [IP], Credentials: [User/Pass]
3. Connect and verify IP change

### Android Quick Steps
1. Settings → VPN → Add VPN
2. Type: IKEv2/IPSec, Server: [IP], Credentials: [User/Pass]
3. Connect and verify IP change

### Verification Checklist
✅ VPN icon appears in status bar
✅ IP address changes to server IP
✅ Internet browsing works normally
✅ Connection appears in admin dashboard
✅ DNS leaks test passes

**Support:** Monitor your mobile connection at http://[SERVER_IP]:5000 for real-time status and troubleshooting.
