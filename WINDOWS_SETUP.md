# Windows VPN Client Setup Guide
# SecureConnect VPN - Windows 10/11 Configuration

## Prerequisites
✅ SecureConnect VPN server running (use verify_complete.sh to check)
✅ VPN user account created (using OTP CLI tool)
✅ Server IP address noted
✅ Windows 10 or Windows 11

## Step-by-Step Windows Setup

### Method 1: Windows Settings (Recommended)

1. **Open VPN Settings**
   - Press `Win + I` to open Settings
   - Navigate to `Network & Internet` → `VPN`
   - Click `Add VPN`

2. **Configure VPN Connection**
   ```
   VPN Provider: Windows (built-in)
   Connection Name: SecureConnect VPN
   Server Name or Address: [YOUR_SERVER_IP]
   VPN Type: IKEv2
   Type of Sign-in Info: User name and password
   ```

3. **Enter Credentials**
   - Username: [Created via OTP CLI]
   - Password: [Set during user creation]
   - Check "Remember my sign-in info" (optional)

4. **Save and Connect**
   - Click `Save`
   - Click on your new VPN connection
   - Click `Connect`

### Method 2: Control Panel (Alternative)

1. **Open Network Connections**
   - Press `Win + R`, type `ncpa.cpl`, press Enter
   - Or Control Panel → Network and Sharing Center → Change adapter settings

2. **Create New Connection**
   - Press `Alt` to show menu bar
   - File → New Incoming Connection
   - Follow wizard to create VPN connection

3. **Configure Connection Properties**
   - Right-click new connection → Properties
   - Security tab → Type: IKEv2
   - Authentication → Use Extensible Authentication Protocol (EAP)

### Method 3: PowerShell (Advanced Users)

```powershell
# Run as Administrator
Add-VpnConnection -Name "SecureConnect" -ServerAddress "[YOUR_SERVER_IP]" -TunnelType IKEv2 -AuthenticationMethod EAP -EncryptionLevel Required
```

## Verification Steps

### 1. Check Connection Status
```powershell
# Check VPN status
Get-VpnConnection -Name "SecureConnect"

# Test connectivity
ping 10.10.10.1
```

### 2. Verify IP Address
```powershell
# Check your new IP
curl ifconfig.me
# Or visit: https://whatismyipaddress.com
```

### 3. DNS Leak Test
- Visit: https://dnsleaktest.com
- Verify DNS requests go through VPN

## Troubleshooting Common Issues

### Connection Failed - Error 809
**Cause:** Windows firewall or NAT-T issues
**Solution:**
```powershell
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "AssumeUDPEncapsulationContextOnSendRule" -Value 2 -PropertyType DWord
Restart-Computer
```

### Connection Failed - Error 13806
**Cause:** IKEv2 configuration mismatch
**Solution:**
1. Delete existing connection
2. Recreate with exact server IP (no DNS names)
3. Ensure authentication method is correct

### Cannot Access Internet After Connection
**Cause:** Routing issues
**Solution:**
```powershell
# Reset network adapter
netsh winsock reset
netsh int ip reset
ipconfig /flushdns
Restart-Computer
```

### Authentication Failed
**Cause:** Wrong credentials or server not reachable
**Solution:**
1. Verify username/password with OTP CLI
2. Check server is running: `ping [SERVER_IP]`
3. Test ports: `telnet [SERVER_IP] 500`

## Advanced Configuration

### Split Tunneling (Route Specific Traffic)
```powershell
# Route only specific networks through VPN
Set-VpnConnection -Name "SecureConnect" -SplitTunneling $True
Add-VpnConnectionRoute -ConnectionName "SecureConnect" -DestinationPrefix "192.168.1.0/24"
```

### Always-On VPN
```powershell
# Enable auto-connect
Set-VpnConnection -Name "SecureConnect" -AllUserConnection $True
```

### Custom DNS Servers
1. VPN Connection Properties
2. Networking tab → Internet Protocol Version 4 (TCP/IPv4)
3. Properties → Advanced → DNS tab
4. Add custom DNS servers

## Monitoring and Logs

### Connection Events
```powershell
# View VPN connection logs
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='RasClient'}
```

### Performance Monitoring
```powershell
# Monitor VPN adapter
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*WAN Miniport*"}
```

## Security Best Practices

### 1. Regular Updates
- Keep Windows updated
- Update VPN credentials regularly
- Monitor connection logs on dashboard

### 2. Firewall Configuration
```powershell
# Allow VPN traffic
New-NetFirewallRule -DisplayName "VPN IKEv2" -Direction Inbound -Protocol UDP -LocalPort 500,4500
```

### 3. Kill Switch (Disconnect if VPN Fails)
```powershell
# Block internet if VPN disconnects
New-NetFirewallRule -DisplayName "Block Non-VPN" -Direction Outbound -Action Block -InterfaceType !("SecureConnect")
```

## Testing Connection Quality

### Speed Test
```powershell
# Install speedtest CLI
winget install Ookla.Speedtest.CLI
# Test speed
speedtest
```

### Latency Test
```powershell
# Test ping to various servers
ping 8.8.8.8
ping 1.1.1.1
ping google.com
```

## Mobile Hotspot Sharing

### Share VPN Connection via Hotspot
1. Settings → Network & Internet → Mobile hotspot
2. Share my Internet connection from: SecureConnect VPN
3. Turn on Mobile hotspot

## Automation Scripts

### Auto-Connect on Boot
Create `vpn_autoconnect.ps1`:
```powershell
# Auto-connect to VPN on startup
Start-Sleep -Seconds 30  # Wait for network
rasdial "SecureConnect" [username] [password]
```

Add to Task Scheduler:
- Trigger: At startup
- Action: Start PowerShell script
- Run with highest privileges

### Connection Monitor
Create `vpn_monitor.ps1`:
```powershell
# Monitor VPN connection and reconnect if needed
while ($true) {
    $vpn = Get-VpnConnection -Name "SecureConnect"
    if ($vpn.ConnectionStatus -ne "Connected") {
        rasdial "SecureConnect"
        Write-Host "$(Get-Date): VPN reconnected"
    }
    Start-Sleep -Seconds 60
}
```

## Dashboard Integration

### View Your Connection
- Open browser: http://[SERVER_IP]:5000
- Login: admin / admin123
- View your IP address in connection logs
- Monitor bandwidth usage
- Check authentication history

### Real-time Monitoring
Your connection will appear in the dashboard with:
- Your Windows username
- Public IP address
- Connection time
- Data transferred
- Authentication logs

## Summary

✅ **Connection Method:** Windows built-in IKEv2
✅ **Security:** AES-256 encryption with certificate authentication
✅ **Compatibility:** Windows 10/11 native support
✅ **Monitoring:** Real-time IP tracking on admin dashboard
✅ **Authentication:** OTP-based user management

**Support:** Check dashboard at http://[SERVER_IP]:5000 for connection status and troubleshooting.
