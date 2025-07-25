# SecureConnect VPN - Configuration Reference

This document provides comprehensive configuration options for SecureConnect VPN.

## 📁 Configuration File Locations

### Server Configuration Files
- `/etc/ipsec.conf` - Main StrongSwan connection definitions
- `/etc/ipsec.secrets` - Authentication secrets and keys
- `/etc/strongswan.d/charon.conf` - Charon daemon configuration
- `server/otp_auth/users.db` - User database (SQLite)
- `web_dashboard/app.py` - Dashboard configuration

### Client Configuration Files
- `client/configs/` - Client-specific configurations
- `$HOME/.secureconnect/` - User configuration directory

## 🔧 StrongSwan Configuration

### Main Configuration (/etc/ipsec.conf)

#### Basic Connection Template
```conf
conn connection-name
    # Connection type and mode
    type=tunnel                    # tunnel mode (vs transport)
    keyexchange=ikev2             # IKE version (ikev1 or ikev2)
    
    # Left side (typically server)
    left=%any                     # IP address (%any for auto-detect)
    leftid=@server.domain.com     # Identity string
    leftsubnet=0.0.0.0/0         # Subnets to tunnel
    leftcert=server-cert.pem      # Server certificate
    leftkey=server-key.pem        # Server private key
    leftsendcert=always           # Send certificate policy
    
    # Right side (typically client)
    right=%any                    # Accept any client IP
    rightid=%any                  # Accept any client identity
    rightsourceip=10.10.10.0/24   # IP pool for clients
    rightdns=8.8.8.8,8.8.4.4     # DNS servers for clients
    
    # Authentication
    authby=pubkey                 # Authentication method
    
    # Encryption algorithms
    ike=aes256-sha256-modp2048!   # IKE encryption proposal
    esp=aes256-sha256-modp2048!   # ESP encryption proposal
    
    # Connection behavior
    auto=add                      # Load but don't start automatically
    closeaction=restart           # Action on unexpected close
    dpdaction=restart             # Dead peer detection action
    dpddelay=30s                  # DPD check interval
    dpdtimeout=120s              # DPD timeout
    
    # Key management
    keylife=1h                    # SA lifetime
    rekeymargin=3m                # Rekey margin
    keyingtries=3                 # Key exchange retry attempts
```

#### Encryption Algorithms

**Strong encryption (recommended)**:
```conf
ike=aes256-sha256-modp2048!
esp=aes256-sha256-modp2048!
```

**Maximum security**:
```conf
ike=aes256-sha384-modp4096!
esp=aes256-sha384-modp4096!
```

**Compatibility mode** (for older clients):
```conf
ike=aes128-sha1-modp1024,aes256-sha256-modp2048!
esp=aes128-sha1,aes256-sha256!
```

#### Client Pool Configuration

**Single subnet**:
```conf
rightsourceip=10.10.10.0/24
```

**Multiple subnets**:
```conf
rightsourceip=10.10.10.0/24,10.10.11.0/24
```

**Individual IP assignment**:
```conf
rightsourceip=10.10.10.100
```

### Secrets Configuration (/etc/ipsec.secrets)

#### Certificate-based authentication:
```conf
# Server private key
: RSA server-key.pem

# Client certificates
client1@domain.com : RSA client1-key.pem
client2@domain.com : RSA client2-key.pem
```

#### Pre-shared key authentication:
```conf
# Global PSK (not recommended for production)
%any %any : PSK "your-very-strong-psk-here"

# User-specific PSKs
server.domain.com client1@domain.com : PSK "user1-specific-psk"
server.domain.com client2@domain.com : PSK "user2-specific-psk"
```

#### EAP authentication:
```conf
# Username/password for EAP
username1 : EAP "password1"
username2 : EAP "password2"
```

### Charon Configuration (/etc/strongswan.d/charon.conf)

#### Logging Configuration
```conf
charon {
    filelog {
        /var/log/strongswan.log {
            time_format = %b %e %T
            default = 1
            append = yes
            flush_line = yes
            ike = 2
            cfg = 2
            knl = 2
            net = 2
            esp = 2
            dmn = 2
            mgr = 2
        }
    }
}
```

#### Performance Tuning
```conf
charon {
    threads = 16                  # Worker threads
    processor {
        priority_threads {
            high = 3
            medium = 2
            low = 1
        }
    }
    
    # Network settings
    port = 500                    # IKE port
    port_nat_t = 4500            # NAT-T port
    keep_alive = 20              # Keep-alive interval
    max_packet = 10000           # Maximum packet size
    
    # Connection limits
    ikesa_limit = 0              # No limit on IKE SAs
    half_open_timeout = 30       # Half-open SA timeout
}
```

## 🔐 OTP Authentication Configuration

### Database Configuration

#### SQLite Database Schema
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    secret_key TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Authentication logs
CREATE TABLE auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);
```

### OTP Server Configuration

#### Email Settings (server/otp_auth/config.py)
```python
# SMTP configuration for email-based OTP
SMTP_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'from_email': 'vpn-noreply@yourdomain.com',
    'password': 'your-app-password',
    'use_tls': True
}

# OTP settings
OTP_CONFIG = {
    'issuer_name': 'SecureConnect VPN',
    'valid_window': 1,           # Allow 1 time step tolerance
    'lockout_attempts': 5,       # Lock after 5 failed attempts
    'lockout_duration': 900,     # 15 minutes lockout
    'session_timeout': 3600      # 1 hour session timeout
}
```

#### Database Configuration
```python
# Database settings
DATABASE_CONFIG = {
    'path': 'users.db',
    'backup_interval': 3600,     # Backup every hour
    'backup_retention': 30,      # Keep 30 backups
    'vacuum_interval': 86400     # Vacuum daily
}
```

## 🌐 Web Dashboard Configuration

### Flask Application Settings

#### Basic Configuration (web_dashboard/app.py)
```python
# Dashboard configuration
DASHBOARD_CONFIG = {
    'title': 'SecureConnect VPN Dashboard',
    'version': '1.0.0',
    'admin_user': 'admin',
    'admin_password': 'secure_password_here',  # Change this!
    'refresh_interval': 30,      # Auto-refresh interval (seconds)
    'session_timeout': 3600,     # Session timeout (seconds)
    'max_login_attempts': 3,     # Max login attempts before lockout
    'lockout_duration': 300      # Lockout duration (seconds)
}

# Flask settings
app.config.update({
    'SECRET_KEY': 'your-secret-key-here',
    'SESSION_COOKIE_SECURE': True,     # Enable for HTTPS
    'SESSION_COOKIE_HTTPONLY': True,
    'PERMANENT_SESSION_LIFETIME': 3600,
    'DEBUG': False                     # Disable in production
})
```

#### Security Headers
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

## 🔥 Firewall Configuration

### iptables Rules

#### Basic VPN Rules
```bash
#!/bin/bash
# firewall_rules.sh

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH (change port as needed)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow IKE (Internet Key Exchange)
iptables -A INPUT -p udp --dport 500 -j ACCEPT

# Allow NAT-T (NAT Traversal)
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# Allow ESP (Encapsulating Security Payload)
iptables -A INPUT -p esp -j ACCEPT

# Allow web dashboard (optional)
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

# Forward VPN traffic
iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT

# NAT for VPN clients
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE

# Drop everything else
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
```

#### Advanced Security Rules
```bash
# Rate limiting for VPN connections
iptables -A INPUT -p udp --dport 500 -m limit --limit 10/min --limit-burst 5 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -m limit --limit 10/min --limit-burst 5 -j ACCEPT

# Block common attack patterns
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Geographic blocking (example: block specific countries)
# iptables -A INPUT -m geoip --src-cc CN,RU -j DROP

# DDoS protection
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
```

### UFW Configuration (Ubuntu)

#### Enable UFW and set defaults
```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

#### Allow VPN traffic
```bash
# SSH access
sudo ufw allow 22/tcp

# VPN ports
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

# Web dashboard
sudo ufw allow 5000/tcp

# Enable UFW
sudo ufw --force enable
```

#### VPN-specific UFW rules
```bash
# Add to /etc/ufw/before.rules before the *filter section:
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
COMMIT

# Add to *filter section:
-A ufw-before-forward -s 10.10.10.0/24 -j ACCEPT
-A ufw-before-forward -d 10.10.10.0/24 -j ACCEPT
```

## 🚀 Performance Optimization

### Kernel Parameters (/etc/sysctl.conf)

#### Network optimization
```conf
# IP forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# TCP optimization
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# UDP optimization
net.core.netdev_max_backlog = 5000
net.ipv4.udp_mem = 102400 873800 16777216

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 86400

# Security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
```

### StrongSwan Performance Tuning

#### High-load configuration
```conf
charon {
    # Increase worker threads for high load
    threads = 32
    
    # Processor settings
    processor {
        priority_threads {
            high = 8
            medium = 4
            low = 2
        }
    }
    
    # Reduce timers for faster processing
    half_open_timeout = 15
    keep_alive = 10
    
    # Increase packet size for better throughput
    max_packet = 65536
    
    # Enable hardware acceleration
    plugins {
        aesni {
            load = yes
        }
    }
}
```

## 📊 Monitoring Configuration

### Log Configuration

#### StrongSwan detailed logging
```conf
charon {
    filelog {
        /var/log/strongswan.log {
            time_format = %b %e %T
            default = 1
            append = yes
            flush_line = yes
            ike = 3
            cfg = 2
            knl = 2
            net = 2
            esp = 2
            dmn = 2
            mgr = 2
        }
        stderr {
            default = 1
            ike = 2
            cfg = 2
        }
    }
}
```

#### Logrotate configuration (/etc/logrotate.d/strongswan)
```conf
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
```

### SNMP Monitoring (Optional)

#### Install and configure SNMP
```bash
sudo apt install snmp snmp-mibs-downloader
sudo download-mibs

# Configure SNMP community
echo "rocommunity public" | sudo tee -a /etc/snmp/snmpd.conf
sudo systemctl restart snmpd
```

#### Monitor VPN connections via SNMP
```bash
# Get interface statistics
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.2.2.1.10

# Get system uptime
snmpget -v2c -c public localhost 1.3.6.1.2.1.1.3.0
```

## 🔒 Certificate Management

### Certificate Authority Configuration

#### OpenSSL CA configuration (ca.conf)
```conf
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[req_distinguished_name]
countryName = Country Name (2 letter code)
stateOrProvinceName = State or Province Name
localityName = Locality Name
0.organizationName = Organization Name
organizationalUnitName = Organizational Unit Name
commonName = Common Name
emailAddress = Email Address

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

#### Server certificate configuration (server.conf)
```conf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
CN = secureconnect.vpn

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = serverAuth, 1.3.6.1.5.5.8.2.2

[alt_names]
DNS.1 = secureconnect.vpn
DNS.2 = vpn.yourdomain.com
IP.1 = 192.168.1.100
```

### Automated Certificate Renewal

#### Certificate renewal script
```bash
#!/bin/bash
# renew_certificates.sh

CERT_DIR="/etc/ipsec.d"
PKI_DIR="/root/pki"
BACKUP_DIR="/backup/certificates"

# Create backup
mkdir -p "$BACKUP_DIR/$(date +%Y%m%d)"
cp -r "$CERT_DIR" "$BACKUP_DIR/$(date +%Y%m%d)/"

# Check certificate expiry
EXPIRY_DATE=$(openssl x509 -in "$CERT_DIR/certs/server-cert.pem" -noout -enddate | cut -d= -f2)
EXPIRY_TIMESTAMP=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_TIMESTAMP=$(date +%s)
DAYS_UNTIL_EXPIRY=$(( (EXPIRY_TIMESTAMP - CURRENT_TIMESTAMP) / 86400 ))

# Renew if less than 30 days until expiry
if [ $DAYS_UNTIL_EXPIRY -lt 30 ]; then
    echo "Certificate expires in $DAYS_UNTIL_EXPIRY days. Renewing..."
    
    # Generate new certificate
    cd "$PKI_DIR"
    ./generate_server_cert.sh
    
    # Install new certificate
    cp server-cert-new.pem "$CERT_DIR/certs/server-cert.pem"
    cp server-key-new.pem "$CERT_DIR/private/server-key.pem"
    chmod 600 "$CERT_DIR/private/server-key.pem"
    
    # Restart StrongSwan
    systemctl restart strongswan
    
    echo "Certificate renewed successfully"
else
    echo "Certificate valid for $DAYS_UNTIL_EXPIRY days. No renewal needed."
fi
```

This comprehensive configuration reference covers all major aspects of SecureConnect VPN configuration. Adjust the settings based on your specific requirements and security policies.
