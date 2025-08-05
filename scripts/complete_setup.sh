#!/bin/bash

# SecureConnect VPN - Complete Setup Script
# This script sets up everything for Windows, Mobile, and IP tracking

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  SecureConnect VPN - Complete Setup${NC}"
echo -e "${BLUE}=================================================${NC}"
echo

# Get project directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_IP=$(hostname -I | awk '{print $1}')

echo -e "${BLUE}🌐 Server IP: $SERVER_IP${NC}"
echo -e "${BLUE}📁 Project directory: $PROJECT_ROOT${NC}"
echo

# Step 1: Update system
echo -e "${YELLOW}📦 Step 1: Updating system packages...${NC}"
apt update && apt upgrade -y
echo -e "${GREEN}✅ System updated${NC}"
echo

# Step 2: Install required packages
echo -e "${YELLOW}📦 Step 2: Installing VPN and security packages...${NC}"
apt install -y \
    strongswan \
    strongswan-pki \
    libcharon-extra-plugins \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    openssl \
    iptables \
    iptables-persistent \
    net-tools \
    sqlite3 \
    ufw
echo -e "${GREEN}✅ Packages installed${NC}"
echo

# Step 3: Setup Python environment
echo -e "${YELLOW}🐍 Step 3: Setting up Python environment...${NC}"
cd "$PROJECT_ROOT"

# Remove existing venv if it exists
if [ -d "venv" ]; then
    rm -rf venv
fi

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install --break-system-packages flask pyotp qrcode[pil] requests sqlite3
echo -e "${GREEN}✅ Python environment ready${NC}"
echo

# Step 4: Configure network settings
echo -e "${YELLOW}🌐 Step 4: Configuring network settings...${NC}"
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p
echo -e "${GREEN}✅ IP forwarding enabled${NC}"
echo

# Step 5: Generate certificates
echo -e "${YELLOW}🔐 Step 5: Generating SSL certificates...${NC}"
mkdir -p /etc/ipsec.d/{private,certs,cacerts}

cd "$PROJECT_ROOT"

# Generate CA key
ipsec pki --gen --type rsa --size 4096 --outform pem > ca-key.pem

# Generate CA certificate
ipsec pki --self --ca --lifetime 3650 --in ca-key.pem \
    --type rsa --dn "CN=SecureConnect VPN CA" \
    --outform pem > ca-cert.pem

# Generate server key
ipsec pki --gen --type rsa --size 4096 --outform pem > server-key.pem

# Generate server certificate
ipsec pki --pub --in server-key.pem --type rsa | \
ipsec pki --issue --lifetime 1825 --cacert ca-cert.pem \
    --cakey ca-key.pem --dn "CN=$SERVER_IP" \
    --san "$SERVER_IP" --flag serverAuth \
    --flag ikeIntermediate --outform pem > server-cert.pem

# Install certificates
cp ca-cert.pem /etc/ipsec.d/cacerts/
cp server-cert.pem /etc/ipsec.d/certs/
cp server-key.pem /etc/ipsec.d/private/
chmod 600 /etc/ipsec.d/private/server-key.pem

echo -e "${GREEN}✅ Certificates generated and installed${NC}"
echo

# Step 6: Configure StrongSwan for Windows/Mobile support
echo -e "${YELLOW}⚙️  Step 6: Configuring StrongSwan VPN...${NC}"

# Backup original configs
cp /etc/ipsec.conf /etc/ipsec.conf.backup 2>/dev/null || true
cp /etc/ipsec.secrets /etc/ipsec.secrets.backup 2>/dev/null || true

# Create comprehensive ipsec.conf for Windows/Mobile support
cat > /etc/ipsec.conf << EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

# Windows 10/11 IKEv2 connection
conn windows-ikev2
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=$SERVER_IP
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity

# Mobile devices (iOS/Android)
conn mobile-ikev2
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=$SERVER_IP
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.11.0/24
    rightdns=8.8.8.8,1.1.1.1
    rightsendcert=never
    eap_identity=%identity
EOF

# Create ipsec.secrets
cat > /etc/ipsec.secrets << EOF
: RSA "server-key.pem"
: PSK "SecureConnect2024VPN"
EOF

chmod 644 /etc/ipsec.conf
chmod 600 /etc/ipsec.secrets

echo -e "${GREEN}✅ StrongSwan configured for Windows/Mobile${NC}"
echo

# Step 7: Configure advanced firewall
echo -e "${YELLOW}🔥 Step 7: Configuring firewall for VPN access...${NC}"

# Reset firewall
ufw --force reset
ufw --force enable

# Allow SSH (important!)
ufw allow 22/tcp

# Allow VPN ports
ufw allow 500/udp
ufw allow 4500/udp

# Allow web dashboard
ufw allow 5000/tcp

# Advanced iptables rules for VPN
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)

# NAT for Windows clients
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o $INTERFACE -j MASQUERADE

# NAT for Mobile clients
iptables -t nat -A POSTROUTING -s 10.10.11.0/24 -o $INTERFACE -j MASQUERADE

# Forward VPN traffic
iptables -A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out -d 10.10.10.0/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir in -s 10.10.11.0/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out -d 10.10.11.0/24 -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

echo -e "${GREEN}✅ Firewall configured${NC}"
echo

# Step 8: Setup enhanced OTP system with IP tracking
echo -e "${YELLOW}🗄️  Step 8: Setting up enhanced authentication system...${NC}"
cd "$PROJECT_ROOT/server/otp_auth"
source ../../venv/bin/activate

# Create enhanced database with IP tracking
python3 << 'EOF'
import sqlite3
import os

# Create enhanced database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Users table with enhanced fields
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    otp_secret TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active INTEGER DEFAULT 1,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    device_type TEXT,
    last_ip TEXT
)''')

# Connection logs table for IP tracking
c.execute('''CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    client_ip TEXT,
    device_type TEXT,
    connection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    disconnection_time TIMESTAMP,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    status TEXT,
    FOREIGN KEY (username) REFERENCES users (username)
)''')

# Authentication logs
c.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip_address TEXT,
    action TEXT,
    success INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
)''')

conn.commit()
conn.close()
print('✅ Enhanced database with IP tracking created successfully!')
EOF

echo -e "${GREEN}✅ Enhanced authentication system ready${NC}"
echo

# Step 9: Setup enhanced web dashboard
echo -e "${YELLOW}🌐 Step 9: Setting up enhanced web dashboard...${NC}"
cd "$PROJECT_ROOT/web_dashboard"

# Create enhanced Flask app with IP tracking
cat > app.py << 'EOF'
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
import sqlite3
import os
import subprocess
import json
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'SecureConnect2024VPN'

# Database path
DB_PATH = '../server/otp_auth/users.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def check_admin_login(username, password):
    # Simple admin check (you should enhance this)
    return username == 'admin' and password == 'admin123'

def get_vpn_status():
    try:
        result = subprocess.run(['ipsec', 'status'], capture_output=True, text=True)
        return result.stdout
    except:
        return "VPN status unavailable"

def get_connected_clients():
    try:
        result = subprocess.run(['ipsec', 'statusall'], capture_output=True, text=True)
        return result.stdout
    except:
        return "No active connections"

@app.route('/')
def dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    # Get connection statistics
    conn = get_db_connection()
    
    # Active connections
    active_connections = conn.execute('''
        SELECT username, client_ip, device_type, connection_time 
        FROM connection_logs 
        WHERE disconnection_time IS NULL 
        ORDER BY connection_time DESC
    ''').fetchall()
    
    # Recent connections
    recent_connections = conn.execute('''
        SELECT username, client_ip, device_type, connection_time, disconnection_time
        FROM connection_logs 
        ORDER BY connection_time DESC 
        LIMIT 10
    ''').fetchall()
    
    # User statistics
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    active_users = conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0]
    
    # Authentication logs
    auth_logs = conn.execute('''
        SELECT username, ip_address, action, success, timestamp 
        FROM auth_logs 
        ORDER BY timestamp DESC 
        LIMIT 20
    ''').fetchall()
    
    conn.close()
    
    vpn_status = get_vpn_status()
    connected_clients = get_connected_clients()
    
    return render_template('dashboard.html',
                         active_connections=active_connections,
                         recent_connections=recent_connections,
                         total_users=total_users,
                         active_users=active_users,
                         auth_logs=auth_logs,
                         vpn_status=vpn_status,
                         connected_clients=connected_clients)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if check_admin_login(username, password):
            session['admin_logged_in'] = True
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/users')
def users():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    users = conn.execute('''
        SELECT username, created_at, last_login, is_active, last_ip, device_type
        FROM users 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('users.html', users=users)

@app.route('/api/stats')
def api_stats():
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db_connection()
    
    stats = {
        'total_users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'active_connections': conn.execute('SELECT COUNT(*) FROM connection_logs WHERE disconnection_time IS NULL').fetchone()[0],
        'total_connections_today': conn.execute('SELECT COUNT(*) FROM connection_logs WHERE DATE(connection_time) = DATE("now")').fetchone()[0],
        'server_uptime': get_vpn_status()
    }
    
    conn.close()
    return jsonify(stats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

# Create templates directory and basic templates
mkdir -p templates

# Create base template
cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}SecureConnect VPN Admin{% endblock %}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 15px; margin: -20px -20px 20px; border-radius: 8px 8px 0 0; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; padding: 8px 15px; background: #3498db; color: white; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #2980b9; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #ecf0f1; padding: 15px; border-radius: 4px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background: #34495e; color: white; }
        .status-active { color: green; font-weight: bold; }
        .status-inactive { color: red; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SecureConnect VPN Admin Dashboard</h1>
        </div>
        
        {% if session.admin_logged_in %}
        <div class="nav">
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('users') }}">Users</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
        {% endif %}
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
</body>
</html>
EOF

# Create dashboard template
cat > templates/dashboard.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="stats">
    <div class="stat-card">
        <div class="stat-number">{{ total_users }}</div>
        <div>Total Users</div>
    </div>
    <div class="stat-card">
        <div class="stat-number">{{ active_users }}</div>
        <div>Active Users</div>
    </div>
    <div class="stat-card">
        <div class="stat-number">{{ active_connections|length }}</div>
        <div>Active Connections</div>
    </div>
</div>

<h2>🌐 Active VPN Connections</h2>
<table class="table">
    <thead>
        <tr>
            <th>Username</th>
            <th>Client IP</th>
            <th>Device Type</th>
            <th>Connected Since</th>
        </tr>
    </thead>
    <tbody>
        {% for conn in active_connections %}
        <tr>
            <td>{{ conn.username }}</td>
            <td><strong>{{ conn.client_ip }}</strong></td>
            <td>{{ conn.device_type or 'Unknown' }}</td>
            <td>{{ conn.connection_time }}</td>
        </tr>
        {% else %}
        <tr><td colspan="4">No active connections</td></tr>
        {% endfor %}
    </tbody>
</table>

<h2>📊 Recent Authentication Attempts</h2>
<table class="table">
    <thead>
        <tr>
            <th>Username</th>
            <th>IP Address</th>
            <th>Action</th>
            <th>Status</th>
            <th>Timestamp</th>
        </tr>
    </thead>
    <tbody>
        {% for log in auth_logs %}
        <tr>
            <td>{{ log.username }}</td>
            <td><strong>{{ log.ip_address }}</strong></td>
            <td>{{ log.action }}</td>
            <td class="{% if log.success %}status-active{% else %}status-inactive{% endif %}">
                {% if log.success %}✅ Success{% else %}❌ Failed{% endif %}
            </td>
            <td>{{ log.timestamp }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>

<h2>🔍 VPN Server Status</h2>
<pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{{ vpn_status }}</pre>
{% endblock %}
EOF

# Create login template
cat > templates/login.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div style="max-width: 400px; margin: 50px auto;">
    <h2>Admin Login</h2>
    <form method="POST" style="background: #f8f9fa; padding: 20px; border-radius: 4px;">
        <div style="margin-bottom: 15px;">
            <label>Username:</label>
            <input type="text" name="username" required style="width: 100%; padding: 8px; margin-top: 5px;">
        </div>
        <div style="margin-bottom: 15px;">
            <label>Password:</label>
            <input type="password" name="password" required style="width: 100%; padding: 8px; margin-top: 5px;">
        </div>
        <button type="submit" style="background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer;">Login</button>
    </form>
    <p style="margin-top: 20px; text-align: center; color: #666;">
        Default: admin / admin123<br>
        <small>⚠️ Change this password after first login!</small>
    </p>
</div>
{% endblock %}
EOF

# Create users template
cat > templates/users.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<h2>👥 VPN Users</h2>
<table class="table">
    <thead>
        <tr>
            <th>Username</th>
            <th>Created</th>
            <th>Last Login</th>
            <th>Status</th>
            <th>Last IP</th>
            <th>Device Type</th>
        </tr>
    </thead>
    <tbody>
        {% for user in users %}
        <tr>
            <td>{{ user.username }}</td>
            <td>{{ user.created_at }}</td>
            <td>{{ user.last_login or 'Never' }}</td>
            <td class="{% if user.is_active %}status-active{% else %}status-inactive{% endif %}">
                {% if user.is_active %}Active{% else %}Inactive{% endif %}
            </td>
            <td><strong>{{ user.last_ip or 'N/A' }}</strong></td>
            <td>{{ user.device_type or 'Unknown' }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
EOF

echo -e "${GREEN}✅ Enhanced web dashboard created${NC}"
echo

# Step 10: Enable and start services
echo -e "${YELLOW}🚀 Step 10: Starting VPN services...${NC}"

# Enable and start StrongSwan
systemctl enable strongswan-starter
systemctl start strongswan-starter

# Create systemd service for dashboard
cat > /etc/systemd/system/secureconnect-dashboard.service << EOF
[Unit]
Description=SecureConnect VPN Dashboard
After=network.target

[Service]
Type=simple
User=$SUDO_USER
Group=$SUDO_USER
WorkingDirectory=$PROJECT_ROOT/web_dashboard
Environment=PATH=$PROJECT_ROOT/venv/bin
ExecStart=$PROJECT_ROOT/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable secureconnect-dashboard
systemctl start secureconnect-dashboard

echo -e "${GREEN}✅ Services started${NC}"
echo

# Final success message
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}  🎉 SecureConnect VPN Setup Complete!${NC}"
echo -e "${GREEN}=================================================${NC}"
echo
echo -e "${BLUE}🌐 Server Details:${NC}"
echo "  📍 Server IP: $SERVER_IP"
echo "  🔌 VPN Ports: UDP 500, 4500"
echo "  🌐 Web Dashboard: http://$SERVER_IP:5000"
echo "  🔑 Dashboard Login: admin / admin123"
echo
echo -e "${BLUE}📱 Client Configuration:${NC}"
echo "  🖥️  Windows: IKEv2 with server IP $SERVER_IP"
echo "  📱 Mobile: IKEv2/IPSec EAP with server IP $SERVER_IP"
echo "  👤 Users: Create via OTP CLI or web dashboard"
echo
echo -e "${BLUE}🔧 Next Steps:${NC}"
echo "  1. Create VPN users: cd server/otp_auth && python3 otp_cli.py"
echo "  2. Access dashboard: http://$SERVER_IP:5000"
echo "  3. Configure Windows/Mobile clients"
echo "  4. Monitor connections and IPs in dashboard"
echo
echo -e "${YELLOW}⚠️  Security Reminders:${NC}"
echo "  • Change default dashboard password"
echo "  • Update PSK in /etc/ipsec.secrets"
echo "  • Monitor logs regularly"
echo
echo -e "${GREEN}🎯 Your VPN server is ready for Windows, Mobile, and IP tracking!${NC}"
