#!/usr/bin/env python3
"""
SecureConnect VPN - Web Dashboard
Flask-based web interface for monitoring VPN connections and authentication
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
import sys
import os
import json
from datetime import datetime, timedelta
import sqlite3

# Add the parent directory to the path to import otp_server
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'server', 'otp_auth'))

try:
    from otp_server import OTPAuthenticator
except ImportError:
    print("Error: Could not import OTPAuthenticator. Make sure the server module is available.")
    sys.exit(1)

app = Flask(__name__)
app.secret_key = 'secureconnect_dashboard_secret_key_change_in_production'
CORS(app)

# Initialize OTP authenticator
auth = OTPAuthenticator(
    db_path=os.path.join('..', 'server', 'otp_auth', 'users.db'),
    log_path=os.path.join('..', 'server', 'logs', 'dashboard.log')
)

# Dashboard configuration
DASHBOARD_CONFIG = {
    'title': 'SecureConnect VPN Dashboard',
    'version': '1.0.0',
    'admin_user': 'admin',
    'admin_password': 'admin123',  # Change in production!
    'refresh_interval': 30  # seconds
}


def require_auth():
    """Check if user is authenticated"""
    if 'authenticated' not in session or not session['authenticated']:
        return False
    return True


@app.route('/')
def index():
    """Main dashboard page"""
    if not require_auth():
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', config=DASHBOARD_CONFIG)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if (username == DASHBOARD_CONFIG['admin_user'] and 
            password == DASHBOARD_CONFIG['admin_password']):
            session['authenticated'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get authentication logs
        logs = auth.get_auth_logs(limit=100)
        
        # Calculate statistics
        total_attempts = len(logs)
        successful_attempts = sum(1 for log in logs if log['success'])
        failed_attempts = total_attempts - successful_attempts
        
        # Get unique users
        unique_users = len(set(log['username'] for log in logs))
        
        # Recent activity (last 24 hours)
        recent_cutoff = datetime.now() - timedelta(hours=24)
        recent_logs = [
            log for log in logs 
            if datetime.fromisoformat(log['timestamp']) > recent_cutoff
        ]
        recent_attempts = len(recent_logs)
        recent_successful = sum(1 for log in recent_logs if log['success'])
        
        stats = {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'failed_attempts': failed_attempts,
            'success_rate': round((successful_attempts / total_attempts * 100) if total_attempts > 0 else 0, 1),
            'unique_users': unique_users,
            'recent_attempts_24h': recent_attempts,
            'recent_successful_24h': recent_successful,
            'recent_success_rate_24h': round((recent_successful / recent_attempts * 100) if recent_attempts > 0 else 0, 1),
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs')
def get_logs():
    """Get recent authentication logs"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        limit = request.args.get('limit', 50, type=int)
        username = request.args.get('username', None)
        
        logs = auth.get_auth_logs(username=username, limit=limit)
        
        # Format logs for display
        formatted_logs = []
        for log in logs:
            formatted_logs.append({
                'timestamp': log['timestamp'],
                'username': log['username'],
                'action': log['action'],
                'success': log['success'],
                'ip_address': log['ip_address'] or 'N/A',
                'details': log['details'] or '',
                'status_icon': '✅' if log['success'] else '❌',
                'status_class': 'success' if log['success'] else 'danger'
            })
        
        return jsonify({
            'logs': formatted_logs,
            'total': len(formatted_logs)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users')
def get_users():
    """Get user information"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get all users from database
        conn = sqlite3.connect(auth.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT username, email, created_at, last_login, is_active, failed_attempts
            FROM users
            ORDER BY created_at DESC
        ''')
        
        users_data = cursor.fetchall()
        conn.close()
        
        users = []
        for user_data in users_data:
            username, email, created_at, last_login, is_active, failed_attempts = user_data
            
            # Get recent activity for this user
            user_logs = auth.get_auth_logs(username=username, limit=10)
            recent_success = sum(1 for log in user_logs if log['success'])
            recent_total = len(user_logs)
            
            users.append({
                'username': username,
                'email': email,
                'created_at': created_at,
                'last_login': last_login or 'Never',
                'is_active': bool(is_active),
                'failed_attempts': failed_attempts,
                'recent_success_rate': round((recent_success / recent_total * 100) if recent_total > 0 else 0, 1),
                'status': 'Active' if is_active else 'Disabled',
                'status_class': 'success' if is_active else 'secondary'
            })
        
        return jsonify({
            'users': users,
            'total': len(users)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/authenticate', methods=['POST'])
def api_authenticate():
    """API endpoint for VPN client authentication"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400
        
        username = data.get('username')
        password = data.get('password')
        otp_code = data.get('otp_code')
        
        if not all([username, password, otp_code]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Get client IP address
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        
        # Verify OTP
        success, message = auth.verify_otp(username, otp_code, password)
        
        # Log the attempt with IP address
        auth.log_auth_attempt(username, 'api_login', success, ip_address=client_ip)
        
        return jsonify({
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Authentication error: {str(e)}'}), 500


@app.route('/api/system/status')
def system_status():
    """Get system status information"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        import psutil
        import subprocess
        
        # Get system information
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Check StrongSwan status (if available)
        strongswan_status = 'Unknown'
        try:
            result = subprocess.run(['systemctl', 'is-active', 'strongswan'], 
                                  capture_output=True, text=True, timeout=5)
            strongswan_status = result.stdout.strip()
        except:
            pass
        
        # Check network interfaces
        network_interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2:  # IPv4
                    network_interfaces.append({
                        'interface': interface,
                        'ip': addr.address
                    })
        
        status = {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': round(memory.available / (1024**3), 2),
            'disk_percent': disk.percent,
            'disk_free_gb': round(disk.free / (1024**3), 2),
            'strongswan_status': strongswan_status,
            'network_interfaces': network_interfaces,
            'uptime': 'N/A',  # Could be implemented
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Create templates directory and basic templates if they don't exist
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
        
        # Create basic login template
        login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureConnect VPN - Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 50px; }
        .login-container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #666; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #0056b3; }
        .error { color: #dc3545; margin-top: 10px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>SecureConnect VPN</h1>
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
        </form>
    </div>
</body>
</html>
        '''
        
        with open(os.path.join(templates_dir, 'login.html'), 'w') as f:
            f.write(login_template)
        
        # Create basic dashboard template
        dashboard_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ config.title }}</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header h1 { margin: 0; color: #333; display: inline-block; }
        .logout { float: right; color: #007bff; text-decoration: none; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2em; font-weight: bold; color: #007bff; }
        .stat-label { color: #666; margin-top: 5px; }
        .logs-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .log-entry { padding: 10px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
        .log-entry:last-child { border-bottom: none; }
        .success { color: #28a745; }
        .danger { color: #dc3545; }
        .refresh-btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ config.title }}</h1>
        <a href="/logout" class="logout">Logout</a>
    </div>
    
    <button onclick="refreshDashboard()" class="refresh-btn">Refresh Data</button>
    
    <div class="stats-grid" id="stats-grid">
        <!-- Stats will be loaded here -->
    </div>
    
    <div class="logs-container">
        <h3>Recent Authentication Logs</h3>
        <div id="logs-container">
            <!-- Logs will be loaded here -->
        </div>
    </div>

    <script>
        function refreshDashboard() {
            loadStats();
            loadLogs();
        }
        
        function loadStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    const statsGrid = document.getElementById('stats-grid');
                    statsGrid.innerHTML = `
                        <div class="stat-card">
                            <div class="stat-value">${data.total_attempts}</div>
                            <div class="stat-label">Total Attempts</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.success_rate}%</div>
                            <div class="stat-label">Success Rate</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.unique_users}</div>
                            <div class="stat-label">Unique Users</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.recent_attempts_24h}</div>
                            <div class="stat-label">Last 24h Attempts</div>
                        </div>
                    `;
                })
                .catch(error => console.error('Error loading stats:', error));
        }
        
        function loadLogs() {
            fetch('/api/logs?limit=20')
                .then(response => response.json())
                .then(data => {
                    const logsContainer = document.getElementById('logs-container');
                    logsContainer.innerHTML = data.logs.map(log => `
                        <div class="log-entry">
                            <span>${log.status_icon} ${log.username} - ${log.action}</span>
                            <span class="${log.status_class}">${log.timestamp}</span>
                        </div>
                    `).join('');
                })
                .catch(error => console.error('Error loading logs:', error));
        }
        
        // Load data on page load
        refreshDashboard();
        
        // Auto-refresh every 30 seconds
        setInterval(refreshDashboard, {{ config.refresh_interval * 1000 }});
    </script>
</body>
</html>
        '''
        
        with open(os.path.join(templates_dir, 'dashboard.html'), 'w') as f:
            f.write(dashboard_template)
    
    print("Starting SecureConnect VPN Dashboard...")
    print("Access the dashboard at: http://localhost:5000")
    print(f"Default credentials: {DASHBOARD_CONFIG['admin_user']} / {DASHBOARD_CONFIG['admin_password']}")
    print("Change default credentials before production use!")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
