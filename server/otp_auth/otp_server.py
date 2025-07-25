#!/usr/bin/env python3
"""
SecureConnect OTP Authentication Server
Educational VPN project with IPSec and OTP-based authentication

This module handles:
- TOTP (Time-based One-Time Password) generation and validation
- User management and authentication
- Email-based OTP delivery
- Integration with StrongSwan IPSec
"""

import pyotp
import qrcode
import io
import base64
import json
import sqlite3
import smtplib
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from typing import Dict, Optional, Tuple
import os


class OTPAuthenticator:
    """Main OTP authentication class for SecureConnect VPN"""
    
    def __init__(self, db_path: str = "users.db", log_path: str = "../logs/otp_auth.log"):
        self.db_path = db_path
        self.setup_logging(log_path)
        self.setup_database()
        
    def setup_logging(self, log_path: str):
        """Configure logging for authentication events"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_database(self):
        """Initialize SQLite database for user management"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
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
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        self.logger.info("Database initialized successfully")
        
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"
        
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, hash_value = stored_hash.split(':')
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return password_hash == hash_value
        except ValueError:
            return False
            
    def create_user(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """Create a new user with TOTP secret"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT username FROM users WHERE username = ? OR email = ?", 
                          (username, email))
            if cursor.fetchone():
                return False, "User already exists"
                
            # Generate TOTP secret
            secret = pyotp.random_base32()
            password_hash = self.hash_password(password)
            
            cursor.execute('''
                INSERT INTO users (username, email, secret_key, password_hash)
                VALUES (?, ?, ?, ?)
            ''', (username, email, secret, password_hash))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"User {username} created successfully")
            return True, secret
            
        except Exception as e:
            self.logger.error(f"Error creating user {username}: {e}")
            return False, str(e)
            
    def generate_qr_code(self, username: str, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        try:
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=username,
                issuer_name="SecureConnect VPN"
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img_buffer = io.BytesIO()
            img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            # Convert to base64 for easy transmission
            img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            return img_base64
            
        except Exception as e:
            self.logger.error(f"Error generating QR code for {username}: {e}")
            return ""
            
    def verify_otp(self, username: str, otp_code: str, password: str = None) -> Tuple[bool, str]:
        """Verify OTP code for user authentication"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user data
            cursor.execute('''
                SELECT secret_key, password_hash, is_active, failed_attempts, locked_until
                FROM users WHERE username = ?
            ''', (username,))
            
            user_data = cursor.fetchone()
            if not user_data:
                self.log_auth_attempt(username, "login", False, details="User not found")
                return False, "Invalid credentials"
                
            secret_key, password_hash, is_active, failed_attempts, locked_until = user_data
            
            # Check if account is locked
            if locked_until:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < lock_time:
                    self.log_auth_attempt(username, "login", False, details="Account locked")
                    return False, "Account is temporarily locked"
                    
            # Check if account is active
            if not is_active:
                self.log_auth_attempt(username, "login", False, details="Account disabled")
                return False, "Account is disabled"
                
            # Verify password if provided
            if password and not self.verify_password(password, password_hash):
                self.increment_failed_attempts(username)
                self.log_auth_attempt(username, "login", False, details="Invalid password")
                return False, "Invalid credentials"
                
            # Verify OTP
            totp = pyotp.TOTP(secret_key)
            if totp.verify(otp_code, valid_window=1):  # Allow 30-second window
                # Reset failed attempts and update last login
                cursor.execute('''
                    UPDATE users 
                    SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
                    WHERE username = ?
                ''', (username,))
                conn.commit()
                
                self.log_auth_attempt(username, "login", True, details="Successful authentication")
                self.logger.info(f"Successful OTP verification for user {username}")
                return True, "Authentication successful"
            else:
                self.increment_failed_attempts(username)
                self.log_auth_attempt(username, "login", False, details="Invalid OTP")
                return False, "Invalid OTP code"
                
        except Exception as e:
            self.logger.error(f"Error verifying OTP for {username}: {e}")
            self.log_auth_attempt(username, "login", False, details=f"System error: {e}")
            return False, "Authentication error"
        finally:
            conn.close()
            
    def increment_failed_attempts(self, username: str):
        """Increment failed login attempts and lock account if necessary"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = failed_attempts + 1
                WHERE username = ?
            ''', (username,))
            
            # Lock account after 5 failed attempts for 15 minutes
            cursor.execute('''
                UPDATE users 
                SET locked_until = datetime('now', '+15 minutes')
                WHERE username = ? AND failed_attempts >= 5
            ''', (username,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error updating failed attempts for {username}: {e}")
            
    def log_auth_attempt(self, username: str, action: str, success: bool, 
                        ip_address: str = None, details: str = None):
        """Log authentication attempt"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO auth_logs (username, action, success, ip_address, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, action, success, ip_address, details))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error logging auth attempt: {e}")
            
    def get_user_secret(self, username: str) -> Optional[str]:
        """Get user's TOTP secret (for admin purposes)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT secret_key FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
            
        except Exception as e:
            self.logger.error(f"Error getting secret for {username}: {e}")
            return None
            
    def send_otp_email(self, email: str, otp_code: str, smtp_config: Dict) -> bool:
        """Send OTP via email (alternative to TOTP apps)"""
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_config['from_email']
            msg['To'] = email
            msg['Subject'] = "SecureConnect VPN - Your OTP Code"
            
            body = f"""
            Your SecureConnect VPN authentication code is: {otp_code}
            
            This code will expire in 30 seconds.
            If you did not request this code, please contact your administrator.
            
            SecureConnect VPN System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
            server.starttls()
            server.login(smtp_config['from_email'], smtp_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"OTP email sent to {email}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending OTP email to {email}: {e}")
            return False
            
    def get_auth_logs(self, username: str = None, limit: int = 100) -> list:
        """Get authentication logs"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if username:
                cursor.execute('''
                    SELECT username, action, success, ip_address, timestamp, details
                    FROM auth_logs 
                    WHERE username = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (username, limit))
            else:
                cursor.execute('''
                    SELECT username, action, success, ip_address, timestamp, details
                    FROM auth_logs 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
            logs = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'username': log[0],
                    'action': log[1],
                    'success': bool(log[2]),
                    'ip_address': log[3],
                    'timestamp': log[4],
                    'details': log[5]
                }
                for log in logs
            ]
            
        except Exception as e:
            self.logger.error(f"Error getting auth logs: {e}")
            return []


if __name__ == "__main__":
    # Example usage and testing
    auth = OTPAuthenticator()
    
    # Create a test user
    success, result = auth.create_user("testuser", "test@example.com", "testpass123")
    if success:
        print(f"User created successfully. Secret: {result}")
        
        # Generate QR code
        qr_code = auth.generate_qr_code("testuser", result)
        if qr_code:
            print("QR code generated successfully")
            
        # Test OTP verification
        totp = pyotp.TOTP(result)
        current_otp = totp.now()
        print(f"Current OTP: {current_otp}")
        
        # Verify OTP
        verified, message = auth.verify_otp("testuser", current_otp, "testpass123")
        print(f"OTP verification: {verified} - {message}")
    else:
        print(f"Failed to create user: {result}")
