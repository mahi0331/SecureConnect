#!/usr/bin/env python3
"""
SecureConnect VPN - OTP Authentication CLI
Command-line interface for managing OTP authentication
"""

import argparse
import sys
import getpass
from otp_server import OTPAuthenticator
import pyotp


def create_user_interactive(auth: OTPAuthenticator):
    """Interactive user creation"""
    print("\n=== Create New VPN User ===")
    
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty")
        return
        
    email = input("Enter email: ").strip()
    if not email or '@' not in email:
        print("Please enter a valid email address")
        return
        
    password = getpass.getpass("Enter password: ")
    password_confirm = getpass.getpass("Confirm password: ")
    
    if password != password_confirm:
        print("Passwords do not match")
        return
        
    if len(password) < 8:
        print("Password must be at least 8 characters long")
        return
        
    success, result = auth.create_user(username, email, password)
    
    if success:
        print(f"\n✅ User '{username}' created successfully!")
        print(f"TOTP Secret: {result}")
        print(f"Email: {email}")
        
        # Generate QR code
        qr_code = auth.generate_qr_code(username, result)
        if qr_code:
            # Save QR code to file
            import base64
            qr_filename = f"qr_code_{username}.png"
            with open(qr_filename, 'wb') as f:
                f.write(base64.b64decode(qr_code))
            print(f"QR code saved as: {qr_filename}")
            print("Scan this QR code with Google Authenticator or similar app")
            
        print(f"\nManual setup code (if QR doesn't work): {result}")
        print("The user can now connect to the VPN using their credentials and OTP")
        
    else:
        print(f"❌ Failed to create user: {result}")


def verify_otp_interactive(auth: OTPAuthenticator):
    """Interactive OTP verification"""
    print("\n=== Verify OTP Code ===")
    
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty")
        return
        
    password = getpass.getpass("Enter password: ")
    otp_code = input("Enter OTP code: ").strip()
    
    if len(otp_code) != 6 or not otp_code.isdigit():
        print("OTP code must be 6 digits")
        return
        
    success, message = auth.verify_otp(username, otp_code, password)
    
    if success:
        print(f"✅ {message}")
    else:
        print(f"❌ {message}")


def show_user_info(auth: OTPAuthenticator):
    """Show user information and statistics"""
    print("\n=== User Information ===")
    
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty")
        return
        
    # Get authentication logs for this user
    logs = auth.get_auth_logs(username, limit=10)
    
    if not logs:
        print(f"No authentication logs found for user '{username}'")
        return
        
    print(f"\nLast 10 authentication attempts for '{username}':")
    print("-" * 80)
    print(f"{'Timestamp':<20} {'Action':<10} {'Success':<8} {'IP Address':<15} {'Details'}")
    print("-" * 80)
    
    for log in logs:
        success_icon = "✅" if log['success'] else "❌"
        ip_addr = log['ip_address'] or "N/A"
        details = log['details'] or ""
        print(f"{log['timestamp']:<20} {log['action']:<10} {success_icon:<8} {ip_addr:<15} {details}")


def show_all_logs(auth: OTPAuthenticator):
    """Show recent authentication logs for all users"""
    print("\n=== Recent Authentication Logs ===")
    
    limit = input("Number of recent logs to show (default 20): ").strip()
    try:
        limit = int(limit) if limit else 20
    except ValueError:
        limit = 20
        
    logs = auth.get_auth_logs(limit=limit)
    
    if not logs:
        print("No authentication logs found")
        return
        
    print(f"\nLast {len(logs)} authentication attempts:")
    print("-" * 100)
    print(f"{'Timestamp':<20} {'Username':<15} {'Action':<10} {'Success':<8} {'IP Address':<15} {'Details'}")
    print("-" * 100)
    
    for log in logs:
        success_icon = "✅" if log['success'] else "❌"
        ip_addr = log['ip_address'] or "N/A"
        details = log['details'] or ""
        print(f"{log['timestamp']:<20} {log['username']:<15} {log['action']:<10} {success_icon:<8} {ip_addr:<15} {details}")


def generate_test_otp(auth: OTPAuthenticator):
    """Generate current OTP for testing"""
    print("\n=== Generate Test OTP ===")
    
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty")
        return
        
    secret = auth.get_user_secret(username)
    if not secret:
        print(f"User '{username}' not found")
        return
        
    totp = pyotp.TOTP(secret)
    current_otp = totp.now()
    
    print(f"Current OTP for '{username}': {current_otp}")
    print("This code is valid for 30 seconds")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="SecureConnect VPN - OTP Authentication CLI")
    parser.add_argument('--db', default='users.db', help='Database file path')
    parser.add_argument('--logs', default='../logs/otp_auth.log', help='Log file path')
    
    args = parser.parse_args()
    
    # Initialize authenticator
    auth = OTPAuthenticator(db_path=args.db, log_path=args.logs)
    
    while True:
        print("\n" + "="*50)
        print("     SecureConnect VPN - OTP Management")
        print("="*50)
        print("1. Create new user")
        print("2. Verify OTP code")
        print("3. Show user information")
        print("4. Show authentication logs")
        print("5. Generate test OTP")
        print("0. Exit")
        print("-"*50)
        
        choice = input("Enter your choice (0-5): ").strip()
        
        try:
            if choice == '1':
                create_user_interactive(auth)
            elif choice == '2':
                verify_otp_interactive(auth)
            elif choice == '3':
                show_user_info(auth)
            elif choice == '4':
                show_all_logs(auth)
            elif choice == '5':
                generate_test_otp(auth)
            elif choice == '0':
                print("Goodbye!")
                sys.exit(0)
            else:
                print("Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\n\nOperation cancelled.")
        except Exception as e:
            print(f"Error: {e}")
            
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
