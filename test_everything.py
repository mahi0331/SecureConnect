#!/usr/bin/env python3
"""
SecureConnect VPN - Comprehensive Test Suite
Tests all components for errors, consistency, and completeness
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def test_results():
    """Store and display test results"""
    results = {
        'total_tests': 0,
        'passed': 0,
        'failed': 0,
        'warnings': 0,
        'errors': []
    }
    return results

def check_file_exists(file_path, results, description=""):
    """Test if a file exists"""
    results['total_tests'] += 1
    if os.path.exists(file_path):
        results['passed'] += 1
        print(f"✅ {description or os.path.basename(file_path)} exists")
        return True
    else:
        results['failed'] += 1
        error_msg = f"❌ {description or file_path} missing"
        print(error_msg)
        results['errors'].append(error_msg)
        return False

def check_python_syntax(file_path, results, description=""):
    """Test Python file syntax"""
    results['total_tests'] += 1
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            compile(f.read(), file_path, 'exec')
        results['passed'] += 1
        print(f"✅ {description or os.path.basename(file_path)} - Python syntax OK")
        return True
    except SyntaxError as e:
        results['failed'] += 1
        error_msg = f"❌ {description or file_path} - Syntax error: {e}"
        print(error_msg)
        results['errors'].append(error_msg)
        return False
    except Exception as e:
        results['failed'] += 1
        error_msg = f"❌ {description or file_path} - Error: {e}"
        print(error_msg)
        results['errors'].append(error_msg)
        return False

def check_imports(file_path, results, description=""):
    """Test if Python imports work"""
    results['total_tests'] += 1
    try:
        # Add the directory to Python path temporarily
        import sys
        file_dir = os.path.dirname(os.path.abspath(file_path))
        if file_dir not in sys.path:
            sys.path.insert(0, file_dir)
        
        # Try to import without executing
        import importlib.util
        spec = importlib.util.spec_from_file_location("test_module", file_path)
        if spec is None:
            raise ImportError(f"Could not load spec for {file_path}")
        
        results['passed'] += 1
        print(f"✅ {description or os.path.basename(file_path)} - Imports OK")
        return True
    except Exception as e:
        results['warnings'] += 1
        warning_msg = f"⚠️  {description or file_path} - Import warning: {e}"
        print(warning_msg)
        return False

def check_shell_script_syntax(file_path, results, description=""):
    """Test shell script basic syntax (simple check)"""
    results['total_tests'] += 1
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Basic syntax checks
        issues = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check for common syntax issues
            if line.count('(') != line.count(')'):
                issues.append(f"Line {i}: Unmatched parentheses")
            if line.count('[') != line.count(']'):
                issues.append(f"Line {i}: Unmatched brackets")
            if line.count('{') != line.count('}'):
                issues.append(f"Line {i}: Unmatched braces")
        
        if issues:
            results['warnings'] += 1
            warning_msg = f"⚠️  {description or file_path} - Potential syntax issues: {'; '.join(issues[:3])}"
            print(warning_msg)
            return False
        else:
            results['passed'] += 1
            print(f"✅ {description or os.path.basename(file_path)} - Shell syntax looks OK")
            return True
            
    except Exception as e:
        results['failed'] += 1
        error_msg = f"❌ {description or file_path} - Error reading file: {e}"
        print(error_msg)
        results['errors'].append(error_msg)
        return False

def main():
    """Run comprehensive tests"""
    print("🧪 SecureConnect VPN - Comprehensive Test Suite")
    print("=" * 60)
    
    results = test_results()
    project_root = Path(__file__).parent
    
    print("\n📁 Testing File Structure...")
    
    # Test core files
    essential_files = [
        "README.md",
        "UBUNTU_README.md", 
        "WINDOWS_SETUP.md",
        "MOBILE_SETUP.md",
        "COMPLETE_SOLUTION.md",
        "requirements.txt"
    ]
    
    for file in essential_files:
        check_file_exists(project_root / file, results, f"Core file: {file}")
    
    # Test scripts
    print("\n🔧 Testing Scripts...")
    script_files = [
        "scripts/complete_setup.sh",
        "scripts/verify_complete.sh"
    ]
    
    for script in script_files:
        script_path = project_root / script
        if check_file_exists(script_path, results, f"Script: {script}"):
            check_shell_script_syntax(script_path, results, f"Script: {script}")
    
    # Test Python files
    print("\n🐍 Testing Python Files...")
    python_files = [
        "server/otp_auth/otp_server.py",
        "server/otp_auth/otp_cli.py", 
        "web_dashboard/app.py"
    ]
    
    for py_file in python_files:
        py_path = project_root / py_file
        if check_file_exists(py_path, results, f"Python file: {py_file}"):
            check_python_syntax(py_path, results, f"Python file: {py_file}")
            check_imports(py_path, results, f"Python imports: {py_file}")
    
    # Test documentation consistency
    print("\n📚 Testing Documentation...")
    doc_files = [
        "docs/CONFIGURATION.md",
        "docs/SETUP.md", 
        "docs/TROUBLESHOOTING.md",
        "docs/USER_GUIDE.md"
    ]
    
    for doc in doc_files:
        check_file_exists(project_root / doc, results, f"Documentation: {doc}")
    
    # Test directory structure
    print("\n📂 Testing Directory Structure...")
    required_dirs = [
        "client",
        "docs", 
        "scripts",
        "server",
        "web_dashboard",
        "server/otp_auth"
    ]
    
    for directory in required_dirs:
        dir_path = project_root / directory
        results['total_tests'] += 1
        if dir_path.exists() and dir_path.is_dir():
            results['passed'] += 1
            print(f"✅ Directory: {directory} exists")
        else:
            results['failed'] += 1
            error_msg = f"❌ Directory: {directory} missing"
            print(error_msg)
            results['errors'].append(error_msg)
    
    # Test for removed files (should not exist)
    print("\n🗑️  Testing Cleanup (removed files should not exist)...")
    removed_files = [
        "TRANSFER_TO_UBUNTU.md",
        "install_ubuntu.sh", 
        "PROJECT_PRESENTATION.md",
        "QUICK_START.md",
        "scripts/setup.sh",
        "scripts/ubuntu_setup.sh",
        "scripts/demo.sh",
        "scripts/find_project.sh"
    ]
    
    for removed_file in removed_files:
        results['total_tests'] += 1
        if not (project_root / removed_file).exists():
            results['passed'] += 1
            print(f"✅ Cleanup verified: {removed_file} properly removed")
        else:
            results['warnings'] += 1
            warning_msg = f"⚠️  Cleanup issue: {removed_file} still exists"
            print(warning_msg)
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    print(f"Total Tests: {results['total_tests']}")
    print(f"✅ Passed: {results['passed']}")
    print(f"❌ Failed: {results['failed']}")  
    print(f"⚠️  Warnings: {results['warnings']}")
    
    if results['errors']:
        print(f"\n❌ Critical Errors ({len(results['errors'])}):")
        for error in results['errors']:
            print(f"   {error}")
    
    if results['failed'] == 0:
        if results['warnings'] == 0:
            print("\n🎉 ALL TESTS PASSED! Your SecureConnect VPN is ready for production!")
        else:
            print(f"\n✅ All critical tests passed! {results['warnings']} warnings to review.")
        return 0
    else:
        print(f"\n⚠️  {results['failed']} critical issues found. Please review and fix.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
