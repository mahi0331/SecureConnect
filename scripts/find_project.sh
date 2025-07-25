#!/bin/bash

# SecureConnect VPN - Path Helper
# This script helps you find the correct project path

echo "🔍 Finding SecureConnect VPN project location..."
echo

# Common locations to check
POSSIBLE_PATHS=(
    "~/OneDrive/Desktop/Wifisec"
    "~/Desktop/Wifisec"
    "~/Documents/Wifisec"
    "~/Downloads/Wifisec"
    "./Wifisec"
    "."
)

# Expand tilde and check each path
for path in "${POSSIBLE_PATHS[@]}"; do
    # Expand the tilde
    expanded_path="${path/#\~/$HOME}"
    
    if [ -d "$expanded_path" ] && [ -f "$expanded_path/README.md" ]; then
        echo "✅ Found SecureConnect VPN at: $expanded_path"
        echo
        echo "To navigate to the project:"
        echo "cd \"$expanded_path\""
        echo
        echo "Then run the setup:"
        echo "sudo ./scripts/ubuntu_setup.sh"
        exit 0
    fi
done

echo "❌ SecureConnect VPN project not found in common locations."
echo
echo "Please navigate to your project directory manually and run:"
echo "pwd  # This will show your current path"
echo
echo "Then update the documentation with the correct path."
echo
echo "Common commands to find it:"
echo "find ~ -name 'README.md' -type f | grep -i secure"
echo "find ~ -name 'ubuntu_setup.sh' -type f"
