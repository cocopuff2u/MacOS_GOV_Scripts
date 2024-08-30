#!/bin/bash

####################################################################################################
#
# # Reset Keychain with DoD Cert Verify
#
# Purpose: Reset keychain, verifies that the DoD certs are in the correct location before deleting it
# 
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 04/10/24 Original
#
#
####################################################################################################


# Array of certificates to check
required_certs=("DoD Root CA 3" "DoD Root CA 4" "DoD Root CA 5" "DoD Root CA 6")

# Function to display a dialog with a message and the FileVault icon
display_dialog() {
    osascript -e 'display dialog "'"${1}"'" buttons {"OK"} default button "OK" with icon POSIX file "/System/Applications/Utilities/Keychain Access.app/Contents/Resources/AppIcon.icns"'
}

# Function to fix missing certificates
fix_missing_certs() {
    echo "Function to fix missing certificates"
    # Add your code to fix missing certificates here
}

# Prompt the user to confirm before proceeding
osascript -e 'display dialog "This script will check that the required DoD certificates are present in the system keychain before deleting the user keychain. Do you want to continue?" buttons {"Cancel", "Continue"} default button "Continue" cancel button "Cancel" with icon POSIX file "/System/Applications/Utilities/Keychain Access.app/Contents/Resources/AppIcon.icns"'

# Check the user's response to the prompt
response=$(echo $?)

if [ $response -eq 1 ]; then
    echo "User canceled the operation."
    exit 0
fi

loggedInUser=$(ls -l /dev/console | awk '{ print $3 }')

# Initialize a variable to keep track of missing certificates
missing_certs=""

# Loop through each certificate
for cert in "${required_certs[@]}"; do
    if ! sudo security dump-keychain /Library/Keychains/System.keychain | grep -q "$cert"; then
        missing_certs="${missing_certs} ${cert}\n"
    fi
done

# If there are missing certificates, display a dialog and exit
if [ ! -z "$missing_certs" ]; then
    message="The following certificate(s) are missing from the system keychain:\n\n${missing_certs}\nPlease correct this before proceeding. Install DoD Certs into the System keychain then rerun this."
    display_dialog "${message}"
    exit 0
fi

echo "All required certs are present in system keychain. Proceeding with keychain deletion."

# Uncomment the following line to perform keychain deletion
rm -Rf /Users/$loggedInUser/Library/Keychains/*

# Inform the user that the keychain was reset and to reboot
display_dialog "The keychain has been reset. Please reboot your system for changes to take effect."

exit 0
