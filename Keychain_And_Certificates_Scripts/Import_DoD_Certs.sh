#!/bin/bash

####################################################################################################
#
# # Import DoD Certs
#
# Purpose: Import the latest DoD Certs from dod.cyber.mil
#
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 8/07/23 Original
#  1.1 10/21/24 - Removed force smart card removal changed it to a warning, cleaned up log out,
#  added logging, changed OSAprompts, and changed wording for things
#
# Issues: If Smart Card is present it will not accept the pin when granting trust per self-signed cert
# Solution: Ask the user to remove smart card doing those steps, logic put in place if smart card is not
# present to keep running the script.
#
# Issue Update 4/10/24: Noticed with Sonoma 14.4.1 the keychain will accept your pin on trust import, did not change the
# to reflect the changes until i can confirm its working moving forward.
#
# Issue Update 10/21/24: So far every version past that supports smart card with keychain.
#
####################################################################################################

# Log file location for capturing the script's activities
LOG_FILE="/private/var/log/Import_DoD_Certs.log"
ENABLE_LOGGING=false  # Default logging setting

####################################################################################################
# Function to log messages to console and log file
####################################################################################################
SCRIPT_VERSION="1.1"

# Function to display usage instructions
usage() {
    echo "Usage: $0 [--enable-logging | --disable-logging]"
    exit 1
}

# Parse command-line arguments for enabling or disabling logging
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --enable-logging) ENABLE_LOGGING=true ;;  # Enable logging if argument provided
        --disable-logging) ENABLE_LOGGING=false ;;  # Disable logging if argument provided
        *) usage ;;  # Show usage if an unknown argument is provided
    esac
    shift  # Move to the next argument
done

# Function to log messages with timestamps
log_message() {
    local MESSAGE="$1"
    if $ENABLE_LOGGING; then
        echo "DoD Import Certs Script: $(date '+%Y-%m-%d %H:%M:%S') - $MESSAGE" | tee -a "$LOG_FILE"
    else
        echo "DoD Import Certs Script: $MESSAGE"  # Print to console if logging is disabled
    fi
}

# Function to create log file with a header if it doesn't exist
initialize_log_file() {
    if [ ! -f "$LOG_FILE" ]; then
       echo -e "\n##############################################\n# DoD Import Certs Script (v$SCRIPT_VERSION)\n# \n# Always grab the latest at \n# github.com/cocopuff2u/MacOS_GOV_Scripts/blob/main/Keychain_And_Certificates_Scripts/Import_DoD_Certs.sh \n# \n# Script by: https://github.com/cocopuff2u/\n##############################################\n" > "$LOG_FILE"
    fi
}

####################################################################################################

# Initialize logging if enabled
if $ENABLE_LOGGING; then
    initialize_log_file
fi

# Print header to console
echo -e "\n##############################################\n# DoD Import Certs Script (v$SCRIPT_VERSION)\n# \n# Always grab the latest at \n# github.com/cocopuff2u/MacOS_GOV_Scripts/blob/main/Keychain_And_Certificates_Scripts/Import_DoD_Certs.sh \n# \n# Script by: https://github.com/cocopuff2u/\n##############################################\n"
log_message "Initiating Script..."

# Prompt user for confirmation to proceed with the certificate import
log_message "User script confirmation prompt..."
userChoice=$(osascript -e 'tell application "System Events" to set frontmost of process "osascript" to true' -e 'button returned of (display dialog "This script will import DoD certificates directly from dod.cyber.mil into the system keychain.\n\nDo you want to continue with the import?" with title "Confirmation" buttons {"Exit", "Continue"} default button "Continue" with icon caution)')

# Check the user's choice and exit if they chose to exit
if [ "$userChoice" == "Exit" ]; then
    log_message "User selected to exit the script. Exiting."
    exit 1
else
    log_message "User selected to continue with running the script..."
fi

# Notify the user that the import process has started
osascript -e 'display notification "Initiating import of DoD certificates in the background. Please wait..." with title "Certificate Import"'

# Set the URL of the ZIP file containing the certificates
ZIP_URL="https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-dod_approved_external_pkis_trust_chains.zip"

# Define temporary folder and file names for processing
TEMP_DIR="/var/tmp"
GENERIC_FOLDER_NAME="DOD_Certs"
ZIP_FILE_NAME="DOD_Certs.zip"

# Define subfolder names for different certificate types
SUBFOLDER1="_DoD/Intermediate_and_Issuing_CA_Certs"
SUBFOLDER2="_DoD/Trust_Anchors_Self-Signed"

# Calculate full paths for folder and subfolders
FULL_FOLDER_PATH="$TEMP_DIR/$GENERIC_FOLDER_NAME"
FULL_PATH_WITH_CERTS_SUBFOLDERS="$FULL_FOLDER_PATH/$SUBFOLDER1"
FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS="$FULL_FOLDER_PATH/$SUBFOLDER2"

# Function to cleanup and exit the script on error
cleanup_and_exit() {
    log_message "Cleaning up any files created..."
    rm -rf "$TEMP_DIR"  # Remove temporary directory
    log_message "Files cleaned."
    log_message "An error occurred while running the script. Exiting."
    exit 1  # Exit with an error code
}

# Check if the generic folder already exists; if it does, remove it to start fresh
if [ -d "$FULL_FOLDER_PATH" ]; then
    log_message "Generic folder already exists. Removing..."
    rm -rf "$FULL_FOLDER_PATH"
    log_message "Folder removed."
fi

# Download the ZIP file containing the certificates
log_message "Certificate URL: $ZIP_URL"
log_message "Downloading ZIP file..."
if ! curl -L -o "$TEMP_DIR/$ZIP_FILE_NAME" "$ZIP_URL"; then
    log_message "Failed to download the ZIP file."
    cleanup_and_exit  # Exit on failure to download
fi
sleep 2  # Pause for a moment to allow download completion

# Extract the downloaded ZIP file into the temporary directory
log_message "Unzipping the downloaded file..."
unzip -q "$TEMP_DIR/$ZIP_FILE_NAME" -d "$TEMP_DIR"

# Identify the name of the extracted folder (assumed to be the only folder)
extracted_folder_name=$(unzip -l "$TEMP_DIR/$ZIP_FILE_NAME" | awk 'NR==4{print $4}')
if [ -z "$extracted_folder_name" ]; then
    log_message "Failed to determine the extracted folder name."
    cleanup_and_exit  # Exit if unable to determine folder name
fi

# Rename the extracted folder to a more generic name for easier reference
mv "$TEMP_DIR/$extracted_folder_name" "$FULL_FOLDER_PATH"

# Remove the ZIP file after extraction to save space
rm "$TEMP_DIR/$ZIP_FILE_NAME"

log_message "Downloaded and extracted the ZIP file to: $FULL_FOLDER_PATH"
log_message "Full path for DoD Certs: $FULL_PATH_WITH_CERTS_SUBFOLDERS"
log_message "Full path for DoD Self-Signed Certs: $FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS"

# Import all the non-self-signed certificates from the designated folder
log_message "Initiating import of non-self-signed certificates from $FULL_PATH_WITH_CERTS_SUBFOLDERS..."
for cert_file in "$FULL_PATH_WITH_CERTS_SUBFOLDERS"/*; do
    if [ -f "$cert_file" ]; then
        output=$(security import "$cert_file" -k /Library/Keychains/system.keychain 2>&1)  # Import the certificate and capture output

        # Check for an error indicating that the certificate already exists
        if echo "$output" | grep -q "The specified item already exists in the keychain."; then
            short_name="${cert_file#$FULL_PATH_WITH_CERTS_SUBFOLDERS/}"  # Extract short name for logging
            log_message "Certificate $short_name already exists"  # Log the existing certificate
        else
            short_name="${cert_file#$FULL_PATH_WITH_CERTS_SUBFOLDERS/}"  # Extract short name for logging
            log_message "Adding Certificate $short_name to the system keychain"  # Log the addition
        fi
    fi
done
log_message "Completed Import of non-self-signed certificates."

# Prompt the user regarding self-signed certificate import preferences
log_message "User self-signed warning prompt..."

userChoice=$(osascript -e 'tell application "System Events" to set frontmost of process "osascript" to true' -e \
    'set dialogText to "If you select \"Trusted\", you will be prompted for the smart card PIN or your machine password for each certificate. This is an Apple security function.\n\nNote: In certain OS versions (especially 14.3 or below), you will be prompted for the smart card PIN but it may not accept the PIN. It is advised to remove the smart card before proceeding.\n\nDo you want to import self-signed certificates as trusted or untrusted?"' -e \
    'set dialogTitle to "Self-Signed Certificate Import"' -e \
    'set userChoice to display dialog dialogText with title dialogTitle buttons {"Untrusted", "Trusted"} default button "Trusted" with icon caution' -e \
    'return button returned of userChoice')

# Handle the user's choice for importing self-signed certificates
if [ "$userChoice" == "Untrusted" ]; then
    log_message "User selected to import as untrusted."  # Log user choice
    osascript -e 'display notification "Initiating import of Self-Signed DoD certificates as untrusted in the background. Please wait..." with title "Certificate Import"'

    log_message "Initiating import of self-signed certificates from $FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS..."
    # Import self-signed certificates as untrusted
    for cert_file in "$FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS"/*; do
        if [ -f "$cert_file" ]; then
            short_name="${cert_file#$FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS/}"  # Extract short name for logging
            output=$(security import "$cert_file" -k /Library/Keychains/system.keychain 2>&1)

            if echo "$output" | grep -q "The specified item already exists in the keychain."; then
                log_message "Already exists, skipping: $short_name"  # Log if the certificate already exists
            else
                log_message "Adding $short_name to the keychain."  # Log addition of the certificate
            fi
        fi
    done
else
    log_message "User selected to import as trusted."  # Log user choice
    osascript -e 'display notification "Initiating import of Self-Signed DoD certificates as trusted in the background. Will prompt for password/pin. Please wait..." with title "Certificate Import"'

    log_message "Initiating import of self-signed certificates from $FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS..."
    # Import self-signed certificates as trusted
    for cert_file in "$FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS"/*; do
        if [ -f "$cert_file" ]; then
            short_name="${cert_file#$FULL_PATH_WITH_SELF_SIGNED_CERTS_SUBFOLDERS/}"  # Extract short name for logging
            output=$(sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert_file" 2>&1)

            if echo "$output" | grep -q "The authorization was canceled by the user."; then
                log_message "User declined PIN or password for: $short_name"  # Log if the user declined
            else
                log_message "Successfully added trusted certificate: $short_name"  # Log successful addition
            fi
        fi
    done
fi

# Notify the user of the completion of the certificate import process
osascript -e 'display notification "Completed Import of all Certificates" with title "Certificate Import Complete"'
osascript -e 'tell application "System Events" to set frontmost of process "osascript" to true' -e \
    'display dialog "Certificate import completed successfully!" with title "Import Complete" buttons {"OK"} default button "OK" with icon note' > /dev/null 2>&1 &

# Clean up all temporary files and directories created during the process
log_message "Cleaning up files..."
rm -rf "$FULL_FOLDER_PATH"  # Remove the folder containing imported certificates
log_message "Files cleaned."

log_message "Script execution completed."  # Log the completion of the script

exit 0  # Exit the script successfully
