#!/bin/bash
#set -x

####################################################################################################
#
# # SmartCardMapping
#
# Purpose:Maps the PIV UPN from a smartcard to the AltSecurityIdentities attribute for local accounts
#
# https://github.com/cocopuff2u
#
# Note: Tested only with government CAC/smartcards/yubikeys, uses swiftdialog or OSAscript for GUI
#
####################################################################################################
#
#   History
#
#  1.0 03/10/25 - Original
#
#  1.1 03/10/25 - /etc/SmartcardLogin.plist may exist already, having the script recreate it on
#                every run to resolve issues with the smartcard not being recognized.
#
#  1.2 05/27/25 - Added filevault option for M1 Arch, logging, and osascript dialog support
#
#. 1.3 06/13/25 - Improved OSAScript prompt handling, refined swiftDialog checks, added missing user
#                 prompts,and updated default variables for enhanced usability.
#
####################################################################################################

####################################################################################################
#                                    USER CONFIGURATION SECTION
####################################################################################################
# Set to "true" to uninstall (Default is false)
UNINSTALL=false

# Set to "true" to enable logging to /var/log, "false" to disable (Default is true)
ENABLE_LOGGING=true

# Set to "false" to use SwiftDialog for dialogs instead of OSAScript (Default is true)
# Its recommended to use swiftDialog for better user experience
USE_OSASCRIPT=true

####################################################################################################
Script_Name="SmartcardMapping"
LOG_FILE="/var/log/smartcard_mapping.log"
Script_Version="1.2"

# Logging function
log_message() {
    local timestamp=$(date '+%Y-%m-%d %I:%M %p')
    local message="[$Script_Name][$Script_Version][$timestamp] - $1"

    echo "$message"

    if [[ "$ENABLE_LOGGING" == "true" ]]; then
        echo "$message" >> "$LOG_FILE"
    fi
}

####################################################################################################
# Validate / install swiftDialog
####################################################################################################

function dialogInstall() {
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")
    expectedDialogTeamID="PWA5E9TQ59"
    log_message "Installing swiftDialog...."
    workDirectory=$( /usr/bin/basename "$0" )
    tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )
    /usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"
    teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')
    if [[ "$expectedDialogTeamID" == "$teamID" ]]; then
        /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
        sleep 2
        dialogVersion=$( /usr/local/bin/dialog --version )
        log_message "swiftDialog version ${dialogVersion} installed; proceeding...."
    else
        osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Dialog Missing: Error" buttons {"Close"} with icon caution' & exit 0
    fi
    /bin/rm -Rf "$tempDirectory"
}

function dialogCheck() {
    if [[ "$USE_OSASCRIPT" == "true" ]]; then
        log_message "OSASCRIPT mode enabled, skipping swiftDialog check."
        return
    fi
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then
        log_message "swiftDialog not found. Installing...."
        dialogInstall
    else
        dialogVersion=$(/usr/local/bin/dialog --version)
        if [[ "${dialogVersion}" < "${swiftDialogMinimumRequiredVersion}" ]]; then
            log_message "swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating...."
            dialogInstall
        else
            log_message "swiftDialog version ${dialogVersion} found; proceeding...."
        fi
    fi
}

dialogCheck

# Create log file only if logging is enabled
if [[ "$ENABLE_LOGGING" == "true" ]]; then
    touch "$LOG_FILE"
fi
log_message "Script started"

# Smartcard Attribute Mapping for Local Accounts

# Check for logged in user.
currentUser="$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ && ! /loginwindow/ { print $3 }' )"
log_message "Current user: $currentUser"
DIALOG_PATH="/usr/local/bin/dialog"

# Architecture and user info
arch=$(arch)
AUID="$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ && ! /loginwindow/ { print $3 }' )"
AUID_UID=$(id -u $AUID 2>/dev/null)
currentUser="$AUID"

# Check for pairing
checkForPaired (){
    log_message "Checking for existing smartcard pairing"
    tokenCheck=$(/usr/bin/dscl . read /Users/"$AUID" AuthenticationAuthority | grep -c tokenidentity)
    if [[ "$tokenCheck" > 0 ]]; then
        log_message "Unpairing smartcard from $AUID"
        /usr/sbin/sc_auth unpair -u "$AUID"
        log_message "Smartcard unpaired successfully"
    else
        log_message "No existing smartcard pairing found"
    fi
}

# Prompt the user to insert card, once inserted prompt will go away.
prompt (){
    log_message "Checking for inserted smartcard"
    if [[ $( security list-smartcards 2>/dev/null | grep -c com.apple.pivtoken ) -ge 1 ]]; then
        log_message "Smartcard already inserted"
        return 0
    fi

    log_message "Displaying smartcard insertion prompt"
    if [[ "$USE_OSASCRIPT" == "true" ]]; then
        prompt_message="Please insert CAC before proceeding"
        while true; do
            button=$(osascript -e "display dialog \"$prompt_message\" with title \"Smartcard Mapping\" buttons {\"Cancel\", \"Proceed\"} default button \"Proceed\" with icon caution" 2>&1)
            if [[ $? -ne 0 ]] || [[ "$button" == *"Cancel"* ]]; then
                log_message "User cancelled smartcard prompt - exiting script"
                exit 0
            fi
            if [[ $( security list-smartcards 2>/dev/null | grep -c com.apple.pivtoken ) -ge 1 ]]; then
                break
            fi
            prompt_message="CAC not detected, please insert CAC"
        done
    else
        "$DIALOG_PATH" \
            --title "Smartcard Mapping" \
            --messagealignment center \
            --message "Please insert your smartcard to begin." \
            --hideicon \
            --button1text "Cancel" \
            --buttonstyle center \
            --progress 0 \
            --small \
            --ontop \
            --moveable \
            --height 200 \
            --commandfile /var/tmp/dialog.log \
            --position center 2> /dev/null &
        DIALOG_PID=$!
        while [[ $( security list-smartcards 2>/dev/null | grep -c com.apple.pivtoken ) -lt 1 ]]; do 
            if ! kill -0 $DIALOG_PID 2>/dev/null; then
                log_message "Dialog window closed by user - exiting script"
                exit 0
            fi
            sleep 1
        done
        /bin/echo "quit:" >> /var/tmp/dialog.log
    fi
    log_message "Smartcard detected"
}

getUPN(){
    log_message "Beginning UPN extraction process"
    # Create temporary directory to export certs:
    tmpdir=$(/usr/bin/mktemp -d)
    log_message "Created temporary directory: $tmpdir"
    
    # Export certs on smartcard to temporary directory:
    /usr/bin/security export-smartcard -e "$tmpdir"
    log_message "Certificates exported to temporary directory: $tmpdir"
    
    # Get path to Certificate for PIV Authentication:
    piv_path=$(ls "$tmpdir" | /usr/bin/grep '^Certificate For PIV')
    log_message "PIV certificate path: $tmpdir/$piv_path"
    
    # Get User Principle Name from Certificate for PIV Authentication:
    UPN="$(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$piv_path" -strparse $(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$piv_path"  | /usr/bin/awk -F ':' '/X509v3 Subject Alternative Name/ {getline; print $1}') | /usr/bin/awk -F ':' '/UTF8STRING/{print $4}')"
    log_message "Retrieved UPN: $UPN"
    
    # Clean up the temporary directory
    /bin/rm -rf $tmpdir
    log_message "Cleaned up temporary directory: $tmpdir"
}

createAltSecId (){
    log_message "Checking existing AltSecurityIdentities"
    altSecCheck=$(/usr/bin/dscl . -read /Users/"$AUID" AltSecurityIdentities 2>/dev/null | sed -n 's/.*Kerberos:\([^ ]*\).*/\1/p')
    log_message "Current AltSecurityIdentities value: $altSecCheck"
    if [[ "$UPN" = "" ]]; then
        log_message "Error: No UPN found for $AUID"
        if [[ "$USE_OSASCRIPT" == "true" ]]; then
            osascript -e 'display dialog "No UPN found on smartcard" with title "Smartcard Mapping" buttons {"Quit"} default button "Quit" with icon caution'
        else
            "$DIALOG_PATH" \
                --title "Smartcard Mapping" \
                --messagealignment center \
                --message "No UPN found on smartcard" \
                --hideicon \
                --small \
                --ontop \
                --moveable \
                --buttonstyle center \
                --height 200 \
                --button1text "Quit" 2> /dev/null
        fi
    elif [[ "$altSecCheck" = "$UPN" ]]; then
        log_message "AltSecurityIdentities already set to $UPN for $AUID"
        if [[ "$USE_OSASCRIPT" == "true" ]]; then
            osascript -e "display dialog \"Smartcard mapping was already set to $UPN\" with title \"Smartcard Mapping\" buttons {\"Quit\"} default button \"Quit\" with icon note"
        else
            "$DIALOG_PATH" \
                --title "Smartcard Mapping" \
                --messagealignment center \
                --message "Smartcard mapping was already set to <br>$UPN" \
                --hideicon \
                --ontop \
                --moveable \
                --small \
                --buttonstyle center \
                --height 200 \
                --button1text "Quit" 2> /dev/null
        fi
    else
        log_message "Adding $UPN to AltSecurityIdentities for $AUID"
        /usr/bin/dscl . -append /Users/"$AUID" AltSecurityIdentities Kerberos:"$UPN"
        log_message "Successfully added $UPN to AltSecurityIdentities for $AUID"
        if [[ "$USE_OSASCRIPT" == "true" ]]; then
            osascript -e "display dialog \"Successfully added $UPN to $AUID\" with title \"Smartcard Mapping\" buttons {\"Quit\"} default button \"Quit\" with icon note"
        else
            "$DIALOG_PATH" \
                --title "Smartcard Mapping" \
                --messagealignment center \
                --message "Successfully added $UPN to $AUID" \
                --hideicon \
                --ontop \
                --moveable \
                --small \
                --buttonstyle center \
                --height 200 \
                --button1text "Quit" 2> /dev/null
        fi
    fi
}

createMapping (){
    log_message "Setting up SmartcardLogin.plist"
    if [ -f /etc/SmartcardLogin.plist ]; then
        log_message "SmartcardLogin.plist already exists"
        log_message "Removing existing SmartcardLogin.plist"
        rm -f /etc/SmartcardLogin.plist
        log_message "Removed existing SmartcardLogin.plist"
    fi
    log_message "Creating /etc/SmartcardLogin.plist"
    /bin/cat > "/etc/SmartcardLogin.plist" << 'Attr_Mapping'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
     <key>AttributeMapping</key>
     <dict>
          <key>fields</key>
          <array>
               <string>NT Principal Name</string>
          </array>
          <key>formatString</key>
          <string>Kerberos:$1</string>
          <key>dsAttributeString</key>
          <string>dsAttrTypeStandard:AltSecurityIdentities</string>
     </dict>
     <key>TrustedAuthorities</key>
	   <array>
		  <string></string>
	   </array>
     <key>NotEnforcedGroup</key>
     <string></string>
</dict>
</plist>
Attr_Mapping
    log_message "SmartcardLogin.plist created successfully"
}

uninstall() {
    log_message "Starting uninstallation process"
    
    # Remove AltSecurityIdentities
    if /usr/bin/dscl . -read /Users/"$AUID" AltSecurityIdentities &>/dev/null; then
        log_message "Removing AltSecurityIdentities for $AUID"
        /usr/bin/dscl . -delete /Users/"$AUID" AltSecurityIdentities
        log_message "AltSecurityIdentities removed successfully"
    else
        log_message "No AltSecurityIdentities found for $AUID"
    fi
    
    # Remove SmartcardLogin.plist
    if [ -f /etc/SmartcardLogin.plist ]; then
        log_message "Removing SmartcardLogin.plist"
        rm -f /etc/SmartcardLogin.plist
        log_message "SmartcardLogin.plist removed successfully"
    else
        log_message "SmartcardLogin.plist not found"
    fi

    if [[ "$USE_OSASCRIPT" == "true" ]]; then
        osascript -e "display dialog \"Smartcard mapping has been removed for $AUID\" with title \"Smartcard Mapping\" buttons {\"Quit\"} default button \"Quit\" with icon note"
    else
        "$DIALOG_PATH" \
            --title "Smartcard Mapping" \
            --messagealignment center \
            --message "Smartcard mapping has been removed for $AUID" \
            --hideicon \
            --ontop \
            --moveable \
            --small \
            --buttonstyle center \
            --height 200 \
            --button1text "Quit" 2> /dev/null
    fi
    
    log_message "Uninstallation completed"
}

enableFileVault () {
    log_message "Enabling FileVault for $AUID"
    user_uuid=$(dscl . -read /Users/$AUID GeneratedUID 2>/dev/null | awk '{print $2}')
    log_message "User UUID for $AUID: $user_uuid"
    if [[ -z "$user_uuid" ]]; then
        log_message "Could not retrieve UUID for $AUID"
        return 1
    fi

    # Check if user is already a FileVault enabled user
    if fdesetup list | grep -q "$user_uuid"; then
        log_message "FileVault is already enabled for $AUID (UUID: $user_uuid)"
    else
        log_message "User $AUID is not currently a FileVault enabled user"
    fi

    hash=$(sc_auth identities | awk '/PIV/ {print $1}')
    log_message "sc_auth hash for $AUID: $hash"
    if [[ -n "$hash" && -n "$AUID_UID" ]]; then
        # Only proceed if ;amidentity;$hash is not already present
        if ! dscl . -read /Users/$AUID AuthenticationAuthority 2>/dev/null | grep -q ";amidentity;$hash"; then
            log_message "Enabling FileVault with sc_auth for $AUID"
            launchctl asuser $AUID_UID sudo -u $AUID sc_auth filevault -o enable -u $AUID -h $hash
            log_message "FileVault enabled for $AUID with hash $hash"
            dscl . -append /Users/$AUID AuthenticationAuthority ";amidentity;$hash"
            log_message "Appended ;amidentity;$hash to AuthenticationAuthority for $AUID"
            diskutil apfs updatePreboot / >/dev/null 2>&1
            log_message "Updated APFS preboot for $AUID"
            log_message "FileVault enabled for $AUID"
        else
            log_message "AuthenticationAuthority already contains ;amidentity;$hash for $AUID"
        fi
    else
        log_message "Could not enable FileVault: missing hash or UID"
    fi
}

# Main execution
if [[ "$UNINSTALL" == "true" ]]; then
    uninstall
else
    prompt
    checkForPaired
    getUPN
    if [[ $arch == "arm64" ]]; then
        enableFileVault
    fi
    createAltSecId
    createMapping
    # Remove any existing values for SmartCardEnforcement
    dscl . -delete /Users/$AUID SmartCardEnforcement 2>/dev/null
fi
log_message "Script completed successfully"
