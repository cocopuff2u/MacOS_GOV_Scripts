#!/bin/zsh
#set -x

####################################################################################################
#
# # SmartCardMapping
#
# Purpose:Maps the PIV UPN from a smartcard to the AltSecurityIdentities attribute for local accounts
#
# https://github.com/cocopuff2u
#
# Note: Tested only with government smartcards/yubikeys, uses swiftdialog for GUI
#
####################################################################################################
#
#   History
#
#  1.0 03/10/25 - Original
#  1.1 03/10/25 - /etc/SmartcardLogin.plist may exist already, having the script recreate it on
#                every run to resolve issues with the smartcard not being recognized.
#
####################################################################################################

####################################################################################################
#                                    USER CONFIGURATION SECTION
####################################################################################################
# Set to "true" to uninstall
UNINSTALL=false

# Set to "true" to enable logging to /var/log, "false" to disable
ENABLE_LOGGING=true

####################################################################################################
Script_Name="SmartcardMapping"
LOG_FILE="/var/log/smartcard_mapping.log"
Script_Version="1.0"

# Logging function
log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
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

# Check for pairing
checkForPaired (){
    log_message "Checking for existing smartcard pairing"
    tokenCheck=$(/usr/bin/dscl . read /Users/"$currentUser" AuthenticationAuthority | grep -c tokenidentity)
    if [[ "$tokenCheck" > 0 ]]; then
        log_message "Unpairing smartcard from $currentUser"
        /usr/sbin/sc_auth unpair -u "$currentUser"
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
    log_message "Smartcard detected"
    /bin/echo "quit:" >> /var/tmp/dialog.log
}

getUPN(){
    log_message "Beginning UPN extraction process"
    # Create temporary directory to export certs:
    tmpdir=$(/usr/bin/mktemp -d)
    
    # Export certs on smartcard to temporary directory:
    /usr/bin/security export-smartcard -e "$tmpdir"
    log_message "Certificates exported to temporary directory"
    
    # Get path to Certificate for PIV Authentication:
    piv_path=$(ls "$tmpdir" | /usr/bin/grep '^Certificate For PIV')
    
    # Get User Principle Name from Certificate for PIV Authentication:
    UPN="$(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$piv_path" -strparse $(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$piv_path"  | /usr/bin/awk -F ':' '/X509v3 Subject Alternative Name/ {getline; print $1}') | /usr/bin/awk -F ':' '/UTF8STRING/{print $4}')"
    log_message "Retrieved UPN: $UPN"
    
    # Clean up the temporary directory
    /bin/rm -rf $tmpdir
    log_message "Cleaned up temporary directory"
}

createAltSecId (){
    log_message "Checking existing AltSecurityIdentities"
    altSecCheck=$(/usr/bin/dscl . -read /Users/"$currentUser" AltSecurityIdentities 2>/dev/null | sed -n 's/.*Kerberos:\([^ ]*\).*/\1/p')
    if [[ "$UPN" = "" ]]; then
        log_message "Error: No UPN found for $currentUser"
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
    elif [[ "$altSecCheck" = "$UPN" ]]; then
        log_message "AltSecurityIdentities already set to $UPN"
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
    else
        log_message "Adding $UPN to AltSecurityIdentities for $currentUser"
        /usr/bin/dscl . -append /Users/"$currentUser" AltSecurityIdentities Kerberos:"$UPN"
        log_message "Successfully added AltSecurityIdentities"
        "$DIALOG_PATH" \
            --title "Smartcard Mapping" \
            --messagealignment center \
            --message "Successfully added $UPN to $currentUser" \
            --hideicon \
            --ontop \
            --moveable \
            --small \
            --buttonstyle center \
            --height 200 \
            --button1text "Quit" 2> /dev/null
    fi
}

createMapping (){
    log_message "Setting up SmartcardLogin.plist"
    if [ -f /etc/SmartcardLogin.plist ]; then
        log_message "SmartcardLogin.plist already exists"
        log_message "Removing existing SmartcardLogin.plist"
        rm -f /etc/SmartcardLogin.plist
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
    if /usr/bin/dscl . -read /Users/"$currentUser" AltSecurityIdentities &>/dev/null; then
        log_message "Removing AltSecurityIdentities for $currentUser"
        /usr/bin/dscl . -delete /Users/"$currentUser" AltSecurityIdentities
        log_message "AltSecurityIdentities removed successfully"
    else
        log_message "No AltSecurityIdentities found for $currentUser"
    fi
    
    # Remove SmartcardLogin.plist
    if [ -f /etc/SmartcardLogin.plist ]; then
        log_message "Removing SmartcardLogin.plist"
        rm -f /etc/SmartcardLogin.plist
        log_message "SmartcardLogin.plist removed successfully"
    else
        log_message "SmartcardLogin.plist not found"
    fi
    
    "$DIALOG_PATH" \
        --title "Smartcard Mapping" \
        --messagealignment center \
        --message "Smartcard mapping has been removed for $currentUser" \
        --hideicon \
        --ontop \
        --moveable \
        --small \
        --buttonstyle center \
        --height 200 \
        --button1text "Quit" 2> /dev/null
    
    log_message "Uninstallation completed"
}

# Main execution
if [[ "$UNINSTALL" == "true" ]]; then
    uninstall
else
    prompt
    checkForPaired
    getUPN
    createAltSecId
    createMapping
fi
log_message "Script completed successfully"
