#!/bin/zsh
#set -x

####################################################################################################
#
# # SmartCardDumper
#
# Purpose: viewing the certificates on a smartcard and dumping it locally
#
# https://github.com/cocopuff2u
#
# Note: Tested only with government smartcards/yubikeys, uses swiftdialog for GUI
#
####################################################################################################
#
#   History
#
#  1.0 03/04/25 - Original
#
####################################################################################################

####################################################################################################
#                                    USER CONFIGURATION SECTION
####################################################################################################
# Set to "true" to scan the certificate, "false" to skip
SCAN_DIGITAL_SIGNATURE=true
SCAN_KEY_MANAGEMENT=true
SCAN_CARD_AUTH=true
SCAN_PIV_AUTH=true

# Add your custom paths for export here (one per line)
CUSTOM_PATHS=(
    # "/path/to/custom/location1"
    # "/path/to/custom/location2"
)

# Set to "true" to enable logging to /var/log, "false" to disable
ENABLE_LOGGING=true

# Set to "true" to enable detailed certificate information logging, "false" to disable
ENABLE_DETAILED_LOGGING=false

####################################################################################################
#                                    SYSTEM CONFIGURATION SECTION
####################################################################################################
Script_Name="SmartCardDumper"
Script_Version="V1.0"

# Logging configuration
LOG_FILE="/var/log/smartcarddumper.log"

# Enhanced logging function - defined early to ensure it's available everywhere
log_message() {
    local message="[$Script_Name][$Script_Version][$(date '+%Y-%m-%d %H:%M:%S')] - $1"
    echo "$message"
    # Ensure log file is accessible and writable
    if [[ "$ENABLE_LOGGING" == "true" ]]; then
        if [[ -w "$LOG_FILE" ]] || [[ $EUID -eq 0 ]]; then
            echo "$message" >> "$LOG_FILE"
        else
            echo "Warning: Cannot write to log file $LOG_FILE" >&2
        fi
    fi
}

# Check if running as root for log file access
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root for log file access"
    exit 1
fi

# Create or set permissions for log file if it doesn't exist
if [[ ! -f "$LOG_FILE" ]]; then
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
fi

log_message "--------------------------------------------"
log_message "============= Script started ==============="
log_message "--------------------------------------------"

log_message "Script started"
log_message "Initializing configuration"

# Get current console user instead of whoami since we're running as root
log_message "Getting current console user"
CURRENT_USER=$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }')
CURRENT_USER_UID=$(id -u "$CURRENT_USER")
log_message "Current user: $CURRENT_USER (UID: $CURRENT_USER_UID)"

# Default system paths
DEFAULT_PATHS=(
    "/Users/${CURRENT_USER}/Desktop"
    "/Users/${CURRENT_USER}/Downloads"
)

# Combine default and custom paths
ALL_PATHS=("${DEFAULT_PATHS[@]}" "${CUSTOM_PATHS[@]}")

####################################################################################################
# Check for SwiftDialog
log_message "Checking for SwiftDialog"
if ! command -v dialog &> /dev/null; then
    log_message "ERROR: SwiftDialog not found"
    echo "SwiftDialog not found. Please install it first."
    exit 1
fi

# Function to get available smartcards
get_smartcards() {
    local cards=()
    while IFS= read -r line; do
        if [[ $line =~ "com.apple.pivtoken:" ]]; then
            cards+=("$line")
        fi
    done < <(security list-smartcards 2>/dev/null)
    echo "${cards[@]}"
}

# Function to create dialog select values from array
create_dialog_list() {
    local values=""
    local first=true
    for item in "$@"; do
        if [[ "$first" == "true" ]]; then
            values="$item"
            first=false
        else
            values="$values, $item"
        fi
    done
    echo "$values"
}

# Function to display cert info in SwiftDialog
display_cert_info() {
    log_message "Displaying certificate information dialog"
    local info="$1"
    local locations=$(printf ",%s" "${ALL_PATHS[@]}")
    locations=${locations:1} # Remove leading comma
    local dialog_status
    
    dialog_output=$(dialog \
        --title "Certificate Information" \
        --message "$info" \
        --icon "SF=creditcard.circle.fill,palette=white,white,orange" \
        --infotext "$Script_Version" \
        --selecttitle "Export certificates to:" \
        --selectvalues "$locations" \
        --button1text "Export" \
        --button2text "Close" \
        --height 500 \
        --width 700 2>/dev/null)
    dialog_status=$?
    
    # Check if user clicked Export
    if [[ $dialog_status -eq 0 ]]; then
        log_message "User selected export"
        # Get selected location
        selected_location=$(echo "$dialog_output" | grep '"SelectedOption"' | sed 's/"SelectedOption" : "\(.*\)"/\1/')
        
        if [[ -n "$selected_location" ]]; then
            log_message "Exporting certificates to: $selected_location"
            # Create a directory for the certificates with shorter date format
            export_dir="${selected_location}/CAC_Certificates_$(date '+%b_%d_%y_%I_%M_%p')"
            mkdir -p "$export_dir"
            log_message "Created export directory: $export_dir"
            
            # Copy all certificate files
            cp "$tmpdir"/* "$export_dir/"
            log_message "Copied certificates to export directory"
            
            # Set owner to current user's UID and group to staff
            chown -R "${CURRENT_USER_UID}:staff" "$export_dir"
            
            # Set permissions to match -rw-r--r-- (644)
            find "$export_dir" -type f -exec chmod 644 {} \;
            chmod 755 "$export_dir"
            log_message "Set permissions on export directory"
        fi
    fi
    return $dialog_status
}

# Function to process certificate and display info
# Revised to ensure log_message works correctly
process_certificate() {
    local cert_name="$1"
    local cert_path=$(ls "$tmpdir" | /usr/bin/grep "^Certificate For $cert_name")
    
    # Use echo directly for debugging
    log_message "--------------------------------------------"
    log_message "=== Certificate For $cert_name ==="
    log_message "--------------------------------------------"
    
    if [[ -n "$cert_path" ]]; then
        # Try-catch style error handling for certificate processing
        {
            # Get User Principle Name with N/A fallback
            local UPN="$(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$cert_path" -strparse $(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$cert_path" 2>/dev/null | /usr/bin/awk -F ':' '/X509v3 Subject Alternative Name/ {getline; print $1}') 2>/dev/null | /usr/bin/awk -F ':' '/UTF8STRING/{print $4}')"
            UPN="${UPN:-N/A}"
            
            # Get certificate information with N/A fallbacks
            local SUBJECT_DN=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -subject | cut -d ' ' -f 2- | awk -F'=' '{print $NF}')
            SUBJECT_DN="${SUBJECT_DN:-N/A}"
            
            local ISSUER_DN=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -issuer | cut -d ' ' -f 2- | awk -F'=' '{print $NF}')
            ISSUER_DN="${ISSUER_DN:-N/A}"
            
            local SERIAL=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -serial | cut -d '=' -f 2)
            SERIAL="${SERIAL:-N/A}"
            
            # Get and format dates with N/A fallbacks
            local NOT_BEFORE=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -startdate | cut -d'=' -f2)
            local NOT_AFTER=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -enddate | cut -d'=' -f2)
            
            if [[ -n "$NOT_BEFORE" ]]; then
                local NOT_BEFORE_FORMATTED=$(date -jf "%b %d %H:%M:%S %Y %Z" "$NOT_BEFORE" "+%m/%d/%y at %I:%M %p" 2>/dev/null)
                NOT_BEFORE_FORMATTED="${NOT_BEFORE_FORMATTED:-N/A}"
            else
                local NOT_BEFORE_FORMATTED="N/A"
            fi
            
            if [[ -n "$NOT_AFTER" ]]; then
                local NOT_AFTER_FORMATTED=$(date -jf "%b %d %H:%M:%S %Y %Z" "$NOT_AFTER" "+%m/%d/%y at %I:%M %p" 2>/dev/null)
                NOT_AFTER_FORMATTED="${NOT_AFTER_FORMATTED:-N/A}"
            fi
            
            # Display information
            if [[ "$ENABLE_DETAILED_LOGGING" == "true" ]]; then
                log_message "UPN: $UPN"
                log_message "Subject DN: $SUBJECT_DN"
                log_message "Issuer DN: $ISSUER_DN"
                log_message "Serial Number: $SERIAL"
                log_message "Not Valid Before: $NOT_BEFORE_FORMATTED"
                log_message "Not Valid After: $NOT_AFTER_FORMATTED"
            else
                log_message "Output Information Hidden"
            fi
        } || {
            # Handle errors in certificate processing
            log_message "ERROR: Failed to process certificate data for $cert_name"
        }
    else
        log_message "Certificate file not found for: $cert_name"
        if [[ "$ENABLE_DETAILED_LOGGING" == "true" ]]; then
            log_message "UPN: N/A"
            log_message "Subject DN: N/A"
            log_message "Issuer DN: N/A"
            log_message "Serial Number: N/A"
            log_message "Not Valid Before: N/A"
            log_message "Not Valid After: N/A"
        fi
    fi
}

# Get available smartcards
log_message "Checking for available smartcards"
log_message "Scanning for smartcards"
smartcards=($(get_smartcards))
log_message "Smartcards found: ${#smartcards[@]}"
for card in "${smartcards[@]}"; do
    log_message "Smartcard: $card"
done

if [[ ${#smartcards[@]} -eq 0 ]]; then
    log_message "No smartcards found"
    dialog --title "Error" --message "No smartcards found." --icon caution --button1text "OK" 2>/dev/null
    exit 0
elif [[ ${#smartcards[@]} -eq 1 ]]; then
    log_message "Single smartcard found, using automatically"
    selected_card="$smartcards"
else
    log_message "Multiple smartcards found, prompting for selection"
    # Create dialog select values
    dialog_list=$(create_dialog_list "${smartcards[@]}")

    # Show card selection dialog and capture the selected card
    dialog_output=$(dialog \
        --title "Select Smartcard" \
        --message "Several smart cards have been detected. \n\n Please select the certificate you wish to view or export from the list below:" \
        --selectvalues "$dialog_list" \
        --small \
        --height 350 \
        --infotext "$Script_Version" \
        --icon "SF=creditcard.circle.fill,palette=white,white,orange" \
        --button1text "Select" \
        --button2text "Cancel" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        log_message "User cancelled operation"
        exit 0
    fi

    # Extract the selected card from dialog output - now handling the new format
    selected_card=$(echo "$dialog_output" | grep '"SelectedOption"' | sed 's/"SelectedOption" : "\(.*\)"/\1/')

    if [[ -z "$selected_card" ]]; then
        log_message "No card was selected"
        dialog --title "Error" --message "No card was selected." --icon caution --button1text "OK" 2>/dev/null
        exit 1
    fi
fi

# Verify selected card
if [[ -z "$selected_card" ]]; then
    log_message "ERROR: No smartcard selected or found"
    echo "Error: No smartcard selected or found."
    exit 1
fi

log_message "Using smartcard: $selected_card"

# Create temporary directory to export certs
log_message "Creating temporary directory"
tmpdir=$(/usr/bin/mktemp -d)

log_message "Exporting certificates from smartcard"
/usr/bin/security export-smartcard -i "$selected_card" -e "$tmpdir"

# Build array of certificate types based on user configuration
cert_types=()
[[ "$SCAN_PIV_AUTH" == "true" ]] && cert_types+=("PIV Authentication")
[[ "$SCAN_DIGITAL_SIGNATURE" == "true" ]] && cert_types+=("Digital Signature")
[[ "$SCAN_KEY_MANAGEMENT" == "true" ]] && cert_types+=("Key Management")
[[ "$SCAN_CARD_AUTH" == "true" ]] && cert_types+=("Card Authentication")

# Check if any certificates are selected for scanning
if [[ ${#cert_types[@]} -eq 0 ]]; then
    log_message "ERROR: No certificates selected for scanning"
    echo "Error: No certificates selected for scanning. Please enable at least one certificate type in the configuration section."
    exit 1
fi

# Display which certificates will be scanned
log_message "----------------------------------------"
log_message "The following certificates will be scanned:"
for cert_type in "${cert_types[@]}"; do
    log_message "* $cert_type"
done

# Process each certificate type
for cert_type in "${cert_types[@]}"; do
    process_certificate "$cert_type"
done

# Process each certificate type
message=""
for cert_type in "${cert_types[@]}"; do
    cert_path=$(ls "$tmpdir" | /usr/bin/grep "^Certificate For $cert_type")
    
    if [[ -n "$cert_path" ]]; then
        message+="=== Certificate For $cert_type ===  \n\n"
        
        # Get certificate information (reusing existing parsing logic)
        UPN="$(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$cert_path" -strparse $(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$cert_path" 2>/dev/null | /usr/bin/awk -F ':' '/X509v3 Subject Alternative Name/ {getline; print $1}') 2>/dev/null | /usr/bin/awk -F ':' '/UTF8STRING/{print $4}')"
        UPN="${UPN:-N/A}"
        
        ISSUER_DN=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -issuer | cut -d ' ' -f 2- | awk -F'=' '{print $NF}')
        SERIAL=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -serial | cut -d '=' -f 2)
        
        NOT_BEFORE=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -startdate | cut -d'=' -f2)
        NOT_AFTER=$(/usr/bin/openssl x509 -in "$tmpdir/$cert_path" -noout -enddate | cut -d'=' -f2)
        
        if [[ -n "$NOT_BEFORE" ]]; then
            NOT_BEFORE_FORMATTED=$(date -jf "%b %d %H:%M:%S %Y %Z" "$NOT_BEFORE" "+%m/%d/%y at %I:%M %p" 2>/dev/null)
        else
            NOT_BEFORE_FORMATTED="N/A"
        fi
        
        if [[ -n "$NOT_AFTER" ]]; then
            NOT_AFTER_FORMATTED=$(date -jf "%b %d %H:%M:%S %Y %Z" "$NOT_AFTER" "+%m/%d/%y at %I:%M %p" 2>/dev/null)
        else
            NOT_AFTER_FORMATTED="N/A"
        fi
        
        message+="UPN: \`${UPN}\`  \n"
        message+="Issuer DN: \`${ISSUER_DN}\`  \n"
        message+="Serial Number: \`${SERIAL}\`  \n"
        message+="Not Valid Before: \`${NOT_BEFORE_FORMATTED}\`  \n"
        message+="Not Valid After: \`${NOT_AFTER_FORMATTED}\`  \n\n"
    fi
done

# Display certificate information in SwiftDialog
log_message "--------------------------------------------"
log_message "Displaying final certificate information"
display_cert_info "$message"

# Cleanup
if [[ -n "$export_dir" ]]; then
    log_message "Cleaning up temporary directory"
    rm -rf "$tmpdir"
elif [[ $? -eq 2 ]]; then
    log_message "Operation cancelled, cleaning up"
    rm -rf "$tmpdir"
fi

log_message "--------------------------------------------"
log_message "============ Script Completed =============="
log_message "--------------------------------------------"

