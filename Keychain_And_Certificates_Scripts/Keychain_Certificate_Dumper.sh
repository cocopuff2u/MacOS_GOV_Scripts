#!/bin/bash
####################################################################################################
#
# MacOS Keychain Certificate Dumper
#
# Purpose: Dumps all the keychains certificates for an admin to verify via log or terminal output
#
# To run script open terminal and type 'sudo bash /path/to/script.sh'
#
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 08/16/24 - Original
#
####################################################################################################

# Script Variables
ENABLE_LOGGING=true # Disables logging output [ true (default) | false ] )
LOG_FILE="/var/log/Keychain_Dump.log" # Default Log Path [ /var/log/Keychain_Dump.log ]
CLEAR_LOGS=true # Clears existing local logs before running [ true (default) | false ] )

FILTER_DOD=true # Hides all DoD/DOD Certificates present in the keychains
FILTER_CRITERIA=""  # Comma-separated list of additional filtering criteria example ("apple,adobe")

MAKE_TERMINAL_COLORFUL=true # Gives terminal color for the outputs * Requires HIDE_RESULTS_IN_TERMINAL=false * [ true (default) | false ]
HIDE_TERMINAL_OUTPUT=false  # Show output in terminal when running script local [ true | false (default) ]

####################################################################################################
#
# Making Some Colors
#
####################################################################################################

# Color Definitions
if [ -t 1 ]; then
    BLACK=$(tput setaf 0)
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    MAGENTA=$(tput setaf 5)
    CYAN=$(tput setaf 6)
    WHITE=$(tput setaf 7)
    RESET=$(tput sgr0)
    BOLD=$(tput bold)
    ORANGE=$(tput setaf 208)
else
    BLACK=""
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    MAGENTA=""
    CYAN=""
    WHITE=""
    RESET=""
    BOLD=""
    ORANGE=""
fi

# Export color variables
export BLACK RED GREEN YELLOW BLUE MAGENTA CYAN WHITE RESET BOLD ORANGE

# Helper Function
print_colored() {
    local color="$1"
    local message="$2"

    if [ "$HIDE_TERMINAL_OUTPUT" = true ]; then
        return
    fi

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        case "$color" in
            BLACK) color_code="$BLACK" ;;
            RED) color_code="$RED" ;;
            GREEN) color_code="$GREEN" ;;
            YELLOW) color_code="$YELLOW" ;;
            BLUE) color_code="$BLUE" ;;
            MAGENTA) color_code="$MAGENTA" ;;
            CYAN) color_code="$CYAN" ;;
            WHITE) color_code="$WHITE" ;;
            RESET) color_code="$RESET" ;;
            BOLD) color_code="$BOLD" ;;
            ORANGE) color_code="$ORANGE" ;;
            *) color_code="$RESET" ;; # Default to RESET if color not found
        esac

        printf "%b%s%b\n" "${color_code}${BOLD}" "$message" "$RESET"
    else
        echo "$message"
    fi
}

print_label_value() {
    local label="$1"
    local value="$2"

    # Define color variables
    local WHITE=$(tput setaf 7)
    local ORANGE=$(tput setaf 208)
    local RESET=$(tput sgr0)

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
    # Print the label and value
    printf "%b%s%b%b%s%b\n" "${BOLD}$WHITE" "$label: " "${RESET}$ORANGE" "$value" "$RESET"
    else
    echo "$label:" "$value"
    fi
}


log_message() {
    local message="$1"

    if [ "$ENABLE_LOGGING" = true ]; then
        echo "$message" >> "$LOG_FILE"
    fi
}

initialize_log_file() {
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
        echo ""
        print_colored "WHITE" "Log file created: $LOG_FILE"
        echo ""
    fi
}

clear_log_file() {
    if [ "$CLEAR_LOGS" = true ]; then
        : > "$LOG_FILE"
        echo ""
        print_colored "WHITE" "Cleared existing log before starting: $LOG_FILE"
        echo ""
    fi
}

add_date_header() {
    local log_file=$1
    {
        echo "==========================================================="
        echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
        echo "Keychain Certificate Dump"
        echo "Log Date: $(date +'%Y-%m-%d %I:%M:%S %p')"
        echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
        echo "==========================================================="
    } >> "$log_file"
}

process_keychain() {
    local keychain_path=$1
    local keychain_name=$2

    echo ""
    print_colored "CYAN" "####"
    print_colored "CYAN" "Dumping keychain: $keychain_name"
    print_colored "CYAN" "Keychain Path: $keychain_path"
    print_colored "CYAN" "####"
    echo ""

    log_message ""
    log_message "####"
    log_message "Dumping keychain: $keychain_name"
    log_message "Keychain Path: $keychain_path"
    log_message "####"
    log_message ""

    local output
    output=$(/usr/bin/security dump-keychain "$keychain_path" | /usr/bin/awk -F'\"' '/labl/ {print $4}')

    if $FILTER_DOD; then
        output=$(echo "$output" | grep -v -i "DoD")
    fi

    # Apply additional filters if provided
    if [ -n "$FILTER_CRITERIA" ]; then
        IFS=',' read -r -a filters <<< "$FILTER_CRITERIA"
        for filter in "${filters[@]}"; do
            output=$(echo "$output" | grep -v -i "$filter")
        done
    fi

    if [ -z "$output" ]; then
        print_colored "WHITE" "No certs found in $keychain_name"
        log_message "No certs found in $keychain_name"
    else
        print_colored "RED" "$output"
        log_message "$output"
    fi
    echo ""
}

####################################################################################################
#
# Script Starts Here
#
####################################################################################################

print_colored "GREEN" "==========================================================="
print_colored "GREEN" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
print_colored "GREEN" "(⌐■_■) SCRIPT SET VARIABLES"
print_colored "GREEN" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
print_colored "GREEN" "==========================================================="
print_colored "WHITE" "Script written by https://github.com/cocopuff2u"
echo ""
print_label_value "CLEAR_LOGS" "($CLEAR_LOGS)"
print_label_value "FILTER_DOD" "($FILTER_DOD)"
print_label_value "FILTER_CRITERIA" "($FILTER_CRITERIA)"
echo ""
print_label_value "ENABLE_LOGGING" "($ENABLE_LOGGING)"
print_label_value "MAKE_TERMINAL_COLORFUL" "($MAKE_TERMINAL_COLORFUL)"
print_label_value "LOG_FILE" "($LOG_FILE)"
print_label_value "HIDE_RESULTS_IN_TERMINAL" "($HIDE_TERMINAL_OUTPUT)"
print_colored "GREEN" "==========================================================="

initialize_log_file
clear_log_file

print_colored "GREEN" "==========================================================="
print_colored "GREEN" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
print_colored "GREEN" "Dumping Users Keychains"
print_colored "GREEN" "Log Date: $(date +'%Y-%m-%d %I:%M:%S %p')"
print_colored "GREEN" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
print_colored "GREEN" "==========================================================="

if [ "$ENABLE_LOGGING" = true ]; then
    add_date_header "$LOG_FILE"
fi

for home_dir in /Users/*; do
    if [ "$home_dir" = "/Users/Shared" ]; then
        continue
    fi

    if [ -d "$home_dir" ] && [ -d "$home_dir/Library/Keychains" ]; then
        print_colored "MAGENTA" "==========================================================="
        print_colored "MAGENTA" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
        print_colored "MAGENTA" "Processing keychains for user directory: $home_dir..."
        print_colored "MAGENTA" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
        print_colored "MAGENTA" "==========================================================="

        log_message "==========================================================="
        log_message "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
        log_message "Processing keychains for user directory: $home_dir..."
        log_message "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
        log_message "==========================================================="

        KEYCHAIN_DIR="$home_dir/Library/Keychains"
        keychain_files=$(find "$KEYCHAIN_DIR" -name "*.keychain*" -print)

        for keychain in $keychain_files; do
            process_keychain "$keychain" "$(basename "$keychain")"
        done
    else
        print_colored "RED" "No valid keychains directory found for user directory: $home_dir"
        log_message "No valid keychains directory found for user directory: $home_dir"
    fi
    log_message ""
done

print_colored "GREEN" "==========================================================="
print_colored "GREEN" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
print_colored "GREEN" "Dumping System Keychain"
print_colored "GREEN" "Log Date: $(date +'%Y-%m-%d %I:%M:%S %p')"
print_colored "GREEN" "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
print_colored "GREEN" "==========================================================="

log_message "==========================================================="
log_message "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
log_message "Dumping System Keychain"
log_message "Log Date: $(date +'%Y-%m-%d %I:%M:%S %p')"
log_message "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
log_message "==========================================================="

system_keychain_path="/Library/Keychains/System.keychain"
process_keychain "$system_keychain_path" "System.keychain"

exit 0
