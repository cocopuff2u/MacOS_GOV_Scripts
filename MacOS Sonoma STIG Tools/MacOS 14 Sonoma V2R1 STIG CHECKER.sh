#!/bin/sh
####################################################################################################
#
# MacOS 14 (SONOMA) V2R1 STIG CHECKER
#
# Purpose: Checks the requires DISA STIGS against the machines current settings
#
# To run script open terminal and type 'sudo bash /path/to/script.sh'
#
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 7/28/24 - Original (Learned from https://github.com/usnistgov/macos_security?tab=readme-ov-file)
#  1.1 8/01/24 - Added support to hide Nonchip supported commands or run/show them
#  1.2 8/05/24 - Added support for plist logging
#  1.3 8/07/24 - Fix check for V-259427
#  1.4 8/08/24 - Moved current user below adjustable variables and added 2>/dev/null to clean up
#  noise in terminal *result_output=$(eval "$command" 2>/dev/null)*
#  1.5 8/9/24 - Adjusted logging in terminal and file
#  1.6 8/12/24 - fixed check for V-259530 & fixed execute_anyresult_and_log terminal logging
#  1.7 8/13/24 - condensed add header functions
#  2.0 8/13/24 - Added user path logging, added support for CSV, and added more hide
#  2.1 8/15/24 - Created initialize_logging function and condensed all initial logging logic into it
#                Created main funtion and moved most non-function commands from around the script
#                Stylized the settings dialog to be more concise and readable
#                Moved variable's around to better group what is being declared
#                Moved checking for CSV Header from write_to_csv to initialize_logging
#  2.2 8/15/24 - Removed main function as it caused errors within the commands
####################################################################################################
# Script Supported STIG Version
STIG_VERSION="MACOS 14 (SONOMA) V2R1" # [ Do Not Adjust ]

# Script Log Names [ /var/log/Passed_STIG_Scan.log ]
PASS_LOG_FILE_NAME="Passed_STIG_Scan.log"
FAILURE_LOG_FILE_NAME="Failed_STIG_Scan.log"
SINGLE_LOG_FILE_NAME="Complete_STIG_Scan.log"
COMMAND_LOG_FILE_NAME="Command_STIG.log"
CSV_LOG_FILE_NAME="STIG_csv_logs.csv"

# Logging Options
CLEAR_LOGS=true                     # Clears existing local logs before running [ true (default) | false ] )
LOG_PATH=""                         # Change default path [ if left blank the default path is /var/log/ ]
LOG_TO_SINGLE_FILE=false            # Logs failures & passes in one log file [ true | false (default) ]
LOG_COMMANDS=true                   # Shows the commands input and output in a log file, *PERFECT FOR FILLING OUT STIG CHECKS* [ true (default) | false ]
LOG_RESULTS_TO_USER_LOG_FOLDER=true # Logs results to the users log folder [ true (default) | false ]
LOG_TO_PLIST=false                  # logs failures & passes to a plist file [ true  | false (default) ]
LOG_TO_CSV=true                    # logs failures & passes to a csv file [ true  | false (default) ]

# Plist Options
PLIST_LOG_FILE="/Library/Preferences/STIG_Checks.plist" # Default [ /Library/Preferences/STIG_Checks.plist ]

# Other Options
HIDE_RESULTS_IN_TERMINAL=false         # Show output in terminal when running script local [ true | false (default) ]
MAKE_TERMINAL_COLORFUL=true            # Gives terminal color for the outputs * Requires HIDE_RESULTS_IN_TERMINAL=false * [ true (default) | false ]
HIDE_LOGGING_LOCATION_IN_TERMINAL=true # Hides logging location in terminal when running script local [ true (default) | false ]
HIDE_NONCHIP_SUPPORTED_COMMANDS=true   # Only runs commands supported on this hardware [ true (default) | false ]

####################################################################################################
#
# Checks Before Running Script
#
####################################################################################################

# Check if the script is run as root
if [ "$(id -u)" -ne "0" ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Check the CPU type
if sysctl -n machdep.cpu.brand_string | grep -q "Apple"; then
    device_chip="Apple"
else
    device_chip="Intel"
fi

# Pulls Current User
CURRENT_USER=$(/usr/sbin/scutil <<<"show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }')

# Construct the path to the current user's Logs folder
USER_LOG_PATH="/Users/$CURRENT_USER/Library/Logs/"

if [ -z "$LOG_PATH" ]; then
    LOG_PATH="/var/log/"
fi

# Admin Log Locations
PASS_LOG_FILE="$LOG_PATH$PASS_LOG_FILE_NAME"
FAILURE_LOG_FILE="$LOG_PATH$FAILURE_LOG_FILE_NAME"
SINGLE_LOG_FILE="$LOG_PATH$SINGLE_LOG_FILE_NAME"
COMMAND_LOG_FILE="$LOG_PATH$COMMAND_LOG_FILE_NAME"
CSV_LOG_FILE="$LOG_PATH$CSV_LOG_FILE_NAME"

# User Log Locations
# Construct the path to the current user's Logs folder
USER_PASS_LOG_FILE="$USER_LOG_PATH$PASS_LOG_FILE_NAME"
USER_FAILURE_LOG_FILE="$USER_LOG_PATH$FAILURE_LOG_FILE_NAME"
USER_SINGLE_LOG_FILE="$USER_LOG_PATH$SINGLE_LOG_FILE_NAME"
USER_COMMAND_LOG_FILE="$USER_LOG_PATH$COMMAND_LOG_FILE_NAME"
USER_CSV_LOG_FILE="$USER_LOG_PATH$CSV_LOG_FILE_NAME"

####################################################################################################
#
# Making Some Colors
#
####################################################################################################

# Check if terminal supports colors
if [ -t 1 ]; then
    # Basic Colors
    BLACK=$(tput setaf 0)
    BLUE=$(tput setaf 27)
    CYAN=$(tput setaf 6)
    GREEN=$(tput setaf 10)
    MAGENTA=$(tput setaf 5)
    RED=$(tput setaf 9)
    RESET=$(tput sgr0)
    WHITE=$(tput setaf 15)
    YELLOW=$(tput setaf 3)

    # Extended Colors
    ORANGE=$(tput setaf 202)
    LIGHT_BLUE=$(tput setaf 12)
    LIGHT_GREEN=$(tput setaf 10)
    LIGHT_CYAN=$(tput setaf 14)
    LIGHT_MAGENTA=$(tput setaf 13)
    LIGHT_YELLOW=$(tput setaf 11)

    # 256 colors (example with some specific colors)
    COLOR_16=$(tput setaf 8)    # Dark grey
    COLOR_82=$(tput setaf 82)   # Light green
    COLOR_208=$(tput setaf 208) # Orange
    COLOR_75=$(tput setaf 75)   # Light teal
    COLOR_123=$(tput setaf 123) # Light purple
    COLOR_226=$(tput setaf 226) # Light yellow
    COLOR_55=$(tput setaf 55)   ## dark purple

    # Formatting
    BOLD=$(tput bold)
    UNDERLINE=$(tput smul)
    REVERSE=$(tput rev)
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
    ORANGE=""
    LIGHT_BLUE=""
    LIGHT_GREEN=""
    LIGHT_CYAN=""
    LIGHT_MAGENTA=""
    LIGHT_YELLOW=""
    COLOR_16=""
    COLOR_82=""
    COLOR_208=""
    COLOR_75=""
    COLOR_123=""
    COLOR_226=""
    COLOR_55=""
    BOLD=""
    UNDERLINE=""
    REVERSE=""
fi

# Export color variables
export BLACK RED GREEN YELLOW BLUE MAGENTA CYAN WHITE RESET ORANGE LIGHT_BLUE LIGHT_GREEN LIGHT_CYAN LIGHT_MAGENTA LIGHT_YELLOW COLOR_16 COLOR_82 COLOR_208 COLOR_75 COLOR_123 COLOR_226 COLOR_55 BOLD UNDERLINE REVERSE

#####################
### Color helpers ###
#####################

echo__light_green() {
    # Print text in green with bold formatting
    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        printf "%s%s%s\n" "${BOLD}${LIGHT_GREEN}" "$1" "${RESET}"
    else
        echo "$1"
    fi
}

echo_dark_purple() {
    # Print text in white with bold formatting
    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        printf "%s%s%s\n" "${BOLD}${COLOR_55}" "$1" "${RESET}"
    else
        echo "$1"
    fi
}

echo_gray() {
    # Print text in white with bold formatting
    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        printf "%s%s%s\n" "${COLOR_16}" "$1" "${RESET}"
    else
        echo "$1"
    fi
}

echo_rainbow_text() {
    local text="$1"
    local colors=("${RED}" "${ORANGE}" "${YELLOW}" "${GREEN}" "${CYAN}" "${BLUE}" "${MAGENTA}")
    local num_colors=${#colors[@]}
    local color_index=0

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        for ((i = 0; i < ${#text}; i++)); do
            local char="${text:$i:1}"
            printf "%s%s" "${colors[$color_index]}" "$char"
            color_index=$(((color_index + 1) % num_colors))
        done
        printf "%s\n" "$RESET"
    else
        echo "$text"
    fi
}

echo_white() {
    # Print text in white with bold formatting
    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        printf "%s%s%s\n" "${WHITE}" "$1" "${RESET}"
    else
        echo "$1"
    fi
}

echo_white_bold() {
    # Print text in white with bold formatting
    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        printf "%s%s%s\n" "${BOLD}${WHITE}" "$1" "${RESET}"
    else
        echo "$1"
    fi
}

echo_set_variables() {
    local variable_name=$1
    local setting=$2

    # Print variable_name in white and setting in bold blue within parentheses
    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        printf "%s (%s%s%s)\n" "${BOLD}${WHITE}${variable_name}${RESET}" "${ORANGE}${setting}${RESET}" "${RESET}"
    else
        echo "$variable_name ($setting)"
    fi
}

echo_command_check() {
    local V_ID=$1
    local V_ID_NAME=$2

    # Print variable_name in white and setting in bold blue within parentheses
    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        printf "${BOLD}Running STIG check: %s (%s%s%s)\n" "${BOLD}${BLUE}${V_ID}${RESET}" "${WHITE}${V_ID_NAME}${RESET}" "${RESET}"
    else
        echo "Running STIG check: $V_ID ($V_ID_NAME)"
    fi
}

echo_result() {
    # Print the result in white and status in green/red if color is enabled
    local status="$1"

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        if [ "$status" = "Passed" ]; then
            printf "%s${BOLD}Results: (%s%s%s)\n" "${WHITE}" "${RESET}" "${BOLD}${GREEN}Passed${RESET}" "${RESET}"
        elif [ "$status" = "Failed" ]; then
            printf "%s${BOLD}Results: (%s%s%s)\n" "${WHITE}" "${RESET}" "${BOLD}${RED}Failed${RESET}" "${RESET}"
        else
            printf "%s${BOLD}Results: (%s%s%s)\n" "${WHITE}" "${RESET}" "${BOLD}${YELLOW}Manual Verify${RESET}"
        fi
    else
        echo "Check Results: $status"
    fi
}

####################################################################################################
#
# Logging Functions Below
#
####################################################################################################

# Function to initialize the plist file
initialize_plist() {
    echo '<?xml version="1.0" encoding="UTF-8"?>' >"$PLIST_LOG_FILE"
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >>"$PLIST_LOG_FILE"
    echo '<plist version="1.0">' >>"$PLIST_LOG_FILE"
    echo '<dict>' >>"$PLIST_LOG_FILE"
    echo '</dict>' >>"$PLIST_LOG_FILE"
    echo '</plist>' >>"$PLIST_LOG_FILE"
}

# Function to update the plist file with a check result
update_plist() {
    local check_name=$1
    local simple_name=$2
    local boolean_result=$3

    # Create a temporary plist file for processing
    local temp_plist="/var/log/STIG_Checks_temp.plist"

    # Extract the existing plist content
    /usr/libexec/PlistBuddy -x -c "Print" "$PLIST_LOG_FILE" >"$temp_plist"

    # Update the plist with the new check result
    /usr/libexec/PlistBuddy -c "Add :$check_name\_$simple_name dict" "$temp_plist"
    /usr/libexec/PlistBuddy -c "Add :$check_name\_$simple_name:finding bool $boolean_result" "$temp_plist"

    # Replace the original plist file with the updated one
    mv "$temp_plist" "$PLIST_LOG_FILE"
}

# Function to add date header to log files
add_date_header() {
    local log_file=$1
    local checks=$2

    echo "===========================================================" >>"$log_file"
    echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$log_file"
    echo "$STIG_VERSION" >>"$log_file"
    echo "$checks" >>"$log_file"
    echo "Log Date: $(date +'%Y-%m-%d %I:%M:%S %p')" >>"$log_file"
    echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$log_file"
    echo "===========================================================" >>"$log_file"
    echo "" >>"$log_file"
}

# Function to log results to the appropriate file
log_result() {
    local check_name=$1
    local result=$2
    local chip_specific=$3

    if [ "$LOG_TO_SINGLE_FILE" = true ]; then
        log_file="$SINGLE_LOG_FILE"
        User_log_file="$USER_SINGLE_LOG_FILE"
    else
        if [ "$result" = "Passed" ]; then
            log_file="$PASS_LOG_FILE"
            User_log_file="$USER_PASS_LOG_FILE"
        else
            log_file="$FAILURE_LOG_FILE"
            User_log_file="$USER_FAILURE_LOG_FILE"
        fi
    fi

    # Append the log message to the appropriate file with a timestamp
    echo "$check_name: $result$([ "$HIDE_NONCHIP_SUPPORTED_COMMANDS" = false ] && [ -n "$chip_specific" ] && echo " (Chip Specific: $chip_specific)")" >>"$log_file"

    if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
        echo "$check_name: $result$([ "$HIDE_NONCHIP_SUPPORTED_COMMANDS" = false ] && [ -n "$chip_specific" ] && echo " (Chip Specific: $chip_specific)")" >>"$User_log_file"
    fi

    if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
        if [ "$HIDE_LOGGING_LOCATION_IN_TERMINAL" = false ]; then
            echo_gray "Logged result output to $log_file"
            if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                echo_gray "Logged result output to $User_log_file"
            fi
        fi
        echo_result "$result"
    fi
}

# Function to log command outputs
log_command_output() {
    local check_name=$1
    local command=$2
    local command_output=$3
    local expected_result=$4
    local simple_name=$5
    local chip_specific=$6

    if [ "$LOG_TO_CSV" = true ]; then
        write_to_csv "$check_name" "$command_output" "$expected_result" "$simple_name" "$chip_specific"
    fi

    if [ "$LOG_COMMANDS" = true ]; then
        echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$COMMAND_LOG_FILE"
        echo "Run Time: $(date +'%Y-%m-%d %I:%M:%S %p')" >>"$COMMAND_LOG_FILE"
        echo "Vul ID: $check_name ($simple_name)" >>"$COMMAND_LOG_FILE"
        echo "" >>"$COMMAND_LOG_FILE"
        echo "Command Inputted: $command" >>"$COMMAND_LOG_FILE"
        echo "" >>"$COMMAND_LOG_FILE"
        echo "Command Outputted: $command_output" >>"$COMMAND_LOG_FILE"
        echo "Expected STIG Result: $expected_result" >>"$COMMAND_LOG_FILE"
        if [ -n "$chip_specific" ]; then
            echo "Chip Specific: $chip_specific" >>"$COMMAND_LOG_FILE"
        fi
        echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$COMMAND_LOG_FILE"
        if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
            echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$USER_COMMAND_LOG_FILE"
            echo "Run Time: $(date +'%Y-%m-%d %I:%M:%S %p')" >>"$USER_COMMAND_LOG_FILE"
            echo "Vul ID: $check_name ($simple_name)" >>"$USER_COMMAND_LOG_FILE"
            echo "" >>"$USER_COMMAND_LOG_FILE"
            echo "Command Inputted: $command" >>"$USER_COMMAND_LOG_FILE"
            echo "" >>"$USER_COMMAND_LOG_FILE"
            echo "Command Outputted: $command_output" >>"$USER_COMMAND_LOG_FILE"
            echo "Expected STIG Result: $expected_result" >>"$USER_COMMAND_LOG_FILE"
            if [ -n "$chip_specific" ]; then
                echo "Chip Specific: $chip_specific" >>"$USER_COMMAND_LOG_FILE"
            fi
            echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$USER_COMMAND_LOG_FILE"
        fi
        if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
            if [ "$HIDE_LOGGING_LOCATION_IN_TERMINAL" = false ]; then
                echo_gray "Logged command output to $COMMAND_LOG_FILE"
                if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                    echo_gray "Logged command output to $USER_COMMAND_LOG_FILE"
                fi
            fi
        fi
    fi
}

# Function to log results to CSV
write_to_csv() {
    local check_name="$1"
    local command_output="$2"
    local expected_result="$3"
    local simple_name="$4"
    local chip_specific="$5"
    local pass_fail=""

    # Preserve newlines and special characters by quoting the fields

    if [ "$command_output" = "$expected_result" ]; then
        pass_fail="Passed"
    else
        pass_fail="Failed"
    fi

    # Append the data row to the CSV file
    echo "$check_name,$simple_name,$pass_fail,\"$command_output\",\"$expected_result\"" >>"$CSV_LOG_FILE"

    if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
        echo "$check_name,$simple_name,$pass_fail,\"$command_output\",\"$expected_result\"" >>"$USER_CSV_LOG_FILE"
    fi

}

initialize_logging() {
    local file_list=$(declare -p | grep -E '^[^=]+FILE' | grep -Ev '(FILE_NAME|LOG_TO)' | cut -d ' ' -f 3 | cut -d '=' -f 2)
    local removed_files=()
    local csv_header="Check Name,Simple Name,Pass/Fail,Result,Expected"

    if [ "$CLEAR_LOGS" = true ]; then
        for file_name in $file_list; do
            if [ -f "$file_name" ]; then
                rm -f "$file_name"
                removed_files+=("$file_name")
            fi
        done
    fi

    if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
        echo ""
        echo_white_bold "Cleared existing logs before starting:"

        for removed_file in "${removed_files[@]}"; do
            echo_gray "$removed_file"
        done

        echo ""
        echo__light_green "==========================================================="
        echo ""
    fi

    if [ "$LOG_TO_PLIST" = true ]; then
        initialize_plist
    fi

    # Add date header to logs single or combined
    if [ "$LOG_TO_SINGLE_FILE" = false ]; then
        add_date_header "$PASS_LOG_FILE" "PASSED STIG CHECKS"
        add_date_header "$FAILURE_LOG_FILE" "FAILED STIG CHECKS"

        if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
            add_date_header "$USER_PASS_LOG_FILE" "PASSED STIG CHECKS"
            add_date_header "$USER_FAILURE_LOG_FILE" "FAILED STIG CHECKS"
        fi

        # Add date header to command logs
        if [ "$LOG_COMMANDS" = true ]; then
            add_date_header "$COMMAND_LOG_FILE" "STIG COMMAND OUTPUT LOGS"

            if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                add_date_header "$USER_COMMAND_LOG_FILE" "STIG COMMAND OUTPUT LOGS"
            fi

        fi
    else
        add_date_header "$SINGLE_LOG_FILE" "COMPLETE STIG CHECKS"

        if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
            add_date_header "$USER_SINGLE_LOG_FILE" "COMPLETE STIG CHECKS"
        fi

        # Add date header to command logs
        if [ "$LOG_COMMANDS" = true ]; then
            add_date_header "$COMMAND_LOG_FILE" "STIG COMMAND OUTPUT LOGS"

            if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                add_date_header "$USER_COMMAND_LOG_FILE" "STIG COMMAND OUTPUT LOGS"
            fi
        fi
    fi

    if [ "$LOG_TO_CSV" = true ]; then
        if [ ! -f "$CSV_LOG_FILE" ]; then
            # File does not exist; write the header
            echo "$HEADER" >"$CSV_LOG_FILE"

            if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                echo "$HEADER" >"$USER_CSV_LOG_FILE"
            fi

        elif ! grep -q "^$HEADER$" "$CSV_LOG_FILE"; then
            # File exists but does not contain the header; add the header
            echo "$HEADER" >>"$CSV_LOG_FILE"

            if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                echo "$HEADER" >>"$USER_CSV_LOG_FILE"
            fi
        fi
    fi
}

####################################################################################################
#
# Execute and Trigger Log Commands Below
#
####################################################################################################

# Function to execute a command, log the output, and match the result with expected output
execute_and_log() {
    local check_name=$1
    local command=$2
    local expected_result=$3
    local simple_name=$4

    if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
        echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
        echo_command_check "$check_name" "$simple_name"
    fi
    # Execute the command and capture the output
    result_output=$(eval "$command" 2>/dev/null)

    # Log the command output
    log_command_output "$check_name" "$command" "$result_output" "$expected_result" "$simple_name"

    # Determine the result and log it
    if [ "$result_output" = "$expected_result" ]; then
        result="Passed"
        boolean_result="false"
    else
        result="Failed"
        boolean_result="true"
    fi

    # Log to plist file
    if [ "$LOG_TO_PLIST" = true ]; then
        update_plist "$check_name" "$simple_name" "$boolean_result"
    fi

    log_result "$check_name ($simple_name)" "$result"
}

execute_and_log_chip_specific() {
    local check_name=$1
    local command=$2
    local expected_result=$3
    local simple_name=$4
    local chip_specific=$5

    if [[ "$chip_specific" == *"$device_chip"* ]]; then
        if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
            echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
            echo_command_check "$check_name" "$simple_name"
        fi
        # Execute the command and capture the output
        result_output=$(eval "$command" 2>/dev/null)

        # Log the command output
        log_command_output "$check_name" "$command" "$result_output" "$expected_result" "$simple_name" "$chip_specific"

        # Determine the result and log it
        if [ "$result_output" = "$expected_result" ]; then
            result="Passed"
            boolean_result="false"
        else
            result="Failed"
            boolean_result="true"
        fi

        # Log to plist file
        if [ "$LOG_TO_PLIST" = true ]; then
            update_plist "$check_name" "$simple_name" "$boolean_result"
        fi

        log_result "$check_name ($simple_name)" "$result" "$chip_specific"
    else
        if [ "$HIDE_NONCHIP_SUPPORTED_COMMANDS" = false ]; then
            if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
                echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
                echo_command_check "$check_name" "$simple_name"
            fi
            # Execute the command and capture the output
            result_output=$(eval "$command" 2>/dev/null)

            # Log the command output
            log_command_output "$check_name" "$command" "$result_output" "$expected_result" "$simple_name" "$chip_specific"

            # Determine the result and log it
            if [ "$result_output" = "$expected_result" ]; then
                result="Passed"
                boolean_result="false"
            else
                result="Failed"
                boolean_result="true"
            fi

            # Log to plist file
            if [ "$LOG_TO_PLIST" = true ]; then
                update_plist "$check_name" "$simple_name" "$boolean_result"
            fi

            log_result "$check_name ($simple_name)" "$result" "$chip_specific"
        fi
    fi
}

# Function to execute a command, log the output, and determine verify any output
execute_anyresult_and_log() {
    local check_name=$1
    local command=$2
    local expected_result=$3
    local simple_name=$4

    if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
        echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
        echo_command_check "$check_name" "$simple_name"
    fi

    # Execute the command and capture the output
    result_output=$(eval "$command" 2>/dev/null)

    # Log the command output
    log_command_output "$check_name" "$command" "$result_output" "$expected_result" "$simple_name"

    # Determine the result and log it
    if [ -n "$result_output" ]; then
        result="Passed"
        boolean_result="false"
    else
        result="Failed"
        boolean_result="true"
    fi

    # Log to plist file
    if [ "$LOG_TO_PLIST" = true ]; then
        update_plist "$check_name" "$simple_name" "$boolean_result"
    fi

    log_result "$check_name $simple_name" "$result"
}

initialize_logging

####################################################################################################
#
# Echo Settings into Terminal Below
#
####################################################################################################

# Echo the values to the terminal
if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
    echo__light_green "==========================================================="
    echo__light_green "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
    echo__light_green "(⌐■_■) SCRIPT SET VARIABLES"
    echo__light_green "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="
    echo__light_green "==========================================================="
    echo_set_variables "STIG Version:" "$STIG_VERSION"
    echo_white "Script written by https://github.com/cocopuff2u"
    echo ""
    echo_white_bold "~~~ Script Settings ~~~"
    echo_set_variables "Clear Existing Logs" "$CLEAR_LOGS"
    echo_set_variables "Consolidate Logs" "$LOG_TO_SINGLE_FILE"
    echo_set_variables "Log Command Output/Input" "$LOG_COMMANDS"
    echo_set_variables "Log Results to Plist" "$LOG_TO_PLIST"
    echo_set_variables "Log Results to CSV" "$LOG_TO_CSV"
    echo_set_variables "Log Results to Users Log Folder" "$LOG_RESULTS_TO_USER_LOG_FOLDER"
    echo ""
    echo_white_bold "~~~ Log Locations ~~~"

    if [ "$LOG_TO_SINGLE_FILE" = false ]; then
        echo_set_variables "Passed Log File Path" "$PASS_LOG_FILE"
        echo_set_variables "Failed Log File Path" "$FAILURE_LOG_FILE"
    else
        echo_set_variables "Consolidate Log File Path" "$SINGLE_LOG_FILE"
    fi

    echo_set_variables "Command Log File Path" "$COMMAND_LOG_FILE"

    if [ "$LOG_TO_PLIST" = true ]; then
        echo_set_variables "Plist Log File Path" "$PLIST_LOG_FILE"
    fi

    if [ "$LOG_TO_CSV" = true ]; then
        echo_set_variables "CSV Log File Path" "$CSV_LOG_FILE"
    fi

    if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
        echo ""
        if [ "$LOG_TO_SINGLE_FILE" = false ]; then
            echo_set_variables "Passed Log File Path (user)" "$USER_PASS_LOG_FILE"
            echo_set_variables "Failed Log File Path (user)" "$USER_FAILURE_LOG_FILE"
        else
            echo_set_variables "Consolidate Log File Path (user)" "$USER_SINGLE_LOG_FILE"
        fi

        echo_set_variables "Command Log File Path (user)" "$USER_COMMAND_LOG_FILE"

        if [ "$LOG_TO_CSV" = true ]; then
                echo_set_variables "CSV Log File Path (user)" "$USER_CSV_LOG_FILE"
        fi
    fi

    echo ""
    echo_white_bold "~~~ Terminal Settings ~~~"
    echo_set_variables "Hide Results in Ierminal" "$HIDE_RESULTS_IN_TERMINAL"
    echo_rainbow_text "Enable Terminal Colorization ($MAKE_TERMINAL_COLORFUL)"
    echo_set_variables "Hide Logging Location in Ierminal" "$HIDE_LOGGING_LOCATION_IN_TERMINAL"
    echo_set_variables "Hide Nonchip Supported Commands" "$HIDE_NONCHIP_SUPPORTED_COMMANDS"
    echo__light_green "==========================================================="
    echo ""

fi

####################################################################################################
#
# STIG VUL's Checks Below
#
####################################################################################################
#
# # # # # # # # # # # # # # # # # # EXAMPLE EXPLAINED # # # # # # # # # # # # # # # # # # # # # # #
#
#
# ## VUL-ID ##
# check_name="V-259418"
#
# ## PART OF THE RULE TITLE ##
# simple_name="Watch_Allow_Auto_Unlock_Disabled"
#
# ## THE COMMAND TO CHECK FOR THE VULNERABILITY ##
# ## READ NOTES BELOW ##
# command="/usr/bin/dscl localhost -list . \| /usr/bin/grep -qvE '(Contact\|Search\|Local\|^$)'; /bin/echo $?"
#
# ## EXPECTED OUTPUT RESULT ##
# ## READ NOTES BELOW ##
# expected_result="false"
#
# ## TO TRIGGER THE CHECK ##
# ## READ NOTES BELOW ##
# execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"
#
#
# #### NOTES ####
# Some commands that contain $1 or $2 you you need to put \$2
# Some commands that need single quotes "" changed to '' and visa versa
# Some commands need to be ran without "" and use ''
# Expected_value is case sensitive
# Use another execute_anyresult_and_log function for results that need any output as not a finding
# For execute_anyresult_and_log leave expected_result empty
#
# # # # # # # # # # # # # # # # # # EXAMPLE EXPLAINED # # # # # # # # # # # # # # # # # # # # # # #

##############################################
##############################################
# Starting List

if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
    echo_dark_purple "==========================================================="
    echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
    echo_dark_purple " STARTING STIG CHECKS"
    echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
    echo_dark_purple "==========================================================="
fi

##############################################
##############################################
check_name="V-259418"
simple_name="Watch_Allow_Auto_Unlock_Disabled"
command="/usr/bin/osascript -l JavaScript << EOS
var defaults = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess');
var value = defaults.objectForKey('allowAutoUnlock').js;
value;
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259419"
simple_name="Enforce_Screen_Saver_Password"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPassword').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259420"
simple_name="Lock_No_More_Than_5_Seconds_After_Screen_Saver"
command="/usr/bin/osascript -l JavaScript << EOS
function run() {
  let delay = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPasswordDelay'))
  if ( delay <= 5 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"
##############################################
check_name="V-259421"
simple_name="Lock_When_Smart_Token_Removed"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('tokenRemovalAction').js
EOS"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"
##############################################
check_name="V-259422"
simple_name="Disable_Hot_Corners"
command="/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '\"wvous-bl-corner\" = 0|\"wvous-br-corner\" = 0|\"wvous-tl-corner\" = 0|\"wvous-tr-corner\" = 0'"
expected_result="4"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"
##############################################
check_name="V-259423"
simple_name="Prevent_AdminHostInfo_Being_Avaible_At_LoginWindow"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectIsForcedForKey('AdminHostInfo')
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259424"
simple_name="Disable_Temporary_or_Emergency_User_Accounts_Within_72_Hours"
command=""
expected_result=""

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259425"
simple_name="Must_Enforce_Time_Synchronization"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259427"
simple_name="Must_Be_Intergrated_Into_A_Directory_Services_Infrastructure"
command="/usr/bin/dscl localhost -list . \| /usr/bin/grep -qvE '(Contact\|Search\|Local\|^$)'; /bin/echo $?"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259428"
simple_name="Limited_Consecutive_Failed_Log_On_Attempts_To_Three"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail -n +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyAttributeMaximumFailedAuthentications\"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if (\$1 <= 3) {print \"yes\"} else {print \"no\"}}'"
expected_result="yes"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259429"
simple_name="DoD_Notice_And_Consent_Banner_At_Remote_Log_On"
command="/usr/bin/more /etc/banner"
expected_result="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259430"
simple_name="Display_DoD_Notice_and_Consent_Banner"
command="/usr/sbin/sshd -G | /usr/bin/grep -c '^banner /etc/banner'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259431"
simple_name="Display_DoD_Notice_and_Consent_Banner_At_Login_Window"
command="/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="1"

# Comments Looks if file exists, user needs to verify it contains what it needs

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259432"
simple_name="Log_Files_To_Not_Contain_Access_Control_Lists"
command="/bin/ls -le \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '{print \$1}' | /usr/bin/grep -c ':'"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259433"
simple_name="Audit_Log_Folder_To_Not_Contain_Access_Control_List"
command="/bin/ls -lde /var/audit | /usr/bin/awk '{print \$1}' | /usr/bin/grep -c ':'"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259434"
simple_name="Disable_FileVault_Automatic_Log_On"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('DisableFDEAutoLogin').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259435"
simple_name="SSHD_ClientAliveInterval_to_900"
command="/usr/sbin/sshd -G | /usr/bin/awk '/clientaliveinterval/{print \$2}'"
expected_result="900"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259436"
simple_name="SSHD_ClientAliveCountMax_to_1"
command="/usr/sbin/sshd -G | /usr/bin/awk '/clientalivecountmax/{print \$2}'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259437"
simple_name="Login_Grace_Time_To_30"
command="/usr/sbin/sshd -G | /usr/bin/awk '/logingracetime/{print \$2}'"
expected_result="30"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259438"
simple_name="Limit_SSHD_to_FIPS_Compliant"
command='fips_sshd_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256"); total=0; for config in "${fips_sshd_config[@]}"; do total=$(( $(/usr/sbin/sshd -G | /usr/bin/grep -i -c "$config") + total )); done; echo $total'
expected_result="7"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259439"
simple_name="Limit_SSH_to_FIPS_Compliant"
command="fips_ssh_config='Host *
Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256'
/usr/bin/grep -c '$fips_ssh_config' /etc/ssh/ssh_config.d/fips_ssh_config"
expected_result="8"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259440"
simple_name="Set_Account_Lockout_Time_To_15_Minutes"
command='/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail -n +2 | /usr/bin/xmllint --xpath '\''//dict/key[text()="autoEnableInSeconds"]/following-sibling::integer[1]/text()'\'' - | /usr/bin/awk '\''{ if ($1/60 >= 15 ) {print "yes"} else {print "no"}}'\'''
expected_result="yes"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259441"
simple_name="Must_Enforce_Screen_Saver_Timeout"
command="/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('idleTime'))
  if ( timeout <= 900 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259442"
simple_name="Must_Enable_SSH_Server_For_Remote_Access_Sessions"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.openssh.sshd\" => enabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259443"
simple_name="Must_Disable_Logon_To_Other_Users_Active_And_Locked_Sessions"
command="/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c '<string>authenticate-session-owner</string>'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259444"
simple_name="System_Must_Disable_Root_Login"
command="/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c '/usr/bin/false'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259445"
simple_name="SSH_ServerAliveInterval_Set_To_900"
command='ret="pass"; for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '\''$2 > 500 {print $1}'\''); do sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveraliveinterval 900"); if [[ "$sshCheck" == "0" ]]; then ret="fail"; break; fi; done; /bin/echo $ret'
expected_result="pass"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259446"
simple_name="SSH_Channel_Timeout_Set_To_900"
command='/usr/sbin/sshd -G | /usr/bin/awk -F "=" '\''/channeltimeout session:*/{print $2}'\'''
expected_result="900"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259447"
simple_name="SSHD_Unused_Connection_Timeout_To_900"
command='/usr/sbin/sshd -G | /usr/bin/awk '\''/unusedconnectiontimeout/{print $2}'\'''
expected_result="900"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259448"
simple_name="SSH_Active_Server_Alive_Maximum_To_0"
command='ret="pass"; for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '\''$2 > 500 {print $1}'\''); do sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveralivecountmax 0"); if [[ "$sshCheck" == "0" ]]; then ret="fail"; break; fi; done; /bin/echo $ret'
expected_result="pass"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259449"
simple_name="Enforce_Auto_Logout_After_86400_Seconds_of_Inactivity"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('.GlobalPreferences')\
.objectForKey('com.apple.autologout.AutoLogOutDelay').js
EOS"
expected_result="86400"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259450"
simple_name="Configure_Authorized_Time_Server"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('timeServer').js
EOS"
expected_result="*"

execute_anyresult_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259451"
simple_name="Must_Enable_Time_Synchronization_Daemon"
command="/bin/launchctl list | /usr/bin/grep -c com.apple.timed"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259452"
simple_name="Audit_All_Administrative_Action_Events"
command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259453"
simple_name="Audit_All_Log_On_Log_Out"
command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^lo'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259454"
simple_name="Enable_Security_Auditing"
command='LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd); if [[ $LAUNCHD_RUNNING -eq 1 ]] && [[ -e /etc/security/audit_control ]]; then echo "pass"; else echo "fail"; fi'
expected_result="pass"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259455"
simple_name="Configure_System_To_Shutdown_Upon_Audit_Failure"
command='/usr/bin/awk -F":" "/^policy/ {print \$NF}" /etc/security/audit_control | /usr/bin/tr "," "\\n" | /usr/bin/grep -Ec "ahlt"'
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259456"
simple_name="Audit_Log_Files_Owned_By_Root"
command='/bin/ls -n $(/usr/bin/grep "^dir" /etc/security/audit_control | /usr/bin/awk -F: '\''{print $2}'\'') | /usr/bin/awk '\''{s+=$3} END {print s}'\'''
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259457"
simple_name="Audit_Log_Folders_Owned_By_Root"
command='/bin/ls -dn $(/usr/bin/grep "^dir" /etc/security/audit_control | /usr/bin/awk -F: '\''{print $2}'\'') | /usr/bin/awk '\''{print $3}'\'''
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259458"
simple_name="Audit_Log_Files_Group_Owned_By_Wheel"
command='/bin/ls -n $(/usr/bin/grep "^dir" /etc/security/audit_control | /usr/bin/awk -F: '\''{print $2}'\'') | /usr/bin/awk '\''{s+=$4} END {print s}'\'''
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259459"
simple_name="Audit_Log_Folders_Group_Owned_By_Wheel"
command='/bin/ls -dn $(/usr/bin/grep "^dir" /etc/security/audit_control | /usr/bin/awk -F: '\''{print $2}'\'') | /usr/bin/awk '\''{print $4}'\'''
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259460"
simple_name="Audit_Log_Files_Mode_440_or_Less_Permissive"
command="/bin/ls -l \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '!/-r--r-----|current|total/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259461"
simple_name="Audit_Log_Folder_Mode_700_or_Less_Permissive"
command="/usr/bin/stat -f %A \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}')"
expected_result="700"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259462"
simple_name="Audit_All_Deletion_Of_Object_Attributes"
command="/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fd'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259463"
simple_name="Audit_All_Changes_Of_Object_Attributes"
command="/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^fm'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259464"
simple_name="Audit_All_Failed_Read_Actions"
command="/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259465"
simple_name="Audit_All_Failed_Write_Actions"
command="/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fw'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259466"
simple_name="Audit_All_Failed_Program_Executions"
command="/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-ex'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259467"
simple_name="Audit_Retention_Set_To_7_Days"
command="/usr/bin/awk -F: '/expire-after/{print \$2}' /etc/security/audit_control"
expected_result="7d"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259468"
simple_name="Audit_Capacity_Warning"
command="/usr/bin/awk -F: '/^minfree/{print \$2}' /etc/security/audit_control"
expected_result="25"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259469"
simple_name="Audit_Failure_Notification"
command="/usr/bin/grep -c 'logger -s -p' /etc/security/audit_warn"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259470"
simple_name="Audit_All_Authorization_Authentication_Events"
command="/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259471"
simple_name="Set_Smart_Card_Certificate_Trust_To_Moderate"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('checkCertificateTrust').js
EOS"
expected_result="2"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259472"
simple_name="Disable_Root_Login_for_SSH"
command="/usr/sbin/sshd -G | /usr/bin/awk '/permitrootlogin/{print \$2}'"
expected_result="no"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259473"
simple_name="Configure_Audit_Control_Group_To_Wheel"
command="/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print \$4}'"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259474"
simple_name="Configure_Audit_Control_Owner_To_Root"
command="/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print \$3}'"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259475"
simple_name="Configure_Audit_Control_To_Mode_440_or_Less_Permissive"
command="/bin/ls -l /etc/security/audit_control | /usr/bin/awk '!/-r--[r-]-----|current|total/{print \$1}' | /usr/bin/wc -l | /usr/bin/xargs"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259476"
simple_name="Configure_Audit_Control_To_Not_Contain_Access_Control_Lists"
command="/bin/ls -le /etc/security/audit_control | /usr/bin/awk '{print \$1}' | /usr/bin/grep -c \":\""
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259477"
simple_name="Disable_Password_Authentication_For_SSH"
command="/usr/sbin/sshd -G | /usr/bin/grep -Ec '^(passwordauthentication\s+no|kbdinteractiveauthentication\s+no)'"
expected_result="2"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259478"
simple_name="Disable_Server_Message_Block_Sharing"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.smbd\" => disabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259479"
simple_name="Disable_Network_File_System_Service"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.nfsd\" => disabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259480"
simple_name="Disable_Location_Services"
command="/usr/bin/sudo -u _locationd /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd')\
.objectForKey('LocationServicesEnabled').js
EOS
"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259481"
simple_name="Disable_Bonjour_Multicast"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder')\
.objectForKey('NoMulticastAdvertisements').js
EOS
"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259482"
simple_name="Disable_Unix_to_Unix_Copy_Protocol_Service"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.uucp\" => disabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259483"
simple_name="Disable_Internet_Sharing"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259484"
simple_name="Disable_Built-In_Web_Server"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"org.apache.httpd\" => disabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259485"
simple_name="Disable_AirDrop"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259486"
simple_name="Disable_FaceTime"
command="/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == \"/Applications/FaceTime.app\" && pref1 == true ){
          return("true")
      }
  }
  return(\"false\")
  }
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259487"
simple_name="Disable_ICloud_Calendar_Services"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudCalendar').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259488"
simple_name="Disable_ICloud_Calendar_Reminders"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudReminders').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259489"
simple_name="Disable_ICloud_Address_Book"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudAddressBook').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259490"
simple_name="Disable_ICloud_Mail"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudMail').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259491"
simple_name="Disable_ICloud_Notes"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudNotes').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259492"
simple_name="Disable_Camera"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCamera').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259493"
simple_name="Disable_Siri"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAssistant').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259494"
simple_name="Disable_Sending_Diagnostic_and_Useage_Data_To_Apple"
command="/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo')\
.objectForKey('AutoSubmit').js
let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDiagnosticSubmission').js
if ( pref1 == false && pref2 == false ){
    return(\"true\")
} else {
    return(\"false\")
}
}
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259495"
simple_name="Disable_Remote_Apple_Events"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.AEServer\" => disabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259496"
simple_name="Disable_Apple_ID_During_Setup_Assistant"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipCloudSetup').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259497"
simple_name="Disable_Privacy_Setup_Services_During_Setup_Assistant"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipPrivacySetup').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259498"
simple_name="Disable_ICloud_Storage_Setup_During_Setup_Assistant"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipiCloudStorageSetup').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259499"
simple_name="Disable_Trivial_File_Transfer_Protocol_Service"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.tftpd\" => disabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259500"
simple_name="Disable_Siri_Setup_During_Setup_Assistant"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSiriSetup').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259501"
simple_name="Disable_iCloud_Keychain_Synchronization"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudKeychainSync').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259502"
simple_name="Disable_iCloud_Document_Synchronization"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDocumentSync').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259503"
simple_name="Disable_iCloud_Bookmarks"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudBookmarks').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259504"
simple_name="Disable_iCloud_Photo_Library"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPhotoLibrary').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259505"
simple_name="Disable_Screen_Sharing_And_Apple_Remote_Desktop"
command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.screensharing\" => disabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259506"
simple_name="Disable_TouchID_System_Settings_Pane"
command="/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()=\"DisabledSystemSettings\"]/following-sibling::*[1]' - | /usr/bin/grep -c \"com.apple.Touch-ID-Settings.extension\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259507"
simple_name="Disable_Wallet_And_Apple_Pay_Pane"
command="/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()=\"DisabledSystemSettings\"]/following-sibling::*[1]' - | /usr/bin/grep -c \"com.apple.WalletSettingsExtension\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259508"
simple_name="Disable_Siri_Pane"
command="/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()=\"DisabledSystemSettings\"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.Siri-Settings.extension"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259509"
simple_name="Enable_Gatekeeper_To_Block_Applications_From_Unidentified_Developers"
command="/usr/sbin/spctl --status --verbose | /usr/bin/grep -c \"developer id enabled\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259510"
simple_name="Disable_Bluetooth"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCXBluetooth')\
.objectForKey('DisableBluetooth').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259511"
simple_name="Disable_Guest_Account"
command="/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('DisableGuestAccount'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('EnableGuestAccount'))
  if ( pref1 == true && pref2 == false ) {
    return(\"true\")
  } else {
    return(\"false\")
  }
}
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259512"
simple_name="GateKeeper_Enabled"
command="/usr/sbin/spctl --status | /usr/bin/grep -c \"assessments enabled\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259513"
simple_name="Disable_Unattended_Automatic_Log_On"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259514"
simple_name="Secure_Users_Home_Folders"
command="/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v \"Guest\" | /usr/bin/wc -l | /usr/bin/xargs"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259515"
simple_name="System_Must_Require_Administrator_Privileges_To_Modify_Systemwide_Settings"
command="authDBs=(\"system.preferences\" \"system.preferences.energysaver\" \"system.preferences.network\" \"system.preferences.printing\" \"system.preferences.sharing\" \"system.preferences.softwareupdate\" \"system.preferences.startupdisk\" \"system.preferences.timemachine\")
result=\"1\"
for section in \${authDBs[@]}; do
  if [[ \$(/usr/bin/security -q authorizationdb read \"\$section\" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), \"shared\")]/following-sibling::*[1])' -) != \"false\" ]]; then
    result=\"0\"
  fi
done
echo \$result"

expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259516"
simple_name="Disable_Airplay_Receiver"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirPlayIncomingRequests').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259517"
simple_name="Disable_TouchID"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFingerprintForUnlock').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259518"
simple_name="Disable_Media_Sharing"
command="//usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')\
  .objectForKey('homeSharingUIStatus'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')\
  .objectForKey('legacySharingUIStatus'))
  let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')\
  .objectForKey('mediaSharingUIStatus'))
  if ( pref1 == 0 && pref2 == 0 && pref3 == 0 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259519"
simple_name="Disable_Bluetooth_Sharing"
CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' ) ## Required for Command
command="/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259520"
simple_name="Disable_AppleID_And_Internet_Account_Modifications"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAccountModification').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259521"
simple_name="Disable_CD/DVD_Sharing"
command="/usr/bin/pgrep -q ODSAgent; /bin/echo \$?"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259522"
simple_name="Disable_Content_Caching_Service"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowContentCaching').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259523"
simple_name="Disable_iCloud_Desktop_And_Document_Folder_Sync"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDesktopAndDocuments').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259524"
simple_name="Disable_iCloud_Game_Center"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowGameCenter').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259525"
simple_name="Disable_iCloud_Private_Relay"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPrivateRelay').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259526"
simple_name="Disable_Find_My_Service"
command="/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyDevice'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyFriends'))
  let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.icloud.managed')\
.objectForKey('DisableFMMiCloudSetting'))
  if ( pref1 == false && pref2 == false && pref3 == true ) {
    return("true")
  } else {
    return("false")
  }
}
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259527"
simple_name="Disable_Password_Autofill"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordAutoFill').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259528"
simple_name="Disable_Personalized_Advertising"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowApplePersonalizedAdvertising').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259529"
simple_name="Disable_Sending_Siri_Dictation_Information_To_Apple"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Siri Data Sharing Opt-In Status').js
EOS"
expected_result="2"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259530"
simple_name="Enforce_Device_Dictation_Apple_Chip"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('forceOnDeviceOnlyDictation').js
EOS"
expected_result="true"
chip_specific="Apple Only"

execute_and_log_chip_specific "$check_name" "$command" "$expected_result" "$simple_name" "$chip_specific"

##############################################
check_name="V-259531"
simple_name="Disable_Device_Dictation_Intel_Chip"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDictation').js
EOS"
expected_result="true"
chip_specific="Intel Only"

execute_and_log_chip_specific "$check_name" "$command" "$expected_result" "$simple_name" "$chip_specific"

##############################################
check_name="V-259532"
simple_name="Disable_Printer_Sharing"
command="/usr/sbin/cupsctl | /usr/bin/grep -c \"_share_printers=0\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259533"
simple_name="Disable_Remote_Management"
command="/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c \"RemoteDesktopEnabled = 0\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259534"
simple_name="Disable_Bluetooth_System_Pane"
command="/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.BluetoothSettings"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259535"
simple_name="Disable_iCloud_Freeform_Service"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudFreeform').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259536"
simple_name="Obtain_Public_Key_Certifcate_From_Approved_Service_Provider"
command="/usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/awk -F'\"' '/labl/ {print \$4}'"
expected_result=""

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259537"
simple_name="Password_Must_Contain_A_Minmum_Of_One_Number_Character"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyIdentifier\"]/following-sibling::*[1]/text()' - | /usr/bin/grep \"requireAlphanumeric\" -c"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259538"
simple_name="Password_Lifetime_Max_60_Days"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyAttributeExpiresEveryNDays\"]/following-sibling::*[1]/text()' -"
expected_result="60"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259540"
simple_name="Password_Length_of_14_Characters"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),\"policyAttributePassword matches '\''.{14,}'\''\")])' -"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259541"
simple_name="Password_Must_Contain_One_Special_Character"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),\"policyAttributePassword matches '\''(.*[^a-zA-Z0-9].*){1,}'\''\")])' -"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259542"
simple_name="Disable_Password_Hints"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259543"
simple_name="Enable_Firmware_Password_Intel_Chip"
command="/usr/sbin/firmwarepasswd -check | /usr/bin/grep -c \"Password Enabled: Yes\""
expected_result="1"
chip_specific="Intel Only"

execute_and_log_chip_specific "$check_name" "$command" "$expected_result" "$simple_name" "$chip_specific"

##############################################
check_name="V-259544"
simple_name="Remove_Password_Hints_From_User_Accounts"
command="/usr/bin/dscl . -list /Users hint | /usr/bin/awk '{print \$2}' | /usr/bin/wc -l | /usr/bin/xargs"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259545"
simple_name="Enforce_Smart_Card_Authentication"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('enforceSmartCard').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259546"
simple_name="System_Must_Allow_Smart_Card_Authentication"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('allowSmartCard').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259547"
simple_name="System_Must_Enforce_Multifactor_Authentication_for_Logon"
command="/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login"
expected_result="2"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259548"
simple_name="System_Must_Enforce_Multifactor_Authentication_for_SU_Commands"
command="/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su"
expected_result="2"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259549"
simple_name="System_Must_Enforce_Multifactor_Authentication_for_Sudo_Commands"
command="/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo"
expected_result="2"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259550"
simple_name="Password_Must_Contain_A_Minimum_Of_One_Lowercase_Character_One_Uppercase_Character"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),\"policyAttributePassword matches '\''.*[A-Z]{1,}[a-z]{1,}.*'\''\")])' -"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259551"
simple_name="Password_Minimum_Password_Lifetime_24_Hours"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMinimumLifetimeHours"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if (\$1 >= 24 ) {print \"yes\"} else {print \"no\"}}'"
expected_result="yes"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259552"
simple_name="Must_Disable_Accounts_After_35_Days_Of_Inactivity"
command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyAttributeInactiveDays\"]/following-sibling::integer[1]/text()' -"
expected_result="35"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259553"
simple_name="Configure_Apple_System_Log_Files_To_Be_Owned_By_Root_and_Group_To_Wheel"
command="/usr/bin/stat -f '%Su:%Sg:%N' \$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print \$2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259554"
simple_name="Configure_Apple_System_Log_Files_To_Mode_640_Or_Less_Permissive"
command="/usr/bin/stat -f '%A:%N' \$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print \$2 }') 2> /dev/null | /usr/bin/awk '!/640/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259555"
simple_name="System_Must_Reauthenticate_For_Priviledge_Escalations_When_Using_Sudo_Command"
command="/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c \"Authentication timestamp timeout: 0.0 minutes\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259556"
simple_name="Configure_System_Log_Files_To_Be_Owned_By_Root_and_Group_To_Wheel"
command="/usr/bin/stat -f '%Su:%Sg:%N' \$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print \$1 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259557"
simple_name="Configure_System_Log_Files_To_Mode_640_Or_Less_Permissive"
command="/usr/bin/stat -f '%A:%N' \$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print \$1 }') 2> /dev/null | /usr/bin/awk '!/640/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259558"
simple_name="System_Log_Retention_To_365"
command="/usr/sbin/aslmanager -dd 2>&1 | /usr/bin/awk '/\/var\/log\/install.log/ {count++} /Processing module com.apple.install/,/Finished/ { for (i=1;i<=NR;i++) { if (\$i == \"TTL\" && \$(i+2) >= 365) { ttl=\"True\" }; if (\$i == \"MAX\") {max=\"True\"}}} END{if (count > 1) { print \"Multiple config files for /var/log/install, manually remove\"} else if (ttl != \"True\") { print \"TTL not configured\" } else if (max == \"True\") { print \"Max Size is configured, must be removed\" } else { print \"Yes\" }}'"
expected_result="Yes"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259559"
simple_name="Configure_Sudoers_Timestamp_Type"
command="/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/awk -F\": \" '/Type of authentication timestamp record/{print \$2}'"
expected_result="tty"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259560"
simple_name="System_Integrity_Protection_Is_Enabled"
command="/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.' && /usr/bin/grep -c \"logger -s -p\" /etc/security/audit_warn "
expected_result="1
1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259561"
simple_name="Must_Enforce_FileVault"
command="dontAllowDisable=\$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('dontAllowFDEDisable').js
EOS
)
fileVault=\$(/usr/bin/fdesetup status | /usr/bin/grep -c \"FileVault is On.\")
if [[ \"\$dontAllowDisable\" == \"true\" ]] && [[ \"\$fileVault\" == 1 ]]; then
  echo \"1\"
else
  echo \"0\"
fi"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259562"
simple_name="Must_Enable_Firewall"
command="profile=\"\$(/usr/bin/osascript -l JavaScript << EOS
\$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableFirewall').js
EOS
)\"

plist=\"\$(/usr/bin/defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)\"

if [[ \"\$profile\" == \"true\" ]] && [[ \"\$plist\" =~ [1,2] ]]; then
  echo \"true\"
else
  echo \"false\"
fi"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259563"
simple_name="Configure_Login_Window_To_Prompt_Username_And_Password"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259564"
simple_name="Disable_TouchID_During_Setup_Assistant"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipTouchIDSetup').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259565"
simple_name="Disable_Screen_Time_During_Setup_Assistant"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipScreenTime').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259566"
simple_name="Disable_Apple_Watch_During_Setup_Assistant"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipUnlockWithWatch').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259567"
simple_name="Disable_Handoff"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowActivityContinuation').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259568"
simple_name="Disable_Proximity-based_Password_Sharing_Requests"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordProximityRequests').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259569"
simple_name="Disable_Erase_Content_And_Settings"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowEraseContentAndSettings').js
EOS"
expected_result="false"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259570"
simple_name="Enable_Authenticated_Root"
command="/usr/bin/csrutil authenticated-root | /usr/bin/grep -c 'enabled'"
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259571"
simple_name="Prohibit_Users_Installation_Of_Software_Into_/users/"
command="/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Users/" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259572"
simple_name="Authorize_USB_Devices_Before_Allowing_Connection"
command="/usr/bin/osascript -l JavaScript << EOS
  function run() {
    let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
  .objectForKey('allowUSBRestrictedMode'))
    if ( pref1 == false ) {
      return("false")
    } else {
      return("true")
    }
  }
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259573"
simple_name="Secure_Boot_Level_Set_To_Full"
command="/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c \"SecureBootLevel = full\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259574"
simple_name="Enforce_Enrollment_In_Mobile_Device_Management"
command="/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print \$2}' | /usr/bin/grep -c \"Yes (User Approved)\""
expected_result="1"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################
check_name="V-259575"
simple_name="Enable_Recovery_Lock"
command="/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c \"IsRecoveryLockEnabled = 1\""
expected_result="1"
chip_specific="Apple Only"

execute_and_log_chip_specific "$check_name" "$command" "$expected_result" "$simple_name" "$chip_specific"

##############################################
check_name="V-259576"
simple_name="Enforce_Installation_Of_XProtect_Remediator_And_Gatekeeper_Updates_Automatically"
command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS"
expected_result="true"

execute_and_log "$check_name" "$command" "$expected_result" "$simple_name"

##############################################

exit 0
