#!/bin/sh
####################################################################################################
#
# MacOS 26 (Tahoe) STIG Compliance Tool
#
# Purpose: Checks the requires DISA STIGS against the machines current settings
#
# To run script open terminal and type 'sudo bash /path/to/script.sh'
#
# https://github.com/cocopuff2u
#
####################################################################################################
#                                         History                                                  #
####################################################################################################
# Version 1.0 (12/05/2025)
# - Based off Offical Tahoe STIGS V1R1
# - Initial script creation
####################################################################################################
# ==========================
# Script Supported STIG Version
# ==========================
STIG_VERSION="MACOS 26 (TAHOE) V1R1" # [ Do Not Adjust ]

# ==========================
# Flag to Control Fix Execution
# ==========================
# Determines whether the script executes fixes.
EXECUTE_FIX=false  # [ true | false (default) ]

# ==========================
# Usage of getopts
# ==========================
# The getopts built-in is used for parsing command-line options.
# Options:
# - -c: Run checks only
# - -f: Run fixes only
#
# Example usage:
#   sudo bash path_to_script/MacOS_26_Tahoe_V1R1_STIG.sh -f

# ==========================
# Script Log Names
# ==========================
MANUAL_LOG_FILE_NAME="tahoe_stig_scan_manual_check.log"  # For logs that need manual checking
PASS_LOG_FILE_NAME="tahoe_stig_scan_passed.log"          # For passed checks
FAILURE_LOG_FILE_NAME="tahoe_stig_scan_failed.log"        # For failed checks
SINGLE_LOG_FILE_NAME="tahoe_stig_scan_summary.log"        # For a summary of both passed and failed checks
COMMAND_LOG_FILE_NAME="tahoe_stig_scan_command_output.log" # For output of the commands executed
CSV_LOG_FILE_NAME="tahoe_stig_scan_results_combined.csv"  # For a combined CSV of results


# ==========================
# Logging Options
# ==========================
CLEAR_LOGS=true                     # Clears existing local logs before running [ true (default) | false ]
LOG_PATH=""                         # Change default path (default is /var/log/ if left blank)
LOG_TO_SINGLE_FILE=false            # Logs failures & passes in one log file [ true | false (default) ]
LOG_COMMANDS=true                   # Logs commands input/output for STIG checks [ true (default) | false ]
LOG_RESULTS_TO_USER_LOG_FOLDER=true # Logs results to the user's log folder [ true (default) | false ]
LOG_TO_PLIST=true                   # Logs failures & passes to a plist file [ true | false (default) ]
LOG_TO_CSV=true                     # Logs failures & passes to a CSV file [ true | false (default) ]

# ==========================
# Plist Options
# ==========================
PLIST_LOG_FILE="/Library/Preferences/STIG_Checks.plist" # Default path for plist logs

# ==========================
# Other Options
# ==========================
HIDE_RESULTS_IN_TERMINAL=false         # Show output in terminal [ true | false (default) ]
MAKE_TERMINAL_COLORFUL=true            # Colorful terminal output (requires HIDE_RESULTS_IN_TERMINAL=false) [ true (default) | false ]
HIDE_LOGGING_LOCATION_IN_TERMINAL=true # Hides logging location in terminal [ true (default) | false ]
HIDE_SKIPPED_TERMINAL_OUTPUT=true     # Hides output for skipped checks in terminal [ true (default) | false ]

# ==========================
# Define Checks to Skip
# ==========================
General_Skip_Checks=("") # Example: General_Skip_Checks=("APPL-26-002052" "APPL-26-002051")

# ==========================
# Chipset-Specific Checks
# ==========================
Apple_Only_Checks=("APPL-26-002220" "APPL-26-005120") # Example: Apple_Only_Checks=("APPL-26-002052" "APPL-26-002051")
Intel_Only_Checks=("APPL-26-002230" ) # Example: Intel_Only_Checks=("APPL-26-002052" "APPL-26-002051")

# ==========================
# Manual Review Checks
# ==========================
# The following checks require manual review for various reasons.
Manual_Review_Checks=("APPL-26-002022" "APPL-26-000012" "APPL-26-003001" "APPL-26-003050" "APPL-26-003051" "APPL-26-003052") # Example: Manual_Review_Checks=("APPL-26-002052" "APPL-26-002051")

# Note - Running APPL-26-002022 requires Full Disk Access in the Terminal. If you are deploying via MDM, this access is automatically granted. Otherwise, ensure Full Disk Access is enabled for the Terminal in System Preferences.

####################################################################################################
#
# The Variables below are defaulted to the STIG requirement, Adjust accordlingly
#
####################################################################################################

# V-259438  limit SSHD to FIPS (May need to add more approved FIPS Algorithms)
fips_sshd_config="Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"

# V-259439  limit SSH to FIPS (May need to add more approved FIPS Algorithms)
fips_ssh_config="Host *
Ciphers aes128-gcm@openssh.com,aes256-ctr
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"


####################################################################################################
#
# Custom STIG Fix Variables
#
####################################################################################################
#
# Notes:
# Some STIGs require custom fixes due to inconsistent behavior in certain conditions.
# The functions below provide custom fixes for SSH configurations and banner enforcement.
#
# Example:
# - Replacing a fix command with a custom function
#
# check_name="APPL-26-000024"                         # STIG ID
# simple_name="os_policy_banner_ssh_enforce"           # Policy name for easy reference
# check_command="/usr/sbin/sshd -G | /usr/bin/grep -c '^banner /etc/banner'"  # Command to check compliance
# expected_result="1"                                  # Expected result from the check command
# severity="CAT II"                                    # Severity level
# fix_command="complete_ssh_sshd_fix"                  # Custom function to apply fix
# requires_mdm="false"                                 # Specifies if MDM is required
#
####################################################################################################

complete_ssh_sshd_fix() {
    rm -r /private/etc/ssh/*
    ssh-keygen -A > /dev/null 2>&1
    mkdir -p /private/etc/ssh/sshd_config.d/
    mkdir -p /private/etc/ssh/ssh_config.d/

    ssh_config="#	OpenBSD: ssh_config,v 1.36 2023/08/02 23:04:38 djm Exp $

    # This is the ssh client system-wide configuration file.  See
    # ssh_config(5) for more information.  This file provides defaults for
    # users, and the values can be changed in per-user configuration files
    # or on the command line.

    # Configuration data is parsed as follows:
    #  1. command line options
    #  2. user-specific file
    #  3. system-wide file
    # Any configuration value is only changed the first time it is set.
    # Thus, host-specific definitions should be at the beginning of the
    # configuration file, and defaults at the end.

    # This Include directive is not part of the default ssh_config shipped with
    # OpenSSH. Options set in the included configuration files generally override
    # those that follow.  The defaults only apply to options that have not been
    # explicitly set.  Options that appear multiple times keep the first value set,
    # unless they are a multivalue option such as IdentityFile.
    Include /etc/ssh/ssh_config.d/*

    # Site-wide defaults for some commonly used options.  For a comprehensive
    # list of available options, their meanings and defaults, please see the
    # ssh_config(5) man page.

    # Host *
    #   ForwardAgent no
    #   ForwardX11 no
    #   PasswordAuthentication yes
    #   HostbasedAuthentication no
    #   GSSAPIAuthentication no
    #   GSSAPIDelegateCredentials no
    #   BatchMode no
    #   CheckHostIP no
    #   AddressFamily any
    #   ConnectTimeout 0
    #   StrictHostKeyChecking ask
    #   IdentityFile ~/.ssh/id_rsa
    #   IdentityFile ~/.ssh/id_dsa
    #   IdentityFile ~/.ssh/id_ecdsa
    #   IdentityFile ~/.ssh/id_ed25519
    #   Port 22
    #   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
    #   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
    #   EscapeChar ~
    #   Tunnel no
    #   TunnelDevice any:any
    #   PermitLocalCommand no
    #   VisualHostKey no
    #   ProxyCommand ssh -q -W %h:%p gateway.example.com
    #   RekeyLimit 1G 1h
    #   UserKnownHostsFile ~/.ssh/known_hosts.d/%k
    Host *
        SendEnv LANG LC_*
    ServerAliveCountMax 0
    ServerAliveInterval 900"

    /bin/echo "${ssh_config}" > /private/etc/ssh/ssh_config

    sshd_config="#	OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

    # This is the sshd server system-wide configuration file.  See
    # sshd_config(5) for more information.

    # This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

    # The strategy used for options in the default sshd_config shipped with
    # OpenSSH is to specify options with their default value where
    # possible, but leave them commented.  Uncommented options override the
    # default value.

    # This Include directive is not part of the default sshd_config shipped with
    # OpenSSH. Options set in the included configuration files generally override
    # those that follow.  The defaults only apply to options that have not been
    # explicitly set.  Options that appear multiple times keep the first value set,
    # unless they are a multivalue option such as HostKey.
    Include /etc/ssh/sshd_config.d/*

    #Port 22
    #AddressFamily any
    #ListenAddress 0.0.0.0
    #ListenAddress ::

    #HostKey /etc/ssh/ssh_host_rsa_key
    #HostKey /etc/ssh/ssh_host_ecdsa_key
    #HostKey /etc/ssh/ssh_host_ed25519_key

    # Ciphers and keying
    #RekeyLimit default none

    # Logging
    #SyslogFacility AUTH
    #LogLevel INFO

    # Authentication:

    #LoginGraceTime 2m
    #PermitRootLogin prohibit-password
    #StrictModes yes
    #MaxAuthTries 6
    #MaxSessions 10

    #PubkeyAuthentication yes

    # The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
    # but this is overridden so installations will only check .ssh/authorized_keys
    AuthorizedKeysFile	.ssh/authorized_keys

    #AuthorizedPrincipalsFile none

    #AuthorizedKeysCommand none
    #AuthorizedKeysCommandUser nobody

    # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
    #HostbasedAuthentication no
    # Change to yes if you don't trust ~/.ssh/known_hosts for
    # HostbasedAuthentication
    #IgnoreUserKnownHosts no
    # Don't read the user's ~/.rhosts and ~/.shosts files
    #IgnoreRhosts yes

    # To disable tunneled clear text passwords, change to no here!
    #PasswordAuthentication yes
    #PermitEmptyPasswords no

    # Change to no to disable s/key passwords
    #KbdInteractiveAuthentication yes

    # Kerberos options
    #KerberosAuthentication no
    #KerberosOrLocalPasswd yes
    #KerberosTicketCleanup yes
    #KerberosGetAFSToken no

    # GSSAPI options
    #GSSAPIAuthentication no
    #GSSAPICleanupCredentials yes

    # Set this to 'yes' to enable PAM authentication, account processing,
    # and session processing. If this is enabled, PAM authentication will
    # be allowed through the KbdInteractiveAuthentication and
    # PasswordAuthentication.  Depending on your PAM configuration,
    # PAM authentication via KbdInteractiveAuthentication may bypass
    # the setting of PermitRootLogin prohibit-password.
    # If you just want the PAM account and session checks to run without
    # PAM authentication, then enable this but set PasswordAuthentication
    # and KbdInteractiveAuthentication to 'no'.
    #UsePAM no

    #AllowAgentForwarding yes
    #AllowTcpForwarding yes
    #GatewayPorts no
    #X11Forwarding no
    #X11DisplayOffset 10
    #X11UseLocalhost yes
    #PermitTTY yes
    #PrintMotd yes
    #PrintLastLog yes
    #TCPKeepAlive yes
    #PermitUserEnvironment no
    #Compression delayed
    #ClientAliveInterval 0
    #ClientAliveCountMax 3
    #UseDNS no
    #PidFile /var/run/sshd.pid
    #MaxStartups 10:30:100
    #PermitTunnel no
    #ChrootDirectory none
    #VersionAddendum none

    # no default banner path
    Banner /etc/banner

    # override default of no subsystems
    #Subsystem	sftp	/usr/libexec/sftp-server

    # Example of overriding settings on a per-user basis
    #Match User anoncvs
    #	X11Forwarding no
    #	AllowTcpForwarding no
    #	PermitTTY no
    #	ForceCommand cvs server"
    /bin/echo "${sshd_config}" > /private/etc/ssh/sshd_config

    macos="# Options set by macOS that differ from the OpenSSH defaults.
    UsePAM yes
    AcceptEnv LANG LC_*
    Subsystem	sftp	/usr/libexec/sftp-server"
    /bin/echo "${macos}" > /private/etc/ssh/sshd_config.d/100-macos.conf

    /bin/echo "${fips_ssh_config}" > /etc/ssh/ssh_config.d/fips_ssh_config

    include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

    if [[ -z $include_dir ]]; then
    /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
    fi

    mscp_sshd="passwordauthentication no
    kbdinteractiveauthentication no
    banner /etc/banner
    channeltimeout session:*=900
    clientalivecountmax 1
    clientaliveinterval 900
    logingracetime 30
    permitrootlogin no
    unusedconnectiontimeout 900"

    combine_mscp_sshd_fips_sshd_config="${mscp_sshd}
    ${fips_sshd_config}"

    /bin/echo "${combine_mscp_sshd_fips_sshd_config}" > /etc/ssh/sshd_config.d/01-mscp-sshd.conf
    /bin/echo "${fips_sshd_config}" > /etc/ssh/sshd_config.d/fips_sshd_config

    # Directory to process
    include_dir="/private/etc/ssh/sshd_config.d/"

    # Ensure the directory ends with a slash
    include_dir="${include_dir%/}/"

    # Use find to list only non-hidden files
    find "$include_dir" -maxdepth 1 -type f ! -name '.*' | while read -r file; do
        # Extract the base name of the file
        filename=$(basename "$file")

        if [[ "$filename" == "100-macos.conf" ]]; then
            continue
        fi
        if [[ "$filename" == "01-mscp-sshd.conf" ]]; then
            break
        fi

        /bin/mv "$file" "${include_dir}20-${filename}"
    done
}

complete_login_banner_fix() {
    # Hard-coded file path
    local file_path="/Library/Security/PolicyBanner.rtf"

    # Define the text to be written to the file
    local text="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

    # Write the text to the specified file
    echo "$text" | sudo tee "$file_path" > /dev/null

    # Set read permissions for everyone
    chmod o+r "$file_path"

    # Update the APFS preboot volume and suppress the output
    diskutil apfs updatePreboot / > /dev/null 2>&1
}

####################################################################################################
#
# Checks Before Running Script
#
####################################################################################################


# Display usage and details about each option
usage() {
    cat <<EOF
Usage: $0 [-c] [-f] [-h]

Options:
  -c    Run checks only. Executes compliance checks on specified items without making any changes.
  -f    Run fixes only (without checking). Applies fixes to address specific items without performing checks.
  -h    Display this help message, which provides details on each option.

Description:
  This script manages system compliance by running checks and/or applying fixes.

  - Use -c to perform checks only, which will report the status of each compliance item.
  - Use -f to apply fixes only without running checks.
  - Use both -c and -f to perform checks and apply fixes sequentially.
  - Use -h to view this help message at any time.

Examples:
  Run checks only:
    $0 -c

  Run fixes only:
    $0 -f

  Display help:
    $0 -h

EOF
    exit 1
}

# Parse command-line options
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--no-fix)
            EXECUTE_FIX=false ;;    # Set EXECUTE_FIX to false if -c or --no-fix is passed
        -C|--no-fix)
            EXECUTE_FIX=false ;;    # Set EXECUTE_FIX to false if -C is passed
        -f|--fix)
            EXECUTE_FIX=true ;;     # Set EXECUTE_FIX to true if -f or --fix is passed
        -F|--fix)
            EXECUTE_FIX=true ;;     # Set EXECUTE_FIX to true if -F is passed
        -h|--help)
            usage ;;                 # Display usage if -h is passed
        -H|--help)
            usage ;;                 # Display usage if -H is passed
        *)
            usage ;;                # Display usage if an invalid option is passed
    esac
    shift  # Shift to the next argument
done


# Check if the script is run as root
if [ "$(id -u)" -ne "0" ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Check the CPU type
if sysctl -n machdep.cpu.brand_string | grep -q "Apple"; then
    skip_checks=("${Intel_Only_Checks[@]}")
else
    skip_checks=("${Apple_Only_Checks[@]}")
fi

# Add the general checks to skip to the skip_checks array
skip_checks+=("${General_Skip_Checks[@]}")

# Pulls Current User (Needed for some checks/fixes)
CURRENT_USER=$(/usr/sbin/scutil <<<"show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }')

# Construct the path to the current user's Logs folder
USER_LOG_PATH="/Users/$CURRENT_USER/Library/Logs/"

if [ -z "$LOG_PATH" ]; then
    LOG_PATH="/var/log/"
fi

# Admin Log Locations
MANUAL_LOG_FILE="$LOG_PATH$MANUAL_LOG_FILE_NAME"
PASS_LOG_FILE="$LOG_PATH$PASS_LOG_FILE_NAME"
FAILURE_LOG_FILE="$LOG_PATH$FAILURE_LOG_FILE_NAME"
SINGLE_LOG_FILE="$LOG_PATH$SINGLE_LOG_FILE_NAME"
COMMAND_LOG_FILE="$LOG_PATH$COMMAND_LOG_FILE_NAME"
CSV_LOG_FILE="$LOG_PATH$CSV_LOG_FILE_NAME"

# User Log Locations
# Construct the path to the current user's Logs folder
USER_MANUAL_LOG_FILE="$USER_LOG_PATH$MANUAL_LOG_FILE_NAME"
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
    # Print the result in white and status in green/red/yellow if color is enabled
    local status="$1"

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then
        if [ "$status" = "Passed" ]; then
            printf "%s${BOLD}Results: (%s%s%s)\n" "${WHITE}" "${RESET}" "${BOLD}${GREEN}Passed${RESET}" "${RESET}"
        elif [ "$status" = "Failed" ]; then
            printf "%s${BOLD}Results: (%s%s%s)\n" "${WHITE}" "${RESET}" "${BOLD}${RED}Failed${RESET}" "${RESET}"
        elif [ "$status" = "Manual Check" ]; then
            printf "%s${BOLD}Results: (%s%s%s)\n" "${WHITE}" "${RESET}" "${BOLD}${LIGHT_YELLOW}Manual Check${RESET}" "${RESET}"
        fi
    else
        echo "Check Results: $status"
    fi
}

echo_manual_review() {
    # Print the result in white and status in green/red if color is enabled
    local reason="$1"

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then

            printf "%s(${BOLD}${LIGHT_YELLOW}Fix Requires: %s%s%s\n" "${RESET}" "${BOLD}${LIGHT_YELLOW}$reason${RESET}" "${RESET})"
    else
        echo "(Fix Requires: $reason)"
    fi
}

echo_manual_rerun() {
    # Print the result in white and status in green/red if color is enabled
    local reason="$1"

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then

            printf "%s(${BOLD}${LIGHT_YELLOW}%s%s%s\n" "${RESET}" "${BOLD}${LIGHT_YELLOW}$reason${RESET}" "${RESET})"
    else
        echo "(Fix Requires: $reason)"
    fi
}

echo_failed_mdm() {
    # Print the result in white and status in green/red if color is enabled
    local reason="$1"

    if [ "$MAKE_TERMINAL_COLORFUL" = true ]; then

            printf "%s(${BOLD}${RED}Fix Requires: %s%s%s\n" "${RESET}" "${BOLD}${RED}$reason${RESET}" "${RESET})"
    else
        echo "(Fix Requires: $reason)"
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

    # Determine log files based on settings and result type
    if [ "$LOG_TO_SINGLE_FILE" = true ]; then
        log_file="$SINGLE_LOG_FILE"
        User_log_file="$USER_SINGLE_LOG_FILE"
    else
        if [ "$result" = "Passed" ]; then
            log_file="$PASS_LOG_FILE"
            User_log_file="$USER_PASS_LOG_FILE"
        elif [ "$result" = "Manual Check" ]; then
            log_file="$MANUAL_LOG_FILE"  # Assuming you have a manual log file defined
            User_log_file="$USER_MANUAL_LOG_FILE"
        else
            log_file="$FAILURE_LOG_FILE"
            User_log_file="$USER_FAILURE_LOG_FILE"
        fi
    fi

    # Append the log message to the appropriate file with a timestamp
    echo "$check_name: $result" >>"$log_file"

    if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
        echo "$check_name: $result" >>"$User_log_file"
    fi

    # Display log locations in terminal if not hidden
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
    local check_command=$2
    local command_output=$3
    local expected_result=$4
    local simple_name=$5

    if [ "$LOG_TO_CSV" = true ]; then
        write_to_csv "$check_name" "$command_output" "$expected_result" "$simple_name"
    fi

    if [ "$LOG_COMMANDS" = true ]; then
        echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$COMMAND_LOG_FILE"
        echo "Run Time: $(date +'%Y-%m-%d %I:%M:%S %p')" >>"$COMMAND_LOG_FILE"
        echo "STIG ID: $check_name ($simple_name)" >>"$COMMAND_LOG_FILE"
        echo "" >>"$COMMAND_LOG_FILE"
        echo "Command Inputted: $check_command" >>"$COMMAND_LOG_FILE"
        echo "" >>"$COMMAND_LOG_FILE"
        echo "Command Outputted: $command_output" >>"$COMMAND_LOG_FILE"
        echo "Expected STIG Result: $expected_result" >>"$COMMAND_LOG_FILE"
        echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$COMMAND_LOG_FILE"
        if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
            echo "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" >>"$USER_COMMAND_LOG_FILE"
            echo "Run Time: $(date +'%Y-%m-%d %I:%M:%S %p')" >>"$USER_COMMAND_LOG_FILE"
            echo "STIG ID: $check_name ($simple_name)" >>"$USER_COMMAND_LOG_FILE"
            echo "" >>"$USER_COMMAND_LOG_FILE"
            echo "Command Inputted: $check_command" >>"$USER_COMMAND_LOG_FILE"
            echo "" >>"$USER_COMMAND_LOG_FILE"
            echo "Command Outputted: $command_output" >>"$USER_COMMAND_LOG_FILE"
            echo "Expected STIG Result: $expected_result" >>"$USER_COMMAND_LOG_FILE"
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
    local csv_header="STIG ID,Simple Name,Pass/Fail,Result,Expected"

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
        add_date_header "$MANUAL_LOG_FILE" "MANUAL STIG CHECKS"

        if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
            add_date_header "$USER_PASS_LOG_FILE" "PASSED STIG CHECKS"
            add_date_header "$USER_FAILURE_LOG_FILE" "FAILED STIG CHECKS"
            add_date_header "$USER_MANUAL_LOG_FILE" "MANUAL STIG CHECKS"
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
            echo "$csv_header" >"$CSV_LOG_FILE"

            if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                echo "$csv_header" >"$USER_CSV_LOG_FILE"
            fi

        elif ! grep -q "^$csv_header$" "$CSV_LOG_FILE"; then
            # File exists but does not contain the header; add the header
            echo "$csv_header" >>"$CSV_LOG_FILE"

            if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
                echo "$csv_header" >>"$USER_CSV_LOG_FILE"
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
    local check_command=$2
    local expected_result=$3
    local simple_name=$4
    local severity=$5
    local fix_command=$6
    local requires_mdm=$7

    # Skip checks if check_name matches any in skip_checks
    for skip in "${skip_checks[@]}"; do
        if [ "$check_name" == "$skip" ]; then
            if [ "$HIDE_SKIPPED_TERMINAL_OUTPUT" = false ]; then
                echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
                echo_gray "Skipping check: $check_name"
            fi
            return
        fi
    done

    # Prepare for executing the check command
    if [ "$HIDE_RESULTS_IN_TERMINAL" = false ]; then
        echo_dark_purple "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
        echo_command_check "$check_name" "$simple_name"
    fi

    # Execute the command and capture the output
    result_output=$(eval "$check_command" 2>/dev/null)

    # Determine the result based on expected output
    if [ "$expected_result" = "*" ]; then
        # Non-empty results should pass
        if [ -n "$result_output" ]; then
            result="Passed"
            boolean_result="false"
        else
            result="Failed"
            boolean_result="true"
        fi
    else
        if [ "$result_output" = "$expected_result" ]; then
            result="Passed"
            boolean_result="false"
        else
            result="Failed"
            boolean_result="true"
        fi
    fi

    # Check if this is a manual review check BEFORE logging
    if [ "$result" = "Failed" ]; then
        for manual_review in "${Manual_Review_Checks[@]}"; do
            if [ "$check_name" == "$manual_review" ]; then
                result="Manual Check"
                break
            fi
        done
    fi

    # Log Passed/Failed/Manual Check results to log locations
    log_result "$check_name ($simple_name)" "$result"

    # Log the command output
    log_command_output "$check_name" "$check_command" "$result_output" "$expected_result" "$simple_name"

    # Log to plist file if required
    if [ "$LOG_TO_PLIST" = true ]; then
        update_plist "$check_name" "$simple_name" "$boolean_result"
    fi

    # Proceed only if the result indicates a failure (and not a manual check)
    if [ "$result" = "Failed" ]; then
        # Proceed with existing logic only if EXECUTE_FIX is true
        if [ "$EXECUTE_FIX" = true ]; then
            if [ "$requires_mdm" = false ]; then
                echo_white_bold "Running fix command..."
                command_fix_output=$(eval "$fix_command" 2>/dev/null)
                echo_white_bold "Fix performed..."
                echo_manual_rerun "Rerun script or run check STIG script to verify"
            else
                echo_failed_mdm "MDM configuration profile"
            fi
        fi
    elif [ "$result" = "Manual Check" ]; then
        if [ "$EXECUTE_FIX" = true ]; then
            echo_manual_review "Manual review or adjustments based on configuration"
        fi
    fi

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
    echo_set_variables "Execute Fixes" "$EXECUTE_FIX"  # Added variable
    echo ""
    echo_white_bold "~~~ Log Locations ~~~"

    if [ "$LOG_TO_SINGLE_FILE" = false ]; then
        echo_set_variables "Passed Log File Path" "$PASS_LOG_FILE"  # Admin log location
        echo_set_variables "Failed Log File Path" "$FAILURE_LOG_FILE"  # Admin log location
    else
        echo_set_variables "Consolidate Log File Path" "$SINGLE_LOG_FILE"  # Admin log location
    fi

    echo_set_variables "Command Log File Path" "$COMMAND_LOG_FILE"  # Admin log location
    echo_set_variables "Manual Log File Path" "$MANUAL_LOG_FILE"  # Admin log location

    if [ "$LOG_TO_PLIST" = true ]; then
        echo_set_variables "Plist Log File Path" "$PLIST_LOG_FILE"  # Default path for plist logs
    fi

    if [ "$LOG_TO_CSV" = true ]; then
        echo_set_variables "CSV Log File Path" "$CSV_LOG_FILE"  # Admin log location
    fi

    if [ "$LOG_RESULTS_TO_USER_LOG_FOLDER" = true ]; then
        echo ""
        if [ "$LOG_TO_SINGLE_FILE" = false ]; then
            echo_set_variables "Passed Log File Path (user)" "$USER_PASS_LOG_FILE"  # User log location
            echo_set_variables "Failed Log File Path (user)" "$USER_FAILURE_LOG_FILE"  # User log location
        else
            echo_set_variables "Consolidate Log File Path (user)" "$USER_SINGLE_LOG_FILE"  # User log location
        fi

        echo_set_variables "Command Log File Path (user)" "$USER_COMMAND_LOG_FILE"  # User log location
        echo_set_variables "Manual Log File Path (user)" "$USER_MANUAL_LOG_FILE"  # User log location

        if [ "$LOG_TO_CSV" = true ]; then
            echo_set_variables "CSV Log File Path (user)" "$USER_CSV_LOG_FILE"  # User log location
        fi
    fi

    echo ""
    echo_white_bold "~~~ Checks ~~~"
    echo_set_variables "General Skip Checks" "$(printf '%s ' "${General_Skip_Checks[@]}")"  # General skip checks
    echo_set_variables "Apple Only Checks" "$(printf '%s ' "${Apple_Only_Checks[@]}")"  # Apple only checks
    echo_set_variables "Intel Only Checks" "$(printf '%s ' "${Intel_Only_Checks[@]}")"  # Intel only checks
    echo_set_variables "Manual Review Checks" "$(printf '%s ' "${Manual_Review_Checks[@]}")"  # Manual review checks

    echo ""
    echo_white_bold "~~~ Terminal Settings ~~~"
    echo_set_variables "Hide Results in Terminal" "$HIDE_RESULTS_IN_TERMINAL"  # Corrected typo
    echo_rainbow_text "Enable Terminal Colorization ($MAKE_TERMINAL_COLORFUL)"
    echo_set_variables "Hide Logging Location in Terminal" "$HIDE_LOGGING_LOCATION_IN_TERMINAL"  # Corrected typo
    echo_set_variables "Hide Skipped Output in Terminal" "$HIDE_SKIPPED_TERMINAL_OUTPUT"  # Added missing variable
    echo__light_green "==========================================================="
    echo ""
fi


####################################################################################################
#
# STIG VUL's Checks Below
#
####################################################################################################

##########################################################################################
#                                    EXAMPLE EXPLAINED                                   #
##########################################################################################
#
# --- STIG-ID ---
# check_name="APPL-26-000001"
#
# --- PART OF THE RULE TITLE ---
# simple_name="system_settings_apple_watch_unlock_disable"
#
# --- COMMAND TO CHECK FOR VULNERABILITY ---
# check_command="/usr/bin/osascript -l JavaScript << EOS
# var defaults = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess');
# var value = defaults.objectForKey('allowAutoUnlock').js;
# value;
# EOS"
#
# --- EXPECTED OUTPUT RESULT ---
# expected_result="false"
#
# --- SEVERITY ---
# severity="CAT II"
#
# --- FIX COMMAND ---
# fix_command="com.apple.applicationaccess"
#
# --- MDM REQUIREMENT ---
# requires_mdm="true"
#
# --- TRIGGER CHECK EXECUTION ---
# execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"
#
# ------------------------------------------------------------------------------------------
#                                       NOTES
# ------------------------------------------------------------------------------------------
# - For check_commands or fix_commands containing variables (e.g., $1), escape the variable with a backslash (\) as in \$VARIABLE.
# - Commands may require changing quotes: swap double quotes ("") to single quotes ('') as needed.
# - Some commands must run with specific quoting: remove double quotes ("") or use single quotes ('') as appropriate.
#
# Example Adjustments:
#   Original: check_command="/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ':'"
#   Adjusted: check_command="/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ':'"
#
##########################################################################################
#                                    EXAMPLE EXPLAINED                                   #
##########################################################################################


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
check_name="APPL-26-000001"
simple_name="system_settings_apple_watch_unlock_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
var defaults = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess');
var value = defaults.objectForKey('allowAutoUnlock').js;
value;
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000002"
simple_name="system_settings_screensaver_password_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPassword').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.screensaver"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000003"
simple_name="system_settings_screensaver_ask_for_password_delay_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT II"
fix_command="com.apple.screensaver"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000005"
simple_name="system_settings_token_removal_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('tokenRemovalAction').js
EOS"
expected_result="1"
severity="CAT II"
fix_command="com.apple.security.smartcard"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000007"
simple_name="system_settings_hot_corners_disable"
check_command="/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '\"wvous-bl-corner\" = 0|\"wvous-br-corner\" = 0|\"wvous-tl-corner\" = 0|\"wvous-tr-corner\" = 0'"
expected_result="4"
severity="CAT II"
fix_command="com.apple.ManagedClient.preferences"
requires_mdm="true"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000009"
simple_name="Prevent_AdminHostInfo_Being_Avaible_At_LoginWindow"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.integerForKey('AdminHostInfo')
EOS"
expected_result="-1"
severity="CAT II"
fix_command="com.apple.loginwindow"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000012"
simple_name="pwpolicy_temporary_or_emergency_accounts_disable"
check_command="/usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2"
expected_result="manually check"
severity="CAT II"
fix_command=""
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000014"
simple_name="system_settings_time_server_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.timed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000022"
simple_name="pwpolicy_account_lockout_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyAttributeMaximumFailedAuthentications\"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if (\$1 <= 3) {print \"pass\"} else {print \"fail\"}}' | /usr/bin/uniq"
expected_result="pass"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000023"
simple_name="os_policy_banner_ssh_configure"
check_command="/usr/bin/more /etc/banner"
expected_result="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
severity="CAT II"
fix_command="echo \"$expected_result\" > /etc/banner"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000024"
simple_name="os_policy_banner_ssh_enforce"
check_command="/usr/sbin/sshd -G | /usr/bin/grep -c '^banner /etc/banner'"
expected_result="1"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000025"
simple_name="os_policy_banner_loginwindow_enforce"
check_command="/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="1"
severity="CAT II"
fix_command="complete_login_banner_fix"
requires_mdm="false"

# Comments Looks if file exists, user needs to verify it contains what it needs

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000030"
simple_name="audit_acls_files_configure"
check_command="/bin/ls -le \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '{print \$1}' | /usr/bin/grep -c ':'"
expected_result="0"
severity="CAT II"
fix_command="/bin/chmod -RN /var/audit"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000031"
simple_name="audit_acls_folders_configure"
check_command="/bin/ls -lde /var/audit | /usr/bin/awk '{print \$1}' | /usr/bin/grep -c \":\""
expected_result="0"
severity="CAT II"
fix_command="/bin/chmod -N /var/audit"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000033"
simple_name="os_filevault_autologin_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('DisableFDEAutoLogin').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.loginwindow"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000051"
simple_name="os_sshd_client_alive_interval_configure"
check_command="/usr/sbin/sshd -G | /usr/bin/awk '/clientaliveinterval/{print \$2}'"
expected_result="900"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000052"
simple_name="os_sshd_client_alive_count_max_configure"
check_command="/usr/sbin/sshd -G | /usr/bin/awk '/clientalivecountmax/{print \$2}'"
expected_result="1"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000053"
simple_name="os_sshd_login_grace_time_configure"
check_command="/usr/sbin/sshd -G | /usr/bin/awk '/logingracetime/{print \$2}'"
expected_result="30"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000054"
simple_name="os_sshd_fips_compliant"
check_command="fips_sshd_config=(\"Ciphers aes128-gcm@openssh.com\" \"HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com\" \"HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com\" \"KexAlgorithms ecdh-sha2-nistp256\" \"MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256\" \"PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com\" \"CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com\")
total=0
for config in \$fips_sshd_config; do
total=\$(expr \$(/usr/sbin/sshd -G | /usr/bin/grep -i -c \"\$config\") + \$total)
done

echo \$total
"
expected_result="7"
severity="CAT I"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000057"
simple_name="os_ssh_fips_compliant"
check_command="fips_ssh_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com")
total=0
ret="pass"
for config in $fips_ssh_config; do
if [[ "$ret" == "fail" ]]; then
break
fi
for u in $(/usr/bin/dscl . list /users shell | /usr/bin/egrep -v '(^_)|(root)|(/usr/bin/false)' | /usr/bin/awk '{print $1}'); do
sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -ci "$config")
if [[ "$sshCheck" == "0" ]]; then
ret="fail"
break
fi
done
done
echo $ret"
expected_result="8"
severity="CAT I"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000060"
simple_name="pwpolicy_account_lockout_timeout_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"autoEnableInSeconds\"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if (\$1/60 >= 15 ) {print \"pass\"} else {print \"fail\"}}' | /usr/bin/uniq"
expected_result="pass"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000070"
simple_name="system_settings_screensaver_timeout_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT II"
fix_command="com.apple.screensaver"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000090"
simple_name="os_unlock_active_user_session_disable"
check_command="RESULT="FAIL"
  SS_RULE=\$(/usr/bin/security -q authorizationdb read system.login.screensaver  2>&1 | /usr/bin/xmllint --xpath \"//dict/key[.='rule']/following-sibling::array[1]/string/text()\" -)

  if [[ \"\${SS_RULE}\" == \"authenticate-session-owner\" ]]; then
      RESULT=\"PASS\"
  else
      PSSO_CHECK=\$(/usr/bin/security -q authorizationdb read \"\$SS_RULE\"  2>&1 | /usr/bin/xmllint --xpath '//key[.=\"rule\"]/following-sibling::array[1]/string/text()' -)
      if /usr/bin/grep -Fxq \"authenticate-session-owner\" <<<\"\$PSSO_CHECK\"; then
          RESULT=\"PASS\"
      fi
  fi

  echo \$RESULT"
expected_result="PASS"
severity="CAT II"
fix_command="
SS_RULE=\$(/usr/bin/security -q authorizationdb read system.login.screensaver 2>&1 | /usr/bin/xmllint --xpath \"//dict/key[.='rule']/following-sibling::array[1]/string/text()\" -)

  if [[ \"\$SS_RULE\" == *psso* ]]; then
      /usr/bin/security -q authorizationdb read psso-screensaver > \"/tmp/psso-screensaver-mscp.plist\"
      /usr/bin/sed -i.bak 's/<string>authenticate-session-owner-or-admin<\/string>/<string>authenticate-session-owner<\/string>/' /tmp/psso-screensaver-mscp.plist
      /usr/bin/security -q authorizationdb write psso-screensaver-mscp < /tmp/psso-screensaver-mscp.plist
      /usr/bin/security -q authorizationdb write system.login.screensaver psso-screensaver-mscp 2>&1
  else
      /usr/bin/security -q authorizationdb write system.login.screensaver \"authenticate-session-owner\" 2>&1
  fi"
requires_mdm="PASS"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000100"
simple_name="os_root_disable"
check_command="/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c '/usr/bin/false'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/dscl . -create /Users/root UserShell /usr/bin/false"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000110"
simple_name="os_ssh_server_alive_interval_configure"
check_command="ret=\"pass\"
for u in \$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '\$2 > 500 {print \$1}'); do
sshCheck=\$(/usr/bin/sudo -u \$u /usr/bin/ssh -G . | /usr/bin/grep -c \"^serveraliveinterval 900\")
if [[ \"\$sshCheck\" == \"0\" ]]; then
ret=\"fail\"
break
fi
done
/bin/echo \$ret"
expected_result="pass"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000120"
simple_name="os_sshd_channel_timeout_configure"
check_command='/usr/sbin/sshd -G | /usr/bin/awk -F "=" '\''/channeltimeout session:*/{print $2}'\'''
expected_result="900"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000130"
simple_name="os_sshd_unused_connection_timeout_configure"
check_command='/usr/sbin/sshd -G | /usr/bin/awk '\''/unusedconnectiontimeout/{print $2}'\'''
expected_result="900"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000140"
simple_name="os_ssh_server_alive_count_max_configure"
check_command="ret=\"pass\"
for u in \$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '\$2 > 500 {print \$1}'); do
sshCheck=\$(/usr/bin/sudo -u \$u /usr/bin/ssh -G . | /usr/bin/grep -c \"^serveralivecountmax 0\")
if [[ \"\$sshCheck\" == \"0\" ]]; then
ret=\"fail\"
break
fi
done
/bin/echo \$ret"
expected_result="pass"
severity="CAT II"
fix_command="complete_ssh_sshd_fix"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000160"
simple_name="system_settings_automatic_logout_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('.GlobalPreferences')\
.objectForKey('com.apple.autologout.AutoLogOutDelay').js
EOS"
expected_result="86400"
severity="CAT II"
fix_command="com.apple.GlobalPreferences"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000170"
simple_name="system_settings_time_server_configure"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('timeServer').js
EOS"
expected_result="*" # Any output is accepted
severity="CAT II"
fix_command="com.apple.MCX"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-000180"
simple_name="os_time_server_enabled"
check_command="/bin/launchctl list | /usr/bin/grep -c com.apple.timed"
expected_result="1"
severity="CAT II"
fix_command="/bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"


##############################################
check_name="APPL-26-000190"
simple_name="os_sudo_log_enforce"
check_command="/usr/bin/sudo -V | /usr/bin/grep -c \"Log when a command is allowed by sudoers"\"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/^Defaults[[:blank:]]*\!log_allowed/s/^/# /' '{}' \;
/bin/echo \"Defaults log_allowed\" >> /etc/sudoers.d/mscp"
requires_mdm="1"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001001"
simple_name="audit_flags_ad_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*[^-]lo\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/\$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001002"
simple_name="audit_flags_lo_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^lo'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*[^-]lo\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001003"
simple_name="audit_auditd_enabled"
check_command="LAUNCHD_RUNNING=\$(/bin/launchctl print system | /usr/bin/grep -c -E '\tcom.apple.auditd')
AUDITD_RUNNING=\$(/usr/sbin/audit -c | /usr/bin/grep -c \"AUC_AUDITING\")
if [[ \$LAUNCHD_RUNNING == 1 ]] && [[ -e /etc/security/audit_control ]] && [[ \$AUDITD_RUNNING == 1 ]]; then
  echo \"pass\"
else
  echo \"fail\"
fi"
expected_result="pass"
severity="CAT II"
fix_command="if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]];then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
fi

/bin/launchctl enable system/com.apple.auditd
/bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist
/usr/sbin/audit -i"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001012"
simple_name="audit_files_owner_configure"
check_command="/bin/ls -n \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '{s+=\$3} END {print s}'"
expected_result="0"
severity="CAT II"
fix_command="/usr/sbin/chown -R root /var/audit/*"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001013"
simple_name="audit_folder_owner_configure"
check_command="/bin/ls -dn \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '{print \$3}'"
expected_result="0"
severity="CAT II"
fix_command="/usr/sbin/chown root /var/audit"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001014"
simple_name="audit_files_group_configure"
check_command="/bin/ls -n \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '{s+=\$4} END {print s}'"
expected_result="0"
severity="CAT II"
fix_command="/usr/bin/chgrp -R wheel /var/audit/*"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001015"
simple_name="audit_folder_group_configure"
check_command="/bin/ls -dn \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '{print \$4}'"
expected_result="0"
severity="CAT II"
fix_command="/usr/bin/chgrp wheel /var/audit"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001016"
simple_name="audit_files_mode_configure"
check_command="/bin/ls -l \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}') | /usr/bin/awk '!/-r--r-----|current|total/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"
severity="CAT II"
fix_command="/bin/chmod 440 /var/audit/*"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001017"
simple_name="audit_folders_mode_configure"
check_command="/usr/bin/stat -f %A \$(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print \$2}')"
expected_result="700"
severity="CAT II"
fix_command="/bin/chmod 700 /var/audit"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001020"
simple_name="audit_flags_fd_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fd'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*-fd\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/\$/,-fd/' /etc/security/audit_control;/usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001021"
simple_name="audit_flags_fm_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^fm'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*fm\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/\$/,fm/' /etc/security/audit_control;/usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001022"
simple_name="audit_flags_fr_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*-fr\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/\$/,-fr/' /etc/security/audit_control;/usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001023"
simple_name="audit_flags_fw_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fw'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*-fw\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/\$/,-fw/' /etc/security/audit_control;/usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001024"
simple_name="audit_flags_ex_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-ex'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*-ex\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/\$/,-ex/' /etc/security/audit_control; /usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001029"
simple_name="audit_retention_configure"
check_command="/usr/bin/awk -F: '/expire-after/{print \$2}' /etc/security/audit_control"
expected_result="7d"
severity="CAT III"
fix_command="/usr/bin/sed -i.bak 's/^expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001030"
simple_name="audit_configure_capacity_notify"
check_command="/usr/bin/awk -F: '/^minfree/{print \$2}' /etc/security/audit_control"
expected_result="25"
severity="CAT II"
fix_command="/usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001031"
simple_name="audit_settings_failure_notify"
check_command="/usr/bin/grep -c 'logger -s -p' /etc/security/audit_warn"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001044"
simple_name="audit_flags_aa_configure"
check_command="/usr/bin/awk -F':' '/^flags/ { print \$NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa'"
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/grep -qE \"^flags.*[^-]aa\" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/\$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001060"
simple_name="auth_smartcard_certificate_trust_enforce_moderate"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('checkCertificateTrust').js
EOS"
expected_result="2"
severity="CAT II"
fix_command="com.apple.security.smartcard"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001100"
simple_name="os_sshd_permit_root_login_configure"
check_command="/usr/sbin/sshd -G | /usr/bin/awk '/permitrootlogin/{print \$2}'"
expected_result="no"
severity="CAT II"
fix_command="include_dir=\$(/usr/bin/awk '/^Include/ {print \$2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z \$include_dir ]]; then
  /usr/bin/sed -i.bk \"1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/\" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'permitrootlogin no' \"\${include_dir}01-mscp-sshd.conf\" 2>/dev/null || echo \"permitrootlogin no\" >> \"\${include_dir}01-mscp-sshd.conf\"

for file in \$(ls \${include_dir}); do
  if [[ \"\$file\" == \"100-macos.conf\" ]]; then
      continue
  fi
  if [[ \"\$file\" == \"01-mscp-sshd.conf\" ]]; then
      break
  fi
  /bin/mv \${include_dir}\${file} \${include_dir}20-\${file}
done"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001110"
simple_name="audit_control_group_configure"
check_command="/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print \$4}'"
expected_result="0"
severity="CAT II"
fix_command="/usr/bin/chgrp wheel /etc/security/audit_control"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001120"
simple_name="audit_control_owner_configure"
check_command="/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print \$3}'"
expected_result="0"
severity="CAT II"
fix_command="/usr/sbin/chown root /etc/security/audit_control"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001130"
simple_name="audit_control_mode_configure"
check_command="/bin/ls -l /etc/security/audit_control | /usr/bin/awk '!/-r--[r-]-----|current|total/{print \$1}' | /usr/bin/wc -l | /usr/bin/xargs"
expected_result="0"
severity="CAT II"
fix_command="/bin/chmod 440 /etc/security/audit_control"
requires_mdm="false"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001140"
simple_name="audit_control_acls_configure"
check_command="/bin/ls -le /etc/security/audit_control | /usr/bin/awk '{print \$1}' | /usr/bin/grep -c \":\""
expected_result="0"
severity="CAT II"
fix_command="/bin/chmod -N /etc/security/audit_control"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-001150"
simple_name="auth_ssh_password_authentication_disable"
check_command="/usr/sbin/sshd -G | /usr/bin/grep -Ec '^(passwordauthentication\s+no|kbdinteractiveauthentication\s+no)'"
expected_result="2"
severity="CAT I"
fix_command="include_dir=\$(/usr/bin/awk '/^Include/ {print \$2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')
if [[ -z \$include_dir ]]; then
  /usr/bin/sed -i.bk \"1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/\" /etc/ssh/sshd_config
fi
echo \"passwordauthentication no\" >> \"\${include_dir}01-mscp-sshd.conf\"
echo \"kbdinteractiveauthentication no\" >> \"\${include_dir}01-mscp-sshd.conf\"

for file in \$(ls \${include_dir}); do
  if [[ \"\$file\" == \"100-macos.conf\" ]]; then
      continue
  fi
  if [[ \"\$file\" == \"01-mscp-sshd.conf\" ]]; then
      break
  fi
  /bin/mv \${include_dir}\${file} \${include_dir}20-\${file}
done"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002001"
simple_name="system_settings_smbd_disable"
check_command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.smbd\" => disabled'"
expected_result="1"
severity="CAT II"
fix_command="/bin/launchctl disable system/com.apple.smbd"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002003"
simple_name="os_nfsd_disable"
check_command="isDisabled=\$(/sbin/nfsd status | /usr/bin/awk '/nfsd service/ {print \$NF}') && \
if [[ \"\$isDisabled\" == \"disabled\" ]] && [[ -z \$(/usr/bin/pgrep nfsd) ]]; then \
  echo \"pass\" \
else \
  echo \"fail\" \
fi"
expected_result="pass"
severity="CAT II"
fix_command="/bin/launchctl disable system/com.apple.nfsd"
requires_mdm="false"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002004"
simple_name="system_settings_location_services_disable"
check_command="/usr/bin/sudo -u _locationd /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd')\
.objectForKey('LocationServicesEnabled').js
EOS
"
expected_result="false"
severity="CAT II"
fix_command="/usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /bin/launchctl kickstart -k system/com.apple.locationd"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002005"
simple_name="os_bonjour_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder')\
.objectForKey('NoMulticastAdvertisements').js
EOS
"
expected_result="true"
severity="CAT II"
fix_command="com.apple.mDNSResponder"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002006"
simple_name="os_uucp_disable"
check_command="result=\"FAIL\"
enabled=\$(/bin/launchctl print-disabled system | /usr/bin/grep '\"com.apple.uucp\" => enabled')
running=\$(/bin/launchctl print system/com.apple.uucp 2>/dev/null)

if [[ -z \"\$running\" ]] && [[ -z \"\$enabled\" ]]; then
  result=\"PASS\"
elif [[ -n \"\$running\" ]]; then
  result=\"\$result RUNNING\"
elif [[ -n \"\$enabled\" ]]; then
  result=\"\$result ENABLED\"
fi
echo \$result"
expected_result="PASS"
severity="CAT II"
fix_command="/bin/launchctl bootout system/com.apple.uucp
/bin/launchctl disable system/com.apple.uucp"
requires_mdm="false"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002007"
simple_name="system_settings_internet_sharing_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.MCX"
requires_mdm="true"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002008"
simple_name="os_httpd_disable"
check_command="result=\"FAIL\"
enabled=\$(/bin/launchctl print-disabled system | /usr/bin/grep '\"org.apache.httpd\" => enabled')
running=\$(/bin/launchctl print system/org.apache.httpd 2>/dev/null)

if [[ -z \"\$running\" ]] && [[ -z \"\$enabled\" ]]; then
  result=\"PASS\"
elif [[ -n \"\$running\" ]]; then
  result=\"\$result RUNNING\"
elif [[ -n \"\$enabled\" ]]; then
  result=\"\$result ENABLED\"
fi
echo \$result"
expected_result="PASS"
severity="CAT II"
fix_command="/usr/sbin/apachectl stop 2>/dev/null
/bin/launchctl disable system/org.apache.httpd"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002009"
simple_name="os_airdrop_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"


##############################################
check_name="APPL-26-002010"
simple_name="os_facetime_app_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT II"
fix_command="com.apple.applicationaccess.new"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002012"
simple_name="icloud_calendar_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudCalendar').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002013"
simple_name="icloud_reminders_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudReminders').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002014"
simple_name="icloud_addressbook_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudAddressBook').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002015"
simple_name="icloud_mail_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudMail').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002016"
simple_name="icloud_notes_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudNotes').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002017"
simple_name="os_camera_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCamera').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002020"
simple_name="system_settings_siri_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAssistant').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002021"
simple_name="system_settings_diagnostics_reports_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002022"
simple_name="system_settings_rae_disable"
check_command="/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.AEServer\" => disabled'"
expected_result="1"
severity="CAT II"
fix_command="/usr/sbin/systemsetup -setremoteappleevents off && /bin/launchctl disable system/com.apple.AEServer"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002023"
simple_name="system_settings_improve_assistive_voice_disable"
check_command="/usr/bin/sudo -u \"\$CURRENT_USER\" /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Accessibility')\
.objectForKey('AXSAudioDonationSiriImprovementEnabled').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.accessibility"
requires_mdm="Yes"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002024"
simple_name="system_settings_improve_search_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Search Queries Data Sharing Status').js
EOS"
expected_result="2"
severity="CAT II"
fix_command="com.apple.assistant.support"
requires_mdm="Yes"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002035"
simple_name="os_appleid_prompt_disable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("AppleID")
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002036"
simple_name="os_privacy_setup_prompt_disable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Privacy")
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002037"
simple_name="os_icloud_storage_prompt_disable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("iCloudStorage")
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"


##############################################
check_name="APPL-26-002038"
simple_name="os_tftpd_disable"
check_command="result=\"FAIL\"
enabled=\$(/bin/launchctl print-disabled system | /usr/bin/grep '\"com.apple.tftpd\" => enabled')
running=\$(/bin/launchctl print system/com.apple.tftpd 2>/dev/null)

if [[ -z \"\$running\" ]] && [[ -z \"\$enabled\" ]]; then
  result=\"PASS\"
elif [[ -n \"\$running\" ]]; then
  result=\"\$result RUNNING\"
elif [[ -n \"\$enabled\" ]]; then
  result=\"\$result ENABLED\"
fi
echo \$result"
expected_result="PASS"
severity="CAT I"
fix_command="/bin/launchctl bootout system/com.apple.tftpd 
/bin/launchctl disable system/com.apple.tftpd"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002039"
simple_name="os_siri_prompt_disable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Siri")
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002040"
simple_name="icloud_keychain_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudKeychainSync').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002041"
simple_name="icloud_drive_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDocumentSync').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002042"
simple_name="icloud_bookmarks_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudBookmarks').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002043"
simple_name="icloud_photos_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPhotoLibrary').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002050"
simple_name="system_settings_screen_sharing_disable"
check_command="result=\"FAIL\"
enabled=\$(/bin/launchctl print-disabled system | /usr/bin/grep '\"com.apple.screensharing\" => enabled')
running=\$(/bin/launchctl print system/com.apple.screensharing 2>/dev/null)

if [[ -z \"\$running\" ]] && [[ -z \"\$enabled\" ]]; then
  result=\"PASS\"
elif [[ -n \"\$running\" ]]; then
  result=\"\$result RUNNING\"
elif [[ -n \"\$enabled\" ]]; then
  result=\"\$result ENABLED\"
fi
echo \$result"
expected_result="PASS"
severity="CAT II"
fix_command="/bin/launchctl disable system/com.apple.screensharing"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002052"
simple_name="system_settings_wallet_applepay_settings_disable"
check_command="/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()=\"DisabledSystemSettings\"]/following-sibling::*[1]' - | /usr/bin/grep -c \"com.apple.WalletSettingsExtension\""
expected_result="1"
severity="CAT II"
fix_command="com.apple.systempreferences"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002053"
simple_name="system_settings_siri_settings_disable"
check_command="/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()=\"DisabledSystemSettings\"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.Siri-Settings.extension"
expected_result="1"
severity="CAT II"
fix_command="com.apple.systempreferences"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002060"
simple_name="system_settings_gatekeeper_identified_developers_allowed"
check_command="/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.control')\
.objectForKey('AllowIdentifiedDevelopers'))
let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.control')\
.objectForKey('EnableAssessment'))
if ( pref1 == true && pref2 == true ) {
return("true")
} else {
return("false")
}
}
EOS"
expected_result="true"
severity="CAT I"
fix_command="com.apple.systempolicy.control"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002062"
simple_name="system_settings_bluetooth_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCXBluetooth')\
.objectForKey('DisableBluetooth').js
EOS"
expected_result="true"
severity="CAT I"
fix_command="com.apple.MCXBluetooth"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002063"
simple_name="system_settings_guest_account_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT I"
fix_command="com.apple.MCX"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002064"
simple_name="os_gatekeeper_enable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.control')\
.objectForKey('EnableAssessment').js
EOS"
expected_result="true"
severity="CAT I"
fix_command="com.apple.systempolicy.control"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002066"
simple_name="system_settings_automatic_login_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS"
expected_result="true"
severity="CAT I"
fix_command="com.apple.loginwindow"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002068"
simple_name="os_home_folders_secure"
check_command="/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v \"Guest\" | /usr/bin/wc -l | /usr/bin/xargs"
expected_result="0"
severity="CAT II"
fix_command="IFS=\$'\n'
for userDirs in \$( /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v \"Shared\" | /usr/bin/grep -v \"Guest\" ); do
  /bin/chmod og-rwx \"\$userDirs\"
done
unset IFS"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002069"
simple_name="system_settings_system_wide_preferences_configure"
check_command="authDBs=(\"system.preferences\" \"system.preferences.energysaver\" \"system.preferences.network\" \"system.preferences.printing\" \"system.preferences.sharing\" \"system.preferences.softwareupdate\" \"system.preferences.startupdisk\" \"system.preferences.timemachine\")
result=\"1\"
for section in \${authDBs[@]}; do
  if [[ \$(/usr/bin/security -q authorizationdb read \"\$section\" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), \"shared\")]/following-sibling::*[1])' -) != \"false\" ]]; then
    result=\"0\"
  fi
  if [[ \$(/usr/bin/security -q authorizationdb read \"\$section\" | /usr/bin/xmllint -xpath '//*[contains(text(), \"group\")]/following-sibling::*[1]/text()' -) != \"admin\" ]]; then
    result=\"0\"
  fi
  if [[ \$(/usr/bin/security -q authorizationdb read \"\$section\" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), \"authenticate-user\")]/following-sibling::*[1])' -) != \"true\" ]]; then
    result=\"0\"
  fi
  if [[ \$(/usr/bin/security -q authorizationdb read \"\$section\" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), \"session-owner\")]/following-sibling::*[1])' -) != \"false\" ]]; then
    result=\"0\"
  fi
done
echo \$result"
expected_result="1"
severity="CAT I"
fix_command="authDBs=(\"system.preferences\" \"system.preferences.energysaver\" \"system.preferences.network\" \"system.preferences.printing\" \"system.preferences.sharing\" \"system.preferences.softwareupdate\" \"system.preferences.startupdisk\" \"system.preferences.timemachine\")

for section in \${authDBs[@]}; do
  /usr/bin/security -q authorizationdb read \"\$section\" > \"/tmp/\$section.plist\"

  class_key_value=\$(/usr/libexec/PlistBuddy -c \"Print :class\" \"/tmp/\$section.plist\" 2>&1)
  if [[ \"\$class_key_value\" == *\"Does Not Exist\"* ]]; then
    /usr/libexec/PlistBuddy -c \"Add :class string user\" \"/tmp/\$section.plist\"
  else
    /usr/libexec/PlistBuddy -c \"Set :class user\" \"/tmp/\$section.plist\"
  fi

  key_value=\$(/usr/libexec/PlistBuddy -c \"Print :shared\" \"/tmp/\$section.plist\" 2>&1)  
  if [[ \"\$key_value\" == *\"Does Not Exist\"* ]]; then
    /usr/libexec/PlistBuddy -c \"Add :shared bool false\" \"/tmp/\$section.plist\"
  else
    /usr/libexec/PlistBuddy -c \"Set :shared false\" \"/tmp/\$section.plist\"
  fi

  auth_user_key=\$(/usr/libexec/PlistBuddy -c \"Print :authenticate-user\" \"/tmp/\$section.plist\" 2>&1)  
  if [[ \"\$auth_user_key\" == *\"Does Not Exist\"* ]]; then
    /usr/libexec/PlistBuddy -c \"Add :authenticate-user bool true\" \"/tmp/\$section.plist\"
  else
    /usr/libexec/PlistBuddy -c \"Set :authenticate-user true\" \"/tmp/\$section.plist\"
  fi

  session_owner_key=\$(/usr/libexec/PlistBuddy -c \"Print :session-owner\" \"/tmp/\$section.plist\" 2>&1)  
  if [[ \"\$session_owner_key\" == *\"Does Not Exist\"* ]]; then
    /usr/libexec/PlistBuddy -c \"Add :session-owner bool false\" \"/tmp/\$section.plist\"
  else
    /usr/libexec/PlistBuddy -c \"Set :session-owner false\" \"/tmp/\$section.plist\"
  fi

  group_key=\$(/usr/libexec/PlistBuddy -c \"Print :group\" \"/tmp/\$section.plist\" 2>&1)
  if [[ \"\$group_key\" == *\"Does Not Exist\"* ]]; then
    /usr/libexec/PlistBuddy -c \"Add :group string admin\" \"/tmp/\$section.plist\"
  else
    /usr/libexec/PlistBuddy -c \"Set :group admin\" \"/tmp/\$section.plist\"
  fi

  /usr/bin/security -q authorizationdb write \"\$section\" < \"/tmp/\$section.plist\"
done"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002080"
simple_name="system_settings_airplay_receiver_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirPlayIncomingRequests').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002090"
simple_name="system_settings_touchid_unlock_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFingerprintForUnlock').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002100"
simple_name="system_settings_media_sharing_disabled"
check_command="/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowMediaSharing'))
let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowMediaSharingModification'))
if ( pref1 == false && pref2 == false ) {
return("true")
} else {
return("false")
}
}
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002110"
simple_name="system_settings_bluetooth_sharing_disable"
check_command="/usr/bin/sudo -u \"\$CURRENT_USER\" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled"
expected_result="0"
severity="CAT II"
fix_command="/usr/bin/sudo -u \"\$CURRENT_USER\" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"


##############################################
check_name="APPL-26-002120"
simple_name="os_account_modification_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAccountModification').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002140"
simple_name="system_settings_content_caching_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowContentCaching').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002150"
simple_name="icloud_sync_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDesktopAndDocuments').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002160"
simple_name="icloud_game_center_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowGameCenter').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002170"
simple_name="icloud_private_relay_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPrivateRelay').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002180"
simple_name="system_settings_find_my_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT II"
fix_command="com.apple.applicationaccess && com.apple.icloud.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002200"
simple_name="system_settings_personalized_advertising_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowApplePersonalizedAdvertising').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002210"
simple_name="system_settings_improve_siri_dictation_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Siri Data Sharing Opt-In Status').js
EOS"
expected_result="2"
severity="CAT II"
fix_command="com.apple.assistant.support"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002220"
simple_name="os_on_device_dictation_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('forceOnDeviceOnlyDictation').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002230"
simple_name="os_dictation_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDictation').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002240"
simple_name="system_settings_printer_sharing_disable"
check_command="/usr/sbin/cupsctl | /usr/bin/grep -c \"_share_printers=0\""
expected_result="1"
severity="CAT II"
fix_command="/usr/sbin/cupsctl --no-share-printers && /usr/bin/lpstat -p | awk '{print \$2}'| /usr/bin/xargs -I{} lpadmin -p {} -o printer-is-shared=false"
requires_mdm="false"


execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002250"
simple_name="system_settings_remote_management_disable"
check_command="/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c \"RemoteDesktopEnabled = 0\""
expected_result="1"
severity="CAT II"
fix_command="/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002260"
simple_name="system_settings_bluetooth_settings_disable"
check_command="/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.BluetoothSettings"
expected_result="1"
severity="CAT II"
fix_command="com.apple.systempreferences"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002270"
simple_name="icloud_freeform_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudFreeform').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-002271"
simple_name="iphone_mirroring_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowiPhoneMirroring').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003001"
simple_name="os_certificate_authority_trust"
check_command="/usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/awk -F'\"' '/labl/ {print \$4}'"
expected_result=""
severity="CAT II"
fix_command=""
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003007"
simple_name="pwpolicy_alpha_numeric_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyIdentifier\"]/following-sibling::*[1]/text()' - | /usr/bin/grep \"requireAlphanumeric\" -c"
expected_result="1"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003008"
simple_name="pwpolicy_max_lifetime_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeExpiresEveryNDays"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if (\$1 <= 60 ) {print "pass"} else {print "fail"}}' | /usr/bin/uniq"
expected_result="pass"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003010"
simple_name="pwpolicy_minimum_length_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | tail +2 | grep -oE \"policyAttributePassword matches '.\{[0-9]+,\" | awk -F'[{,]' -v ODV=14 '{if (\$2 > max) max=\$2} END {print (max >= ODV) ? \"pass\" : \"fail\"}'"
expected_result="pass"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003011"
simple_name="pwpolicy_special_character_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/tail -n +2 | /usr/bin/xmllint --xpath \"//string[contains(text(), \"policyAttributePassword matches '(.*[^a-zA-Z0-9].*){\")]\" - 2>/dev/null | /usr/bin/awk -F\"{|}\" '{if (\$2 >= 1) {print \"pass\"} else {print \"fail\"}}'"
expected_result="pass"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003012"
simple_name="os_password_hint_remove"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS"
expected_result="0"
severity="CAT II"
fix_command="com.apple.loginwindow"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003014"
simple_name="os_password_hint_remove"
check_command="HINT=$(/usr/bin/dscl . -list /Users hint | /usr/bin/awk '{ print $2 }')

if [ -z "$HINT" ]; then
echo "PASS"
else
echo "FAIL"
fi"
expected_result="PASS"
severity="CAT II"
fix_command="for u in \$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '\$2 > 500 {print \$1}'); do
  /usr/bin/dscl . -delete /Users/\$u hint
done"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003020"
simple_name="auth_smartcard_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('enforceSmartCard').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.security.smartcard"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003030"
simple_name="auth_smartcard_allow"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('allowSmartCard').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.security.smartcard"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003050"
simple_name="auth_pam_login_smartcard_enforce"
check_command="/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login"
expected_result="2"
severity="CAT II"
fix_command=""
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003051"
simple_name="auth_pam_su_smartcard_enforce"
check_command="/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su"
expected_result="2"
severity="CAT II"
fix_command=""
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003052"
simple_name="auth_pam_sudo_smartcard_enforce"
check_command="/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo"
expected_result="2"
severity="CAT II"
fix_command=""
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003060"
simple_name="pwpolicy_custom_regex_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),\"policyAttributePassword matches '\''.*[A-Z]{1,}[a-z]{1,}.*'\''\")])' -"
expected_result="true"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003070"
simple_name="pwpolicy_minimum_lifetime_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyAttributeMinimumLifetimeHours\"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if (\$1 >= 24 ) {print \"pass\"} else {print \"fail\"}}'"
expected_result="pass"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-003080"
simple_name="pwpolicy_account_inactivity_enforce"
check_command="/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()=\"policyAttributeInactiveDays\"]/following-sibling::integer[1]/text()' -"
expected_result="35"
severity="CAT II"
fix_command="com.apple.mobiledevice.passwordpolicy"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-004001"
simple_name="os_asl_log_files_owner_group_configure"
check_command="/usr/bin/stat -f '%Su:%Sg:%N' \$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print \$2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"
severity="CAT II"
fix_command="/usr/sbin/chown root:wheel \$(/usr/bin/stat -f '%Su:%Sg:%N' \$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print \$2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print \$1}' | /usr/bin/awk -F\":\" '!/^root:wheel:/{print \$3}')"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-004002"
simple_name="os_asl_log_files_permissions_configure"
check_command="/usr/bin/stat -f '%A:%N' \$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print \$2 }') 2> /dev/null | /usr/bin/awk '!/640/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"
severity="CAT II"
fix_command="/bin/chmod 640 \$(/usr/bin/stat -f '%A:%N' \$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print \$2 }') 2> /dev/null | /usr/bin/awk -F\":\" '!/640/{print \$2}')"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-004022"
simple_name="reauthenticate_when_using_sudo"
check_command="/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c \"Authentication timestamp timeout: 0.0 minutes\""
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/timestamp_timeout/d' '{}' \; && /bin/echo \"Defaults timestamp_timeout=0\" >> /etc/sudoers.d/mscp"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-004030"
simple_name="os_newsyslog_files_owner_group_configure"
check_command="/usr/bin/stat -f '%Su:%Sg:%N' \$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print \$1 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"
severity="CAT II"
fix_command="/usr/sbin/chown root:wheel \$(/usr/bin/stat -f '%Su:%Sg:%N' \$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print \$1 }') 2> /dev/null | /usr/bin/awk -F":" '!/^root:wheel:/{print \$3}')"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-004040"
simple_name="os_newsyslog_files_permissions_configure"
check_command="/usr/bin/stat -f '%A:%N' \$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print \$1 }') 2> /dev/null | /usr/bin/awk '!/640/{print \$1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '"
expected_result="0"
severity="CAT II"
fix_command="/bin/chmod 640 \$(/usr/bin/stat -f '%A:%N' \$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print \$1 }') 2> /dev/null | /usr/bin/awk '!/640/{print \$1}' | awk -F":" '!/640/{print \$2}')"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-004050"
simple_name="os_install_log_retention_configure"
check_command="/usr/sbin/aslmanager -dd 2>&1 | /usr/bin/awk '/\/var\/log\/install.log/ {count++} /Processing module com.apple.install/,/Finished/ { for (i=1;i<=NR;i++) { if (\$i == \"TTL\" && \$(i+2) >= 365) { ttl=\"True\" }; if (\$i == \"MAX\") {max=\"True\"}}} END{if (count > 1) { print \"Multiple config files for /var/log/install, manually remove\"} else if (ttl != \"True\") { print \"TTL not configured\" } else if (max == \"True\") { print \"Max Size is configured, must be removed\" } else { print \"Yes\" }}'"
expected_result="Yes"
severity="CAT III"
fix_command="/usr/bin/sed -i '' \"s/\* file \/var\/log\/install.log.*/\* file \/var\/log\/install.log format='\$\(\(Time\)\(JZ\)\) \$Host \$\(Sender\)\[\$\(PID\\)\]: \$Message' rotate=utc compress file_max=50M size_only ttl=365/g\" /etc/asl/com.apple.install"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-004060"
simple_name="os_install_log_timestamp_configure"
check_command="/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/awk -F\": \" '/Type of authentication timestamp record/{print \$2}'"
expected_result="tty"
severity="CAT II"
fix_command="/usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/timestamp_type/d; /!tty_tickets/d' '{}' \;"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"


##############################################
check_name="APPL-26-005001"
simple_name="os_sip_enable"
check_command="/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'"
expected_result="1"
severity="CAT I"
fix_command="/usr/bin/csrutil enable"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005020"
simple_name="system_settings_filevault_enforce"
check_command="dontAllowDisable=\$(/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT I"
fix_command="com.apple.MCX"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005050"
simple_name="system_settings_firewall_enable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableFirewall').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.security.firewall"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005052"
simple_name="system_settings_loginwindow_prompt_username_password_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.loginwindow"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005054"
simple_name="os_touchid_prompt_disable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Biometric")
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005055"
simple_name="os_skip_screen_time_prompt_enable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("ScreenTime")
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005056"
simple_name="os_skip_unlock_with_watch_enable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("WatchMigration")
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005058"
simple_name="os_handoff_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowActivityContinuation').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005060"
simple_name="os_password_proximity_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordProximityRequests').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005061"
simple_name="os_erase_content_and_settings_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowEraseContentAndSettings').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005070"
simple_name="os_authenticated_root_enable"
check_command="/usr/libexec/mdmclient QuerySecurityInfo 2>/dev/null | /usr/bin/grep -c \"AuthenticatedRootVolumeEnabled = 1;\""
expected_result="1"
severity="CAT II"
fix_command="/usr/bin/csrutil authenticated-root enable"
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005080"
simple_name="os_user_app_installation_prohibit"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT II"
fix_command="com.apple.applicationaccess.new"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005090"
simple_name="system_settings_usb_restricted_mode"
check_command="/usr/bin/osascript -l JavaScript << EOS
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
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005100"
simple_name="os_secure_boot_verify"
check_command="/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c \"SecureBootLevel = full\""
expected_result="1"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005110"
simple_name="os_mdm_require"
check_command="/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print \$2}' | /usr/bin/grep -c \"Yes (User Approved)\""
expected_result="1"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005120"
simple_name="os_recovery_lock_enable"
check_command="/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c \"IsRecoveryLockEnabled = 1\""
expected_result="1"
severity="CAT II"
fix_command=""
requires_mdm="false"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005130"
simple_name="os_config_data_install_enforce"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS"
expected_result="true"
severity="CAT II"
fix_command="com.apple.SoftwareUpdate"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005140"
simple_name="os_genmoji_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowGenmoji').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005150"
simple_name="os_image_generation_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowImagePlayground').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005160"
simple_name="os_writing_tools_disable"
check_command="/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowWritingTools').js
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.applicationaccess"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################
check_name="APPL-26-005170"
simple_name="os_apple_intelligence_disable"
check_command="/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Intelligence")
EOS"
expected_result="false"
severity="CAT II"
fix_command="com.apple.SetupAssistant.managed"
requires_mdm="true"

execute_and_log "$check_name" "$check_command" "$expected_result" "$simple_name" "$severity" "$fix_command" "$requires_mdm"

##############################################

exit 0
