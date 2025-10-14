#!/bin/bash

audit_file="/Library/Preferences/STIG_Checks.plist"

# Check if the file exists
if [[ ! -f "$audit_file" ]]; then
    echo "<result>No STIG check file found</result>"
    exit 1
fi

FAILED_RULES=()

# Use PlistBuddy to get the list of rules
rules=($(/usr/libexec/PlistBuddy -c "print :" "${audit_file}" | /usr/bin/awk '/Dict/ { print $1 }'))

for rule in "${rules[@]}"; do
    if [[ $rule == "Dict" ]]; then
        continue
    fi
    FINDING=$(/usr/libexec/PlistBuddy -c "print :$rule:finding" "${audit_file}")
    if [[ "$FINDING" == "true" ]]; then
        FAILED_RULES+=($rule)
    fi
done

# Check if any rules failed
if [[ ${#FAILED_RULES[@]} -eq 0 ]]; then
    echo "<result>No STIG findings</result>"
else

IFS=$'
' sorted=($(/usr/bin/sort <<<"${FAILED_RULES[*]}")); unset IFS

printf "<result>"
printf "%s
" "${sorted[@]}"
printf "</result>"
fi
