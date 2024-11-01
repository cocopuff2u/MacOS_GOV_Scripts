#!/usr/bin/env python3

####################################################################################################
#
# MacOS Configuration Profiles Checker
#
# Purpose: Extracts and analyzes MacOS configuration profiles to extract profile details
#          and identifies profiles with matching payload types.
#
# To run this script, execute it in a Python environment with the necessary permissions.
#
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 8/21/24 - Initial release to extract and analyze MacOS configuration profiles.
#
####################################################################################################

import subprocess
import re
from collections import defaultdict
import sys

# Function to execute the command and get the output
def get_profiles_output():
    try:
        result = subprocess.run(['sudo', 'profiles', '-C', '-v'], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return None

# Function to parse the profiles output
def parse_profiles_output(output):
    profiles = []
    current_profile = None

    profile_name_pattern = re.compile(r'_computerlevel\[\d+\] attribute: name:\s*(.*)')
    organization_pattern = re.compile(r'_computerlevel\[\d+\] attribute: organization:\s*(.*)')
    payload_count_pattern = re.compile(r'_computerlevel\[\d+\] payload count = (\d+)')
    payload_type_pattern = re.compile(r'_computerlevel\[\d+\]            payload\[\d+\] type\s*=\s*(.*)')

    lines = output.splitlines()
    for line in lines:
        profile_name_match = profile_name_pattern.match(line)
        if profile_name_match:
            if current_profile:
                profiles.append(current_profile)
            profile_name = profile_name_match.group(1).strip()
            current_profile = {
                'name': profile_name,
                'organization': 'Unknown',
                'payload_count': 0,
                'payload_types': set()
            }
            continue

        organization_match = organization_pattern.match(line)
        if organization_match and current_profile:
            current_profile['organization'] = organization_match.group(1).strip()
            continue

        payload_count_match = payload_count_pattern.match(line)
        if payload_count_match and current_profile:
            current_profile['payload_count'] = int(payload_count_match.group(1))
            continue

        payload_type_match = payload_type_pattern.match(line)
        if payload_type_match and current_profile:
            current_profile['payload_types'].add(payload_type_match.group(1).strip())
            continue

    if current_profile:
        profiles.append(current_profile)

    return profiles

# Function to find profiles with matching payload types
def find_matching_payload_profiles(profiles):
    payload_type_to_profiles = defaultdict(list)

    for profile in profiles:
        for payload_type in profile['payload_types']:
            payload_type_to_profiles[payload_type].append(profile['name'])

    matching_payload_types = {ptype: names for ptype, names in payload_type_to_profiles.items() if len(names) > 1}

    return matching_payload_types

def print_header(header):
    green = "\033[92m"
    purple = "\033[95m"
    reset = "\033[0m"

    line_length = 60
    border = "=" * line_length
    inner_border = "= = = = = = = = = = = = = = = = = = = = = = = = = = = = = ="

    header_length = len(header)
    total_padding = line_length - header_length
    left_padding = total_padding // 2
    right_padding = total_padding - left_padding

    header_line = f"{' ' * left_padding}{header}{' ' * right_padding}"

    print(f"{green}{border}{reset}")
    print(f"{green}{inner_border}{reset}")
    print(f"{green}{header_line}{reset}")
    print(f"{green}{inner_border}{reset}")
    print(f"{green}{border}{reset}")

def display_profiles_info(profiles, matching_payload_types):
    purple = "\033[95m"
    reset = "\033[0m"

    print_header("Profile Information")
    for profile in profiles:
        print(f"Profile Name: {profile['name']}")
        print(f"Payload Count: {profile['payload_count']}")
        print(f"Payload Types: {', '.join(profile['payload_types'])}")
        print(f"{purple}{'-' * 30}{reset}")

    if matching_payload_types:
        print_header("Profiles with Matching Payload Types")
        for payload_type, profile_names in matching_payload_types.items():
            print(f"Payload Type: {payload_type}")
            print("Profiles:")
            for name in profile_names:
                print(f"  - {name}")
            print(f"{purple}{'-' * 30}{reset}")
    else:
        print_header("No Matching Payload Types Found")

    print(f"{purple}{'-' * 30}{reset}")

def main():
    output = get_profiles_output()
    if output:
        profiles = parse_profiles_output(output)
        matching_payload_types = find_matching_payload_profiles(profiles)
        display_profiles_info(profiles, matching_payload_types)

if __name__ == "__main__":
    main()
