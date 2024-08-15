# <p align="center">MacOS 14 (SONOMA) DISA STIG Scripts </p>

  These scripts are designed to check and address MacOS Sonoma STIG requirements. However, please note that not all STIG requirements can be resolved via command line; some require configuration profiles that need to be deployed through an MDM. These profiles are available at https://public.cyber.mil/stigs/, but I have not included them here. For any recommendations or issues, please feel free to reach out.
<br />
<br />
## <p align="center"> <ins> Script Variables</ins> </p>
Each script includes variables that can be tailored to produce different type of logs on your local machine. Please adjust these settings accordingly. Here are some examples:
```
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
```
To modify these variables, open the script in your preferred IDE (such as Visual Studio Code) and change the relevant line from true to false. See the example below:
```
### BEFORE
HIDE_RESULTS_IN_TERMINAL=false         # Show output in terminal when running script local [ true | false (default) ]

### AFTER
HIDE_RESULTS_IN_TERMINAL=true         # Show output in terminal when running script local [ true | false (default) ]
```

## <p align="center"> <ins> Executing Scripts</ins> </p>
To execute the script, use the command `sudo bash` followed by the script's name. See the example below:
```
sudo bash "PATH/TO/SCRIPT/MacOS 14 Sonoma V2R1 STIG CHECKER.sh"
```
* <strong>Note:</strong> The file path will depend on where you downloaded the file. For example, if it was saved to the Downloads folder in your home directory, the command would look like this:
```
sudo bash "~/downloads/MacOS 14 Sonoma V2R1 STIG CHECKER.sh"
```

## [MacOS 14 Sonoma STIG Checker](https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/a2c0f162172935a523bbb7736e575634c8e41667/MacOS%20Sonoma%20STIG%20Tools/MacOS%2014%20Sonoma%20V2R1%20STIG%20CHECKER.sh)
This script evaluates your machine's configuration against the specified DISA STIGs and generates detailed logs for the administrator. By default, logs are saved in the `/var/log/` or `~/log` directory, but you can customize the storage location within the script. The script now supports output in plist, CSV, and log formats. Below are examples of various outputs and their appearance.
<br />

<p align="center"> Terminal Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/1c4c60dd607640367ae24679899debc79d6157f7/MacOS%20Sonoma%20STIG%20Tools/images/Example_check_terminal_log.png">
</p>

<p align="center"> Plist Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/1c4c60dd607640367ae24679899debc79d6157f7/MacOS%20Sonoma%20STIG%20Tools/images/Example_plist_output.png">
</p>

<p align="center"> CSV Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/1c4c60dd607640367ae24679899debc79d6157f7/MacOS%20Sonoma%20STIG%20Tools/images/Example_csv_output.png">
</p>

<p align="center"> Command Log Output</p>
<p align="center">
<img src="https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/1c4c60dd607640367ae24679899debc79d6157f7/MacOS%20Sonoma%20STIG%20Tools/images/Example_Command_output_log.png">
</p>

<p align="center"> Failed/Passed Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/1c4c60dd607640367ae24679899debc79d6157f7/MacOS%20Sonoma%20STIG%20Tools/images/Example_Passed_STIG_log.png">
</p>

## [MacOS 14 Sonoma STIG Fixer](https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/a2c0f162172935a523bbb7736e575634c8e41667/MacOS%20Sonoma%20STIG%20Tools/MacOS%2014%20Sonoma%20V2R1%20STIG%20FIXER.sh)
The script evaluates your machine's current settings against the required DISA STIGs and applies necessary fixes when failures are detected. It will only perform a fix if a problem is identified. Please note that some STIG requirements cannot be addressed through the command line alone and may require MDM configuration profiles. Below are examples of various outputs and their appearance.<br />

<p align="center"> Terminal Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/1c4c60dd607640367ae24679899debc79d6157f7/MacOS%20Sonoma%20STIG%20Tools/images/Example_terminal_fixer_log.png">
</p>

<p align="center"> Fixer Command Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/1c4c60dd607640367ae24679899debc79d6157f7/MacOS%20Sonoma%20STIG%20Tools/images/Example_Fixer_Command_output_log.png">
</p>
