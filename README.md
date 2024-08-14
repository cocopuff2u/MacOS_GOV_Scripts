# <p align="center"> DISA STIG Scripts </p>

  These scripts are designed to check and address STIG requirements. However, please note that not all STIG requirements can be resolved via command line; some require configuration profiles that need to be deployed through an MDM. These profiles are available at https://public.cyber.mil/stigs/, but I have not included them here. For any recommendations or issues, please feel free to reach out.
<br />
<br />
  Each script contains variables that need to be adjusted to generate logs locally on your machine, so please configure these settings as needed.
<br />
<br />
Additionally, I have included a script for importing DoD certificates, which will facilitate the process of adding the required certificates into the system keychain.
<br />
### <p align="center"> <ins> Executing Scripts</ins> </p>

```
sudo bash "PATH/MacOS 14 Sonoma V2R1 STIG CHECKER.sh"
```
<br />
* <strong>Note:</strong> The file path will depend on where you downloaded the file. For example, if it was saved to the Downloads folder in your home directory, the command would look like this:

```
sudo bash "~/downloads/MacOS 14 Sonoma V2R1 STIG CHECKER.sh"
``` 

## <p align="center"> [Sonoma STIG Checker](https://github.com/cocopuff2u/Mac-Scripts/blob/130024b9664872bddc16938225adc5fd6af0d194/DISA%20STIG%20Scripts/MacOS%2014%20Sonoma%20V2R1%20STIG%20CHECKER.sh) </p> 
<p align="center"> This script assesses the machine's current configuration against the specified DISA STIGs and produces comprehensive logs for the administrator. By default, logs are saved in the /var/log/ or ~/log directory, but you can customize the location within the script. The script now supports output in plist, CSV, and log formats.</p>
<br />

<p align="center"> Terminal Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/Mac-Scripts/blob/130024b9664872bddc16938225adc5fd6af0d194/DISA%20STIG%20Scripts/images/check_terminal_log.png">
</p>

<p align="center"> Plist Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/Mac-Scripts/blob/9751e2cbc619b14727ffd0c5537efdd87d01bbb8/DISA%20STIG%20Scripts/images/Example_plist_output.png">
</p>

<p align="center"> CSV Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/Mac-Scripts/blob/9751e2cbc619b14727ffd0c5537efdd87d01bbb8/DISA%20STIG%20Scripts/images/Example_csv_output.png">
</p>

<p align="center"> Command Log Output</p>
<p align="center">
<img src="https://github.com/cocopuff2u/Mac-Scripts/blob/130024b9664872bddc16938225adc5fd6af0d194/DISA%20STIG%20Scripts/images/Example_Command_output_log.png">
</p>

<p align="center"> Failed/Passed Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/Mac-Scripts/blob/130024b9664872bddc16938225adc5fd6af0d194/DISA%20STIG%20Scripts/images/Example_Passed_STIG_log.png">
</p>

## <p align="center"> [Sonoma STIG Fixer](https://github.com/cocopuff2u/Mac-Scripts/blob/1c495c72ff1970292f19b3427a9d5323cfff658e/DISA%20STIG%20Scripts/MacOS%2014%20Sonoma%20V2R1%20STIG%20FIXER.sh) </p> 
<p align="center">The script assesses the machine's current settings against the required DISA STIGs and applies fixes as needed. It will only execute a fix if a failure is detected. Please note that not all STIG requirements can be resolved through command line alone; some may necessitate MDM configuration profiles</p>
<br />

<p align="center"> Terminal Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/Mac-Scripts/blob/19c94b71ecbfbbd43fe66bdcbfd4aad0b257702c/DISA%20STIG%20Scripts/images/Example_terminal_fixer_log.png">
</p>

<p align="center"> Fixer Command Log Output </p>
<p align="center">
<img src="https://github.com/cocopuff2u/Mac-Scripts/blob/c8cb3bbcebf59154d79bc9836d8b991324fd2f6e/DISA%20STIG%20Scripts/images/Example_Fixer_Command_output_log.png">
</p>
