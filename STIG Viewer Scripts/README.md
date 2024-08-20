# STIG Viewer Scripts

This folder contains scripts designed to manage the installation and uninstallation of the STIG Viewer. These scripts automate tasks such as setting up or removing the STIG Viewer application and managing associated files, providing a streamlined and efficient experience.

## STIG Viewer V2

- **[STIG Viewer V2 Setup](https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/563ef7d09e68e1fb110b73b1ea33f90e40852d8a/STIG%20Viewer%20Scripts/STIG%20Viewer%20V2%20Setup.sh)**: Automates the installation and uninstallation of STIG Viewer V2. This script sets up the application as a macOS application and can optionally create a desktop icon for convenient access.

  ![STIG Viewer V2 Setup](https://github.com/cocopuff2u/MacOS_GOV_Scripts/blob/563ef7d09e68e1fb110b73b1ea33f90e40852d8a/STIG%20Viewer%20Scripts/images/Example_STIGViewer.png)

  **Note:** STIG Viewer V2 is compatible exclusively with the Java version specified for macOS and requires the full Java JDK to function correctly. The necessary Java JDK is included in the Setup script.

## STIG Viewer V3

Currently, **STIG Viewer V3** is not compatible with macOS. Despite Electron’s support for macOS, this version of the application has specific implementation issues or dependencies that are not yet resolved for macOS. 

Future updates may provide compatibility if DISA addresses these issues. To expedite this process, consider contacting DISA via email at **disa.letterkenny.re.mbx.stig-customer-support-mailbox@mail.mil** to express interest in macOS support. 

Alternatively, if you have the expertise to repackage the Linux or Windows version, it might be possible to develop a functional macOS version of STIG Viewer V3.

## Script Variables

Scripts include variables that you can modify to produce different types of logs on your local machine. Be aware that URLs or file names may change over time, requiring updates to these variables. Examples include:

```bash
# JDK URL and filename
JDK_URL="https://download.bell-sw.com/java/22.0.2+11/bellsoft-jdk22.0.2+11-macos-aarch64-full.pkg"
JDK_PKG="bellsoft-jdk22.0.2+11-macos-aarch64-full.pkg"

# STIG Viewer URL and filenames
STIG_VIEWER_URL="https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIGViewer_2-18.zip"
STIG_VIEWER_ZIP="U_STIGViewer_2-18.zip"
STIG_VIEWER_DIR="/Applications/STIG Viewer"
STIG_VIEWER_JAR="$STIG_VIEWER_DIR/STIGViewer-2.18.jar"
STIG_VIEWER_APP="$STIG_VIEWER_DIR/STIGViewer.app"

# System icon path
SYSTEM_ICON="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/ToolbarCustomizeIcon.icns"
```

To modify these variables, open the script in your preferred IDE (e.g., Visual Studio Code) and update the relevant lines. For example:

```bash
### BEFORE
JDK_URL="https://download.bell-sw.com/java/22.0.2+11/bellsoft-jdk22.0.2+11-macos-aarch64-full.pkg"

### AFTER
JDK_URL="https://download.bell-sw.com/java/17.0.2+11/bellsoft-jdk17.0.2+11-macos-aarch64-full.pkg"
```

## Executing Scripts

To execute a script, use the command `sudo bash` followed by the script's name. For example:

```bash
sudo bash "PATH/TO/SCRIPT/STIG Viewer V2 Setup.sh"
```

*Note:* Adjust the file path based on where you saved the file. For instance, if saved in your Downloads folder, the command would be:

```bash
sudo bash "~/downloads/STIG Viewer V2 Setup.sh"
```
