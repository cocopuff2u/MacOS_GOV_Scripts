#!/bin/bash
####################################################################################################
#
# MacOS STIG Viewer V2 Setup
#
# Purpose: Automates the installation and uninstallation of STIG Viewer V2.
# This script sets up STIG Viewer V2 as a macOS application and optionally
# configures it with a desktop icon for easy access.
#
# To run script open terminal and type 'sudo bash /path/to/script.sh'
#
# Jamf Usage: Pass "install" or "uninstall" as Parameter 4
#
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 08/20/24 - Original
#  1.1 01/16/26 - Jamf compatibility fixes
#
####################################################################################################
# Configuration Section

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

####################################################################################################
#
# Script Starts Below
#
####################################################################################################

# Get the currently logged-in user (works when running as root via Jamf)
CURRENT_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }')
if [ -z "$CURRENT_USER" ] || [ "$CURRENT_USER" = "root" ]; then
    CURRENT_USER=$(stat -f%Su /dev/console)
fi
CURRENT_USER_HOME=$(dscl . -read /Users/"$CURRENT_USER" NFSHomeDirectory | awk '{print $2}')

# Jamf passes parameters starting at $4; support both direct CLI and Jamf usage
# $1 = mount point (Jamf) or action (CLI)
# $4 = action (Jamf)
if [ -n "$4" ]; then
    # Running via Jamf
    ACTION="$4"
elif [ -n "$1" ] && [ "$1" != "/" ]; then
    # Running via CLI (and $1 is not a mount point)
    ACTION="$1"
else
    # Default to install if no parameter provided
    ACTION="install"
fi

# Function to display usage
usage() {
    echo "Usage:"
    echo "  CLI:  $0 [install|uninstall]"
    echo "  Jamf: Pass 'install' or 'uninstall' as Parameter 4"
    echo ""
    echo "  install   Install the JDK and STIG Viewer (default if no action specified)"
    echo "  uninstall Uninstall the JDK and STIG Viewer"
    exit 1
}

# Function to install JDK
install_jdk() {
    # Create a temporary directory
    TEMP_DIR=$(mktemp -d)

    # Ensure the temporary directory is removed on script exit
    trap 'rm -rf "$TEMP_DIR"' EXIT

    # Download JDK
    echo "Downloading JDK..."
    curl -L -o "$TEMP_DIR/$JDK_PKG" "$JDK_URL"

    # Install JDK
    echo "Installing JDK..."
    installer -pkg "$TEMP_DIR/$JDK_PKG" -target /

    # Clean up
    echo "Cleaning up..."
    rm -rf "$TEMP_DIR"

    # Set JAVA_HOME and PATH for the current user
    echo "Setting up environment variables for user: $CURRENT_USER..."

    # Update both .zshrc and .bash_profile for the logged-in user
    JAVA_HOME=$(/usr/libexec/java_home 2>/dev/null)

    if [ -n "$JAVA_HOME" ]; then
        for PROFILE in "$CURRENT_USER_HOME/.zshrc" "$CURRENT_USER_HOME/.bash_profile"; do
            # Only add if not already present
            if ! grep -q "JAVA_HOME" "$PROFILE" 2>/dev/null; then
                echo "export JAVA_HOME=\"$JAVA_HOME\"" >> "$PROFILE"
                echo "export PATH=\"\$JAVA_HOME/bin:\$PATH\"" >> "$PROFILE"
                chown "$CURRENT_USER" "$PROFILE"
            fi
        done
    fi

    # Verify installation
    echo "Verifying installations..."
    java -version
    javac -version

    echo "Java installation complete!"
}

# Function to install STIG Viewer
install_stig_viewer() {
    # Create a temporary directory
    TEMP_DIR=$(mktemp -d)

    # Ensure the temporary directory is removed on script exit
    trap 'rm -rf "$TEMP_DIR"' EXIT

    # Download STIG Viewer
    echo "Downloading STIG Viewer..."
    curl -L -o "$TEMP_DIR/$STIG_VIEWER_ZIP" "$STIG_VIEWER_URL"

    # Create the destination directory if it does not exist
    echo "Creating destination directory..."
    mkdir -p "$STIG_VIEWER_DIR"

    # Extract the ZIP file
    echo "Extracting STIG Viewer..."
    unzip -q "$TEMP_DIR/$STIG_VIEWER_ZIP" -d "$STIG_VIEWER_DIR"

    # Create a minimal .app bundle
    echo "Creating application bundle..."
    mkdir -p "$STIG_VIEWER_APP/Contents/MacOS"
    mkdir -p "$STIG_VIEWER_APP/Contents/Resources"
    cat <<EOF > "$STIG_VIEWER_APP/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>java</string>
    <key>CFBundleIdentifier</key>
    <string>com.stig.viewer</string>
    <key>CFBundleName</key>
    <string>STIG Viewer</string>
    <key>CFBundleVersion</key>
    <string>2.18</string>
    <key>CFBundleIconFile</key>
    <string>STIGViewerIcon</string>
    <key>CFBundleTypeName</key>
    <string>Java Application</string>
    <key>CFBundleTypeRole</key>
    <string>Viewer</string>
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeName</key>
            <string>Java Application</string>
            <key>CFBundleTypeRole</key>
            <string>Viewer</string>
            <key>LSItemContentTypes</key>
            <array>
                <string>public.data</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
EOF

    # Create an executable script inside the app bundle
    echo '#!/bin/bash' > "$STIG_VIEWER_APP/Contents/MacOS/java"
    echo "exec java -jar \"$STIG_VIEWER_JAR\"" >> "$STIG_VIEWER_APP/Contents/MacOS/java"
    chmod +x "$STIG_VIEWER_APP/Contents/MacOS/java"

    # Copy the system icon to the application bundle
    echo "Copying system icon..."
    cp "$SYSTEM_ICON" "$STIG_VIEWER_APP/Contents/Resources/STIGViewerIcon.icns"

    # Clean up
    echo "Cleaning up..."
    rm -rf "$TEMP_DIR"

    echo "STIG Viewer installation complete!"
}

# Function to uninstall JDK and STIG Viewer
uninstall_jdk() {
    echo "Uninstalling JDK and STIG Viewer..."

    # Find and remove JDK installations that start with liberica-jdk
    for JDK_DIR in /Library/Java/JavaVirtualMachines/liberica-jdk*.jdk; do
        if [ -d "$JDK_DIR" ]; then
            echo "Removing $JDK_DIR..."
            rm -rf "$JDK_DIR"
        fi
    done

    # Remove JAVA_HOME and PATH from the user's profile files
    echo "Removing environment variables for user: $CURRENT_USER..."
    for PROFILE in "$CURRENT_USER_HOME/.zshrc" "$CURRENT_USER_HOME/.bash_profile"; do
        if [ -f "$PROFILE" ]; then
            sed -i '' '/JAVA_HOME/d' "$PROFILE"
            sed -i '' '/PATH.*JAVA_HOME/d' "$PROFILE"
        fi
    done

    # Remove STIG Viewer
    echo "Removing STIG Viewer..."
    rm -rf "$STIG_VIEWER_DIR"

    echo "Uninstallation complete!"
}

# Main script logic - uses ACTION variable set earlier (supports both Jamf and CLI)
echo "Running with action: $ACTION"
echo "Current user detected: $CURRENT_USER"
echo "User home directory: $CURRENT_USER_HOME"

case "$ACTION" in
    install)
        install_jdk
        install_stig_viewer
        ;;
    uninstall)
        uninstall_jdk
        ;;
    *)
        echo "Invalid action: $ACTION"
        usage
        ;;
esac

exit 0
