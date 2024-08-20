#!/bin/sh
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
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 08/20/24 - Original
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

# Function to display usage
usage() {
    echo "Usage: $0 [install|uninstall]"
    echo "  install   Install the JDK and STIG Viewer"
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
    sudo installer -pkg "$TEMP_DIR/$JDK_PKG" -target /

    # Clean up
    echo "Cleaning up..."
    rm -rf "$TEMP_DIR"

    # Set JAVA_HOME and PATH
    echo "Setting up environment variables..."

    # Determine the shell and update the appropriate profile
    if [ -n "$ZSH_VERSION" ]; then
        PROFILE="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ]; then
        PROFILE="$HOME/.bash_profile"
    else
        echo "Unsupported shell. Please set JAVA_HOME and PATH manually."
        exit 1
    fi

    # Set JAVA_HOME and PATH
    JAVA_HOME=$(/usr/libexec/java_home)
    echo "export JAVA_HOME=\"$JAVA_HOME\"" >> "$PROFILE"
    echo "export PATH=\"\$JAVA_HOME/bin:\$PATH\"" >> "$PROFILE"

    # Source the updated profile
    echo "Sourcing the updated profile..."
    source "$PROFILE"

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
    sudo mkdir -p "$STIG_VIEWER_DIR"

    # Extract the ZIP file
    echo "Extracting STIG Viewer..."
    sudo unzip -q "$TEMP_DIR/$STIG_VIEWER_ZIP" -d "$STIG_VIEWER_DIR"

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
    sudo cp "$SYSTEM_ICON" "$STIG_VIEWER_APP/Contents/Resources/STIGViewerIcon.icns"

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
            sudo rm -rf "$JDK_DIR"
        fi
    done

    # Remove JAVA_HOME and PATH from the profile
    if [ -n "$ZSH_VERSION" ]; then
        PROFILE="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ]; then
        PROFILE="$HOME/.bash_profile"
    else
        echo "Unsupported shell. Please remove JAVA_HOME and PATH manually."
        exit 1
    fi

    # Remove JAVA_HOME and PATH settings
    sed -i '' '/JAVA_HOME/d' "$PROFILE"
    sed -i '' '/PATH.*JAVA_HOME/d' "$PROFILE"

    # Remove STIG Viewer
    echo "Removing STIG Viewer..."
    sudo rm -rf "$STIG_VIEWER_DIR"

    # Source the updated profile
    echo "Sourcing the updated profile..."
    source "$PROFILE"

    echo "Uninstallation complete!"
}

# Function to prompt user for action
prompt_user() {
    echo "Do you want to install or uninstall the JDK and STIG Viewer?"
    echo "1) Install"
    echo "2) Uninstall"
    read -p "Please enter your choice (1 or 2): " choice
    case $choice in
        1)
            install_jdk
            install_stig_viewer
            ;;
        2)
            uninstall_jdk
            ;;
        *)
            echo "Invalid choice."
            usage
            ;;
    esac
}

# Main script logic
if [ "$#" -eq 1 ]; then
    case "$1" in
        install)
            install_jdk
            install_stig_viewer
            ;;
        uninstall)
            uninstall_jdk
            ;;
        *)
            usage
            ;;
    esac
elif [ "$#" -eq 0 ]; then
    prompt_user
else
    usage
fi
