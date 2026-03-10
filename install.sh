#!/usr/bin/env bash
# install.sh — Install StackSentry CLI
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="stacksentry"

echo ""
echo "  StackSentry Installer"
echo "  ====================="
echo ""

# Check if running with sufficient permissions
if [[ ! -w "$INSTALL_DIR" ]]; then
    echo "  [!] Need write access to ${INSTALL_DIR}"
    echo "  Run: sudo bash install.sh"
    echo ""
    exit 1
fi

# Verify the entrypoint exists
if [[ ! -f "${SCRIPT_DIR}/bin/stacksentry" ]]; then
    echo "  [!] bin/stacksentry not found. Run from the project root."
    exit 1
fi

# Make executable
chmod +x "${SCRIPT_DIR}/bin/stacksentry"

# Create symlink
if [[ -L "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
    echo "  Removing existing symlink..."
    rm "${INSTALL_DIR}/${BINARY_NAME}"
fi

ln -s "${SCRIPT_DIR}/bin/stacksentry" "${INSTALL_DIR}/${BINARY_NAME}"

echo "  [OK] Installed: ${INSTALL_DIR}/${BINARY_NAME} -> ${SCRIPT_DIR}/bin/stacksentry"
echo ""

# Run doctor to verify
echo "  Running dependency check..."
echo ""
"${SCRIPT_DIR}/bin/stacksentry" doctor

echo ""
echo "  Installation complete! Run: stacksentry --help"
echo ""
