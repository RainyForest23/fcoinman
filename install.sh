#!/usr/bin/env bash
# fcoinman — Linux server compromise detector
# Install script: detects architecture, downloads binary from GitHub Releases
set -euo pipefail

REPO="RainyForest23/fcoinman"
BINARY="fcoinman"
INSTALL_DIR="/usr/local/bin"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo ""
echo "  fcoinman — Linux server compromise detector"
echo "  https://github.com/${REPO}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Run with sudo for full functionality: sudo bash install.sh${NC}"
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    armv7l)  TARGET="armv7-unknown-linux-musleabihf" ;;
    *)
        echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

# Get latest release tag
echo "[*] Fetching latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo -e "${RED}[!] Could not determine latest release. Check your internet connection.${NC}"
    exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}-${TARGET}"
echo "[*] Downloading ${BINARY} ${LATEST} (${TARGET})..."

curl -fsSL "$URL" -o "/tmp/${BINARY}"
chmod +x "/tmp/${BINARY}"

install -m 755 "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
rm -f "/tmp/${BINARY}"

echo ""
echo -e "${GREEN}[✓] Installed to ${INSTALL_DIR}/${BINARY}${NC}"
echo ""
echo "  Usage:"
echo "    sudo fcoinman scan          # Full compromise scan"
echo "    sudo fcoinman logs          # Attack timeline from auth.log"
echo "    fcoinman analyze /usr/bin/socket  # Analyze a specific binary"
echo "    fcoinman check-ip 1.2.3.4   # Check if IP is a known mining pool"
echo ""
