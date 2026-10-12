#!/usr/bin/env bash
set -e

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$APP_DIR/dist/packet-monitor-gui"

if [ ! -f "$BIN_PATH" ]; then
    echo "Compiled binary not found. Running build.sh first..."
    "$APP_DIR/build.sh"
fi

DESKTOP_FILE="$HOME/.local/share/applications/packet-monitor.desktop"
mkdir -p "$HOME/.local/share/applications"

cat << DESKTOP > "$DESKTOP_FILE"
[Desktop Entry]
Version=1.0
Type=Application
Name=Packet Monitor
GenericName=Network Packet Analyzer
Comment=Lightweight packet sniffer and Ethernet frame analyzer
Exec=$BIN_PATH
Icon=utilities-system-monitor
Terminal=false
Categories=Network;Security;Development;
Keywords=packet;network;sniffer;wireshark;scapy;capture;
DESKTOP

chmod +x "$DESKTOP_FILE"
echo "Successfully installed desktop launcher to $DESKTOP_FILE"
echo "You can now find and launch 'Packet Monitor' from your system application menu!"
