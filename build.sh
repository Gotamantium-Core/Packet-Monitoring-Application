#!/usr/bin/env bash
set -e

echo "=== Building Packet Monitor Standalone Executable ==="
python3 -m pip install -q pyinstaller PyQt6 scapy

pyinstaller --onefile \
    --name "packet-monitor-gui" \
    --clean \
    gui.py

echo "Build complete! Executable located at: dist/packet-monitor-gui"
