@echo off
echo === Building Packet Monitor Standalone Executable for Windows ===
python -m pip install -q pyinstaller PyQt6 scapy
pyinstaller --onefile --noconsole --name "packet-monitor-gui" --clean gui.py
echo Build complete! Executable located at: dist\packet-monitor-gui.exe
pause
