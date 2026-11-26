@echo off
rem Builds DFX.exe with PyInstaller (pip install pyinstaller first).
cd /d "%~dp0"
python -m PyInstaller --noconfirm --onefile --name DFX --console ^
  --add-data "dfx\web;dfx\web" --add-data "dfx\carve\signatures;dfx\carve\signatures" ^
  --add-data "VERSION;." dfx_launcher.py
