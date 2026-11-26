@echo off
rem Builds DFX.exe with PyInstaller (pip install pyinstaller first).
rem The vendored modules are both data (for the SHA-256 check in "doctor") and
rem analyzed imports (--hidden-import), so their stdlib needs (bz2, lzma...) are bundled.
cd /d "%~dp0"
python -m PyInstaller --noconfirm --onefile --name DFX --console ^
  --add-data "dfx\web;dfx\web" --add-data "dfx\carve\signatures;dfx\carve\signatures" ^
  --add-data "dfx\vendor;dfx\vendor" ^
  --paths "dfx\vendor" --hidden-import ewfprobe --hidden-import mediacarve ^
  --add-data "VERSION;." dfx_launcher.py
