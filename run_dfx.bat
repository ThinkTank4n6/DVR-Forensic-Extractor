@echo off
rem Starts DVR Forensic Extractor. Right-click > Run as administrator to read physical drives.
cd /d "%~dp0"
python -m dfx gui
if errorlevel 1 pause
