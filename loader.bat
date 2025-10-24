@echo off
REM
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    REM
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe' -OutFile '$env:TEMP\python-installer.exe'; Start-Process -FilePath '$env:TEMP\python-installer.exe' -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; Remove-Item '$env:TEMP\python-installer.exe'"
)

REM
python bootstrapper.py
pause

