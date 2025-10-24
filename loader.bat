@echo off
setlocal

REM FALSE DETECTED BY ANTI VIRUSES!

python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo [Launcher] Python not found.

    choice /M "Do you want to download and install Python now?"
    IF ERRORLEVEL 2 (
        echo [Launcher] Installation canceled by user.
        pause
        exit /B
    )

    echo [Launcher] Downloading & installing Python...

    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe' -OutFile '$env:TEMP\python-installer.exe'"

    powershell -Command "Start-Process -FilePath '$env:TEMP\python-installer.exe' -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait"

    powershell -Command "Remove-Item '$env:TEMP\python-installer.exe'"

    echo [Launcher] Python installed.
) ELSE (
    echo [Launcher] Python detected.
)

echo [Launcher] Running bootstrapper...
python bootstrapper.py

pause

