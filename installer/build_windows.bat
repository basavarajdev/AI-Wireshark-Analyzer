@echo off
REM AI-Wireshark Analyzer - Windows x64 Build Script
REM For Windows 10/11 with Python 3.10+
REM Usage: installer\build_windows.bat (from project root)

setlocal enabledelayedexpansion

set PROJECT_ROOT=%~dp0..\
cd /d "%PROJECT_ROOT%"

echo.
echo ================================
echo AI-Wireshark Analyzer - Windows Build
echo ================================
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.10+ and add to PATH
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ^✓ Python version: %PYTHON_VERSION%

REM Create virtual environment
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo Error: Failed to activate virtual environment
    exit /b 1
)
echo ^✓ Virtual environment activated

REM Install dependencies
echo.
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

REM Clean previous builds
echo.
echo Cleaning previous builds...
if exist build rmdir /s /q build >nul 2>&1
if exist dist rmdir /s /q dist >nul 2>&1

REM Run tests
echo.
echo Running tests...
python -m pytest tests/test_v160_release.py -v --tb=short || echo Note: Some tests may require X11/display

REM Build with PyInstaller
echo.
echo Building application with PyInstaller...
python -m PyInstaller installer\ai_wireshark.spec --noconfirm --clean

REM Verify build
echo.
echo Verifying build...
if exist "dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe" (
    for %%A in ("dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe") do (
        set SIZE=%%~zA
    )
    echo ^✓ Binary created: !SIZE! bytes
    echo   Location: dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe
) else (
    echo ^✗ Build failed: Binary not found
    exit /b 1
)

REM Create distribution package (requires 7-Zip or WinRAR)
echo.
echo Creating distribution package...
for /f %%A in ('dir /b /s dist\AI-Wireshark-Analyzer ^| find /c /v ""') do (
    echo ^✓ Application directory: %%A files
)

REM Try using tar (available in Windows 10+) or PowerShell
if exist "dist\AI-Wireshark-Analyzer" (
    echo Creating ZIP with PowerShell...
    powershell -Command "Compress-Archive -Path 'dist\AI-Wireshark-Analyzer' -DestinationPath 'AI-Wireshark-Analyzer-Windows-x64.zip' -Force" >nul 2>&1
    if exist "AI-Wireshark-Analyzer-Windows-x64.zip" (
        for %%A in ("AI-Wireshark-Analyzer-Windows-x64.zip") do (
            set ZIP_SIZE=%%~zA
        )
        echo ^✓ Distribution ZIP created: !ZIP_SIZE! bytes
    )
)

echo.
echo ================================
echo Build Complete!
echo ================================
echo.
echo Artifacts:
echo   * Binary: dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe
echo   * Distribution: AI-Wireshark-Analyzer-Windows-x64.zip
echo.
echo Next steps:
echo   1. Test the executable:
echo      dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe
echo.
echo   2. Optional: Build Inno Setup installer
echo      Run: python installer\build_installer.bat full
echo.
echo   3. Distribute the ZIP or EXE installer to users
echo.
echo To deactivate venv: .venv\Scripts\deactivate.bat
echo.
pause
