@echo off
REM ══════════════════════════════════════════════════════════════════════════════
REM  AI-Wireshark Analyzer — Windows Build Script
REM  
REM  This script builds the standalone .exe and (optionally) the installer.
REM  
REM  Prerequisites:
REM    1. Python 3.10+ with pip
REM    2. Virtual environment activated (or dependencies installed globally)
REM    3. Inno Setup 6+ installed (for installer step)
REM       Download: https://jrsoftware.org/isdl.php
REM  
REM  Usage:
REM    build_installer.bat           — Build .exe only
REM    build_installer.bat full      — Build .exe + Windows installer
REM    build_installer.bat clean     — Remove build artifacts
REM ══════════════════════════════════════════════════════════════════════════════

setlocal enabledelayedexpansion
cd /d "%~dp0\.."

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║   AI-Wireshark Analyzer — Build System                  ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

REM ── Step 0: Check Python ──
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+ and add to PATH.
    exit /b 1
)
echo [OK] Python found: 
python --version

REM ── Step 1: Install/verify build dependencies ──
echo.
echo [1/4] Checking build dependencies...
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo      Installing PyInstaller...
    pip install pyinstaller
)
echo [OK] PyInstaller ready

REM ── Step 2: Clean previous builds ──
if "%1"=="clean" (
    echo [CLEAN] Removing build artifacts...
    rmdir /s /q dist 2>nul
    rmdir /s /q build 2>nul
    del /q *.spec 2>nul
    rmdir /s /q installer\output 2>nul
    echo [OK] Clean complete.
    exit /b 0
)

echo.
echo [2/4] Building standalone executable with PyInstaller...
echo      This may take 3-5 minutes on first build...
echo.

pyinstaller installer\ai_wireshark.spec --noconfirm --clean

if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build failed. Check errors above.
    exit /b 1
)

echo.
echo [OK] Executable built successfully!
echo     Location: dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe
echo.

REM ── Step 3: Verify the build ──
echo [3/4] Verifying build...
if not exist "dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe" (
    echo [ERROR] Executable not found at expected location.
    exit /b 1
)

REM Get size
for %%A in ("dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe") do (
    set "SIZE=%%~zA"
)
echo [OK] Executable size: %SIZE% bytes
echo.

REM ── Step 4: Build Windows Installer (optional) ──
if /i "%1"=="full" (
    echo [4/4] Building Windows Installer with Inno Setup...
    
    REM Try common Inno Setup locations
    set "ISCC="
    if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
        set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    )
    if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
        set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
    )
    
    if "!ISCC!"=="" (
        echo [WARNING] Inno Setup not found.
        echo          Install from: https://jrsoftware.org/isdl.php
        echo          Then run: "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\setup.iss
        echo.
        echo [PARTIAL] .exe built successfully but installer was skipped.
        exit /b 0
    )
    
    "!ISCC!" installer\setup.iss
    
    if errorlevel 1 (
        echo [ERROR] Inno Setup compilation failed.
        exit /b 1
    )
    
    echo.
    echo [OK] Windows Installer built successfully!
    echo     Location: installer\output\AI-Wireshark-Analyzer-Setup-x64.exe
) else (
    echo [4/4] Skipping installer build. Run with "full" argument to build installer:
    echo       build_installer.bat full
)

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║   BUILD COMPLETE                                        ║
echo  ╠══════════════════════════════════════════════════════════╣
echo  ║   .exe: dist\AI-Wireshark-Analyzer\                    ║
if /i "%1"=="full" (
echo  ║   Installer: installer\output\*-Setup-x64.exe          ║
)
echo  ╚══════════════════════════════════════════════════════════╝
echo.

exit /b 0
