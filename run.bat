@echo off

echo ======================================
echo   VaultIQ - Self-Healing Post-Quantum File Vault
echo ======================================
echo.

cd /d "%~dp0"

echo Compiling Java server and vault...
javac backend\Server.java backend\VaultService.java

if errorlevel 1 (
    echo.
    echo Compilation failed.
    pause
    exit /b
)

echo.
echo Compilation successful.
echo.
echo Starting server...
echo Open the local URL printed by the server above.
echo.
echo Press Ctrl+C to stop the server.
echo.

java -cp backend Server

pause
