@echo off
REM SecureConnect VPN Client for Windows
REM This batch script provides basic VPN connection functionality for Windows clients

setlocal enabledelayedexpansion

REM Configuration
set "VPN_SERVER=your-vpn-server.com"
set "CONFIG_DIR=%USERPROFILE%\.secureconnect"
set "LOG_FILE=%CONFIG_DIR%\client.log"

REM Create configuration directory
if not exist "%CONFIG_DIR%" (
    mkdir "%CONFIG_DIR%"
    echo Created configuration directory: %CONFIG_DIR%
)

REM Function to log messages
:log
echo %date% %time% - %~1 >> "%LOG_FILE%"
echo %~1
goto :eof

REM Function to get user input securely
:get_credentials
set /p VPN_USER="Enter your VPN username: "
if "%VPN_USER%"=="" (
    echo Error: Username cannot be empty
    exit /b 1
)

REM Note: For production, consider using a more secure method for password input
set /p VPN_PASSWORD="Enter your password: "
if "%VPN_PASSWORD%"=="" (
    echo Error: Password cannot be empty
    exit /b 1
)

set /p OTP_CODE="Enter your 6-digit OTP code: "
if "%OTP_CODE%"=="" (
    echo Error: OTP code cannot be empty
    exit /b 1
)
goto :eof

REM Function to authenticate with OTP server
:authenticate_otp
echo Authenticating with OTP server...

REM Create temporary JSON file for authentication
set "AUTH_FILE=%TEMP%\secureconnect_auth.json"
echo { > "%AUTH_FILE%"
echo   "username": "%VPN_USER%", >> "%AUTH_FILE%"
echo   "password": "%VPN_PASSWORD%", >> "%AUTH_FILE%"
echo   "otp_code": "%OTP_CODE%" >> "%AUTH_FILE%"
echo } >> "%AUTH_FILE%"

REM Use curl to authenticate (requires curl to be installed)
curl -s -X POST -H "Content-Type: application/json" -d @"%AUTH_FILE%" "http://%VPN_SERVER%:5000/api/authenticate" > "%TEMP%\auth_response.json" 2>nul

if errorlevel 1 (
    echo Error: Failed to connect to authentication server
    del "%AUTH_FILE%" 2>nul
    exit /b 1
)

REM Check if authentication was successful (basic check)
findstr /C:"success.*true" "%TEMP%\auth_response.json" >nul
if errorlevel 1 (
    echo Error: Authentication failed
    type "%TEMP%\auth_response.json"
    del "%AUTH_FILE%" 2>nul
    del "%TEMP%\auth_response.json" 2>nul
    exit /b 1
)

echo Authentication successful!
del "%AUTH_FILE%" 2>nul
del "%TEMP%\auth_response.json" 2>nul
goto :eof

REM Function to create VPN connection (Windows built-in VPN)
:create_vpn_connection
echo Creating VPN connection...

REM Remove existing connection if it exists
rasphone -h "SecureConnect" 2>nul

REM Create new VPN connection
rasdial "SecureConnect" /disconnect 2>nul

REM Note: For IKEv2, you might need to use PowerShell commands
REM This is a simplified version using built-in Windows VPN

powershell -Command "& {
    try {
        Remove-VpnConnection -Name 'SecureConnect' -Force -ErrorAction SilentlyContinue
        Add-VpnConnection -Name 'SecureConnect' -ServerAddress '%VPN_SERVER%' -TunnelType 'IKEv2' -AuthenticationMethod 'MSChapv2' -EncryptionLevel 'Maximum'
        Write-Host 'VPN connection created successfully'
    } catch {
        Write-Host 'Error creating VPN connection:' $_.Exception.Message
        exit 1
    }
}"

if errorlevel 1 (
    echo Error: Failed to create VPN connection
    exit /b 1
)
goto :eof

REM Function to connect to VPN
:connect_vpn
echo Connecting to VPN...

REM Connect using rasdial
rasdial "SecureConnect" "%VPN_USER%" "%VPN_PASSWORD%"

if errorlevel 1 (
    echo Error: Failed to connect to VPN
    exit /b 1
)

echo VPN connection established successfully!

REM Test connectivity
ping -n 3 8.8.8.8 >nul
if errorlevel 1 (
    echo Warning: Internet connectivity test failed
) else (
    echo Internet connectivity confirmed
)
goto :eof

REM Function to disconnect VPN
:disconnect_vpn
echo Disconnecting VPN...
rasdial "SecureConnect" /disconnect
echo VPN disconnected
goto :eof

REM Function to show connection status
:show_status
echo Checking VPN status...
rasdial | findstr "SecureConnect"
if errorlevel 1 (
    echo VPN is not connected
) else (
    echo VPN is connected
    REM Show IP configuration
    ipconfig | findstr /C:"PPP adapter" /A:5
)
goto :eof

REM Function to show help
:show_help
echo SecureConnect VPN Client for Windows
echo.
echo Usage: %~nx0 [command]
echo.
echo Commands:
echo   connect     Connect to VPN (default)
echo   disconnect  Disconnect from VPN
echo   status      Show connection status
echo   help        Show this help message
echo.
echo Requirements:
echo   - Windows 10/11
echo   - curl.exe (included in Windows 10 1803+)
echo   - Administrative privileges may be required
echo.
echo Note: For advanced IPSec configuration, consider using
echo       third-party clients like strongSwan for Windows
goto :eof

REM Main script logic
if "%~1"=="" goto :connect
if /i "%~1"=="connect" goto :connect
if /i "%~1"=="disconnect" goto :disconnect
if /i "%~1"=="status" goto :status
if /i "%~1"=="help" goto :help
if "%~1"=="-h" goto :help
if "%~1"=="--help" goto :help

echo Unknown command: %~1
echo Use 'help' for usage information.
exit /b 1

:connect
call :log "Starting SecureConnect VPN client"
call :get_credentials
if errorlevel 1 exit /b 1
call :authenticate_otp
if errorlevel 1 exit /b 1
call :create_vpn_connection
if errorlevel 1 exit /b 1
call :connect_vpn
goto :end

:disconnect
call :disconnect_vpn
goto :end

:status
call :show_status
goto :end

:help
call :show_help
goto :end

:end
pause
