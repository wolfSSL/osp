@echo off
setlocal enabledelayedexpansion

:: Initialize counters
set "successCount=0"
set "failureCount=0"

:: Root directory to search for .vcxproj files
set "rootDir=%cd%"

echo Searching for .vcxproj files in: %rootDir%
echo.

:: Loop through all .vcxproj files in the directory tree
del failure_list.log
for /R "%rootDir%" %%f in (*.vcxproj) do (
    echo Building: %%f
    call :run_command "msbuild %%f /t:Build /p:Configuration=Debug /p:Platform=x64 /p:WOLFSSL_ROOT=%rootDir%\..\..\..\wolfssl "
    if !errorlevel! neq 0 (
        echo FAILED: %%f
        echo FAILED: %%f >> failure_list.log
        set /a failureCount+=1
    ) else (
        echo SUCCEEDED: %%f
        set /a successCount+=1
    )
    echo.
)

:: Display summary
echo ========================================
echo Summary:
echo Total projects: %successCount% successful, %failureCount% failed.
echo ========================================

exit /b

:: Function to run a command
:run_command
    set "cmd=%~1"
    %cmd%
    exit /b %errorlevel%
