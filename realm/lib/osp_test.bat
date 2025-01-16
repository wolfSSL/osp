:: set USE_REALM_CORE_DEV for gojimmypi dev branch, otherwise realm/realm-core with patch applied
set USE_REALM_CORE_DEV=1

:: set THIS_CLONE_DEPTH=--depth 1
set THIS_CLONE_DEPTH=
set THIS_GIT_CONFIG=--config core.fileMode=false
SET THIS_WOLFSSL_CLONE_DEPTH=--depth 1

:: Choose wolfSSL Version:
set THIS_WOLFSSL_VERSION="v5.7.6-stable"

:: Original development was for the a5e8 for realm-core v13.26.0 release on 1/22/2024
:: set REALM_CORE_COMMIT="a5e87a39"

:: We can use the same patch file, and instead apply it to the 5533 commit from 1/29/2024
set REALM_CORE_COMMIT="5533505d1"

:: Reference the PR branch or dev branch:
set THIS_OSP_BRANCH="pr-realm-vs2022"

if "%USE_REALM_CORE_DEV%"=="1" set THIS_OSP_BRANCH="dev"

:: Ensure %ERRORLEVEL% inside if/else blocks not evaluated too early
SETLOCAL EnableDelayedExpansion

if "%VSCMD_VER%"=="" (
    echo This script must be run from a Visual Studio Developer Command Prompt.
    exit /b 1
)

if exist ".\osp"     echo "osp exists, remove to proceed." && exit /b 1
if exist ".\wolfssl" echo "wolfssl exists,remove to proceed." && exit /b 1

set THIS_PATH=%cd%
echo Setting up wolfSSL OSP Realm for Visual Studio in %THIS_PATH% 

:: # wolfSSL
git clone %THIS_GIT_CONFIG% --branch %THIS_WOLFSSL_VERSION% https://github.com/wolfssl/wolfssl.git %THIS_WOLFSSL_CLONE_DEPTH%
if %ERRORLEVEL% neq 0 goto ERROR

:: # wolfSSL OSP branch pr-realm-vs2022 from gojimmypi fork
git clone %THIS_GIT_CONFIG% --branch %THIS_OSP_BRANCH% https://github.com/gojimmypi/osp.git %THIS_CLONE_DEPTH%
if %ERRORLEVEL% neq 0 goto ERROR

cd osp

:: git checkout dev
:: # git submodule update --init --recursive

:: # realm-core is part of wolfssl osp/realm
cd realm

echo "Checking if using gojimmypi DEV branch."
if "%USE_REALM_CORE_DEV%"=="0" goto REALM_FETCH

:REALM_DEV_FETCH
    git clone %THIS_GIT_CONFIG% --branch dev https://github.com/gojimmypi/realm-core.git %THIS_CLONE_DEPTH%
    if !ERRORLEVEL! neq 0 goto ERROR

    cd realm-core

    git submodule update --init --recursive
    if !ERRORLEVEL! neq 0 goto ERROR
    goto REALM_FETCH_DONE

:REALM_FETCH
    :: Note the desired commit is so old, we can't do a shallow clone
    git clone %THIS_GIT_CONFIG% https://github.com/realm/realm-core.git
    if !ERRORLEVEL! neq 0 goto ERROR

    cd realm-core

    echo "Checking out REALM_CORE_COMMIT=%REALM_CORE_COMMIT%"
    git checkout %REALM_CORE_COMMIT%
    if !ERRORLEVEL! neq 0 goto ERROR

    git apply ../realm-commit-a5e87a39.patch
    if !ERRORLEVEL! neq 0 goto ERROR
    echo "Patch applied to commit %REALM_CORE_COMMIT%"

    :: If later calling the build_wolfssl_with_realm.sh bash script, create semaphore file that patch was applied:
    echo "Patch Applied to %REALM_CORE_COMMIT% from DOS Batch file" > REALM_CORE_COMMIT_COMPLETE.log

    git submodule update --init --recursive
    if !ERRORLEVEL! neq 0 goto ERROR

:REALM_FETCH_DONE

cd ..\..\..\

:: Set wolfSSL config (instead of ./configure --options...)
copy %THIS_PATH%\osp\realm\lib\options.h %THIS_PATH%\wolfssl\wolfssl\options.h

:: # Do not use quotes in path here:
set  WOLFSSL_ROOT=%THIS_PATH%\wolfssl

:: # Quotes are required here:
setx WOLFSSL_ROOT "%WOLFSSL_ROOT%"

echo See %THIS_PATH%\osp\realm\VS2022 for WOLFSSL_ROOT to %THIS_PATH%\wolfssl

:: start Visual Studio from a fresh shell that contains a new WOLFSSL_ROOT value
start "wolfSSL Realm" /wait cmd /c "@echo 'WOLFSSL_ROOT=%WOLFSSL_ROOT%' && devenv %THIS_PATH%\osp\realm\VS2022\RealmCore.sln"
goto DONE


:ERROR
echo Error: !ERRORLEVEL!


:DONE
