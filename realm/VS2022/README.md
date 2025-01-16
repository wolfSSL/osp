# wolfSSL Realm Visual Studio

This VS2022 directory is for building Realm with wolfSSL support in Visual Studio 2022.

The main solution file is named `RealmCore.sln`.

Ensure `#pragma comment(lib, "Ws2_32.lib")` exists in the `user_settings.h` This
is required to ensure the lrquired library is linked, Otherwise errors like this will be encountered:

```
Error	LNK2019	unresolved external symbol __imp_closesocket referenced in function wolfSSL_BIO_free	Realm2JSON	[wolfssl/osp]\realm\VS2022\src\realm\exec\wolfssl.lib(ssl.obj)	1
Error	LNK2001	unresolved external symbol __imp_htons	Realm2JSON
...etc
```

This is a typical section in the `user_settings.h`:

```
/* Verify this is Windows */
#ifdef _WIN32
    #ifdef WOLFSSL_VERBOSE_MSBUILD
        #pragma message("include Ws2_32")
    #endif
    /* Microsoft-specific pragma to link Ws2_32.lib */
    #pragma comment(lib, "Ws2_32.lib")
#else
    #error This user_settings.h header is only designed for Windows
#endif

#ifdef WOLFSSL_VERBOSE_MSBUILD
    /* See the wolfssl-GlobalProperties.props for build verbosity setting */
    #pragma message("Confirmed using realm/VS2022/include/user_settings.h")
#endif
```

The enclosed project files use cmake. See the [Microsoft CMake projects in Visual Studio](https://learn.microsoft.com/en-us/cpp/build/cmake-projects-in-visual-studio?view=msvc-170).

## Sample Build

Create a directory called `C:\test` and put this text in a batch file called `osp_test.bat`:

```DOS
:: set THIS_CLONE_DEPTH=--depth 1
set THIS_CLONE_DEPTH=
set THIS_GIT_CONFIG=--config core.fileMode=false
set REALM_CORE_COMMIT="a5e87a39"
set THIS_WOLFSSL_VERSION="v5.7.6-stable"
set THIS_OSP_BRANCH="pr-realm-vs2022"
set USE_REALM_CORE_DEV=1

:: Ensure %ERRORLEVEL% inside if/elsee blocks not evaulated too early
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
git clone %THIS_GIT_CONFIG% --branch %THIS_WOLFSSL_VERSION% https://github.com/wolfssl/wolfssl.git %THIS_CLONE_DEPTH%
if %ERRORLEVEL% neq 0 goto ERROR

:: # wolfSSL OSP branch pr-realm-vs2022 from gojimmypi fork
git clone %THIS_GIT_CONFIG% --branch %THIS_OSP_BRANCH% https://github.com/gojimmypi/osp.git %THIS_CLONE_DEPTH%
if %ERRORLEVEL% neq 0 goto ERROR

cd osp

:: git checkout dev
:: # git submodule update --init --recursive

:: # realm-core is part of wolfssl osp/realm
cd realm

if "%USE_REALM_CORE_DEV%"=="1" (
    git clone %THIS_GIT_CONFIG% --branch dev https://github.com/gojimmypi/realm-core.git %THIS_CLONE_DEPTH%
    if !ERRORLEVEL! neq 0 goto ERROR

    cd realm-core

    git submodule update --init --recursive
    if !ERRORLEVEL! neq 0 goto ERROR
) else (
    git clone %THIS_GIT_CONFIG% https://github.com/realm/realm-core.git
    if !ERRORLEVEL! neq 0 goto ERROR

    cd realm-core

    git checkout %REALM_CORE_COMMIT%
    if !ERRORLEVEL! neq 0 goto ERROR

    git apply ../realm-commit-a5e87a39.patch
    if !ERRORLEVEL! neq 0 goto ERROR
    echo "Patch applied"

    git submodule update --init --recursive
    if !ERRORLEVEL! neq 0 goto ERROR
)

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
```
