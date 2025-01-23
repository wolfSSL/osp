# REALM with wolfSSL

The wolfSSL library is enabled in [realm-core](https://github.com/realm/realm-core) with the `-DREALM_HAVE_WOLFSSL=1` parameter.

The upstream `realm-core` does NOT yet support wolfSSL. Please see the enclosed `realm-commit-[hash].patch files`.

The Linux Script Build automatically applies these patches as needed. Modify as desired with the `REALM_CORE_COMMIT` script variable.

## Linux Script Build

The [build_wolfssl_with_realm.sh](./build_wolfssl_with_realm.sh) script can be used.

### Script Parameters:

* `-t` use tarball, not git
* `-u` use $USER name suffix for repository

### Notes

Defaults are to clone [wolfSSL](https://github.com/wolfSSL/wolfssl) and [realm-core](https://github.com/realm/realm-core) to local directory.

If you have forks of each with your GitHub ID the same as your local user name, the `-u` is recommended.

Run directly from the `realm` directory:

```bash
./build_wolfssl_with_realm.sh -u
```

This will create these local directories, and add respective `upstream` repository settings:

```text
./wolfssl-<your username>
./realm-core-<your username>
```

Once the desired wolfSSL library has been fetched and installed, the clone / config / build can be skipped by making these changes in the script file:

```
# Choose to skip parts of wolfSSL build:
FETCH_WOLFSSL=false
CONFIGURE_WOLFSSL=false
BUILD_WOLFSSL=false
INSTALL_WOLFSSL=false
```

Example:

```bash
cmake -B build -DREALM_INCLUDE_CERTS=1 -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_HAVE_WOLFSSL=1 -DREALM_WOLFSSL_ROOT_DIR=/home/gojimmypi/wolfssl-install-dir
```

## Linux manual build: Build wolfSSL

These commands are wrapped in the `build_wolfssl_with_realm.sh` script, mentioned above:

To configure wolfSSL, use the following command:

```
./configure --enable-static --enable-opensslall --enable-enckeys --enable-certgen --enable-context-extra-user-data
sudo make install
```

Configuring wolfSSL for local installation can be specified with `--prefix=/path/to/install`

Downloading and applying the patch for realm-core git commit a5e87a39:

```
git clone https://github.com/realm/realm-core.git
cd realm-core
git reset --hard HEAD
git checkout a5e87a39
git submodule update --init --recursive
git apply ../realm-v13.26.0.patch
```

Building realm-core:

```
mkdir build
cmake -B build -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_HAVE_WOLFSSL=1 -DREALM_WOLFSSL_ROOT_DIR=/usr/local/lib
cmake --build build
./build/test/realm-tests
```

You can also use the `build_wolfssl_with_realm.sh [-u]` script after adjusting the global variables as needed.

## Visual Studio

To fetch files for a Visual Studio build:

```
#!/bin/bash

# wolfSSL OSP
git clone https://github.com/gojimmypi/osp.git
cd osp
git checkout dev
git submodule update --init --recursive

# realm-core is part of wolfssl osp/realm
cd realm
git clone https://github.com/gojimmypi/realm-core.git

# If not cloned to osp/realm/realm-core,
# Edit REALM_DIR_TEMP and REALM_CORE_ROOT values in
#   [workspace]/osp/realm/VS2022/realm-core-GlobalProperties.props

cd realm-core
git checkout dev
git submodule update --init --recursive
```

The main Ream-Core solution file is located in `VS2022\RealmCore.sln`.

There's also a stand-alone wolfSSH solution that contains only the wolfSSL project in `VS2022\wolfssl-VS2022-cmake.sln`

The platform and machine independent settings such as `$(CurrentVsInstallRoot)` will likely be reset to fully-qualified paths at build time.

See the `vs_clean.sh` to reset variables such as Visual Studio Edition paths to `$(CurrentVsInstallRoot)`.

If no other changes have made, the project `*.vcxproj` changes can also be reverted. Builds should be successful with either full paths or VS macros.

The project files assume there are already source code directories available. For instance:

```
cd \workspace
git clone https://github.com/wolfSSL/wolfssl.git   [wolfssl-%USERNAME%]
git clone https://github.com/wolfSSL/osp.git       [osp-%USERNAME%]

cd [osp-%USERNAME%]
git clone https://github.com/realm/realm-core.git  [realm-core-%USERNAME%]
```

Resulting in directories like this (user suffixes optional, but must be consistent):

```
C:\workspace\wolfssl[-%USERNAME%]
C:\workspace\osp[-%USERNAME%]
C:\workspace\osp[-%USERNAME%]\realm-core[-%USERNAME%]
```

The patch must be applied:

```
cd C:\workspace\realm-core
git apply ../osp-gojimmypi/realm/realm-commit-a5e87a39.patch
```

There's an enclosed WSL script called [build_wolfssl_with_realm.sh](./build_wolfssl_with_realm.sh) that automates installation.

## Clean from DOS Prompt or Visual Studio Developer Command Prompt

Run the enclosed `clean_realm.bat` in the `osp[-%USERNAME%]/realm` directory to delete all build-time generated files:

```
cd realm
.\clean_realm.bat
```

Optionally clean in quiet mode with `/Q` parameter:

```
cd realm
.\clean_realm.bat /Q
```

## Build from Visual Studio Developer Command Prompt

Start a Developer Command Prompt for VS 2022

```
cd C:\workspace\osp-%USERNAME%\realm\VS2022
msbuild .\wolfssl-VS2022-cmake.vcxproj /p:Configuration=Debug /p:Platform=x64
msbuild .\ALL_BUILD.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## Known Visual Studio Issues

Project files were designed with Visual Studio 2022 version 17.11.5.

Some minor issues are known:

### Project Reload Path Replacements

Occasionally the project files may spontaneously reload, replacing all parameterized values with current fixed paths.

This should be fine for typical end-users, but is highly undesired for developers wishing to contribute changes to project files.

There's no known solution at this time. Undo all changes in the `VS2022` directories, in particular for `.vscproj` and `.filters` files.

Consider performing a full, brute-force clean with `clean_realm.bat`.

For more information see [dotnet/msbuild #5486](https://github.com/dotnet/msbuild/issues/5486) and [Visual Studio Developer Community](https://developercommunity.visualstudio.com/t/NETSdk-build-runs-unexpectedly-undesir/10816622?).

After the initial undo of changes, the reload typically does not occur again.

This issue seems to be related to the `VS2022/CMakeFiles/VerifyGlobs.cmake` file (see below).

# Extra VerifyGlobs.cmake file in CMakeFiles

There's a `VerifyGlobs.cmake` placeholder file located in `[osp]\realm\VS2022\CMakeFiles` that is required for fresh clones to build properly.

### Maximum Path Length

The default Windows configuration has a maximum 256 character path limitation.
See [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry) for more details.

###  VerifyGlobs.cmake Placeholder

Without the `VS2022/CMakeFiles/VerifyGlobs.cmake` file, the initial project build fails due to this auto-generated file being "missing".

Subsequent build attempts are typically successful. Not that _including_ this file also seems to be related to the undesired Project Reload (see above).

## Generating a new Realm-core patch file:

To generate a new patch compare a particular commit (a5e87a39) to your fork/branch (`dev`):

Save the generated file from this link to the `realm-commit-a5e87a39.patch` file:

```
https://github.com/gojimmypi/realm-core/compare/a5e87a39...dev.patch

or

https://github.com/gojimmypi/realm-core/compare/a5e87a39...gojimmypi:realm-core:dev-consolidated.patch
```

Do *not* edit the patch file for tailing spaces, etc. It must be saved exactly as generated.

## Troubleshooting

### Unexpected value of WOLFSSL_ROOT

Check system and user environment settings.

```powershell
Get-ChildItem Env:WOLFSSL_ROOT
```

Check registry, particularly if you use `SETX`:

* User-specific: `HKEY_CURRENT_USER\Environment`
* System-wide: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

Check any other parent processes, startup scripts, Group Policy, etc.

If the registry value continues to be undesirably cached, try one or more of these options:

* Use `SET` and `SETX` to update the value.
* Log out and back in.
* Restart Windows Explorer from Task Manager.
* Reboot.

### Confirming build with wolfSSL

See generated `config.h` files:

For Linux compile: `build` directory:
```
[wolfssl osp root]\realm\realm-core[-username]\build\src\realm\util
```

For Visual Studio compile: `out` directory, plus build configuration (e.g. `build\x64-Debug`):

```
[wolfssl osp root]\realm\realm-core[-username]\out\build\x64-Debug\src\realm\util
```

### Cannot find OpenSSL

```
Cannot open include file: 'openssl/sha.h': No such file or directory	Storage	C:\workspace\osp-gojimmypi\realm\realm-core-gojimmypi\src\realm\util\aes_cryptor.hpp
```

Check the `osp\realm\VS2022\src\realm\util` directory. The generated `config.h` should have
openSSL disabled `0` and wolfSSL enabled `1` like this:

```
#define REALM_HAVE_OPENSSL 0
#define REALM_HAVE_WOLFSSL 1
```

### CMake error Not a file: VerifyGlobs.cmake

This file is typically not included in source control, but was found to be problematic when missing in this solution. Thus, there's a placeholder file.

```
1>Checking File Globs
1>EXEC : CMake error : Not a file: C:/workspace/osp-gojimmypi/realm/VS2022/CMakeFiles/VerifyGlobs.cmake
1>EXEC : CMake error : Error processing file: C:/workspace/osp-gojimmypi/realm/VS2022/CMakeFiles/VerifyGlobs.cmake
```

### Missing LibUV

Open the cloned `realm-core` in Visual Studio and let cmake download and setup LibUV.

```
1> [CMake] -- Could NOT find LibUV (missing: LibUV_LIBRARY LibUV_INCLUDE_DIR) (found version "")
1> [CMake] -- LibUV not found, building from source with FetchContent
```
