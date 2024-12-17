#!/bin/bash

#bash -x ./build_wolfssl_with_realm.sh

# parameters:
#   -t use tarball, not git
#   -u use $USER name suffix for repository

    # While the support to build from a tarball is included,
    # Please note that to successfully build,
    # you will need to manually download and set up Catch2 to match the Git
    # repository structure when using the tarball. For example,
        # mkdir -p test/external/generated/catch2
        # curl -L -O
        # https://github.com/catchorg/Catch2/archive/refs/tags/v2.13.9.tar.gz
        # tar -xvf v2.13.9.tar.gz --strip-components=1 -C
        # test/external/generated/catch2
# Run shell check to ensure this a good script.
# Specify the executable shell checker you want to use:
MY_SHELLCHECK="shellcheck"

# Check if the executable is available in the PATH
if command -v "$MY_SHELLCHECK" >/dev/null 2>&1; then
    # Run your command here
    $MY_SHELLCHECK "$0" || exit 1
else
    echo "$MY_SHELLCHECK is not installed. Please install it if changes to this script have been made."
    exit 1
fi

# Command-line parameters

# Default method is using git, -t to disable; set this to false to use curl for tarball
USE_GIT=true

# Default repo names is not to use user name suffix. -u to enable.
USER_REPO_NAME=false

# Check if user wants to use git
while getopts ":tu" opt; do
  case $opt in
    # Specify -t to use tarball, not git
    t)
      USE_GIT=false
      ;;

    # specify -u to use $USER repository fork and file suffix
    u)
      USER_REPO_NAME=true
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# Commit hashes for specific versions when using git
WOLFSSL_COMMIT="e814d1ba"

# Adjust if necessary:
#REALM_CORE_COMMIT="c729fc80"
REALM_CORE_COMMIT="a5e87a39"

# Variables

# To build *without* wolfSSL, set REALM_HAVE_WOLFSSL=0
REALM_HAVE_WOLFSSL=1

WOLFSSL_UPSTREAM=""
REALM_CORE_UPSTREAM=""

if [ "$USER_REPO_NAME" = true ]; then
    echo "Found user-suffix for repository clones: -$USER"
    WOLFSSL_REPO="https://github.com/$USER/wolfssl.git"
    WOLFSSL_DIR="wolfssl-$USER"
    WOLFSSL_UPSTREAM="https://github.com/wolfSSL/wolfssl.git"

    REALM_CORE_REPO="https://github.com/$USER/realm-core.git"
    REALM_CORE_DIR="realm-core-$USER"
    REALM_CORE_UPSTREAM="https://github.com/realm/realm-core.git"
else
    echo "User-suffix for repository clones: no"
    WOLFSSL_REPO="https://github.com/wolfSSL/wolfssl.git"
    WOLFSSL_DIR="wolfssl"

    REALM_CORE_REPO="https://github.com/realm/realm-core.git"
    REALM_CORE_DIR="realm-core"
fi

WOLFSSL_VERSION="v5.7.2-stable"
REALM_CORE_VERSION="v13.26.0"
WOLFSSL_TAR="${WOLFSSL_VERSION}.tar.gz"
REALM_TAR="${REALM_CORE_VERSION}.tar.gz"
WOLFSSL_URL="https://github.com/wolfSSL/wolfssl/archive/refs/tags/${WOLFSSL_TAR}"
REALM_URL="https://github.com/realm/realm-core/archive/refs/tags/${REALM_TAR}"
# OSP_REALM_DIR="realm"


BUILD_DIR="build"
TEST_EXECUTABLE="$BUILD_DIR/test/realm-tests"
WOLFSSL_INSTALL_DIR="$HOME/wolfssl-install-dir"

# Change this to true if you want to use system-wide wolfSSL installation:
USE_SYSTEM_INSTALL=false

# Choose to skip parts of wolfSSL build:
FETCH_WOLFSSL=false
CONFIGURE_WOLFSSL=false
BUILD_WOLFSSL=false
INSTALL_WOLFSSL=false

# Choose to skip parts of realm-core build:
FETCH_REALM_CORE=true

# Show summary of key config settings:
echo "USE_GIT:             $USE_GIT"

echo "WOLFSSL_REPO:        $WOLFSSL_REPO"
echo "WOLFSSL_DIR:         $WOLFSSL_DIR"
echo "FETCH_WOLFSSL:       $FETCH_WOLFSSL"
echo "CONFIGURE_WOLFSSL:   $CONFIGURE_WOLFSSL"
echo "BUILD_WOLFSSL:       $BUILD_WOLFSSL"
echo "WOLFSSL_INSTALL_DIR: $WOLFSSL_INSTALL_DIR"

echo "REALM_CORE_REPO:     $REALM_CORE_REPO"
echo "REALM_CORE_DIR:      $REALM_CORE_DIR"


# Patch file based on REALM_CORE_COMMIT or REALM_CORE_VERSION
PATCH_FILE=""

if [ "$FETCH_WOLFSSL" = true ]; then
    # Step 2: Download or clone wolfSSL
    if [ "$USE_GIT" = true ]; then
        if [ ! -d "$WOLFSSL_DIR" ]; then
            echo "Cloning the wolfSSL repository $WOLFSSL_REPO"
            git clone "$WOLFSSL_REPO" "$WOLFSSL_DIR" || { echo "Failed to clone $WOLFSSL_REPO"; exit 1; }
            cd "$WOLFSSL_DIR" || exit

            if [ -z "$WOLFSSL_UPSTREAM" ]; then
                echo "No git upstream to set for $WOLFSSL_DIR"
            else
                echo "Set upstream wolfssl: $WOLFSSL_UPSTREAM"
                git remote add upstream "$WOLFSSL_UPSTREAM"
            fi

            if [ -n "$WSL_DISTRO_NAME" ]; then
                # Ignore file permissions changes in WSL
                git config core.fileMode false
            fi

            echo "Checking out commit $WOLFSSL_COMMIT..."
            git checkout "$WOLFSSL_COMMIT"
        else
            cd "$WOLFSSL_DIR" || exit
            git fetch
            echo "Checking out commit $WOLFSSL_COMMIT..."
            git checkout "$WOLFSSL_COMMIT"
        fi
        cd ..
    else
        if [ ! -d "$WOLFSSL_DIR" ]; then
            echo "Downloading wolfSSL..."
            curl -L -O "$WOLFSSL_URL"
            echo "Extracting wolfSSL..."
            tar -xvf "$WOLFSSL_TAR"

            EXTRACTED_WOLFSSL_DIR=$(tar -tzf "$WOLFSSL_TAR" | head -1 | cut -f1 -d"/")
            if [ -d "$EXTRACTED_WOLFSSL_DIR" ]; then
                mv "$EXTRACTED_WOLFSSL_DIR" "$WOLFSSL_DIR"
            else
                echo "Error: Failed to extract or find the wolfSSL directory."
                exit 1
            fi
        fi
    fi
else
    echo "Skipping wolfSSL source fetch"
    if [ ! -d "$WOLFSSL_DIR" ]; then
        echo "Warning: wolfSSL fetch skipped, but directory not found: $WOLFSSL_DIR"
    fi
    if [ ! -d "$WOLFSSL_INSTALL_DIR" ]; then
        echo "Error: wolfSSL fetch skipped and install directory not found: $WOLFSSL_INSTALL_DIR"
        exit 1
    else
        echo "Warning: wolfSSL fetch skipped, using prior install found in: $WOLFSSL_INSTALL_DIR"
    fi
fi

if [ "$CONFIGURE_WOLFSSL" = true ]; then
    cd "$WOLFSSL_DIR" || exit 1
    # Step 3: Build and install wolfSSL
    if [ "$USE_SYSTEM_INSTALL" = true ]; then
        echo "Configuring wolfSSL for system-wide installation..."
        ./autogen.sh
        ./configure --enable-static --enable-opensslall --enable-enckeys --enable-certgen --enable-context-extra-user-data
    else
        ./autogen.sh
        echo "Configuring wolfSSL for local installation at $WOLFSSL_INSTALL_DIR..."
        ./configure --enable-static --enable-opensslall --enable-enckeys --enable-certgen --enable-context-extra-user-data --prefix="$WOLFSSL_INSTALL_DIR"
    fi
    cd ..
else
    echo "Skipping wolfSSL configure"
fi

if [ "$BUILD_WOLFSSL" = true ]; then
    cd "$WOLFSSL_DIR" || exit 1
    echo "Building and installing wolfSSL..."
    make -j"$(nproc)"
    cd ..
else
    echo "Skipping wolfSSL build"
fi

if [ "$INSTALL_WOLFSSL" = true ]; then
    cd "$WOLFSSL_DIR" || exit
    make install
    cd ..
else
    echo "Skipping wolfSSL install"
fi

# Step 4: Download or clone realm-core
echo "Current working directory to fetch realm-core: $(pwd)"

if [ "$FETCH_REALM_CORE" = true ]; then
    if [ "$USE_GIT" = true ]; then
        PATCH_FILE="realm-commit-${REALM_CORE_COMMIT}.patch"
        if [ ! -d "$REALM_CORE_DIR" ]; then
            echo "Confirmed directory not found: REALM_CORE_DIR=$REALM_CORE_DIR"
            echo "Cloning the realm-core repository from $REALM_CORE_REPO"
            git clone "$REALM_CORE_REPO" "$REALM_CORE_DIR"  || { echo "Failed to clone $REALM_CORE_REPO"; exit 1; }

            if [ -z "$REALM_CORE_UPSTREAM" ]; then
                echo "No git upstream to set for $REALM_CORE_DIR."
            else
                echo "Set upstream wolfssl: $REALM_CORE_UPSTREAM"
                git remote add upstream "$REALM_CORE_UPSTREAM"
            fi


            cd "$REALM_CORE_DIR" || exit 1
        else
            echo "Skipping git clone, found existing REALM_CORE_DIR=$REALM_CORE_DIR"
            cd "$REALM_CORE_DIR" || exit 1
        fi

        if [ -n "$WSL_DISTRO_NAME" ]; then
            echo "Found WSL distro, setting core.fileMode"
            # Ignore file permissions changes in WSL
            git config core.fileMode false
        else
            echo "Not a WSL distro, not setting core.fileMode"
        fi

        echo "Current directory: $(pwd)"
        if [ -f "REALM_CORE_COMMIT_COMPLETE.log" ]; then
            echo "Skipping git reset; REALM_CORE_COMMIT_COMPLETE.log found"
            git status
        else
            # Reset the branch before checking out the specific commit and applying patch
            echo "git reset --hard HEAD"
            git reset --hard HEAD || { echo "Failed to git reset"; exit 1; }

            echo "git checkout $REALM_CORE_COMMIT"
            git checkout "$REALM_CORE_COMMIT" || { echo "Failed to checkout commit $REALM_CORE_COMMIT"; exit 1; }

            echo "git submodule update --init --recursive"
            git submodule update --init --recursive || { echo "Failed git submodule update"; exit 1; }
        fi
        cd ..
    else
        PATCH_FILE="../realm-${REALM_CORE_VERSION}.patch"
        if [ ! -d "$REALM_CORE_DIR" ]; then
            echo "Downloading realm-core..."
            curl -L -O "$REALM_URL" || { echo "Failed curl for $REALM_URL"; exit 1; }
            echo "Extracting realm-core..."
            tar -xvf "$REALM_TAR"

            EXTRACTED_REALM_DIR=$(tar -tzf "$REALM_TAR" | head -1 | cut -f1 -d"/")
            if [ -d "$EXTRACTED_REALM_DIR" ]; then
                mv "$EXTRACTED_REALM_DIR" "$REALM_CORE_DIR"
            else
                echo "Error: Failed to extract or find the realm-core directory."
                exit 1
            fi

            cd "$REALM_CORE_DIR" || exit 1
        else
            cd "$REALM_CORE_DIR" || exit
        fi
        cd ..
    fi
else
    echo "Skipping fetch REALM_CORE source"
fi

cd "$REALM_CORE_DIR" || { echo "Cannot find $REALM_CORE_DIR"; exit 1; }

if [ -f "REALM_CORE_COMMIT_COMPLETE.log" ]; then
    echo "Found REALM_CORE_COMMIT_COMPLETE.log, skipping patch."
else
    echo "Current directory to apply $PATCH_FILE patch: $(pwd)"
    # Step 5: Apply patch if patch file exists for realm-core
    echo "Looking for path file $PATCH_FILE in $(pwd)"
    if [ -f "../$PATCH_FILE" ]; then
        echo "Applying patch to realm-core: ../$PATCH_FILE"

        git apply "../$PATCH_FILE" || { echo "Failed to apply patch: ../$PATCH_FILE"; git status; exit 1; }

        echo "breadcrumb" > "REALM_CORE_COMMIT_COMPLETE.log"
    else
        # The current build systems expect no upstream support. Patch is required.
        # See also: https://github.com/realm/realm-core/pull/6535
        echo "No patch applied, abort"
        exit 1
    fi
fi

# Step 6: Build realm-core
if [ ! -d "$BUILD_DIR" ]; then
    mkdir "$BUILD_DIR"
else
    echo "Found BUILD_DIR: $BUILD_DIR"
fi

if [ "$USE_SYSTEM_INSTALL" = true ]; then
    echo "Configuring realm-core to use system-wide wolfSSL installation /usr/local/lib"
    cmake -B "$BUILD_DIR"                         -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_HAVE_WOLFSSL="$REALM_HAVE_WOLFSSL" -DREALM_WOLFSSL_ROOT_DIR="/usr/local/lib"        || { echo "cmake failed"; exit 1; }
else
    echo "Configuring realm-core to use local wolfSSL installation from $WOLFSSL_INSTALL_DIR"
    cmake -B "$BUILD_DIR" -DREALM_INCLUDE_CERTS=1 -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_HAVE_WOLFSSL="$REALM_HAVE_WOLFSSL" -DREALM_WOLFSSL_ROOT_DIR="$WOLFSSL_INSTALL_DIR"  || { echo "cmake failed"; exit 1; }
fi

echo "realm-core configuration complete."
echo "Building realm-core..."
cmake --build "$BUILD_DIR" || { echo "Build failed"; exit 1; }
#2>&1 | tee -a output.log

# Step 7: Run the tests
if [ -f "$TEST_EXECUTABLE" ]; then
    echo "Running the test: $TEST_EXECUTABLE"
    "$TEST_EXECUTABLE"
else
    echo "Test executable not found. Make sure the build was successful."
fi
