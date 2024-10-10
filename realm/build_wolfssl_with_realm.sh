#!/bin/bash

#bash -x ./build_wolfssl_with_realm.sh -g

# Commit hashes for specific versions when using git
WOLFSSL_COMMIT="e814d1ba"
#REALM_CORE_COMMIT="c729fc80"
REALM_CORE_COMMIT="a5e87a39"  # Adjust if necessary

# Variables
WOLFSSL_VERSION="v5.7.2-stable"
REALM_CORE_VERSION="v13.26.0"
WOLFSSL_TAR="${WOLFSSL_VERSION}.tar.gz"
REALM_TAR="${REALM_CORE_VERSION}.tar.gz"
WOLFSSL_URL="https://github.com/wolfSSL/wolfssl/archive/refs/tags/${WOLFSSL_TAR}"
REALM_URL="https://github.com/realm/realm-core/archive/refs/tags/${REALM_TAR}"
OSP_REALM_DIR="realm"
WOLFSSL_DIR="wolfssl"
REALM_CORE_DIR="realm-core"
BUILD_DIR="build"
TEST_EXECUTABLE="$BUILD_DIR/test/realm-tests"
WOLFSSL_INSTALL_DIR="$HOME/wolfssl-install-dir"
USE_SYSTEM_INSTALL=true  # Change this to true if you want to use system-wide wolfSSL installation
USE_GIT=false  # Default method is using curl, set this to true to use git

# Patch file based on REALM_CORE_COMMIT or REALM_CORE_VERSION
PATCH_FILE=""

# Check if user wants to use git
while getopts ":g" opt; do
  case $opt in
    g)
      USE_GIT=true
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# Step 2: Download or clone wolfSSL
if [ "$USE_GIT" = true ]; then
    if [ ! -d "$WOLFSSL_DIR" ]; then
        echo "Cloning the wolfSSL repository..."
        git clone https://github.com/wolfSSL/wolfssl.git "$WOLFSSL_DIR"
        cd "$WOLFSSL_DIR" || exit
        echo "Checking out commit $WOLFSSL_COMMIT..."
        git checkout "$WOLFSSL_COMMIT"
    else
        cd "$WOLFSSL_DIR" || exit
        git fetch
        echo "Checking out commit $WOLFSSL_COMMIT..."
        git checkout "$WOLFSSL_COMMIT"
    fi
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
    cd "$WOLFSSL_DIR" || exit
fi

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

echo "Building and installing wolfSSL..."
make -j$(nproc)
sudo make install

# Step 4: Download or clone realm-core
cd ..
if [ "$USE_GIT" = true ]; then
    PATCH_FILE="realm-commit-${REALM_CORE_COMMIT}.patch"
    if [ ! -d "$REALM_CORE_DIR" ]; then
        echo "Cloning the realm-core repository..."
        git clone https://github.com/realm/realm-core.git "$REALM_CORE_DIR"
        cd "$REALM_CORE_DIR" || exit
    else
        cd "$REALM_CORE_DIR" || exit
    fi
    # Reset the branch before checking out the specific commit and applying patch
    git reset --hard HEAD
    git checkout "$REALM_CORE_COMMIT"
    git submodule update --init --recursive
else
    PATCH_FILE="realm-${REALM_CORE_VERSION}.patch"
    if [ ! -d "$REALM_CORE_DIR" ]; then
        echo "Downloading realm-core..."
        curl -L -O "$REALM_URL"
        echo "Extracting realm-core..."
        tar -xvf "$REALM_TAR"

        EXTRACTED_REALM_DIR=$(tar -tzf "$REALM_TAR" | head -1 | cut -f1 -d"/")
        if [ -d "$EXTRACTED_REALM_DIR" ]; then
            mv "$EXTRACTED_REALM_DIR" "$REALM_CORE_DIR"
        else
            echo "Error: Failed to extract or find the realm-core directory."
            exit 1
        fi

        cd "$REALM_CORE_DIR" || exit
    else
        cd "$REALM_CORE_DIR" || exit
    fi
fi

# Step 5: Apply patch if patch file exists for realm-core
if [ -f "../$PATCH_FILE" ]; then
    echo "Applying patch to realm-core..."
    git apply "../$PATCH_FILE"
fi

# Step 6: Build realm-core
if [ ! -d "$BUILD_DIR" ]; then
    mkdir "$BUILD_DIR"
fi

if [ "$USE_SYSTEM_INSTALL" = true ]; then
    echo "Configuring realm-core to use system-wide wolfSSL installation..."
    cmake -B "$BUILD_DIR" -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_USE_WOLFSSL=1 -DREALM_WOLFSSL_ROOT_DIR=/usr/local/lib
else
    echo "Configuring realm-core to use local wolfSSL installation from $WOLFSSL_INSTALL_DIR..."
    cmake -B "$BUILD_DIR" -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_USE_WOLFSSL=1 -DREALM_WOLFSSL_ROOT_DIR="$WOLFSSL_INSTALL_DIR"
fi

echo "Building realm-core..."
cmake --build "$BUILD_DIR"

# Step 7: Run the tests
if [ -f "$TEST_EXECUTABLE" ]; then
    echo "Running the test: $TEST_EXECUTABLE"
    "$TEST_EXECUTABLE"
else
    echo "Test executable not found. Make sure the build was successful."
fi
