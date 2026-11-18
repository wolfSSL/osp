#!/bin/sh
#
# build-freebsd.sh - build wolfguard-go and wg-fips for pfSense on FreeBSD.
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Run as a normal user with sudo on a FreeBSD system whose major version
# matches the target pfSense release (FreeBSD 16.0-CURRENT for pfSense CE
# 2.9.0). wolfSSL is linked statically, so the resulting binaries only need
# FreeBSD base system libraries and can be copied onto pfSense as-is.
#
# usage: build-freebsd.sh [-w <wolfssl-src>] [-o <outdir>] [-j <jobs>]
#   -w  use an existing wolfSSL source tree (e.g. an unpacked FIPS bundle)
#       instead of cloning wolfSSL master
#   -o  where to put the binaries (default: ./out)
#   -j  parallel make jobs (default: number of CPUs)
#
# Environment:
#   WOLFSSL_EXTRA_CONFIGURE  extra ./configure options for the wolfguard-go
#                            wolfSSL build, e.g. "--enable-fips=v5" for a
#                            FIPS bundle (run its fips-hash.sh step yourself)
#   WOLFGUARD_REPO           wolfguard repository to build wg-fips from
#                            (default https://github.com/wolfSSL/wolfguard.git)
#   WOLFGUARD_REF            branch, tag or commit of WOLFGUARD_REPO
#                            (default master). wg-fips needs the fix from
#                            wolfSSL/wolfGuard#33 to configure wolfguard-go.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
OSP_WG=$(cd "$HERE/.." && pwd)
WORK=$(pwd)/work
OUT=$(pwd)/out
JOBS=$(sysctl -n hw.ncpu)
WOLFSSL_SRC=
WIREGUARD_GO_TAG=0.0.20250522
WOLFGUARD_REPO=${WOLFGUARD_REPO:-https://github.com/wolfSSL/wolfguard.git}
WOLFGUARD_REF=${WOLFGUARD_REF:-master}

while getopts "w:o:j:" opt; do
	case "$opt" in
	w) WOLFSSL_SRC=$(cd "$OPTARG" && pwd) ;;
	o) OUT=$OPTARG ;;
	j) JOBS=$OPTARG ;;
	*) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
	esac
done

echo "==> Installing build dependencies"
sudo env ASSUME_ALWAYS_YES=yes pkg install -q go git autoconf automake libtool gmake bash pkgconf

mkdir -p "$WORK" "$OUT"
cd "$WORK"

clone() {
	# clone <url> <dir> [<ref>]
	if [ ! -d "$2" ]; then
		git clone -q "$1" "$2"
	fi
	if [ -n "${3:-}" ]; then
		git -C "$2" checkout -q "$3"
	fi
}

if [ -z "$WOLFSSL_SRC" ]; then
	clone https://github.com/wolfSSL/wolfssl.git wolfssl
	WOLFSSL_SRC=$WORK/wolfssl
fi
clone https://github.com/wolfSSL/go-wolfssl.git go-wolfssl
clone https://github.com/WireGuard/wireguard-go.git wireguard-go "$WIREGUARD_GO_TAG"
clone "$WOLFGUARD_REPO" wolfguard
git -C wolfguard fetch -q origin "$WOLFGUARD_REF"
git -C wolfguard checkout -q FETCH_HEAD

# wolfSSL for wolfguard-go: P-256 SP math and Intel assembly (AES-NI/AVX2).
# Without --enable-intelasm AES-GCM runs in C and the tunnel is about 35%
# slower.
build_wolfssl() {
	# build_wolfssl <builddir> <prefix> <configure options...>
	dir=$1; prefix=$2; shift 2
	rm -rf "$dir"
	cp -R "$WOLFSSL_SRC" "$dir"
	cd "$dir"
	[ -x ./configure ] || ./autogen.sh
	./configure --quiet --prefix="$prefix" --enable-static --disable-shared --with-pic "$@"
	gmake -j"$JOBS"
	./wolfcrypt/test/testwolfcrypt
	sudo gmake install
	cd "$WORK"
}

echo "==> Building wolfSSL for wolfguard-go"
# shellcheck disable=SC2086
build_wolfssl "$WORK/wolfssl-go" /opt/wolfssl \
	--enable-sp="yes, 256" --enable-sp-asm --enable-intelasm ${WOLFSSL_EXTRA_CONFIGURE:-}

echo "==> Building wolfSSL for wg-fips"
build_wolfssl "$WORK/wolfssl-wg" /opt/wolfssl-wg \
	--enable-wolfguard --enable-intelasm

echo "==> Building wolfguard-go"
cd "$WORK/go-wolfssl"
bash ./generateOptions.sh /opt/wolfssl
cd "$WORK/wireguard-go"
if ! git diff --quiet; then
	git checkout -q .
fi
patch -p1 -s < "$OSP_WG/Wireguard-Go-FIPS-wolfCrypt-port.patch"
go mod edit -replace "github.com/wolfssl/go-wolfssl=$WORK/go-wolfssl"
go mod tidy
# Use /var/run/wolfguard for UAPI sockets, where wg-fips looks for them.
go build -a -o "$OUT/wolfguard-go" \
	-ldflags "-X golang.zx2c4.com/wireguard/ipc.socketDirectory=/var/run/wolfguard" .
(cd device && go test)

echo "==> Building wg-fips"
cd "$WORK/wolfguard/user-src"
gmake clean >/dev/null
# The static libwolfssl needs libm and libpthread on FreeBSD (also added by
# the user-src Makefile once wolfSSL/wolfGuard#33 is merged).
gmake -j"$JOBS" WOLFSSL_ROOT=/opt/wolfssl-wg \
	LDLIBS="-L/opt/wolfssl-wg/lib -lwolfssl -lm -lpthread"
install -m 0755 wg-fips "$OUT/wg-fips"

echo "==> Done"
ls -l "$OUT"
for b in "$OUT/wolfguard-go" "$OUT/wg-fips"; do
	ldd "$b"
done
"$OUT/wolfguard-go" --version | head -1
"$OUT/wg-fips" --version
