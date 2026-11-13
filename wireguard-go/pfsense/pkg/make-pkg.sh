#!/bin/sh
#
# make-pkg.sh - build pfSense-pkg-wolfGuard as a FreeBSD pkg without needing
# the pfSense FreeBSD-ports tree.
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Run on a FreeBSD system with the same major version as the target pfSense
# release (FreeBSD 16 for pfSense CE 2.9). The resulting package bundles the
# wolfguard-go and wg-fips binaries built by build-freebsd.sh.
#
# usage: make-pkg.sh -b <bindir> [-v <version>] [-o <outdir>]
#   -b  directory containing wolfguard-go and wg-fips
#   -v  package version (default 0.1.0)
#   -o  output directory (default: current directory)

set -eu

VERSION=0.1.0
OUTDIR=$(pwd)
BINDIR=

while getopts "b:v:o:" opt; do
	case "$opt" in
	b) BINDIR=$OPTARG ;;
	v) VERSION=$OPTARG ;;
	o) OUTDIR=$OPTARG ;;
	*) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
	esac
done

if [ -z "$BINDIR" ] || [ ! -x "$BINDIR/wolfguard-go" ] || [ ! -x "$BINDIR/wg-fips" ]; then
	echo "error: -b must name a directory containing wolfguard-go and wg-fips" >&2
	exit 1
fi

NAME=pfSense-pkg-wolfGuard
SRC=$(cd "$(dirname "$0")/$NAME" && pwd)
WORK=$(mktemp -d -t wolfguard-pkg)
STAGE=$WORK/stage
trap 'rm -rf "$WORK"' EXIT

# Stage package files.
mkdir -p "$STAGE"
(cd "$SRC/files" && find . -type f) | while read -r f; do
	f=${f#./}
	mkdir -p "$STAGE/$(dirname "$f")"
	sed "s/%%PKGVERSION%%/$VERSION/g" "$SRC/files/$f" > "$STAGE/$f"
done
chmod 0755 "$STAGE/usr/local/etc/rc.d/wolfguard.sh"
install -d "$STAGE/usr/local/sbin" "$STAGE/usr/local/bin"
install -m 0755 "$BINDIR/wolfguard-go" "$STAGE/usr/local/sbin/wolfguard-go"
install -m 0755 "$BINDIR/wg-fips" "$STAGE/usr/local/bin/wg-fips"
install -d "$STAGE/usr/local/share/licenses/$NAME-$VERSION"
cp "$SRC/LICENSE" "$STAGE/usr/local/share/licenses/$NAME-$VERSION/LICENSE"

# Packing list: everything staged, as absolute paths, plus the directories
# the package owns so that removing it also removes them.
(cd "$STAGE" && find . -type f | sed 's|^\.||' | sort) > "$WORK/plist"
for d in /usr/local/pkg/wolfguard /usr/local/www/wolfguard \
    /usr/local/share/$NAME /usr/local/share/licenses/$NAME-$VERSION; do
	echo "@dir $d" >> "$WORK/plist"
done

ABI=$(pkg config ABI)
cat > "$WORK/+MANIFEST" <<EOF
name: $NAME
version: "$VERSION"
origin: net/$NAME
comment: "pfSense package for wolfGuard VPN (wolfguard-go)"
desc: <<EOD
wolfGuard VPN for pfSense using wolfguard-go, a userspace WireGuard-style
daemon with cryptography from wolfCrypt (ECC P-256, AES-256-GCM, SHA-256).
Interoperates with the wolfGuard Linux kernel module and other wolfGuard
peers. It does not interoperate with WireGuard.
EOD
maintainer: "support@wolfssl.com"
www: "https://github.com/wolfSSL/osp/tree/master/wireguard-go/pfsense"
abi: "$ABI"
prefix: /
licenselogic: single
licenses: [GPLv3+]
categories: [net]
scripts: {
  post-install: "/usr/local/bin/php -f /etc/rc.packages $NAME POST-INSTALL",
  pre-deinstall: "/usr/local/bin/php -f /etc/rc.packages $NAME DEINSTALL",
  post-deinstall: "/usr/local/bin/php -f /etc/rc.packages $NAME POST-DEINSTALL"
}
EOF

mkdir -p "$OUTDIR"
pkg create -M "$WORK/+MANIFEST" -p "$WORK/plist" -r "$STAGE" -o "$OUTDIR"
ls -l "$OUTDIR/$NAME-$VERSION".pkg
