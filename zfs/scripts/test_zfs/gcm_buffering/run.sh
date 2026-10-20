#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "Usage: $0 APPLIED_OPENZFS_SOURCE_TREE" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/wolfzfs-gcm-buffering.XXXXXXXX")
trap 'rm -rf -- "$build_dir"' EXIT
ulimit -c 0
python3 "$script_dir/extract.py" "$1" "$build_dir"
cp -- "$script_dir/harness.c" "$build_dir/harness.c"
cat "$build_dir/provenance.json"
for profile in buffered stream; do
    flags=()
    if [[ $profile == stream ]]; then
        flags=(-DWOLFSSL_AESGCM_STREAM)
    fi
    "${CC:-cc}" -Wall -Wextra -Werror -Wno-unused-function -Wno-sign-compare \
        -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        "${flags[@]}" "$build_dir/harness.c" -lcrypto \
        -o "$build_dir/harness-$profile"
    echo "PROFILE $profile"
    ASAN_OPTIONS=detect_leaks=1 "$build_dir/harness-$profile"
done
