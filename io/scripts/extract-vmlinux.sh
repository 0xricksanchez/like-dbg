#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# extract-vmlinux - carve an uncompressed vmlinux ELF out of a kernel image.
set -eu

check_vmlinux() {
  readelf -h "$1" >/dev/null 2>&1 || return 1
  cat "$1" >"$2"
  exit 0
}

try_decompress() {
  for pos in $(tr "$1\n$2" "\n$2=" <"$img" | grep -abo "^$2"); do
    pos=${pos%%:*}
    tail -c+"$pos" "$img" | $3 >"$tmp" 2>/dev/null || true
    check_vmlinux "$tmp" "$out"
  done
}

img=$1
out=$2
tmp=$(mktemp /tmp/vmlinux-XXXXXX)
trap 'rm -f "$tmp"' EXIT

try_decompress '\037\213\010' xy gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh' xy bunzip2
try_decompress '\135\0\0\0' xxx unlzma
try_decompress '\211\114\132' xy 'lzop -d'
try_decompress '\002!L\030' xxx 'lz4 -d'
try_decompress '(\265/\375' xxx unzstd
check_vmlinux "$img" "$out"

echo "extract-vmlinux: cannot find vmlinux in $img" >&2
exit 1
