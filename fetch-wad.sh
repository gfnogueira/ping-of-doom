#!/usr/bin/env bash
# Downloads the shareware doom1.wad (freely redistributable) and checks its md5.
set -euo pipefail
cd "$(dirname "$0")"

OUT="wad/doom1.wad"
WANT_MD5="f0cefca49926d00903cf57551d901abe"
URL="https://cdn.jsdelivr.net/gh/Akbar30Bill/DOOM_wads@master/doom1.wad"

md5_of() { md5 -q "$1" 2>/dev/null || md5sum "$1" | cut -d' ' -f1; }

mkdir -p wad
if [ -f "$OUT" ] && [ "$(md5_of "$OUT")" = "$WANT_MD5" ]; then
  echo "WAD already there: $OUT"
  exit 0
fi

echo "Downloading doom1.wad ..."
curl -sSL --max-time 60 -o "$OUT" "$URL"
got=$(md5_of "$OUT")
[ "$got" = "$WANT_MD5" ] || { echo "md5 mismatch: $got" >&2; exit 1; }
echo "OK: $OUT ($(wc -c < "$OUT") bytes)"
