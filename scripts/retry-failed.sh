#!/usr/bin/env bash
# usage: retry-failed.sh OUTDIR
set -euo pipefail
. "$(dirname "$0")/env.sh"
out=$1
[ -s "$out/failed" ] || exit 0
mv "$out/failed" "$out/failed.prev"
sort -u "$out/failed.prev" | xargs -P "$jobs" -n4 "$root/scripts/scan-one.sh" "$out"
[ ! -s "$out/failed" ]
