#!/usr/bin/env bash
# usage: scan-one.sh OUTDIR INDEX TOTAL SUBDIR/FILENAME URL
set -euo pipefail
. "$(dirname "$0")/env.sh"
out=$1 index=$2 total=$3 label=$4 url=$5
[ -e "$out/done/$index" ] && exit 0
export CACERT_SCAN_TEMP_DIR="${CACERT_SCAN_TEMP_DIR:-$out/tmp}"
printf '[%s/%s] %s\n' "$index" "$total" "$label" >&2
if "$SCANNER" scan "$url" > "$out/res/$index.jsonl" 2> "$out/err/$index"; then
  touch "$out/done/$index"
else
  printf 'failed: %s (see %s/err/%s)\n' "$label" "$out" "$index" >&2
  printf '%s\t%s\t%s\t%s\n' "$index" "$total" "$label" "$url" >> "$out/failed"
fi
