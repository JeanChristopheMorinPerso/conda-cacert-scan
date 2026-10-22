#!/usr/bin/env bash
# usage: run.sh OUTDIR CHANNEL --subdirs SUBDIR... [--include FILE] [--temp-dir DIR]
# env: JOBS=4; resumes the saved artifact snapshot and automatically retries once
set -euo pipefail
. "$(dirname "$0")/env.sh"
[ "$#" -ge 2 ] || { printf 'usage: run.sh OUTDIR CHANNEL --subdirs SUBDIR... [--include FILE] [--temp-dir DIR]\n' >&2; exit 2; }
out=$1; shift
mkdir -p "$out"/{res,err,done,tmp}
temp_dir=${CACERT_SCAN_TEMP_DIR:-$out/tmp}
selection=()
while [ "$#" -gt 0 ]; do
  case $1 in
    --temp-dir) [ "$#" -ge 2 ] || exit 2; temp_dir=$2; shift 2 ;;
    --temp-dir=*) temp_dir=${1#*=}; shift ;;
    *) selection+=("$1"); shift ;;
  esac
done
[ "${#selection[@]}" -gt 0 ] || exit 2
export CACERT_SCAN_TEMP_DIR=$temp_dir
if [ ! -e "$out/packages.tsv" ]; then
  "$SCANNER" list "${selection[@]}" --manifest > "$out/packages.tsv.tmp"
  mv "$out/packages.tsv.tmp" "$out/packages.tsv"
fi
if [ -s "$out/packages.tsv" ]; then
  xargs -P "$jobs" -n4 "$root/scripts/scan-one.sh" "$out" < "$out/packages.tsv"
fi
"$root/scripts/retry-failed.sh" "$out"
