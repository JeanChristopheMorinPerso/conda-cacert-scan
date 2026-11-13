# Scanning Anaconda's main channel

The scanner treats `https://repo.anaconda.com/pkgs/main` like any other conda
channel. It downloads every latest-version artifact in the selected subdirs,
extracts it, and reports files that carry their own CA trust store, including
stores that still trust the revoked eMudhra/Sectigo paths.

Use a PBP dev instance type `z1d.6xlarge`.

Build the scanner once:

```sh
pixi run build
```

Run the resumable batch scanner. `JOBS` sets package-level parallelism; temporary
archives and extracted files go under the output directory by default.

```sh
JOBS=24 pixi run bash scripts/run.sh out/anaconda-main \
  https://repo.anaconda.com/pkgs/main \
  --subdirs noarch linux-64 linux-aarch64 osx-arm64 win-64 win-arm64
```

Re-running the same command resumes: completed artifacts are skipped from
`done/`, and the saved artifact list in `packages.tsv` is reused. Use a new
output directory to refresh the package selection. Raw findings are in
`res/INDEX.jsonl`.

Aggregate the results:

```sh
python3 scripts/analyze.py out/anaconda-main out/anaconda-main/report
python3 tools/package-list.py out/anaconda-main/report/findings.tsv
```

This writes `findings.tsv` (one row per file), `packages.tsv` (one row per
package) and `summary.txt` to `out/anaconda-main/report`.
