# cacert-scan

Finds Conda packages that carry their own CA trust store. The Rust scanner uses
rattler to extract packages into temporary disk storage and scan their contents.

This is a fork of https://github.com/zimbatm/nix-cacert-scan adapted for conda.
We thank @zimbatm for the idea nd the work he did for nix and are grateful that we
could reuse his work.

## Conda Usage

Development uses Pixi on macOS ARM64:

```sh
pixi install
pixi run build
pixi run test
```

Scan the latest packages in a channel with the resumable Bash runner:

```sh
JOBS=96 ./scripts/run.sh /mnt/nvme/data-cf https://conda.anaconda.org/conda-forge --subdirs noarch osx-arm64 linux-64 linux-aarch64 win-64 win-arm64

python3 scripts/analyze.py /mnt/nvme/data-cf /mnt/nvme/data-cf/report
python3 tools/package-list.py /mnt/nvme/data-cf/report/findings.tsv
```

For channel discovery, the channel URL and `--subdirs` are both required and have no defaults. Supply a channel root
URL and space- or comma-separated subdirectories, such as `--subdirs osx-arm64 noarch`
or `--subdirs linux-64,noarch`.
The scanner uses rattler's repodata gateway (including compressed repodata) and
Conda version ordering to select the highest version per package name and
subdirectory. All builds of that version are scanned, preferring `.conda` over a
duplicate `.tar.bz2` build. Removed packages are excluded. No dependency solve is
performed. Bash runs individual package scans through `xargs -P`, continues after
package failures, and returns nonzero if failures remain after retry.

Rust scans sequentially. For parallel scans with persistent results, resume, and
retry, use the Bash runner inside Pixi after building:

```sh
JOBS=8 pixi run bash scripts/run.sh out/conda-forge https://conda.anaconda.org/conda-forge --subdirs osx-arm64 noarch --include packages.txt --temp-dir ./scratch
JOBS=8 pixi run bash scripts/retry-failed.sh out/conda-forge
```

`JOBS` controls the number of concurrent package processes (default: 4). The runner
saves the artifact selection in `packages.tsv`, results in `res/INDEX.jsonl`,
errors in `err/INDEX`, and successful completion markers in `done/INDEX`. It
automatically retries unfinished packages once and exits nonzero if failures
remain. Re-running the same command resumes the saved snapshot, skipping completed
packages, without fetching channel repodata again. Use a new output directory to
refresh the selection or change its arguments. `failed` contains failed artifact
rows; `failed.prev` records the last retry batch. Only results with a matching
`done/INDEX` marker are complete; failed scans can leave partial results. Do not
run multiple runners/retries against the same output directory.

Progress includes the subdirectory, such as
`[152/19434] osx-arm64/adtk-0.6.2-py310h2f386ee_1.conda`. The artifact manifest is
TSV with index, total, subdirectory/filename, and URL. The single `cacert-scan`
command uses `list CHANNEL --subdirs ...` for rattler-based channel discovery,
printing one URL per line. `list --manifest` emits the TSV used by the batch
runner. `scan URL` scans exactly one package sequentially. `SCANNER` can override
the executable path.

`--include FILE` limits discovery to exact package names, one per line:

```text
certifi
openssl
python
```

Names are case-insensitive; surrounding whitespace, blank lines, and duplicates
are ignored. Version constraints and comments are not supported. An empty file
selects no packages. Names missing from the selected subdirectories produce warnings.

`--roots` and `--watch` default to `patterns/roots.pem` and `patterns/watch.pem`,
and can also be set with `CACERT_SCAN_ROOTS` and `CACERT_SCAN_WATCH`.

Scan output is JSON Lines, one finding per file, with `package` identifying the URL
and `file` identifying its package-relative path. Both metadata and
payload files are scanned; symbolic links are not followed. Hard links extracted
by rattler are scanned as regular files. Existing
nested-archive and certificate detection is preserved.

Both `.conda` and `.tar.bz2` packages are supported; HTTP range support is not
required. Packages are downloaded completely before extraction. The CLI accepts
one package URL through `scan`, or a channel URL with `--subdirs` through `list`
for discovery only.
There is no local archive or stdin CLI input.

`--temp-dir DIR` (or `CACERT_SCAN_TEMP_DIR`) selects the parent directory for
temporary files, defaulting to the system temporary directory. The directory is
created if needed. Each package gets a private subdirectory containing its
download and extracted files, removed after scanning or on ordinary errors.
The batch runner defaults temporary storage to `OUTDIR/tmp`. Set
`CACERT_SCAN_TEMP_DIR` when invoking standalone retries to reuse another temporary
directory. Up to `JOBS` packages are stored at a time; allow enough disk space for their
compressed archives and extracted contents. Memory use also scales with worker
count. Abrupt termination can leave temporary files.

Files larger than 1 GiB use the existing chunked scanner, which does not unpack
nested archives inside those files. Smaller files and nested archives retain the
scanner's existing memory and depth limits.

## Historical Nix Usage

Any store path or `result` link works, and you can give more than one. Each output line is one embedded trust store:

```
osquery-5.23.1   /share/osquery/certs/certs.pem   135 roots   ECC G3,AAA
```

- "ECC G3" means the store trusts `emSign ECC Root CA - G3`, the root on the compromised eMudhra path.
- "AAA" means it trusts Sectigo `AAA Certificate Services`, which cross-signs the same intermediates.
- Copies of the nixpkgs `cacert` bundle are left out.
- A hit means the bundle is in the package, not that the program uses it. For example, nixpkgs `nodejs` embeds roots but uses the system store by default.

Add `--json` for the raw scanner output (one JSON object per file). To scan a directory without its closure, use `nix shell github:zimbatm/nix-cacert-scan -c cacert-scan --path DIR`.

On 2026-10-18/19, eMudhra and Sectigo revoked the certificates of eight eMudhra intermediates as compromised (cACompromise in CCADB).
A package with its own trust store does not get root-store updates from `cacert`.
Each package below must be patched to use `cacert`, or rebuilt.

The scan covers all 209,053 NARs of NixOS 26.05 (`nixos-26.05.12250.f3a73bcf5d1c`) from cache.nixos.org.
828 packages need a fix. Some need more than one, so the list has 882 entries. See [RESULTS.md](RESULTS.md) for the analysis and [DETECTION.md](DETECTION.md) for the method.

"ECC G3" marks a store that holds `emSign ECC Root CA - G3`, the root on the compromised path.
"Stale bundle" marks a store older than the emSign roots; it is out of date for other reasons too.
"Trusts AAA" marks a store that trusts Sectigo `AAA Certificate Services` as a root. AAA cross-signed the eight compromised intermediates (valid until 2028), so such a store is affected even when it is stale and has no ECC G3.
