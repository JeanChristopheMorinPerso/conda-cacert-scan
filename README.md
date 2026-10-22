# cacert-scan

Finds Conda packages that carry their own CA trust store. The Rust scanner uses
rattler to extract packages into temporary disk storage and scan their contents.

## Conda Usage

Development uses Pixi on macOS ARM64:

```sh
pixi install
pixi run build
pixi run test
```

Scan the latest packages in a channel with the resumable Bash runner:

```sh
JOBS=8 pixi run bash scripts/run.sh out/conda-forge https://conda.anaconda.org/conda-forge --subdirs osx-arm64 noarch --temp-dir ./scratch
JOBS=8 pixi run bash scripts/run.sh out/filtered https://conda.anaconda.org/conda-forge --subdirs osx-arm64 noarch --include packages.txt --temp-dir ./scratch
pixi run scan list https://conda.anaconda.org/conda-forge --subdirs linux-64 noarch
pixi run scan scan https://conda.anaconda.org/conda-forge/noarch/ca-certificates-2026.10.19-hbd8a1cb_0.conda --temp-dir ./scratch
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

The closure helper, analysis/report scripts, checked-in reports, and usage below
are historical Nix workflows. The analysis scripts are not yet compatible with
the Conda `package` output field; the batch runner and retry scripts above are ported.

## Historical Nix Usage

Scan the closure of your running system:

```
nix run github:zimbatm/nix-cacert-scan -- /run/current-system
```

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

## Use

```
nix build                                   # or: cargo build --release
./result/bin/cacert-scan --roots patterns/roots.pem --watch patterns/watch.pem --path /nix/store/...-foo
nix develop -c scripts/run.sh out nixos-26.05   # whole release; needs about 2 h on 48 cores
python3 scripts/analyze.py out report
python3 tools/package-list.py report/findings.tsv
```

`scripts/run.sh` expects the scanner at `target/release/cacert-scan` (`cargo build --release`).

## Packages to patch

Generated by `tools/package-list.py` from [report/findings.tsv](report/findings.tsv).
Python and Ruby packages are listed once for all interpreter versions.
### Vendored PEM bundle (95)

Fix: Replace the file with a symlink to `${cacert}/etc/ssl/certs/ca-bundle.crt`, or point the program at it.

- [ ] **akkoma** — `/lib/castore-1.0.17/priv/cacerts.pem` (+1 more)
- [ ] **anki** — `/lib/python3.13/site-packages/pip/_vendor/certifi/cacert.pem`
- [ ] **ansible-language-server** — `/lib/node_modules/ansible-language-server/node_modules/@vscode/vsce-sign-darwin-x64/bin/vsce-sign` (+3 more) · trusts AAA
- [ ] **arduino-core** — `/share/arduino/tools/WiFi101/tool/firmwares/NINA/1.1.0/NINA_W102.bin` (+32 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **autenticacao-gov-pt-bin** — `/app/share/certs/cacerts.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **autopsy** — `/autopsy/plaso/plaso-20180818-Win32/certifi/cacert.pem` (+2 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **awscli2** — `/lib/python3.13/site-packages/awscli/botocore/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **azure-functions-core-tools** — `/lib/azure-functions-core-tools/workers/powershell/7/Grpc.Core.dll` (+6 more) · trusts AAA
- [ ] **bazarr** — `/share/bazarr/libs/certifi/cacert.pem`
- [ ] **blink-qt** — `/share/blink/tls/ca.crt` · trusts AAA
- [ ] **box** — `/share/php/box/fixtures/build/dir019/composer.phar` (+2 more) · trusts AAA
- [ ] **castopod** — `/share/castopod/vendor/composer/ca-bundle/res/cacert.pem` · trusts AAA
- [ ] **castor** — `/share/php/castor/vendor/composer/ca-bundle/res/cacert.pem`
- [ ] **cheating-daddy** — `/share/cheating-daddy/resources/app.asar` · trusts AAA
- [ ] **civicrm** — `/civicrm/vendor/totten/ca-config/src/CA/Config/cacert.pem` · trusts AAA
- [ ] **composer** — `/share/php/composer/vendor/composer/ca-bundle/res/cacert.pem`
- [ ] **cudatext** — `/share/cudatext/py/sys/certifi/cacert.pem` · trusts AAA
- [ ] **cypress** — `/opt/cypress/browser_v8_context_snapshot.bin` · stale bundle, no ECC G3 · trusts AAA
- [ ] **dolibarr** — `/htdocs/includes/geoip2/geoip2.phar` (+1 more) · trusts AAA
- [ ] **dotnet-repl** — `/lib/dotnet-repl/.store/dotnet-repl/0.3.250/dotnet-repl/0.3.250/dotnet-repl.nupkg` (+3 more) · trusts AAA
- [ ] **dotnet-vmr** — `/lib/dotnet-sdk-8.0.131-linux-x64/sdk/8.0.131/trustedroots/codesignctl.pem` (+19 more) · trusts AAA
- [ ] **eddie** — `/share/eddie-ui/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **equibop** — `/opt/Equibop/resources/app.asar`
- [ ] **flyspray** — `/share/php/flyspray/vendor/guzzle/guzzle/src/Guzzle/Http/Resources/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **freefilesync** — `/Resources/cacert.pem`
- [ ] **gam** — `/lib/python3.13/site-packages/gam/cacerts.pem` · stale bundle, no ECC G3
- [ ] **gnustep-base** — `/lib/GNUstep/Libraries/gnustep-base/Versions/1.29/Resources/GSTLS/ca-certificates.crt` · stale bundle, no ECC G3 · trusts AAA
- [ ] **google-app-engine-go-sdk** — `/share/go_appengine/lib/cacerts/cacerts.txt` (+5 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **gpac** — `/share/gpac/res/ca-bundle.crt` · trusts AAA
- [ ] **grav** — `/bin/composer.phar` (+1 more) · trusts AAA
- [ ] **grpc** — `/share/grpc/roots.pem` · trusts AAA
- [ ] **gsoap** — `/share/gsoap/plugin/cacerts.c` · trusts AAA
- [ ] **h2o** — `/share/h2o/ca-bundle.crt` · trusts AAA
- [ ] **headphones** — `/opt/headphones/lib/certifi/cacert.pem` · trusts AAA
- [ ] **httptoolkit** — `/share/httptoolkit/resources/app.asar` · trusts AAA
- [ ] **invoiceplane** — `/application/config/cacert.pem` (+1 more) · trusts AAA
- [ ] **it-tools** — `/lib/assets/pdf-signature-checker-420532d1.js` · trusts AAA
- [ ] **itgmania** — `/itgmania/Data/ca-bundle.crt` · trusts AAA
- [ ] **ivette** — `/share/lib/ivette/resources/app.asar` · trusts AAA
- [ ] **julia** — `/share/julia/cert.pem` · trusts AAA
- [ ] **julia-bin** — `/share/julia/cert.pem` · trusts AAA
- [ ] **kodi** — `/share/kodi/system/certs/cacert.pem`
- [ ] **liblinphone** — `/share/linphone/rootca.pem` · trusts AAA
- [ ] **libressl** — `/etc/ssl/cert.pem`
- [ ] **logstash-oss** — `/logstash-core/lib/logstash/certs/cacert.pem` (+3 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **matomo** — `/share/vendor/composer/ca-bundle/res/cacert.pem`
- [ ] **mobilizon** — `/lib/castore-1.0.18/priv/cacerts.pem` (+1 more)
- [ ] **modsecurity** — `/iis/curl-ca-bundle.crt` · stale bundle, no ECC G3 · trusts AAA
- [ ] **monica** — `/vendor/composer/ca-bundle/res/cacert.pem` (+1 more) · trusts AAA
- [ ] **moodle** — `/share/moodle/public/lib/cacert.pem` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **movim** — `/share/php/movim/vendor/composer/ca-bundle/res/cacert.pem`
- [ ] **mstflint** — `/etc/mstflint/ca-bundle.crt` · trusts AAA
- [ ] **n98-magerun2** — `/share/php/n98-magerun2/vendor/rmccue/requests/certificates/cacert.pem`
- [ ] **netsurf** — `/share/ca-bundle.txt` · trusts AAA
- [ ] **nextcloud** — `/resources/config/ca-bundle.crt`
- [ ] **nmap** — `/share/ncat/ca-bundle.crt` · stale bundle, no ECC G3 · trusts AAA
- [ ] **osquery** — `/share/osquery/certs/certs.pem` · trusts AAA
- [ ] **part-db** — `/vendor/composer/ca-bundle/res/cacert.pem`
- [ ] **pgsql-tools** — `/lib/pgsql-tools/_internal/certifi/cacert.pem`
- [ ] **pinchflat** — `/lib/castore-1.0.14/priv/cacerts.pem` (+1 more)
- [ ] **pipenv** — `/lib/python3.13/site-packages/pipenv/patched/pip/_vendor/certifi/cacert.pem`
- [ ] **plausible** — `/lib/castore-1.0.16/priv/cacerts.pem` (+1 more)
- [ ] **pleroma** — `/lib/castore-1.0.15/priv/cacerts.pem` (+1 more) · trusts AAA
- [ ] **polar-bookshelf1** — `/share/polar-bookshelf/resources/app.asar` · trusts AAA
- [ ] **poptracker** — `/share/poptracker/cacert.pem`
- [ ] **pur** — `/lib/python3.13/site-packages/pur/packages/pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **python3Packages.aliyun-python-sdk-core** — `/lib/python3.13/site-packages/aliyunsdkcore/vendored/requests/packages/certifi/cacert.pem` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.botocore** — `/lib/python3.13/site-packages/botocore/cacert.pem` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.cryptodatahub** — `/lib/python3.13/site-packages/cryptodatahub/common/root-certificate.json` (+1 more) · trusts AAA
- [ ] **python3Packages.grpcio** — `/lib/python3.13/site-packages/grpc/_cython/_credentials/roots.pem` (+1 more) · trusts AAA
- [ ] **python3Packages.httplib2** — `/lib/python3.13/site-packages/httplib2/cacerts.txt` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.mscerts** — `/lib/python3.13/site-packages/mscerts/cacert.pem` (+1 more) · trusts AAA
- [ ] **python3Packages.pex** — `/lib/python3.13/site-packages/pex/vendor/_vendored/pip/pip/_vendor/certifi/cacert.pem` (+1 more) · trusts AAA
- [ ] **python3Packages.pip** — `/lib/python3.13/site-packages/pip/_vendor/certifi/cacert.pem` (+1 more)
- [ ] **python3Packages.raven** — `/lib/python3.13/site-packages/raven/data/cacert.pem` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.stripe** — `/lib/python3.13/site-packages/stripe/data/ca-certificates.crt` (+1 more)
- [ ] **python3Packages.wassima** — `/lib/python3.13/site-packages/wassima/_os/_embed.py` (+5 more)
- [ ] **rainloop-community** — `/rainloop/v/1.16.0/app/libraries/tmhOAuth/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **renpy** — `/share/renpy/lib/python3.12/certifi/cacert.pem`
- [ ] **roave-backward-compatibility-check** — `/share/php/roave-backward-compatibility-check/vendor/composer/ca-bundle/res/cacert.pem`
- [ ] **rubyPackages.algoliasearch** — `/lib/ruby/gems/3.3.0/gems/algoliasearch-1.27.5/resources/ca-bundle.crt` (+2 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **rubyPackages.certified** — `/lib/ruby/gems/3.3.0/gems/certified-1.0.0/certs/ca-bundle.crt` (+2 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **rubyPackages.excon** — `/lib/ruby/gems/3.3.0/gems/excon-1.3.1/data/cacert.pem` (+2 more)
- [ ] **rubyPackages.httpclient** — `/lib/ruby/gems/3.3.0/gems/httpclient-2.9.0/lib/httpclient/cacert.pem` (+5 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **rubyPackages.nap** — `/lib/ruby/gems/3.3.0/gems/nap-1.1.0/support/cacert.pem` (+2 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **sickgear** — `/opt/sickgear/lib/certifi/cacert.pem`
- [ ] **supertuxkart** — `/share/supertuxkart/data/cacert.pem` · trusts AAA
- [ ] **tautulli** — `/libexec/tautulli/lib/certifi/cacert.pem`
- [ ] **testssl.sh** — `/etc/Java.pem` (+4 more) · trusts AAA
- [ ] **vscode-extension-tsyesika-guile-scheme-enhanced** — `/share/vscode/extensions/tsyesika.guile-scheme-enhanced/node_modules/node/bin/node` (+2 more) · trusts AAA
- [ ] **wordpress** — `/share/wordpress/wp-includes/certificates/ca-bundle.crt`
- [ ] **wordpress-plugin-hcaptcha-for-forms-and-more** — `/vendor/composer/ca-bundle/res/cacert.pem`
- [ ] **wordpress-plugin-wpforms-lite** — `/vendor_prefixed/stripe/stripe-php/data/ca-certificates.crt` · trusts AAA
- [ ] **wp-cli** — `/share/wp-cli/wp-cli.phar` · trusts AAA
- [ ] **zoneminder** — `/share/zoneminder/www/api/lib/Cake/Config/cacert.pem` · stale bundle, no ECC G3 · trusts AAA

### Bundle inside a wheel, jar or zip (88)

Fix: Patch the bundle inside the archive at build time, or patch the code to use the system store.

- [ ] **apache-druid** — `/lib/google-api-client-2.2.0.jar!com/google/api/client/googleapis/google.jks` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **archipelago** — `/lib/opt/Archipelago/lib/library.zip!certifi/cacert.pem`
- [ ] **autopsy** — `/autopsy/modules/ext/google-api-client-2.7.0.jar!com/google/api/client/googleapis/google.jks` (+1 more) · trusts AAA
- [ ] **awscli2** — `/awscli-2.34.24-py3-none-any.whl!awscli/botocore/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **biglybt** — `/share/biglybt/plugins/aercm/aercm_1.4.1.jar!com/aelitis/plugins/rcmplugin/resources/cacerts.def` · stale bundle, no ECC G3 · trusts AAA
- [ ] **blink-qt** — `/blink-6.0.6-cp313-cp313-linux_x86_64.whl!blink-6.0.6.data/data/share/blink/tls/ca.crt` (+1 more) · trusts AAA
- [ ] **confluent-platform** — `/share/java/acl/acl-7.7.0.jar!com/google/api/client/googleapis/google.jks` (+3 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **cratedb** — `/lib/google-api-client-1.30.10.jar!com/google/api/client/googleapis/google.jks` (+1 more) · trusts AAA
- [ ] **dependency-track** — `/share/dependency-track/dependency-track.jar!WEB-INF/lib/google-api-client-2.9.0.jar!com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **dotnet-repl** — `/lib/dotnet-repl/.store/dotnet-repl/0.3.250/dotnet-repl/0.3.250/dotnet-repl.nupkg!tools/net9.0/any/.playwright/node/mac/node` (+7 more) · trusts AAA
- [ ] **eclipse-committers** — `/eclipse/plugins/org.eclipse.wildwebdeveloper.embedder.node.linux.x86_64_1.1.7.202510292239.jar!resources/node-v22.21.1-linux-x64.tar.gz!gunzip` (+3 more)
- [ ] **eclipse-jee** — `/eclipse/plugins/org.eclipse.wildwebdeveloper.embedder.node.linux.x86_64_1.1.7.202510292239.jar!resources/node-v22.21.1-linux-x64.tar.gz!gunzip` (+3 more)
- [ ] **fiji** — `/fiji/jars/google-api-client-2.7.0.jar!com/google/api/client/googleapis/google.jks` (+1 more) · trusts AAA
- [ ] **flink** — `/opt/flink/opt/flink-gs-fs-hadoop-2.2.0.jar!com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **flyway** — `/share/flyway/drivers/snowflake-jdbc-3.27.0.jar!net/snowflake/client/jdbc/internal/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **freerouting** — `/share/freerouting/freerouting-executable.jar!com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **gam** — `/gam7-7.21.1-py3-none-any.whl!gam/cacerts.pem` · stale bundle, no ECC G3
- [ ] **gatk** — `/bin/gatk-package-4.6.2.0-local.jar!com/google/api/client/googleapis/google.jks` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **ghidra** — `/lib/ghidra/Ghidra/Features/Jython/data/jython-2.7.4/Lib/ensurepip/_bundled/pip-19.1-py2.py3-none-any.whl!pip/_vendor/certifi/cacert.pem` (+1 more) · trusts AAA
- [ ] **graalpy** — `/lib/python3.12/ensurepip/_bundled/pip-24.3.1-py3-none-any.whl!pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **gradle** — `/libexec/gradle/lib/plugins/google-api-client-1.34.0.jar!com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **isabelle** — `/Isabelle2025-2/contrib/vscode_extension-20251205/isabelle-2.0.0.vsix!extension/node-v22.18.0-linux-x64/bin/node` · trusts AAA
- [ ] **jabref** — `/lib/jablib.jar!ssl/truststore.jks` (+4 more) · trusts AAA
- [ ] **jadx** — `/lib/jadx-1.5.6-all.jar!libj2v8_linux_x86_64.so` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **janusgraph** — `/share/janusgraph/bigtable-hbase-2.x-shaded-1.24.0.jar!com/google/bigtable/repackaged/com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **jigasi** — `/share/jigasi/lib/google-api-client-1.34.0.jar!com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **jython** — `/jython.jar!Lib/ensurepip/_bundled/pip-19.1-py2.py3-none-any.whl!pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **maestro** — `/lib/selenium-manager-4.40.0.jar!org/openqa/selenium/manager/linux/selenium-manager` (+2 more)
- [ ] **maptool** — `/share/maptool/webrtc-java-0.9.0-linux-x86_64.jar!libwebrtc-java.so` · stale bundle, no ECC G3 · trusts AAA
- [ ] **mission-planner** — `/opt/mission-planner/lib/ensurepip/_bundled/pip-18.1-py2.py3-none-any.whl!pip/_vendor/certifi/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **mucommander** — `/share/mucommander/bundle/mucommander-protocol-gcs-1.5.2.jar!com/google/api/client/googleapis/google.jks` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **nifi** — `/lib/nifi-gcp-nar-1.28.1.nar!META-INF/bundled-dependencies/google-api-client-2.7.0.jar!com/google/api/client/googleapis/google.jks` (+1 more) · trusts AAA
- [ ] **nzbhydra2** — `/lib/nzbhydra2/lib/core-8.8.1-exec.jar!BOOT-INF/classes/cacerts` · stale bundle, no ECC G3 · trusts AAA
- [ ] **openrefine** — `/lib/webapp/extensions/jython/module/MOD-INF/lib/jython-standalone-2.7.4.jar!Lib/ensurepip/_bundled/pip-19.1-py2.py3-none-any.whl!pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **opensearch** — `/plugins/opensearch-ml/tokenizers-0.31.1.jar!native/lib/win-x86_64/cpu/tokenizers.dll` (+3 more) · trusts AAA
- [ ] **pacu** — `/pacu-1.6.2-py3-none-any.whl!pacu/modules/iam__privesc_scan/lambda.zip!pip/_vendor/certifi/cacert.pem` (+3 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **picard-tools** — `/libexec/picard/picard.jar!com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **pig** — `/lib/jython-standalone-2.7.0.jar!Lib/ensurepip/_bundled/pip-1.6-py2.py3-none-any.whl!pip/_vendor/requests/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **pipenv** — `/pipenv-2026.5.1-py3-none-any.whl!pipenv/patched/pip/_vendor/certifi/cacert.pem`
- [ ] **pur** — `/pur-7.4.0-py3-none-any.whl!pur/packages/pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **pypy** — `/lib-python/2.7/ensurepip/_bundled/pip-20.0.2-py2.py3-none-any.whl!pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **pypy3.10** — `/lib-python/3/ensurepip/_bundled/pip-23.0.1-py3-none-any.whl!pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **pypy3.11** — `/lib-python/3/ensurepip/_bundled/pip-24.0-py3-none-any.whl!pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **python3** — `/lib/python3.11/ensurepip/_bundled/pip-24.0-py3-none-any.whl!pip/_vendor/certifi/cacert.pem` (+7 more) · trusts AAA
- [ ] **python3-minimal** — `/lib/python3.13/ensurepip/_bundled/pip-26.2.1-py3-none-any.whl!pip/_vendor/certifi/cacert.pem`
- [ ] **python3Packages.aliyun-python-sdk-core** — `/aliyun_python_sdk_core-2.16.0-py3-none-any.whl!aliyunsdkcore/vendored/requests/packages/certifi/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.botocore** — `/botocore-1.42.31-py3-none-any.whl!botocore/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.cryptodatahub** — `/cryptodatahub-1.5.0-py3-none-any.whl!cryptodatahub/common/root-certificate.json` · trusts AAA
- [ ] **python3Packages.css-inline** — `/css_inline-0.20.2-cp39-abi3-linux_x86_64.whl!css_inline/css_inline.abi3.so` (+1 more)
- [ ] **python3Packages.deltalake** — `/deltalake-1.4.2-cp310-abi3-linux_x86_64.whl!deltalake/_internal.abi3.so` (+1 more)
- [ ] **python3Packages.grpcio** — `/grpcio-1.80.0-cp313-cp313-linux_x86_64.whl!grpc/_cython/_credentials/roots.pem` (+3 more) · trusts AAA
- [ ] **python3Packages.httplib2** — `/httplib2-0.32.0-py3-none-any.whl!httplib2/cacerts.txt` · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.kaleido** — `/kaleido-0.2.1-py2.py3-none-manylinux1_x86_64.whl!kaleido/executable/bin/kaleido` (+3 more) · trusts AAA
- [ ] **python3Packages.lancedb** — `/lancedb-0.32.0-cp39-abi3-linux_x86_64.whl!lancedb/_lancedb.abi3.so` (+1 more)
- [ ] **python3Packages.mscerts** — `/mscerts-2026.4.30-py3-none-any.whl!mscerts/cacert.pem` · trusts AAA
- [ ] **python3Packages.onepassword-sdk** — `/onepassword_sdk-0.4.0-cp313-cp313-linux_x86_64.whl!onepassword_sdk-0.4.0.data/purelib/onepassword/lib/x86_64/libop_uniffi_core.so` (+3 more)
- [ ] **python3Packages.openai-harmony** — `/openai_harmony-0.0.8-cp38-abi3-linux_x86_64.whl!openai_harmony/openai_harmony.abi3.so` (+1 more) · trusts AAA
- [ ] **python3Packages.opendal** — `/opendal-0.45.2-cp313-cp313-linux_x86_64.whl!opendal/_opendal.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.outlines-core** — `/outlines_core-0.2.14-cp313-cp313-linux_x86_64.whl!outlines_core/outlines_core.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.pdf-oxide** — `/pdf_oxide-0.3.47-cp38-abi3-linux_x86_64.whl!pdf_oxide/pdf_oxide.abi3.so` (+1 more)
- [ ] **python3Packages.pex** — `/pex-2.38.1-py2.py3-none-any.whl!pex/vendor/_vendored/pip/pip/_vendor/certifi/cacert.pem` · trusts AAA
- [ ] **python3Packages.pip** — `/pip-25.3-py3-none-any.whl!pip/_vendor/certifi/cacert.pem`
- [ ] **python3Packages.primp** — `/primp-1.3.0-cp310-abi3-linux_x86_64.whl!primp/primp.abi3.so` (+1 more)
- [ ] **python3Packages.pyiceberg-core** — `/pyiceberg_core-0.9.1-cp310-abi3-linux_x86_64.whl!pyiceberg_core/pyiceberg_core_rust.abi3.so` (+1 more)
- [ ] **python3Packages.pylance** — `/pylance-6.0.1-cp39-abi3-linux_x86_64.whl!lance/lance.abi3.so` (+1 more)
- [ ] **python3Packages.pywebtransport** — `/pywebtransport-0.16.1-cp312-abi3-linux_x86_64.whl!pywebtransport/_wtransport.abi3.so` (+1 more)
- [ ] **python3Packages.qcs-api-client-common** — `/qcs_api_client_common-0.15.0-cp313-cp313-linux_x86_64.whl!qcs_api_client_common/_qcs_api_client_common.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.qcs-sdk-python** — `/qcs_sdk_python-0.26.1-cp313-cp313-linux_x86_64.whl!qcs_sdk/_qcs_sdk.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.raven** — `/raven-6.10.0-py2.py3-none-any.whl!raven/data/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.rerun-sdk** — `/rerun_sdk-0.32.2-cp310-abi3-linux_x86_64.whl!rerun_bindings/rerun_bindings.abi3.so` (+1 more)
- [ ] **python3Packages.solders** — `/solders-0.27.1-cp38-abi3-linux_x86_64.whl!solders/solders.abi3.so` (+1 more)
- [ ] **python3Packages.stripe** — `/stripe-15.1.0-py3-none-any.whl!stripe/data/ca-certificates.crt`
- [ ] **python3Packages.tree-sitter-language-pack** — `/tree_sitter_language_pack-1.4.1-cp310-abi3-linux_x86_64.whl!tree_sitter_language_pack/_native.abi3.so` (+1 more)
- [ ] **python3Packages.vegafusion** — `/vegafusion-2.0.3-cp39-abi3-linux_x86_64.whl!vegafusion/_vegafusion.abi3.so` (+1 more)
- [ ] **python3Packages.virtualenv** — `/lib/python3.13/site-packages/virtualenv/seed/wheels/embed/pip-25.3-py3-none-any.whl!pip/_vendor/certifi/cacert.pem` (+5 more) · trusts AAA
- [ ] **python3Packages.vl-convert-python** — `/vl_convert_python-1.9.0-cp37-abi3-linux_x86_64.whl!vl_convert/vl_convert.abi3.so` (+1 more) · trusts AAA
- [ ] **python3Packages.wasmtime** — `/wasmtime-45.0.0-py3-none-any.whl!wasmtime/linux-x86_64/_libwasmtime.so` (+1 more) · trusts AAA
- [ ] **python3Packages.wassima** — `/wassima-2.1.0-py3-none-any.whl!wassima/_os/_embed.py`
- [ ] **python3Packages.zenoh** — `/eclipse_zenoh-1.9.0-cp39-abi3-linux_x86_64.whl!zenoh/zenoh.abi3.so` (+1 more)
- [ ] **quantomatic** — `/libexec/quantomatic/quantomatic.jar!Lib/ensurepip/_bundled/pip-1.6-py2.py3-none-any.whl!pip/_vendor/requests/cacert.pem` · stale bundle, no ECC G3 · trusts AAA
- [ ] **renode** — `/lib/renode/Lib/ensurepip/_bundled/pip-19.2.3-py2.py3-none-any.whl!pip/_vendor/certifi/cacert.pem` (+12 more) · trusts AAA
- [ ] **renode-unstable** — `/libexec/renode/bin/Lib/ensurepip/_bundled/pip-19.2.3-py2.py3-none-any.whl!pip/_vendor/certifi/cacert.pem` (+12 more) · trusts AAA
- [ ] **schemacrawler** — `/lib/snowflake-jdbc-4.0.1.jar!net/snowflake/client/jdbc/internal/google/api/client/googleapis/google.jks` (+1 more) · trusts AAA
- [ ] **spotube** — `/share/spotube/data/flutter_assets/packages/flutter_new_pipe_extractor/assets/NewPipeCLI-linux-x64.zip!NewPipeCLI` (+1 more) · trusts AAA
- [ ] **stirling-pdf** — `/share/stirling-pdf/Stirling-PDF.jar!BOOT-INF/classes/certdata.txt` · trusts AAA
- [ ] **stirling-pdf-desktop** — `/lib/Stirling PDF/libs/stirling-pdf-2.14.3.jar!BOOT-INF/classes/certdata.txt` · trusts AAA
- [ ] **traccar** — `/lib/google-api-client-2.7.2.jar!com/google/api/client/googleapis/google.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **zap** — `/share/zap/plugin/webdriverlinux-release-169.zap!webdriver/linux/64/chromedriver` (+3 more)

### Java keystore (37)

Fix: Generate the keystore from `${cacert}/etc/ssl/certs/ca-bundle.crt` at build time with `jre-generate-cacerts`, as openjdk does. `cacert` has no Java keystore output.

- [ ] **corretto11** — `/lib/corretto/lib/security/cacerts` · trusts AAA
- [ ] **corretto17** — `/lib/corretto/lib/security/cacerts` · trusts AAA
- [ ] **corretto21** — `/lib/corretto/lib/security/cacerts` · trusts AAA
- [ ] **corretto25** — `/lib/corretto/lib/security/cacerts` · trusts AAA
- [ ] **eclipse-committers** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **eclipse-cpp** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **eclipse-dsl** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **eclipse-embedcpp** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **eclipse-java** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **eclipse-jee** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **eclipse-modeling** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **eclipse-rcp** — `/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.linux.x86_64_21.0.10.v20260205-0638/jre/lib/security/cacerts` (+1 more)
- [ ] **ed-odyssey-materials-helper** — `/share/ed-odyssey-materials-helper/lib/runtime/lib/security/cacerts` · trusts AAA
- [ ] **frostwire** — `/share/java/jre/lib/security/cacerts` · trusts AAA
- [ ] **graalvm-ce** — `/lib/security/cacerts` · trusts AAA
- [ ] **jabref** — `/share/java/jabref/resources/main/ssl/truststore.jks` · stale bundle, no ECC G3 · trusts AAA
- [ ] **java-language-server** — `/share/java/java-language-server/linux/lib/security/cacerts` · trusts AAA
- [ ] **jetbrains-jdk** — `/lib/openjdk/lib/security/cacerts` · trusts AAA
- [ ] **jetbrains-jdk-jcef** — `/lib/openjdk/lib/security/cacerts` · trusts AAA
- [ ] **jextract** — `/opt/jextract/runtime/lib/security/cacerts` · trusts AAA
- [ ] **olvid** — `/lib/security/cacerts` · trusts AAA
- [ ] **openjdk** — `/lib/openjdk/lib/security/cacerts` (+1 more) · trusts AAA
- [ ] **openjdk-headless** — `/lib/openjdk/lib/security/cacerts` (+1 more) · trusts AAA
- [ ] **openjdk-minimal-jre** — `/lib/security/cacerts` · trusts AAA
- [ ] **processing** — `/lib/runtime/lib/security/cacerts` · trusts AAA
- [ ] **schildi-revenge** — `/lib/runtime/lib/security/cacerts` · trusts AAA
- [ ] **scilab-bin** — `/thirdparty/java/lib/security/cacerts` · trusts AAA
- [ ] **semeru-bin** — `/lib/security/cacerts` (+1 more) · trusts AAA
- [ ] **semeru-jre-bin** — `/lib/security/cacerts` · trusts AAA
- [ ] **stirling-pdf-desktop** — `/lib/Stirling PDF/runtime/jre/lib/security/cacerts` · trusts AAA
- [ ] **temurin-bin** — `/lib/security/cacerts` (+1 more)
- [ ] **temurin-jre-bin** — `/lib/security/cacerts`
- [ ] **tlaplus-toolbox** — `/libexec/toolbox/plugins/org.lamport.openjdk.linux.x86_64_14.0.1.7/jre/lib/security/cacerts` · stale bundle, no ECC G3 · trusts AAA
- [ ] **tracecompass** — `/trace-compass/plugins/org.eclipse.justj.openjdk.hotspot.jre.minimal.stripped.linux.x86_64_21.0.9.v20251105-0741/jre/lib/security/cacerts`
- [ ] **vscode-extension-valentjn-vscode-ltex** — `/share/vscode/extensions/valentjn.vscode-ltex/lib/ltex-ls-15.2.0/jdk-11.0.12+7/lib/security/cacerts` · trusts AAA
- [ ] **weasis** — `/opt/Weasis/lib/runtime/lib/security/cacerts` · trusts AAA
- [ ] **zulu-ca-jdk** — `/lib/security/cacerts` (+1 more) · trusts AAA

### Compiled into a binary (662)

Fix: Rebuild with a system-store option (rustls-native-certs, `--use-system-ca`, NSS from cacert), or bump the embedded root crate.

- [ ] **64gram** — `/bin/.Telegram-wrapped` · stale bundle, no ECC G3 · trusts AAA
- [ ] **BoilR** — `/bin/boilr` · trusts AAA
- [ ] **MozWire** — `/bin/mozwire` · trusts AAA
- [ ] **adguardian** — `/bin/adguardian` · trusts AAA
- [ ] **agent-browser** — `/bin/agent-browser`
- [ ] **agnos** — `/bin/agnos` · trusts AAA
- [ ] **aichat** — `/bin/aichat`
- [ ] **airgorah** — `/bin/.airgorah-wrapped`
- [ ] **airshipper** — `/bin/.airshipper-wrapped`
- [ ] **alfis** — `/bin/alfis` (+1 more)
- [ ] **alistral** — `/bin/alistral`
- [ ] **alvr** — `/bin/alvr_launcher` (+4 more) · trusts AAA
- [ ] **amazon-q-cli** — `/bin/amazon-q` · trusts AAA
- [ ] **anchor** — `/bin/anchor`
- [ ] **anda** — `/bin/anda`
- [ ] **anki** — `/lib/python3.13/site-packages/anki/_rsbridge.so`
- [ ] **ansible-language-server** — `/lib/node_modules/ansible-language-server/node_modules/@vscode/vsce-sign-linux-x64/bin/vsce-sign` (+4 more) · trusts AAA
- [ ] **anup** — `/bin/anup` · trusts AAA
- [ ] **anyrun** — `/lib/librink.so` (+3 more) · trusts AAA
- [ ] **aphorme** — `/bin/aphorme`
- [ ] **apt-swarm** — `/bin/apt-swarm`
- [ ] **argon** — `/bin/argon` · trusts AAA
- [ ] **artem** — `/bin/artem` · trusts AAA
- [ ] **astro-language-server** — `/lib/node_modules/astro-language-server/node_modules/.pnpm/turbo-linux-64@2.8.15/node_modules/turbo-linux-64/bin/turbo` (+1 more)
- [ ] **attic** — `/bin/attic` (+1 more)
- [ ] **atuin** — `/bin/atuin-server`
- [ ] **atuin-desktop** — `/bin/.atuin-desktop-wrapped`
- [ ] **aube** — `/bin/aube` (+2 more)
- [ ] **autocorrect** — `/bin/autocorrect` · trusts AAA
- [ ] **autopush** — `/bin/autoconnect` (+1 more)
- [ ] **ayugram-desktop** — `/bin/.AyuGram-wrapped` · stale bundle, no ECC G3 · trusts AAA
- [ ] **babashka-unwrapped** — `/bin/bb` · trusts AAA
- [ ] **basedpyright** — `/lib/node_modules/pyright-root/node_modules/@vscode/vsce-sign/bin/vsce-sign` (+2 more) · trusts AAA
- [ ] **beekeeper-studio** — `/opt/beekeeper-studio/beekeeper-studio-bin` · trusts AAA
- [ ] **bencher-cli** — `/bin/bencher`
- [ ] **bibiman** — `/bin/bibiman`
- [ ] **biliup-rs** — `/bin/biliup` (+1 more) · trusts AAA
- [ ] **bleep** — `/bin/bleep` · trusts AAA
- [ ] **blightmud** — `/bin/blightmud`
- [ ] **blocky** — `/bin/blocky`
- [ ] **bloop** — `/.bloop-wrapped` · stale bundle, no ECC G3 · trusts AAA
- [ ] **bmputil** — `/bin/bmputil-cli`
- [ ] **brave** — `/opt/brave.com/brave/brave` · trusts AAA
- [ ] **brave-search-cli** — `/bin/bx`
- [ ] **brush-splat** — `/bin/brush_app`
- [ ] **buck2-unstable** — `/bin/buck2`
- [ ] **buckle** — `/bin/buckle` · trusts AAA
- [ ] **buildkite-test-collector-rust** — `/bin/buildkite-test-collector` · trusts AAA
- [ ] **bun** — `/bin/bun`
- [ ] **buttplug-lite** — `/bin/.buttplug-lite-wrapped`
- [ ] **c2patool** — `/bin/c2patool` (+3 more)
- [ ] **caddy** — `/bin/caddy`
- [ ] **cantus** — `/bin/cantus`
- [ ] **cargo-aoc** — `/bin/cargo-aoc` · trusts AAA
- [ ] **cargo-component** — `/bin/cargo-component` · trusts AAA
- [ ] **cargo-deadlinks** — `/bin/deadlinks` (+1 more) · trusts AAA
- [ ] **cargo-edit** — `/bin/cargo-upgrade`
- [ ] **cargo-lambda** — `/bin/.cargo-lambda-wrapped` · trusts AAA
- [ ] **cargo-make** — `/bin/makers` (+1 more) · trusts AAA
- [ ] **cargo-mobile2** — `/bin/.cargo-mobile-wrapped` (+1 more) · trusts AAA
- [ ] **cargo-msrv** — `/bin/.cargo-msrv-wrapped`
- [ ] **cargo-nextest** — `/bin/cargo-nextest`
- [ ] **cargo-pgrx** — `/bin/cargo-pgrx` · trusts AAA
- [ ] **cargo-pio** — `/bin/cargo-pio` · trusts AAA
- [ ] **cargo-release** — `/bin/cargo-release`
- [ ] **cargo-risczero** — `/bin/cargo-risczero` · trusts AAA
- [ ] **cargo-shuttle** — `/bin/shuttle` (+1 more)
- [ ] **cargo-v5** — `/bin/cargo-v5`
- [ ] **cargo-vet** — `/bin/cargo-vet` · trusts AAA
- [ ] **cargo-wasi** — `/bin/cargo-wasi` · trusts AAA
- [ ] **cargo-workspaces** — `/bin/cargo-ws` (+1 more) · trusts AAA
- [ ] **cargo-xwin** — `/bin/cargo-xwin`
- [ ] **cef-binary** — `/Release/libcef.so` · trusts AAA
- [ ] **certificate-ripper** — `/bin/crip` · trusts AAA
- [ ] **cfspeedtest** — `/bin/cfspeedtest`
- [ ] **checkpwn** — `/bin/checkpwn`
- [ ] **cherrybomb** — `/bin/cherrybomb` · trusts AAA
- [ ] **chiptrack** — `/bin/.chiptrack-wrapped`
- [ ] **chromedriver-unwrapped** — `/bin/chromedriver`
- [ ] **ciel** — `/bin/ciel`
- [ ] **cilium-cli** — `/bin/cilium` · trusts AAA
- [ ] **cirrus-cli** — `/bin/cirrus`
- [ ] **clash-rs** — `/bin/clash-rs` (+2 more)
- [ ] **clash-verge-rev** — `/bin/.clash-verge-wrapped`
- [ ] **clashtui** — `/bin/clashtui` · trusts AAA
- [ ] **click** — `/bin/click` · trusts AAA
- [ ] **cliflux** — `/bin/cliflux` · trusts AAA
- [ ] **clj-kondo** — `/bin/clj-kondo` · trusts AAA
- [ ] **clojure-lsp** — `/bin/clojure-lsp` · trusts AAA
- [ ] **code** — `/bin/code` (+2 more)
- [ ] **code-server** — `/libexec/code-server/lib/node`
- [ ] **codeberg-cli** — `/bin/berg`
- [ ] **codebook** — `/bin/codebook-lsp`
- [ ] **codex** — `/bin/.codex-wrapped`
- [ ] **coinlive** — `/bin/coinlive`
- [ ] **comet-gog** — `/bin/comet` · trusts AAA
- [ ] **comigo** — `/bin/comigo` · stale bundle, no ECC G3
- [ ] **commet-chat** — `/app/commet-chat/lib/libwebrtc.so` · stale bundle, no ECC G3 · trusts AAA
- [ ] **commitlint** — `/lib/node_modules/@commitlint/root/node_modules/@nx/nx-linux-x64-gnu/nx.linux-x64-gnu.node` (+3 more) · trusts AAA
- [ ] **convoyeur** — `/bin/convoyeur`
- [ ] **cook-cli** — `/bin/cook`
- [ ] **cosmic-ext-applet-sysinfo** — `/bin/.cosmic-ext-applet-sysinfo-wrapped`
- [ ] **couchbase-shell** — `/bin/cbsh`
- [ ] **crates-lsp** — `/bin/crates-lsp`
- [ ] **css-variables-language-server** — `/lib/node_modules/turbo-linux-64/bin/turbo` (+4 more) · trusts AAA
- [ ] **cup-docker** — `/bin/cup` · trusts AAA
- [ ] **cyberia** — `/bin/.cyberia-wrapped`
- [ ] **cypress** — `/opt/cypress/Cypress` · trusts AAA
- [ ] **dart** — `/bin/dart` (+5 more) · trusts AAA
- [ ] **dart-sass** — `/bin/sass` · trusts AAA
- [ ] **ddns-updater** — `/bin/.ddns-updater-wrapped`
- [ ] **deadlock-mod-manager** — `/bin/.deadlock-mod-manager-wrapped`
- [ ] **deezer-enhanced** — `/lib/deezer-enhanced/deezer-enhanced` · trusts AAA
- [ ] **deltachat-repl** — `/bin/deltachat-repl` · trusts AAA
- [ ] **deltachat-rpc-server** — `/bin/deltachat-rpc-server` · trusts AAA
- [ ] **deltachat-tauri** — `/bin/.deltachat-tauri-wrapped`
- [ ] **deno** — `/bin/deno` · trusts AAA
- [ ] **devpod-desktop** — `/bin/.DevPod Desktop-wrapped`
- [ ] **dim** — `/bin/.dim-wrapped` · trusts AAA
- [ ] **dioxus-cli** — `/bin/.dx-wrapped`
- [ ] **diswall** — `/bin/diswall` · trusts AAA
- [ ] **dness** — `/bin/dness` · trusts AAA
- [ ] **domine-nightly** — `/bin/domine` · trusts AAA
- [ ] **dotenv-linter** — `/bin/dotenv-linter`
- [ ] **dotnet-repl** — `/lib/dotnet-repl/.store/dotnet-repl/0.3.250/dotnet-repl/0.3.250/tools/net9.0/any/.playwright/node/linux-x64/node` (+1 more) · trusts AAA
- [ ] **dprint** — `/bin/dprint` · trusts AAA
- [ ] **dsq** — `/bin/dsq` · trusts AAA
- [ ] **dtop** — `/bin/dtop`
- [ ] **ducker** — `/bin/ducker`
- [ ] **duckscript_cli** — `/bin/duck` · trusts AAA
- [ ] **dumbpipe** — `/bin/dumbpipe`
- [ ] **dump_syms** — `/bin/dump_syms`
- [ ] **easytier** — `/bin/easytier-web` (+1 more) · trusts AAA
- [ ] **eigenwallet** — `/bin/unstoppableswap-gui-rs` · trusts AAA
- [ ] **electron** — `/libexec/electron/electron` · trusts AAA
- [ ] **electron-chromedriver** — `/bin/chromedriver`
- [ ] **elm-test-rs** — `/bin/elm-test-rs`
- [ ] **eludris** — `/bin/eludris` · trusts AAA
- [ ] **emuflight-configurator** — `/share/emuflight-configurator/lib/libnw.so` (+1 more) · trusts AAA
- [ ] **en-croissant** — `/bin/.en-croissant-wrapped` · trusts AAA
- [ ] **equibop** — `/opt/Equibop/resources/arrpc/arrpc`
- [ ] **esp-generate** — `/bin/esp-generate`
- [ ] **espanso** — `/bin/.espanso-wrapped` · trusts AAA
- [ ] **espflash** — `/bin/espflash` (+1 more)
- [ ] **espup** — `/bin/espup`
- [ ] **evcc** — `/bin/evcc`
- [ ] **evebox** — `/bin/evebox` · trusts AAA
- [ ] **everest** — `/lib/Celeste/MiniInstaller-osx` (+15 more) · trusts AAA
- [ ] **fedigroups** — `/bin/fedigroups`
- [ ] **fedistar** — `/bin/.fedistar-wrapped`
- [ ] **ferium** — `/bin/ferium` · trusts AAA
- [ ] **fermyon-spin** — `/bin/spin` · trusts AAA
- [ ] **ferretdb** — `/bin/ferretdb` · trusts AAA
- [ ] **ferron** — `/bin/ferron`
- [ ] **ffizer** — `/bin/ffizer`
- [ ] **ffsend** — `/bin/ffsend` · trusts AAA
- [ ] **filen-cli** — `/bin/.filen-wrapped`
- [ ] **fim-rs** — `/bin/fim`
- [ ] **findomain** — `/bin/findomain`
- [ ] **firefox-beta-unwrapped** — `/lib/firefox-beta/libxul.so` · trusts AAA
- [ ] **firefox-devedition-unwrapped** — `/lib/firefox-devedition/libxul.so` · trusts AAA
- [ ] **firefox-unwrapped** — `/lib/firefox/libxul.so` · trusts AAA
- [ ] **firefoxpwa-unwrapped** — `/share/firefoxpwa/runtime/libxul.so` · trusts AAA
- [ ] **firezone-gateway** — `/bin/firezone-gateway`
- [ ] **firezone-gui-client** — `/bin/.firezone-client-gui-wrapped` (+1 more)
- [ ] **firezone-headless-client** — `/bin/firezone-headless-client`
- [ ] **firezone-relay** — `/bin/firezone-relay` · trusts AAA
- [ ] **firmware-manager** — `/lib/libfirmware_manager.so` (+2 more) · trusts AAA
- [ ] **fishnet** — `/bin/fishnet`
- [ ] **flake-edit** — `/bin/flake-edit`
- [ ] **fldigi** — `/bin/fldigi` · stale bundle, no ECC G3 · trusts AAA
- [ ] **fleet** — `/bin/fleet`
- [ ] **fleetctl** — `/bin/fleetctl`
- [ ] **fluffychat-linux** — `/app/fluffychat-linux/lib/libwebrtc.so` · stale bundle, no ECC G3 · trusts AAA
- [ ] **flux9s** — `/bin/flux9s`
- [ ] **fnm** — `/bin/fnm` · trusts AAA
- [ ] **folo** — `/share/follow/node_modules/.pnpm/@next+swc-linux-x64-gnu@16.0.11/node_modules/@next/swc-linux-x64-gnu/next-swc.linux-x64-gnu.node` (+6 more) · trusts AAA
- [ ] **foundry** — `/bin/cast` (+3 more)
- [ ] **frankenphp** — `/bin/.frankenphp-wrapped`
- [ ] **fresh** — `/bin/.fresh-wrapped`
- [ ] **fselect** — `/bin/fselect`
- [ ] **fvm** — `/bin/fvm` · trusts AAA
- [ ] **fzf-make** — `/bin/.fzf-make-wrapped`
- [ ] **g3proxy** — `/bin/g3proxy`
- [ ] **gale** — `/bin/.gale-wrapped`
- [ ] **game-rs** — `/bin/game-rs` · trusts AAA
- [ ] **gel** — `/bin/gel`
- [ ] **gen-license** — `/bin/gen-license` · trusts AAA
- [ ] **geph5** — `/bin/.geph5-exit-wrapped` (+3 more) · trusts AAA
- [ ] **gephgui-wry** — `/bin/.gephgui-wry-wrapped` · trusts AAA
- [ ] **gg** — `/bin/.gg-wrapped`
- [ ] **ghdump** — `/bin/ghdump`
- [ ] **git-cliff** — `/bin/git-cliff`
- [ ] **git-ignore** — `/bin/git-ignore` · trusts AAA
- [ ] **git-ps-rs** — `/bin/gps` · trusts AAA
- [ ] **gitbeaker-cli** — `/lib/node_modules/@nx/nx-linux-x64-gnu/nx.linux-x64-gnu.node` · trusts AAA
- [ ] **gitlab-duo** — `/bin/.duo-wrapped`
- [ ] **gitlab-workhorse** — `/bin/gitlab-zip-cat` (+2 more) · trusts AAA
- [ ] **go-migrate** — `/bin/migrate` · trusts AAA
- [ ] **gokrazy** — `/bin/gok`
- [ ] **golem** — `/bin/golem` (+2 more) · trusts AAA
- [ ] **goose-cli** — `/bin/goosed` (+1 more)
- [ ] **gotify-desktop** — `/bin/gotify-desktop`
- [ ] **goupile** — `/bin/goupile`
- [ ] **goxlr-utility** — `/bin/goxlr-client` (+2 more)
- [ ] **gptcommit** — `/bin/gptcommit` · trusts AAA
- [ ] **graaljs** — `/lib/libjsvm.so` · trusts AAA
- [ ] **graalnodejs** — `/bin/node` (+1 more) · trusts AAA
- [ ] **graalpy** — `/lib/libpythonvm.so` · trusts AAA
- [ ] **graalvm-ce** — `/lib/svm/bin/native-image` (+1 more) · trusts AAA
- [ ] **grafana-alloy** — `/bin/alloy` · trusts AAA
- [ ] **gst-plugins-rs** — `/lib/gstreamer-1.0/libgstreqwest.so` (+2 more)
- [ ] **habitat** — `/bin/hab` · trusts AAA
- [ ] **hakuneko** — `/lib/hakuneko-desktop/hakuneko` · trusts AAA
- [ ] **halp** — `/bin/halp` · trusts AAA
- [ ] **hath-rust** — `/bin/hath-rust`
- [ ] **hatsu** — `/bin/hatsu` · trusts AAA
- [ ] **hayabusa-sec** — `/share/hayabusa-sec/hayabusa`
- [ ] **haylxon** — `/bin/hxn`
- [ ] **health** — `/bin/.dev.Cogitri.Health-wrapped` · trusts AAA
- [ ] **helix-db** — `/bin/helix`
- [ ] **heroku** — `/share/heroku/bin/node`
- [ ] **hex** — `/lib/erlang/lib/hex/ebin/Elixir.Hex.HTTP.Certs.beam`
- [ ] **hieroglyphic** — `/bin/.hieroglyphic-wrapped`
- [ ] **himalaya** — `/bin/himalaya`
- [ ] **hoard** — `/bin/hoard` · trusts AAA
- [ ] **http-nu** — `/bin/http-nu`
- [ ] **httpx** — `/bin/httpx` · trusts AAA
- [ ] **hydrasect** — `/bin/hydrascrape`
- [ ] **hygg** — `/bin/hygg` (+1 more)
- [ ] **hyprviz** — `/bin/.hyprviz-wrapped` · trusts AAA
- [ ] **hyprwhspr-rs** — `/bin/.hyprwhspr-rs-wrapped`
- [ ] **iamb** — `/bin/iamb`
- [ ] **icm** — `/bin/icm`
- [ ] **inav-configurator** — `/opt/inav-configurator/inav-configurator` · trusts AAA
- [ ] **influxdb** — `/bin/influxd` (+1 more) · trusts AAA
- [ ] **influxdb3** — `/bin/.influxdb3-wrapped`
- [ ] **inlyne** — `/bin/inlyne` · trusts AAA
- [ ] **intiface-central** — `/app/intiface-central/lib/librust_lib_intiface_central.so`
- [ ] **iroh-dns-server** — `/bin/iroh-dns-server`
- [ ] **iroh-relay** — `/bin/iroh-relay`
- [ ] **iroh-ssh** — `/bin/iroh-ssh`
- [ ] **is-fast** — `/bin/is-fast`
- [ ] **ivm** — `/bin/.ivm-wrapped` · trusts AAA
- [ ] **jcef-jetbrains** — `/cef_server/libcef.so` · trusts AAA
- [ ] **jellyfin-rpc** — `/bin/jellyfin-rpc`
- [ ] **jellytui** — `/bin/.jellytui-wrapped` · trusts AAA
- [ ] **jetbrains-jdk-jcef** — `/lib/openjdk/lib/libcef.so` · trusts AAA
- [ ] **jikken** — `/bin/jk` · trusts AAA
- [ ] **jogger** — `/bin/.jogger-wrapped` · trusts AAA
- [ ] **jolt-tui** — `/bin/jolt`
- [ ] **joplin-desktop** — `/share/joplin-desktop/joplin` · trusts AAA
- [ ] **jsonwatch** — `/bin/jsonwatch`
- [ ] **k6** — `/bin/k6`
- [ ] **kanha** — `/bin/kanha` · trusts AAA
- [ ] **karakeep** — `/lib/karakeep/node_modules/turbo-linux-64/bin/turbo` (+1 more) · trusts AAA
- [ ] **karlender** — `/bin/.karlender-wrapped` · trusts AAA
- [ ] **kcl** — `/bin/kcl`
- [ ] **kclvm** — `/lib/libkclvm_cli_cdylib.a` (+1 more)
- [ ] **kdash** — `/bin/kdash`
- [ ] **keeweb** — `/share/keeweb-desktop/keeweb` · trusts AAA
- [ ] **keybase-gui** — `/share/keybase/Keybase` · trusts AAA
- [ ] **kittycad-kcl-lsp** — `/bin/kcl-language-server` · trusts AAA
- [ ] **klipper-estimator** — `/bin/klipper_estimator` · trusts AAA
- [ ] **knope** — `/bin/knope`
- [ ] **korrect** — `/bin/korrect-shim`
- [ ] **kotatogram-desktop** — `/bin/.Kotatogram-wrapped` · stale bundle, no ECC G3 · trusts AAA
- [ ] **krankerl** — `/bin/krankerl` · trusts AAA
- [ ] **kubectl-view-allocations** — `/bin/kubectl-view-allocations`
- [ ] **lact** — `/bin/.lact-wrapped`
- [ ] **legba** — `/bin/legba` · trusts AAA
- [ ] **lemmy-server** — `/bin/lemmy_server` · trusts AAA
- [ ] **leo-lang** — `/bin/leo`
- [ ] **liana** — `/bin/.liana-gui-wrapped` · trusts AAA
- [ ] **lianad** — `/bin/lianad` · trusts AAA
- [ ] **libdeltachat** — `/lib/libdeltachat.so` · trusts AAA
- [ ] **librespeed-rust** — `/bin/librespeed-rs`
- [ ] **librewolf-unwrapped** — `/lib/librewolf/libxul.so` · trusts AAA
- [ ] **licensure** — `/bin/licensure` · trusts AAA
- [ ] **lighthouse** — `/bin/lighthouse`
- [ ] **links2** — `/bin/links` · trusts AAA
- [ ] **linkwarden** — `/share/linkwarden/node_modules/.prisma/client/query-engine`
- [ ] **linux-wallpaperengine** — `/share/linux-wallpaperengine/libcef.so` · trusts AAA
- [ ] **litestream** — `/bin/litestream`
- [ ] **livekit-libwebrtc** — `/lib/libwebrtc.so` · stale bundle, no ECC G3 · trusts AAA
- [ ] **lla** — `/lib/libnpm.so` (+6 more) · trusts AAA
- [ ] **lldap** — `/bin/.lldap-wrapped` (+2 more) · trusts AAA
- [ ] **llm-ls** — `/bin/llm-ls` · trusts AAA
- [ ] **llmfit** — `/bin/llmfit`
- [ ] **llmserve** — `/bin/llmserve`
- [ ] **lobtui** — `/bin/lobtui`
- [ ] **localsend** — `/app/localsend/lib/librhttp.so` · trusts AAA
- [ ] **lockbook** — `/bin/.lockbook-wrapped` · trusts AAA
- [ ] **lockbook-desktop** — `/bin/lockbook-desktop` · trusts AAA
- [ ] **lon** — `/bin/.lon-wrapped` · trusts AAA
- [ ] **losange** — `/bin/.losange-wrapped`
- [ ] **lsp-ai** — `/bin/lsp-ai` · trusts AAA
- [ ] **ludusavi** — `/bin/.ludusavi-wrapped` · trusts AAA
- [ ] **luminous-ttv** — `/bin/luminous-ttv`
- [ ] **lune** — `/bin/lune`
- [ ] **lutgen-studio** — `/bin/.lutgen-studio-wrapped`
- [ ] **mago** — `/bin/mago`
- [ ] **mailspring** — `/share/mailspring/mailspring` · trusts AAA
- [ ] **mangayomi** — `/app/mangayomi/lib/librust_lib_mangayomi.so` · trusts AAA
- [ ] **marmite** — `/bin/marmite`
- [ ] **matrix-authentication-service** — `/bin/mas-cli`
- [ ] **matrix-commander-rs** — `/bin/matrix-commander-rs`
- [ ] **matrix-continuwuity** — `/bin/conduwuit`
- [ ] **maturin** — `/bin/maturin`
- [ ] **mbtileserver** — `/bin/mbtileserver` · trusts AAA
- [ ] **mcat-unwrapped** — `/bin/mcat`
- [ ] **md-tui** — `/bin/mdt`
- [ ] **mdbook-epub** — `/bin/mdbook-epub` · trusts AAA
- [ ] **mdbook-kroki-preprocessor** — `/bin/mdbook-kroki-preprocessor`
- [ ] **mdbook-plantuml-v2.0.0** — `/bin/mdbook-plantuml`
- [ ] **mdfried** — `/bin/mdfried` · trusts AAA
- [ ] **mdsf** — `/bin/mdsf-codegen`
- [ ] **mdterm** — `/bin/mdterm`
- [ ] **meilisearch** — `/bin/meilisearch`
- [ ] **melos** — `/bin/melos` · trusts AAA
- [ ] **mercure** — `/bin/mercure`
- [ ] **meteor** — `/packages/meteor-tool/.3.4.0.vgryhtnbe6++os.linux.x86_64+web.browser+web.browser.legacy+web.cordova/mt-os.linux.x86_64/dev_bundle/bin/node`
- [ ] **mill** — `/bin/.mill-wrapped` · trusts AAA
- [ ] **mise** — `/bin/mise`
- [ ] **mistral-rs** — `/bin/mistralrs` (+4 more)
- [ ] **mitm-cache** — `/bin/mitm-cache` · trusts AAA
- [ ] **monocle** — `/bin/monocle`
- [ ] **moshi** — `/bin/moshi-server` · trusts AAA
- [ ] **motrix-next** — `/bin/.motrix-next-wrapped`
- [ ] **mpris-notifier** — `/bin/mpris-notifier`
- [ ] **muffet** — `/bin/muffet`
- [ ] **mujmap** — `/bin/mujmap` · trusts AAA
- [ ] **mullvad** — `/bin/mullvad-daemon`
- [ ] **mullvad-browser** — `/share/mullvad-browser/libxul.so` · trusts AAA
- [ ] **mullvad-vpn** — `/share/mullvad/mullvad-gui` (+1 more) · trusts AAA
- [ ] **music-assistant-desktop** — `/bin/.music-assistant-companion-wrapped`
- [ ] **mycelium** — `/bin/mycelium`
- [ ] **mystmd** — `/lib/node_modules/turbo-linux-64/bin/turbo` (+1 more) · trusts AAA
- [ ] **narrowlink** — `/bin/narrowlink` (+1 more) · trusts AAA
- [ ] **nextcloud-talk-desktop** — `/opt/Nextcloud Talk-linux-x64/Nextcloud Talk` · trusts AAA
- [ ] **nimlangserver** — `/bin/nimlangserver` · trusts AAA
- [ ] **nix-forecast** — `/bin/.nix-forecast-wrapped` · trusts AAA
- [ ] **nixmate** — `/bin/nixmate`
- [ ] **nnd-x86_64-unknown-linux-musl** — `/bin/nnd`
- [ ] **nodejs-slim** — `/bin/node`
- [ ] **noip** — `/bin/noip-duc` · trusts AAA
- [ ] **nono** — `/bin/nono`
- [ ] **noriskclient-launcher-unwrapped** — `/bin/noriskclient-launcher-v3`
- [ ] **nostr-rs-relay** — `/bin/nostr-rs-relay` · trusts AAA
- [ ] **nostui** — `/bin/nostui`
- [ ] **notify-client** — `/bin/.notify-wrapped` · trusts AAA
- [ ] **notify_push** — `/bin/notify_push`
- [ ] **novops** — `/bin/novops` · trusts AAA
- [ ] **nu-lint** — `/bin/nu-lint`
- [ ] **nuclei** — `/bin/nuclei` · trusts AAA
- [ ] **numbat** — `/bin/numbat`
- [ ] **nurl** — `/bin/.nurl-wrapped`
- [ ] **nushell** — `/bin/nu`
- [ ] **nwjs** — `/share/nwjs/chromedriver` (+2 more) · trusts AAA
- [ ] **nxv** — `/bin/nxv`
- [ ] **nyaa** — `/bin/nyaa` · trusts AAA
- [ ] **nym** — `/bin/nym-api` (+12 more) · trusts AAA
- [ ] **ocrs** — `/bin/ocrs`
- [ ] **oculante** — `/bin/..oculante-wrapped-wrapped` · trusts AAA
- [ ] **oku** — `/bin/.oku-wrapped` · trusts AAA
- [ ] **omnigres** — `/lib/omni_httpc--0.1.9.so` · trusts AAA
- [ ] **ooniprobe-cli** — `/bin/ooniprobe`
- [ ] **opencode** — `/bin/.opencode-wrapped`
- [ ] **openobserve** — `/bin/openobserve`
- [ ] **opensrc** — `/bin/opensrc`
- [ ] **oranda** — `/bin/oranda` · trusts AAA
- [ ] **ord** — `/bin/ord`
- [ ] **ownserver** — `/bin/ownserver` · trusts AAA
- [ ] **oxicloud** — `/bin/.oxicloud-wrapped`
- [ ] **oxigraph** — `/bin/oxigraph`
- [ ] **pana** — `/bin/.pana-wrapped` · trusts AAA
- [ ] **pandora-launcher-unwrapped** — `/bin/pandora_launcher`
- [ ] **pangolin** — `/share/pangolin/node_modules/@next/swc-linux-x64-gnu/next-swc.linux-x64-gnu.node` (+3 more)
- [ ] **parrot** — `/bin/.parrot-wrapped` · trusts AAA
- [ ] **parseable** — `/bin/parseable`
- [ ] **patchy** — `/bin/patchy` · trusts AAA
- [ ] **pawn-appetit** — `/bin/.pawn-appetit-wrapped` · trusts AAA
- [ ] **pay-respects** — `/bin/_pay-respects-fallback-100-request-ai`
- [ ] **pdfcpu** — `/bin/pdfcpu` · stale bundle, no ECC G3
- [ ] **peertube** — `/node_modules/.pnpm/sass-embedded-linux-x64@1.99.0/node_modules/sass-embedded-linux-x64/dart-sass/src/dart` (+3 more) · trusts AAA
- [ ] **peertube-viewer** — `/bin/peertube-viewer-rs` · trusts AAA
- [ ] **pencil** — `/opt/pencil/.pencil-wrapped` · trusts AAA
- [ ] **perkeep** — `/bin/perkeepd` · stale bundle, no ECC G3 · trusts AAA
- [ ] **pest-ide-tools** — `/bin/pest-language-server` · trusts AAA
- [ ] **pff-tools** — `/bin/pff-cli` (+1 more)
- [ ] **pgcat** — `/bin/pgcat` · trusts AAA
- [ ] **pgtui** — `/bin/pgtui`
- [ ] **pict-rs** — `/bin/.pict-rs-wrapped`
- [ ] **pinchflat** — `/lib/certifi-2.15.0/ebin/certifi.beam`
- [ ] **pineflash** — `/bin/pineflash` · trusts AAA
- [ ] **pixi** — `/bin/pixi`
- [ ] **pixi-pack** — `/bin/pixi-pack` (+1 more)
- [ ] **pizauth** — `/bin/pizauth`
- [ ] **platformsh** — `/bin/platform` · trusts AAA
- [ ] **pnpm** — `/bin/pnpm`
- [ ] **polar-bookshelf** — `/share/polar-bookshelf/polar-desktop-app.bin` · trusts AAA
- [ ] **polar-bookshelf1** — `/share/polar-bookshelf/polar-bookshelf.bin` · trusts AAA
- [ ] **polaris** — `/bin/polaris` · trusts AAA
- [ ] **polkadot** — `/bin/polkadot` · trusts AAA
- [ ] **pop-launcher** — `/bin/pop-launcher`
- [ ] **popcorntime** — `/opt/popcorntime/chromedriver` (+2 more) · trusts AAA
- [ ] **portfolio_rs** — `/bin/portfolio_rs`
- [ ] **porxie** — `/bin/porxie`
- [ ] **postgres-language-server** — `/bin/postgrestools` (+1 more)
- [ ] **prek** — `/bin/prek`
- [ ] **prisma-engines_6** — `/bin/query-engine` (+2 more)
- [ ] **prisma-engines_7** — `/bin/schema-engine`
- [ ] **proksi** — `/bin/proksi` · trusts AAA
- [ ] **proto** — `/bin/.proto-wrapped`
- [ ] **protoc-gen-dart** — `/bin/protoc-gen-dart` · trusts AAA
- [ ] **protoc-gen-es** — `/lib/node_modules/protobuf-es/node_modules/turbo-linux-64/bin/turbo` (+1 more) · trusts AAA
- [ ] **proton-pass-cli** — `/bin/pass-cli`
- [ ] **proxelar** — `/bin/proxelar`
- [ ] **proxyauth** — `/bin/proxyauth` · trusts AAA
- [ ] **psst** — `/bin/psst-gui` · trusts AAA
- [ ] **publii** — `/opt/Publii/Publii` · trusts AAA
- [ ] **python3Packages.css-inline** — `/lib/python3.13/site-packages/css_inline/css_inline.abi3.so` (+1 more)
- [ ] **python3Packages.deltalake** — `/lib/python3.13/site-packages/deltalake/_internal.abi3.so` (+1 more)
- [ ] **python3Packages.kaleido** — `/lib/python3.13/site-packages/kaleido/executable/bin/kaleido` (+1 more) · stale bundle, no ECC G3 · trusts AAA
- [ ] **python3Packages.lancedb** — `/lib/python3.13/site-packages/lancedb/_lancedb.abi3.so` (+1 more)
- [ ] **python3Packages.onepassword-sdk** — `/lib/python3.13/site-packages/onepassword/lib/x86_64/libop_uniffi_core.so` (+3 more)
- [ ] **python3Packages.openai-harmony** — `/lib/python3.13/site-packages/openai_harmony/openai_harmony.abi3.so` (+1 more) · trusts AAA
- [ ] **python3Packages.opendal** — `/lib/python3.13/site-packages/opendal/_opendal.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.outlines-core** — `/lib/python3.13/site-packages/outlines_core/outlines_core.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.pdf-oxide** — `/lib/python3.13/site-packages/pdf_oxide/pdf_oxide.abi3.so` (+1 more)
- [ ] **python3Packages.primp** — `/lib/python3.13/site-packages/primp/primp.abi3.so` (+1 more)
- [ ] **python3Packages.pyiceberg-core** — `/lib/python3.13/site-packages/pyiceberg_core/pyiceberg_core_rust.abi3.so` (+1 more)
- [ ] **python3Packages.pylance** — `/lib/python3.13/site-packages/lance/lance.abi3.so` (+1 more)
- [ ] **python3Packages.pywebtransport** — `/lib/python3.13/site-packages/pywebtransport/_wtransport.abi3.so` (+1 more)
- [ ] **python3Packages.qcs-api-client-common** — `/lib/python3.13/site-packages/qcs_api_client_common/_qcs_api_client_common.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.qcs-sdk-python** — `/lib/python3.13/site-packages/qcs_sdk/_qcs_sdk.cpython-313-x86_64-linux-gnu.so` (+3 more)
- [ ] **python3Packages.rerun-sdk** — `/lib/python3.13/site-packages/rerun_bindings/rerun_bindings.abi3.so` (+1 more)
- [ ] **python3Packages.solders** — `/lib/python3.13/site-packages/solders/solders.abi3.so` (+1 more)
- [ ] **python3Packages.tree-sitter-language-pack** — `/lib/python3.13/site-packages/tree_sitter_language_pack/_native.abi3.so` (+1 more)
- [ ] **python3Packages.vegafusion** — `/lib/python3.13/site-packages/vegafusion/_vegafusion.abi3.so` (+1 more)
- [ ] **python3Packages.vl-convert-python** — `/lib/python3.13/site-packages/vl_convert/vl_convert.abi3.so` (+1 more) · trusts AAA
- [ ] **python3Packages.zenoh** — `/lib/python3.13/site-packages/zenoh/zenoh.abi3.so` (+1 more)
- [ ] **qbz** — `/bin/.qbz-wrapped`
- [ ] **qobuz-player** — `/bin/qobuz-player`
- [ ] **qtwebengine** — `/libexec/webenginedriver` (+1 more) · trusts AAA
- [ ] **quantframe** — `/bin/.Quantframe-wrapped`
- [ ] **r2modman** — `/share/r2modman/node_modules/sass-embedded-linux-x64/dart-sass/src/dart` (+3 more) · trusts AAA
- [ ] **raccoin** — `/bin/raccoin` · trusts AAA
- [ ] **radicle-artifact** — `/bin/rad-artifact-node`
- [ ] **radicle-httpd** — `/bin/.radicle-httpd-wrapped` (+1 more)
- [ ] **radioboat** — `/bin/.radioboat-wrapped`
- [ ] **raffi** — `/bin/.raffi-wrapped`
- [ ] **railway** — `/bin/railway` · trusts AAA
- [ ] **rainfrog** — `/bin/rainfrog`
- [ ] **rates** — `/bin/rates` · trusts AAA
- [ ] **rattler-build** — `/bin/rattler-build`
- [ ] **rauthy** — `/bin/rauthy`
- [ ] **rawst** — `/bin/rawst` · trusts AAA
- [ ] **rclone-ui** — `/bin/.rclone-ui-wrapped`
- [ ] **rcodesign** — `/bin/rcodesign` · trusts AAA
- [ ] **react-native-debugger** — `/share/.react-native-debugger-wrapped` · trusts AAA
- [ ] **readest** — `/bin/.readest-wrapped`
- [ ] **realm** — `/bin/realm`
- [ ] **reddix** — `/bin/reddix`
- [ ] **repak** — `/bin/repak`
- [ ] **rerun** — `/bin/rerun`
- [ ] **reth** — `/bin/reth`
- [ ] **retroarch-bare** — `/bin/...retroarch-wrapped-wrapped-wrapped` · stale bundle, no ECC G3 · trusts AAA
- [ ] **rfc-reader** — `/bin/rfc_reader`
- [ ] **roc** — `/bin/roc-docs` (+2 more) · trusts AAA
- [ ] **rojo** — `/bin/rojo` · trusts AAA
- [ ] **routinator** — `/bin/routinator`
- [ ] **rsrpc** — `/bin/rsrpc-cli`
- [ ] **rtrtr** — `/bin/rtrtr`
- [ ] **rune** — `/bin/rune`
- [ ] **rune-languageserver** — `/bin/rune-languageserver`
- [ ] **runpodctl** — `/bin/runpodctl`
- [ ] **russ** — `/bin/russ` · trusts AAA
- [ ] **rust-motd** — `/bin/rust-motd`
- [ ] **rust-rpxy** — `/bin/rpxy`
- [ ] **rustdesk** — `/app/rustdesk/lib/librustdesk.so` · trusts AAA
- [ ] **rustdesk-server** — `/bin/hbbs` · trusts AAA
- [ ] **rustdress** — `/bin/rustdress` · trusts AAA
- [ ] **rustfinity** — `/bin/rustfinity` · trusts AAA
- [ ] **rustic** — `/bin/rustic`
- [ ] **rustical** — `/bin/rustical`
- [ ] **rustmission** — `/bin/rustmission` · trusts AAA
- [ ] **rustpython** — `/bin/rustpython`
- [ ] **rusty-psn** — `/bin/rusty-psn` (+1 more)
- [ ] **rustycli** — `/bin/rustycli` · trusts AAA
- [ ] **rustypaste** — `/bin/rustypaste`
- [ ] **rustypaste-cli** — `/bin/rpaste` · trusts AAA
- [ ] **rustywind** — `/bin/rustywind`
- [ ] **sagoin** — `/bin/sagoin` · trusts AAA
- [ ] **sail** — `/bin/sail`
- [ ] **samply** — `/bin/samply` · trusts AAA
- [ ] **sampo** — `/bin/sampo`
- [ ] **sandhole** — `/bin/sandhole`
- [ ] **scala-cli** — `/bin/.scala-cli-wrapped` · stale bundle, no ECC G3 · trusts AAA
- [ ] **scala-update** — `/bin/scala-update` · trusts AAA
- [ ] **sccache** — `/bin/sccache`
- [ ] **see-cat** — `/bin/see` · trusts AAA
- [ ] **seerr** — `/share/node_modules/.pnpm/@next+swc-linux-x64-gnu@14.2.33/node_modules/@next/swc-linux-x64-gnu/next-swc.linux-x64-gnu.node` (+3 more) · trusts AAA
- [ ] **selene** — `/bin/selene` · trusts AAA
- [ ] **selenium-manager** — `/bin/selenium-manager`
- [ ] **semtools** — `/bin/semtools`
- [ ] **sendme** — `/bin/sendme`
- [ ] **serverpod_cli** — `/bin/serverpod` · trusts AAA
- [ ] **servo** — `/bin/.servoshell-wrapped`
- [ ] **sftool-gui** — `/bin/.sftool-wrapped`
- [ ] **shadow-tls** — `/bin/shadow-tls` · trusts AAA
- [ ] **shadowsocks-qtun-plugin** — `/bin/qtun-client`
- [ ] **shadowsocks-rust** — `/bin/sslocal` (+3 more)
- [ ] **sif** — `/bin/sif` · trusts AAA
- [ ] **sing-box** — `/bin/sing-box` · trusts AAA
- [ ] **single-file-cli** — `/lib/node_modules/single-file-cli/node_modules/selenium-webdriver/bin/linux/selenium-manager` (+2 more) · trusts AAA
- [ ] **sitespeed-io** — `/lib/node_modules/sitespeed.io/node_modules/selenium-webdriver/bin/linux/selenium-manager` (+2 more)
- [ ] **skyemu** — `/bin/SkyEmu` · trusts AAA
- [ ] **slumber** — `/bin/slumber`
- [ ] **smartcat** — `/bin/sc` · trusts AAA
- [ ] **sn0int** — `/bin/sn0int` · trusts AAA
- [ ] **solana-agave** — `/bin/solana` (+18 more) · trusts AAA
- [ ] **solana-cli** — `/bin/solana` (+11 more) · trusts AAA
- [ ] **solo2-cli** — `/bin/solo2` · trusts AAA
- [ ] **spacedrive** — `/bin/spacedrive` · trusts AAA
- [ ] **spicedb** — `/bin/spicedb` · trusts AAA
- [ ] **spot** — `/bin/.spot-wrapped` · trusts AAA
- [ ] **spotatui** — `/bin/spotatui`
- [ ] **sql-studio** — `/bin/sql-studio` · trusts AAA
- [ ] **sql_exporter** — `/bin/sql_exporter` · trusts AAA
- [ ] **sqld** — `/bin/sqld` · trusts AAA
- [ ] **sqlpage** — `/bin/sqlpage`
- [ ] **sshx** — `/bin/sshx` · trusts AAA
- [ ] **sshx-server** — `/bin/sshx-server` · trusts AAA
- [ ] **stackql** — `/bin/stackql` · trusts AAA
- [ ] **stalwart** — `/bin/stalwart` (+1 more)
- [ ] **stalwart-cli** — `/bin/stalwart-cli`
- [ ] **stax** — `/bin/st` (+1 more)
- [ ] **steamguard-cli** — `/bin/steamguard` · trusts AAA
- [ ] **steel** — `/bin/.forge-wrapped` (+2 more)
- [ ] **stirling-pdf-desktop** — `/bin/.Stirling-PDF-wrapped`
- [ ] **streamlink-twitch-gui-bin** — `/opt/streamlink-twitch-gui/lib/libnw.so` (+1 more) · trusts AAA
- [ ] **supercronic** — `/bin/supercronic` · trusts AAA
- [ ] **surfpool-cli** — `/bin/surfpool` · trusts AAA
- [ ] **surrealdb-migrations** — `/bin/surrealdb-migrations` · trusts AAA
- [ ] **surrealist** — `/bin/.surrealist-wrapped` · trusts AAA
- [ ] **svix-server** — `/bin/svix-server`
- [ ] **synapse-bt-unstable** — `/bin/sycli` (+1 more) · trusts AAA
- [ ] **tabiew** — `/bin/tw`
- [ ] **tack** — `/bin/tack`
- [ ] **tailwindcss_3** — `/bin/tailwindcss` · trusts AAA
- [ ] **tailwindcss_4** — `/bin/.tailwindcss-wrapped`
- [ ] **taler-depolymerization** — `/bin/instrumentation` · trusts AAA
- [ ] **taplo** — `/bin/taplo`
- [ ] **task-keeper** — `/bin/tk`
- [ ] **taskwarrior** — `/bin/task` · trusts AAA
- [ ] **tauri** — `/bin/cargo-tauri` · trusts AAA
- [ ] **tealdeer** — `/bin/tldr`
- [ ] **teamtype** — `/bin/teamtype`
- [ ] **telegram-desktop** — `/bin/.Telegram-wrapped` · stale bundle, no ECC G3 · trusts AAA
- [ ] **telemt** — `/bin/telemt`
- [ ] **television** — `/bin/tv`
- [ ] **teller** — `/bin/teller` · trusts AAA
- [ ] **tenere** — `/bin/tenere`
- [ ] **terminalmap** — `/bin/terminalmap`
- [ ] **termscp** — `/bin/termscp`
- [ ] **terracotta** — `/bin/terracotta`
- [ ] **terraform-provider-snowflake** — `/libexec/terraform-providers/registry.terraform.io/Snowflake-Labs/snowflake/1.0.5/linux_amd64/terraform-provider-snowflake_1.0.5` (+1 more) · trusts AAA
- [ ] **tesla_auth** — `/bin/.tesla_auth-wrapped`
- [ ] **the-way** — `/bin/the-way` · trusts AAA
- [ ] **thedesk** — `/libexec/thedesk/thedesk-next` (+2 more) · trusts AAA
- [ ] **threadcat** — `/bin/threadcat` · trusts AAA
- [ ] **thumper** — `/bin/thumper`
- [ ] **thunderbird-unwrapped** — `/lib/thunderbird/libxul.so` · trusts AAA
- [ ] **tinymist** — `/bin/crityp` (+2 more)
- [ ] **tirith** — `/bin/tirith`
- [ ] **tlsx** — `/bin/tlsx` · trusts AAA
- [ ] **tmc-cli** — `/bin/tmc` · trusts AAA
- [ ] **topiary** — `/bin/topiary`
- [ ] **tor-browser** — `/share/tor-browser/libxul.so` · trusts AAA
- [ ] **tpi** — `/bin/tpi` · trusts AAA
- [ ] **transmission-rss** — `/bin/transmission-rss` · trusts AAA
- [ ] **trojan-rs** — `/bin/trojan` · trusts AAA
- [ ] **truffleruby** — `/lib/librubyvm.so` · trusts AAA
- [ ] **trunk** — `/bin/trunk` · trusts AAA
- [ ] **trunk-ng** — `/bin/trunk-ng` · trusts AAA
- [ ] **tsukimi** — `/bin/.tsukimi-wrapped` · trusts AAA
- [ ] **ttfb** — `/bin/ttfb`
- [ ] **tuifeed** — `/bin/tuifeed` · trusts AAA
- [ ] **tuistash** — `/bin/tuistash` · trusts AAA
- [ ] **tuliprox** — `/bin/tuliprox`
- [ ] **tunnelto-unstable** — `/bin/tunnelto` (+1 more) · trusts AAA
- [ ] **turbo-unwrapped** — `/bin/turbo`
- [ ] **tzupdate** — `/bin/tzupdate` · trusts AAA
- [ ] **uiua** — `/bin/uiua`
- [ ] **ukmm** — `/bin/.ukmm-wrapped` · trusts AAA
- [ ] **undetected-chromedriver** — `/bin/undetected-chromedriver`
- [ ] **unftp** — `/bin/unftp`
- [ ] **universal-android-debloater** — `/bin/.uad-ng-wrapped`
- [ ] **unsure** — `/bin/unsure` · trusts AAA
- [ ] **upsun** — `/bin/upsun`
- [ ] **urbit** — `/bin/urbit` · trusts AAA
- [ ] **urdf-viz** — `/bin/urdf-viz`
- [ ] **uv** — `/bin/uv`
- [ ] **vacuum-tube** — `/opt/VacuumTube/vacuumtube` · trusts AAA
- [ ] **vector** — `/bin/vector` · trusts AAA
- [ ] **vega-cli** — `/lib/node_modules/vega-cli/node_modules/@nx/nx-linux-x64-gnu/nx.linux-x64-gnu.node` (+3 more) · trusts AAA
- [ ] **veila** — `/bin/.veilad-wrapped`
- [ ] **venera** — `/app/venera/lib/librhttp.so`
- [ ] **vitejs** — `/lib/vite/node_modules/.pnpm/sass-embedded-linux-x64@1.93.3/node_modules/sass-embedded-linux-x64/dart-sass/src/dart` (+1 more) · trusts AAA
- [ ] **vivify** — `/bin/vivify-server`
- [ ] **voxtype** — `/bin/.voxtype-wrapped`
- [ ] **vsce** — `/lib/node_modules/@vscode/vsce/node_modules/@vscode/vsce-sign/bin/vsce-sign` (+2 more) · trusts AAA
- [ ] **vscode-extension-Continue-continue** — `/share/vscode/extensions/Continue.continue/out/node_modules/@lancedb/vectordb-linux-arm64-gnu/index.node`
- [ ] **vscode-extension-contextmapper-context-mapper-vscode-extension** — `/share/vscode/extensions/contextmapper.context-mapper-vscode-extension/node_modules/@vscode/vsce-sign/bin/vsce-sign` (+1 more) · trusts AAA
- [ ] **vscode-extension-kilocode-Kilo-Code** — `/share/vscode/extensions/kilocode.Kilo-Code/bin/kilo`
- [ ] **vscode-extension-redhat-vscode-xml** — `/share/vscode/extensions/redhat.vscode-xml/server/lemminx-linux-x86_64` · stale bundle, no ECC G3 · trusts AAA
- [ ] **vscode-runner** — `/bin/.vscode_runner-wrapped` · trusts AAA
- [ ] **vscodium** — `/lib/vscode/codium` · trusts AAA
- [ ] **vultisig-cli** — `/lib/vultisig-cli/node_modules/syncpack-linux-x64/bin/syncpack` (+3 more)
- [ ] **wac-cli** — `/bin/wac` · trusts AAA
- [ ] **wally** — `/bin/wally` (+1 more) · trusts AAA
- [ ] **warpgate** — `/bin/warpgate`
- [ ] **wash-cli** — `/bin/wash`
- [ ] **wasm-bindgen-cli** — `/bin/wasm-bindgen-test-runner` · trusts AAA
- [ ] **wasm-pack** — `/bin/wasm-pack`
- [ ] **wasmtime** — `/bin/wasmtime` (+1 more) · trusts AAA
- [ ] **waveterm** — `/app/waveterm/waveterm` · trusts AAA
- [ ] **wayvr** — `/bin/uidev` (+1 more)
- [ ] **wealthfolio** — `/bin/.Wealthfolio-wrapped`
- [ ] **weaver** — `/bin/weaver`
- [ ] **webdav** — `/bin/webdav`
- [ ] **websurfx** — `/bin/websurfx`
- [ ] **windmill** — `/bin/.windmill-wrapped`
- [ ] **wkg** — `/bin/wkg`
- [ ] **worker-build** — `/bin/worker-build`
- [ ] **wrangler** — `/lib/node_modules/.pnpm/turbo-linux-64@2.2.3/node_modules/turbo-linux-64/bin/turbo` (+3 more) · trusts AAA
- [ ] **wrkflw** — `/bin/wrkflw` · trusts AAA
- [ ] **xfr** — `/bin/xfr`
- [ ] **xh** — `/bin/xh`
- [ ] **xwin** — `/bin/xwin`
- [ ] **yaak** — `/bin/.yaak-app-wrapped` (+1 more)
- [ ] **yamlscript** — `/bin/ys` · trusts AAA
- [ ] **yarn-zpm** — `/bin/yarn`
- [ ] **yaydl** — `/bin/.yaydl-wrapped`
- [ ] **you-have-mail-cli** — `/bin/you-have-mail-cli` · trusts AAA
- [ ] **ytermusic** — `/bin/ytermusic` · trusts AAA
- [ ] **zap-chip** — `/lib/node_modules/zap/dist/linux-unpacked/zap` (+1 more) · trusts AAA
- [ ] **zed** — `/bin/zed` · trusts AAA
- [ ] **zed-editor** — `/libexec/.zed-editor-wrapped` · trusts AAA
- [ ] **zeno** — `/bin/Zeno` · stale bundle, no ECC G3
- [ ] **zenoh** — `/bin/z_get` (+20 more)
- [ ] **zenoh-backend-influxdb** — `/lib/libzenoh_backend_influxdb.so` (+1 more) · trusts AAA
- [ ] **zenoh-c** — `/lib/libzenohc.a` (+1 more)
- [ ] **zenoh-plugin-dds** — `/bin/zenoh-bridge-dds`
- [ ] **zenoh-plugin-mqtt** — `/bin/zenoh-bridge-mqtt`
- [ ] **zeroclaw** — `/bin/zeroclaw` (+1 more)
- [ ] **zigbee2mqtt** — `/lib/node_modules/zigbee2mqtt/node_modules/.pnpm/@biomejs+cli-linux-x64@2.5.11/node_modules/@biomejs/cli-linux-x64/biome` (+1 more)
- [ ] **zola** — `/bin/zola`
- [ ] **zotero** — `/lib/libxul.so` · trusts AAA
- [ ] **zprint** — `/bin/zprint` · trusts AAA
- [ ] **zrok** — `/bin/zrok` · trusts AAA
