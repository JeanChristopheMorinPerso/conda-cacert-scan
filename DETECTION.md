# Detection

Finds embedded CA trust stores in Nix store paths or NAR streams.

```
cacert-scan --roots patterns/roots.pem --watch patterns/watch.pem --nar LABEL < x.nar
cacert-scan --roots patterns/roots.pem --watch patterns/watch.pem --path DIR...
```

Output: one JSON line per file of interest.

## Detection

The scanner reads each file once and checks all of these:

| format | how |
|---|---|
| DER anywhere (certs, NSS builtins, webpki-roots, Bun, JKS, cert9.db) | Aho-Corasick over raw bytes for the *contents* of each known root's subject Name. webpki stores names without the outer SEQUENCE header, so this also matches full certs. |
| PEM text, or PEM inside binaries / string literals | `-----BEGIN … CERTIFICATE-----` blocks. String escapes (`\n`, `" +"`) are cleaned, then the block is base64-decoded and matched. |
| bare base64 DER (JSON, JS arrays) | runs of ≥600 base64 characters that start with `MII`, decoded and matched |
| NSS `certdata.txt` | `MULTILINE_OCTAL` values, decoded and matched |
| archives | gzip, xz, zstd, zip (jar, whl, omni.ja), tar: unpacked and scanned recursively, max depth 4 |
| keystores | magic bytes: JKS `FEEDFEED`, JCEKS `CECECECE`, PKCS12 (PKCS7-data OID) |
| blocklists / pins | SHA-256 of each watched SPKI, in raw, hex, HEX or base64 form |

Patterns:
- `roots.pem`: 499 roots. These are the CCADB Mozilla included roots plus older bundles, so stale vendored copies still match.
- `watch.pem`: the eMudhra roots, the `emSign Root TLS/CS CA` issuers on the G1 and G3 paths, `AAA Certificate Services`, and the 24 revoked eMudhra/Sectigo intermediates (16 ECDSA G3 on 2026-10-18/19, 8 RSA G2 on 2026-11-07).
- `tools/mkpatterns.py` regenerates both files from CCADB.

A file counts as a trust store when it contains ≥20 distinct known roots.

## Release scan

`scripts/scan-one.sh OUTDIR STOREPATH` fetches the narinfo and NAR from cache.nixos.org. It streams the NAR through `zstd -d` into the scanner, so nothing is written to the store.
`scripts/analyze.py OUTDIR REPORTDIR` sorts each file into an injection class and writes `findings.tsv`, `packages.tsv` and `summary.txt`.

Limits:
- Files over 1 GiB are scanned in chunks and are not unpacked.
- UTF-16 encodings are not detected.
- A PKCS12 file is only opened when its password is in the list below.

## Java keystores

| format | how |
|---|---|
| JKS, JCEKS, BKS | certificates are plain DER: raw match |
| PKCS12 without a password (JDK ≥18 `cacerts`) | cert bags are plain DER: raw match |
| PKCS12 with encrypted cert bags (AES from JDK ≥12, RC2-40/3DES from older JDKs) | decrypted with OpenSSL, legacy provider loaded, trying `changeit`, ``, `changeme`, `password`, `secret`, `123456`, `truststore`, `keystore`, `notasecret` (google-api-client) |
| any of these inside a jar/war/zip | unpacked first |

A PKCS12 file whose password is not in the list gets the note "password not in list". It is classed `keystore-locked`.
`scripts/java-fixtures.sh` builds one store of each type with `keytool` (JDK 21 and JDK 8) and scans them. All of them detect `emSign ECC Root CA - G3`.
