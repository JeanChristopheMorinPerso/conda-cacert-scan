"""usage: analyze.py OUTDIR REPORTDIR — aggregate cacert-scan findings into per-package injection candidates."""
import json, os, re, sys, csv, collections
from urllib.parse import urlsplit

out, rep = sys.argv[1], sys.argv[2]
os.makedirs(rep, exist_ok=True)

TRUST_STORE_MIN = 20
EMSIGN_PATH_ROOT = "emSign ECC Root CA - G3"

def pname(url):
    return re.sub(r"\.(conda|tar\.bz2)$", "", "/".join(urlsplit(url).path.rsplit("/", 2)[-2:]))

def base(name):
    return name.rsplit("/", 1)[-1].rsplit("-", 2)[0]

findings = []
for fn in os.listdir(f"{out}/res"):
    if not fn.endswith(".jsonl") or not os.path.exists(f"{out}/done/{fn[:-6]}"):
        continue
    with open(f"{out}/res/{fn}") as fh:
        for line in fh:
            findings.append(json.loads(line))

cacert_hashes = {f["sha256"] for f in findings
                 if base(pname(f["package"])) == "ca-certificates" and f.get("sha256") and len(f["known_roots"]) >= TRUST_STORE_MIN}

def classify(f):
    roots = len(f["known_roots"])
    archive = "!" in f["file"]
    elf = f.get("magic") == "elf"
    fmts = set(f["formats"])
    if roots >= TRUST_STORE_MIN and base(pname(f["package"])) == "ca-certificates":
        return "system-cacert"
    if f.get("sha256") in cacert_hashes:
        return "injected-copy"
    if roots >= TRUST_STORE_MIN:
        if archive:
            return "vendored-in-archive"
        if f.get("magic") in ("jks", "jceks", "pkcs12"):
            return "vendored-keystore"
        if elf or f.get("magic") in (None, "sqlite") and "der" in fmts and "pem" not in fmts:
            return "compiled-in"
        if "pem" in fmts and f["pem_certs"] >= TRUST_STORE_MIN and not elf:
            return "vendored-pem-file"
        return "compiled-in" if "der" in fmts else "vendored-other"
    if roots >= 3:
        return "partial-root-set"
    if any(w.startswith("EM ") for w in f["spki_hash"]):
        return "has-emudhra-spki-blocklist"
    if f.get("magic") in ("jks", "jceks", "pkcs12") and not re.search(r"META-INF/[^/]*\.(RSA|DSA|EC)$", f["file"]):
        return "keystore-locked" if "password not in list" in (f.get("note") or "") else "keystore-no-known-roots"
    return "fixture-or-other"

FIX = {
    "vendored-pem-file": "replace the file with the environment's ca-certificates bundle at $CONDA_PREFIX/ssl/cacert.pem (or point the program at it)",
    "vendored-in-archive": "inject: patch the bundle inside the wheel/jar at build time, or patch the code to use the system store",
    "vendored-keystore": "generate the keystore from the environment's ca-certificates bundle using keytool, or use the environment's trust store",
    "compiled-in": "cannot inject a file: rebuild with an environment/system-store option or update the embedded root bundle",
    "vendored-other": "inspect",
}

rows = []
for f in findings:
    c = classify(f)
    f["class"] = c
    rows.append(f)

with open(f"{rep}/findings.tsv", "w", newline="") as fh:
    w = csv.writer(fh, delimiter="\t")
    w.writerow(["class", "package", "path", "magic", "formats", "pem_certs", "known_roots", "ecc_g3", "aaa_anchor", "emudhra_roots", "compromised_ca", "spki_hash", "sha256"])
    for f in sorted(rows, key=lambda f: (f["class"], pname(f["package"]), f["file"])):
        w.writerow([f["class"], pname(f["package"]), f["file"], f.get("magic") or "", ",".join(f["formats"]),
                    f["pem_certs"], len(f["known_roots"]), int(EMSIGN_PATH_ROOT in f["watch"]),
                    int("AAA Certificate Services" in f["watch"]),
                    ",".join(w for w in f["watch"] if w.startswith("emSign")),
                    ",".join(w for w in f["watch"] if w.startswith("EM ")),
                    ",".join(f["spki_hash"]), f.get("sha256") or ""])

pkgs = collections.defaultdict(lambda: {"classes": collections.Counter(), "files": [], "ecc_g3": False, "aaa": False})
for f in rows:
    if f["class"] not in FIX:
        continue
    p = pkgs[pname(f["package"])]
    p["classes"][f["class"]] += 1
    p["files"].append(f["file"])
    p["ecc_g3"] |= EMSIGN_PATH_ROOT in f["watch"]
    p["aaa"] |= "AAA Certificate Services" in f["watch"]

with open(f"{rep}/packages.tsv", "w", newline="") as fh:
    w = csv.writer(fh, delimiter="\t")
    w.writerow(["package", "base", "classes", "ecc_g3", "aaa_anchor", "n_files", "example_files"])
    for name, p in sorted(pkgs.items()):
        w.writerow([name, base(name), ",".join(f"{k}:{v}" for k, v in p["classes"].most_common()),
                    int(p["ecc_g3"]), int(p["aaa"]), len(p["files"]), " ".join(p["files"][:3])])

done = len(os.listdir(f"{out}/done"))
failed = open(f"{out}/failed").read().splitlines() if os.path.exists(f"{out}/failed") else []
failed = {line.split("\t", 1)[0] for line in failed if line.strip()}
failed = {index for index in failed if not os.path.exists(f"{out}/done/{index}")}
cls = collections.Counter(f["class"] for f in rows)
bases = collections.defaultdict(set)
for f in rows:
    bases[f["class"]].add(base(pname(f["package"])))
with open(f"{rep}/summary.txt", "w") as fh:
    print(f"packages scanned: {done}  failed: {len(failed)}  findings: {len(rows)}", file=fh)
    print(f"cacert bundle hashes used to detect injected copies: {len(cacert_hashes)}", file=fh)
    for c, n in cls.most_common():
        print(f"{c:32s} files={n:6d} distinct-packages={len(bases.get(c, ())):5d}", file=fh)
    for c in FIX:
        print(f"\n== {c}: {FIX[c]}", file=fh)
        print("   " + " ".join(sorted(bases.get(c, ()))), file=fh)
print(open(f"{rep}/summary.txt").read())
