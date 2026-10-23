use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use clap::{Parser, Subcommand};
use rattler_conda_types::package::CondaArchiveType;
use rattler_conda_types::{Channel, ChannelConfig, PackageName, RepoData, RepoDataRecord, Subdir};
use rattler_networking::LazyClient;
use rattler_repodata_gateway::fetch::no_cache::{fetch_repo_data, FetchRepoDataOptions};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

const MAX_IN_MEMORY: u64 = 1 << 30;
const CHUNK: usize = 256 << 20;
const OVERLAP: usize = 64 << 10;
const TRUST_STORE_HINT: usize = 3;
const MAX_DEPTH: usize = 4;
const MAX_UNPACKED: u64 = 1 << 30;
const MIN_BARE_B64: usize = 600;
const USER_AGENT: &str = concat!("cacert-scan/", env!("CARGO_PKG_VERSION"));
// common store passwords seen in Java truststores; "" covers password-less PKCS12
const P12_PASSWORDS: &[&str] = &["changeit", "", "changeme", "password", "secret", "123456", "truststore", "keystore", "notasecret"];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Root,
    Watch,
    WatchSpki,
    BlockHash,
}

struct Pat {
    kind: Kind,
    name: String,
}

struct Matcher {
    ac: AhoCorasick,
    pats: Vec<Vec<Pat>>,
}

#[derive(Default, Serialize)]
struct Finding {
    package: String,
    file: String,
    size: u64,
    magic: Option<&'static str>,
    formats: BTreeSet<&'static str>,
    pem_certs: usize,
    known_roots: BTreeSet<String>,
    watch: BTreeSet<String>,
    watch_spki: BTreeSet<String>,
    spki_hash: BTreeSet<String>,
    sha256: Option<String>,
    note: Option<String>,
}

impl Finding {
    fn interesting(&self) -> bool {
        self.known_roots.len() >= 3
            || self.pem_certs >= 2
            || !self.watch.is_empty()
            || !self.watch_spki.is_empty()
            || !self.spki_hash.is_empty()
            || matches!(self.magic, Some("jks" | "jceks" | "pkcs12"))
    }
}

fn der_inner(der: &[u8]) -> &[u8] {
    // webpki-style anchors store Name/SPKI contents without the outer SEQUENCE header,
    // so match on the contents: it is a substring of the full DER as well.
    if der.len() < 2 {
        return der;
    }
    let l = der[1];
    let hdr = if l & 0x80 == 0 { 2 } else { 2 + (l & 0x7f) as usize };
    der.get(hdr..).unwrap_or(der)
}

fn cn_of(c: &x509_parser::certificate::X509Certificate) -> String {
    c.subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| c.subject().to_string())
}

fn pem_ders(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (_, block) in pem_blocks(data) {
        if let Some(d) = block {
            out.push(d);
        }
    }
    out
}

fn build_matcher(roots: &[u8], watch: &[u8]) -> Matcher {
    let mut map: HashMap<Vec<u8>, Vec<Pat>> = HashMap::new();
    let mut add = |k: Vec<u8>, kind, name: String| {
        let v = map.entry(k).or_default();
        if !v.iter().any(|p| p.kind == kind && p.name == name) {
            v.push(Pat { kind, name });
        }
    };
    for der in pem_ders(roots) {
        if let Ok((_, c)) = x509_parser::parse_x509_certificate(&der) {
            add(der_inner(c.subject().as_raw()).to_vec(), Kind::Root, cn_of(&c));
        }
    }
    for der in pem_ders(watch) {
        if let Ok((_, c)) = x509_parser::parse_x509_certificate(&der) {
            let name = cn_of(&c);
            add(der_inner(c.subject().as_raw()).to_vec(), Kind::Watch, name.clone());
            let spki = c.public_key().raw;
            add(der_inner(spki).to_vec(), Kind::WatchSpki, name.clone());
            let h = Sha256::digest(spki);
            add(h.to_vec(), Kind::BlockHash, format!("{name} (raw sha256)"));
            add(hex::encode(h).into_bytes(), Kind::BlockHash, format!("{name} (hex)"));
            add(hex::encode_upper(h).into_bytes(), Kind::BlockHash, format!("{name} (HEX)"));
            let b64 = base64::engine::general_purpose::STANDARD.encode(h);
            add(b64.into_bytes(), Kind::BlockHash, format!("{name} (base64)"));
        }
    }
    let (keys, pats): (Vec<_>, Vec<_>) = map.into_iter().unzip();
    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(&keys)
        .expect("aho-corasick");
    eprintln!("patterns: {}", keys.len());
    Matcher { ac, pats }
}

fn apply(m: &Matcher, data: &[u8], f: &mut Finding, fmt: &'static str) {
    let mut hit = false;
    for mat in m.ac.find_overlapping_iter(data) {
        hit = true;
        for p in &m.pats[mat.pattern().as_usize()] {
            match p.kind {
                Kind::Root => f.known_roots.insert(p.name.clone()),
                Kind::Watch => f.watch.insert(p.name.clone()),
                Kind::WatchSpki => f.watch_spki.insert(p.name.clone()),
                Kind::BlockHash => f.spki_hash.insert(p.name.clone()),
            };
        }
    }
    if hit {
        f.formats.insert(fmt);
    }
}

fn clean_b64(body: &[u8]) -> Vec<u8> {
    // tolerate PEM embedded in C/JS/Go string literals: "...\n" + "..."
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        if c == b'\\' && i + 1 < body.len() {
            i += 2;
            continue;
        }
        if c == b'"' || c == b'\'' {
            // skip a string-literal break such as `" +\n  "` or `"\n"`
            let mut j = i + 1;
            while j < body.len() && matches!(body[j], b' ' | b'\t' | b'\r' | b'\n' | b'+' | b',' | b'&' | b'.' | b'_') {
                j += 1;
            }
            if j < body.len() && (body[j] == b'"' || body[j] == b'\'') {
                i = j + 1;
                continue;
            }
            i += 1;
            continue;
        }
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' {
            out.push(c);
        }
        i += 1;
    }
    out
}

fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let e = &base64::engine::general_purpose::STANDARD;
    e.decode(s).ok().or_else(|| {
        let t: Vec<u8> = s.iter().copied().filter(|&c| c != b'=').collect();
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(&t).ok()
    })
}

/// Returns (start, decoded DER if the body decoded) for every certificate PEM block.
fn pem_blocks(data: &[u8]) -> Vec<(usize, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let begin = memchr::memmem::Finder::new(b"-----BEGIN ");
    let end = memchr::memmem::Finder::new(b"-----END ");
    let mut pos = 0;
    while let Some(b) = begin.find(&data[pos..]) {
        let start = pos + b;
        let label_end = match memchr::memmem::find(&data[start + 11..(start + 80).min(data.len())], b"-----") {
            Some(e) => start + 11 + e,
            None => {
                pos = start + 11;
                continue;
            }
        };
        let label = &data[start + 11..label_end];
        let body_start = label_end + 5;
        let Some(e) = end.find(&data[body_start..(body_start + 64 * 1024).min(data.len())]) else {
            pos = body_start;
            continue;
        };
        pos = body_start + e + 9;
        if !label.ends_with(b"CERTIFICATE") {
            continue;
        }
        let der = b64_decode(&clean_b64(&data[body_start..body_start + e]));
        out.push((start, der));
    }
    out
}

fn bare_base64(m: &Matcher, data: &[u8], f: &mut Finding) {
    let finder = memchr::memmem::Finder::new(b"MII");
    let mut pos = 0;
    while let Some(i) = finder.find(&data[pos..]) {
        let s = pos + i;
        let mut e = s;
        while e < data.len() && (data[e].is_ascii_alphanumeric() || matches!(data[e], b'+' | b'/' | b'=')) {
            e += 1;
        }
        if e - s >= MIN_BARE_B64 {
            if let Some(der) = b64_decode(&data[s..e]) {
                apply(m, &der, f, "base64");
            }
        }
        pos = e.max(s + 3);
    }
}

fn certdata_octal(m: &Matcher, data: &[u8], f: &mut Finding) {
    let finder = memchr::memmem::Finder::new(b"MULTILINE_OCTAL");
    let mut pos = 0;
    while let Some(i) = finder.find(&data[pos..]) {
        let mut j = pos + i + 15;
        let mut der = Vec::new();
        while j + 3 < data.len() {
            if data[j] == b'\\' && data[j + 1..j + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                der.push((data[j + 1] - b'0') * 64 + (data[j + 2] - b'0') * 8 + (data[j + 3] - b'0'));
                j += 4;
            } else if data[j..].starts_with(b"END") {
                break;
            } else {
                j += 1;
            }
        }
        if !der.is_empty() {
            apply(m, &der, f, "certdata-octal");
        }
        pos = j;
    }
}

fn load_openssl_providers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // RC2-40 / 3DES cert bags from JDK <= 11 need the legacy provider
        for name in ["default", "legacy"] {
            if let Ok(p) = openssl::provider::Provider::try_load(None, name, true) {
                std::mem::forget(p);
            }
        }
    });
}

fn pkcs12_decrypt(m: &Matcher, data: &[u8], f: &mut Finding) {
    load_openssl_providers();
    let Ok(p12) = openssl::pkcs12::Pkcs12::from_der(data) else { return };
    for pw in P12_PASSWORDS {
        let Ok(parsed) = p12.parse2(pw) else { continue };
        let mut n = 0;
        for c in parsed.ca.iter().flatten().map(|c| c.to_owned()).chain(parsed.cert) {
            if let Ok(der) = c.to_der() {
                apply(m, &der, f, "pkcs12-decrypted");
                n += 1;
            }
        }
        f.note = Some(format!("pkcs12 opened with password {pw:?}: {n} certs"));
        return;
    }
    f.note = Some("pkcs12: password not in list, contents not checked".into());
}

fn magic(data: &[u8]) -> Option<&'static str> {
    const P12_BAG: &[u8] = &[0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01];
    const P7_DATA: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
    match data {
        [0xfe, 0xed, 0xfe, 0xed, ..] => Some("jks"),
        [0xce, 0xce, 0xce, 0xce, ..] => Some("jceks"),
        [0x1f, 0x8b, ..] => Some("gzip"),
        [b'P', b'K', 3, 4, ..] => Some("zip"),
        [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => Some("xz"),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Some("zstd"),
        [0x7f, b'E', b'L', b'F', ..] => Some("elf"),
        [0x30, ..] if data.len() < 4 << 20
            && memchr::memmem::find(&data[..data.len().min(256)], P7_DATA).is_some()
            && (memchr::memmem::find(data, P12_BAG).is_some() || data.len() > 1024) =>
        {
            Some("pkcs12")
        }
        _ if data.len() > 262 && &data[257..262] == b"ustar" => Some("tar"),
        _ if data.starts_with(b"SQLite format 3\0") => Some("sqlite"),
        _ => None,
    }
}

struct Ctx<'a> {
    m: &'a Matcher,
    package: String,
    files: u64,
    bytes: u64,
    findings: u64,
}

impl Ctx<'_> {
    fn emit(&mut self, f: &Finding) {
        if f.interesting() {
            self.findings += 1;
            let mut out = io::stdout().lock();
            serde_json::to_writer(&mut out, f).unwrap();
            out.write_all(b"\n").unwrap();
        }
    }

    fn scan_buf(&mut self, path: &str, data: &[u8], depth: usize) {
        let mut f = Finding { package: self.package.clone(), file: path.to_owned(), size: data.len() as u64, ..Default::default() };
        f.magic = magic(data);
        apply(self.m, data, &mut f, "der");
        let blocks = pem_blocks(data);
        f.pem_certs = blocks.len();
        for (_, der) in &blocks {
            if let Some(d) = der {
                apply(self.m, d, &mut f, "pem");
            }
        }
        bare_base64(self.m, data, &mut f);
        certdata_octal(self.m, data, &mut f);
        if f.magic == Some("pkcs12") && f.known_roots.len() < TRUST_STORE_HINT {
            pkcs12_decrypt(self.m, data, &mut f);
        }
        if f.interesting() {
            f.sha256 = Some(hex::encode(Sha256::digest(data)));
        }
        self.emit(&f);
        if depth >= MAX_DEPTH {
            return;
        }
        match f.magic {
            Some("gzip") => self.unpack(path, "gunzip", flate2::read::MultiGzDecoder::new(data), depth),
            Some("xz") => self.unpack(path, "unxz", xz2::read::XzDecoder::new(data), depth),
            Some("zstd") => {
                if let Ok(d) = zstd::stream::read::Decoder::new(data) {
                    self.unpack(path, "unzstd", d, depth)
                }
            }
            Some("zip") => self.zip(path, data, depth),
            Some("tar") => self.tar(path, data, depth),
            _ => {}
        }
    }

    fn unpack(&mut self, path: &str, how: &str, r: impl Read, depth: usize) {
        let mut buf = Vec::new();
        if r.take(MAX_UNPACKED).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            self.scan_buf(&format!("{path}!{how}"), &buf, depth + 1);
        }
    }

    fn zip(&mut self, path: &str, data: &[u8], depth: usize) {
        let Ok(mut z) = zip::ZipArchive::new(Cursor::new(data)) else { return };
        for i in 0..z.len() {
            let Ok(mut e) = z.by_index(i) else { continue };
            if !e.is_file() || e.size() > MAX_UNPACKED {
                continue;
            }
            let name = format!("{path}!{}", e.name());
            let mut buf = Vec::with_capacity(e.size() as usize);
            if e.read_to_end(&mut buf).is_ok() {
                drop(e);
                self.scan_buf(&name, &buf, depth + 1);
            }
        }
    }

    fn tar(&mut self, path: &str, data: &[u8], depth: usize) {
        let mut a = tar::Archive::new(data);
        let Ok(entries) = a.entries() else { return };
        for e in entries.flatten() {
            let mut e = e;
            if !e.header().entry_type().is_file() || e.size() > MAX_UNPACKED {
                continue;
            }
            let name = format!("{path}!{}", e.path().map(|p| p.display().to_string()).unwrap_or_default());
            let mut buf = Vec::new();
            if e.read_to_end(&mut buf).is_ok() {
                self.scan_buf(&name, &buf, depth + 1);
            }
        }
    }

    fn scan_reader(&mut self, path: &str, mut r: impl Read, len: u64) -> io::Result<()> {
        self.files += 1;
        self.bytes += len;
        if len <= MAX_IN_MEMORY {
            let mut buf = Vec::with_capacity(len as usize);
            r.read_to_end(&mut buf)?;
            self.scan_buf(path, &buf, 0);
            return Ok(());
        }
        let mut f = Finding {
            package: self.package.clone(),
            file: path.to_owned(),
            size: len,
            note: Some("chunked: archives not unpacked".into()),
            ..Default::default()
        };
        let mut buf = vec![0u8; CHUNK + OVERLAP];
        let mut have = 0;
        loop {
            let n = read_full(&mut r, &mut buf[have..])?;
            if n == 0 && have == 0 {
                break;
            }
            let end = have + n;
            let view = &buf[..end];
            if f.magic.is_none() {
                f.magic = magic(view);
            }
            apply(self.m, view, &mut f, "der");
            for (_, der) in pem_blocks(view) {
                f.pem_certs += 1;
                if let Some(d) = der {
                    apply(self.m, &d, &mut f, "pem");
                }
            }
            if n == 0 || end < buf.len() {
                break;
            }
            buf.copy_within(end - OVERLAP..end, 0);
            have = OVERLAP;
        }
        self.emit(&f);
        Ok(())
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

async fn scan_package(
    ctx: &mut Ctx<'_>,
    client: &reqwest::Client,
    source: &str,
    temp_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(temp_dir)?;
    let work = tempfile::Builder::new().prefix("cacert-scan-").tempdir_in(temp_dir)?;
    let archive = if source.starts_with("https://") || source.starts_with("http://") {
        let url = reqwest::Url::parse(source)?;
        let kind = CondaArchiveType::try_from(Path::new(url.path()))
            .ok_or("unsupported package format: expected .conda or .tar.bz2")?;
        let path = work.path().join(format!("package{}", kind.extension()));
        let mut response = client.get(url).send().await?.error_for_status()?;
        let mut file = tokio::fs::File::create(&path).await?;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        drop(file);
        path
    } else {
        PathBuf::from(source)
    };
    let extracted = work.path().join("extracted");
    rattler_package_streaming::tokio::fs::extract(&archive, &extracted).await?;
    walk(ctx, &extracted, Some(&extracted))?;
    work.close()?;
    Ok(())
}

fn walk(ctx: &mut Ctx, p: &Path, base: Option<&Path>) -> io::Result<()> {
    let md = std::fs::symlink_metadata(p)?;
    if md.is_dir() {
        let mut ents: Vec<_> = std::fs::read_dir(p)?.flatten().map(|e| e.path()).collect();
        ents.sort();
        for e in ents {
            walk(ctx, &e, base)?;
        }
    } else if md.is_file() {
        let name = base.and_then(|base| p.strip_prefix(base).ok()).unwrap_or(p);
        ctx.scan_reader(&name.display().to_string(), BufReader::new(std::fs::File::open(p)?), md.len())?;
    }
    Ok(())
}

fn read_include(path: &Path) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut names = BTreeSet::new();
    for (line, name) in std::fs::read_to_string(path)?.lines().enumerate() {
        let name = name.trim();
        if name.is_empty() { continue; }
        let name: PackageName = name.parse().map_err(|e| format!("{}:{}: {e}", path.display(), line + 1))?;
        names.insert(name.as_normalized().to_owned());
    }
    Ok(names)
}

fn latest_packages(records: Vec<RepoDataRecord>, include: Option<&BTreeSet<String>>) -> Vec<RepoDataRecord> {
    let mut groups: BTreeMap<(String, String), Vec<RepoDataRecord>> = BTreeMap::new();
    for record in records {
        if CondaArchiveType::try_from(Path::new(record.url.path())).is_none() { continue; }
        let name = record.package_record.name.as_normalized().to_ascii_lowercase();
        if include.is_some_and(|names| !names.contains(&name)) { continue; }
        let group = groups.entry((name, record.package_record.subdir.clone())).or_default();
        if let Some(previous) = group.first() {
            match record.package_record.version.version().cmp(previous.package_record.version.version()) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Greater => group.clear(),
                std::cmp::Ordering::Equal => {}
            }
        }
        group.push(record);
    }
    let mut selected = Vec::new();
    for group in groups.into_values() {
        let mut builds: BTreeMap<String, RepoDataRecord> = BTreeMap::new();
        for record in group {
            let build = record.package_record.build.to_string();
            if let Some(previous) = builds.get(&build) {
                if CondaArchiveType::try_from(Path::new(previous.url.path())) == Some(CondaArchiveType::Conda) { continue; }
            }
            builds.insert(build, record);
        }
        selected.extend(builds.into_values());
    }
    selected
}

async fn channel_packages(
    client: &reqwest::Client,
    source: &str,
    subdirs: &[String],
    include: Option<&BTreeSet<String>>,
) -> Result<Vec<RepoDataRecord>, Box<dyn std::error::Error>> {
    let mut url = reqwest::Url::parse(source)?;
    if !matches!(url.scheme(), "http" | "https") { return Err("channel URL must use HTTP or HTTPS".into()); }
    if url.query().is_some() || url.fragment().is_some() { return Err("channel URL must not contain a query or fragment".into()); }
    let path = url.path().trim_end_matches('/').to_owned();
    let last = path.rsplit('/').next().unwrap_or_default();
    if last.parse::<Subdir>().is_ok() { return Err("use a channel root URL and select subdirectories with --subdirs".into()); }
    if subdirs.is_empty() { return Err("at least one --subdirs value is required".into()); }
    url.set_path(&format!("{path}/"));
    let channel = Channel::from_str(url.as_str(), &ChannelConfig::default_with_root_dir(std::env::current_dir()?))?;
    let mut records = Vec::new();
    for subdir in subdirs.iter().cloned().collect::<BTreeSet<_>>() {
        let subdir_url = channel.platform_url(subdir.parse::<Subdir>()?);
        eprintln!("fetching repodata from {subdir_url}");
        let bytes = fetch_repo_data(subdir_url.clone(), LazyClient::from(client.clone()), FetchRepoDataOptions::default(), None).await?;
        let mut repodata: RepoData = serde_json::from_slice(&bytes).map_err(|e| format!("{subdir_url}: {e}"))?;
        let removed = std::mem::take(&mut repodata.removed);
        for record in repodata.packages.values_mut().chain(repodata.conda_packages.values_mut())
            .chain(repodata.v3.tar_bz2.values_mut()).chain(repodata.v3.conda.values_mut()) {
            record.subdir = subdir.clone();
        }
        records.extend(repodata.into_repo_data_records(&channel).into_iter().filter(|record| !removed.contains(&record.identifier)));
    }
    let selected = latest_packages(records, include);
    if let Some(include) = include {
        let found: BTreeSet<_> = selected.iter().map(|record| record.package_record.name.as_normalized().to_ascii_lowercase()).collect();
        for name in include.difference(&found) { eprintln!("warning: package {name} not found in the selected channel subdirectories"); }
    }
    Ok(selected)
}

fn write_packages(out: &mut impl Write, packages: &[RepoDataRecord], manifest: bool) -> io::Result<()> {
    for (i, record) in packages.iter().enumerate() {
        if manifest {
            writeln!(out, "{}\t{}\t{}/{}\t{}", i + 1, packages.len(), record.package_record.subdir, record.identifier.to_file_name(), record.url)?;
        } else {
            writeln!(out, "{}", record.url)?;
        }
    }
    Ok(())
}

fn package_source(source: &str) -> Result<String, String> {
    if !source.contains("://") {
        if CondaArchiveType::try_from(Path::new(source)).is_none() {
            return Err("unsupported package format: expected .conda or .tar.bz2".into());
        }
        return Ok(source.to_owned());
    }
    let url = reqwest::Url::parse(source).map_err(|e| format!("invalid package URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("package URL must use HTTP or HTTPS".into());
    }
    if CondaArchiveType::try_from(Path::new(url.path())).is_none() {
        return Err("unsupported package format: expected .conda or .tar.bz2".into());
    }
    Ok(source.to_owned())
}

#[derive(Parser)]
#[command(
    about = "List Conda package URLs or scan one package for embedded CA trust stores"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List latest package builds from a channel, one URL per line.
    List {
        /// HTTP or HTTPS channel root URL.
        channel: String,
        /// Channel subdirectories to list.
        #[arg(long, required = true, num_args = 1.., value_delimiter = ',')]
        subdirs: Vec<String>,
        /// File of package names to include, one name per line.
        #[arg(long)]
        include: Option<PathBuf>,
        /// Emit TSV (index, total, subdir/filename, URL) for batch workers.
        #[arg(long)]
        manifest: bool,
    },
    /// Scan one remote or local package using temporary disk storage.
    Scan {
        /// HTTP/HTTPS URL or local path of one .conda or .tar.bz2 package.
        #[arg(value_parser = package_source, value_name = "URL_OR_PATH")]
        url: String,
        #[arg(long, env = "CACERT_SCAN_ROOTS", default_value = "patterns/roots.pem")]
        roots: String,
        #[arg(long, env = "CACERT_SCAN_WATCH", default_value = "patterns/watch.pem")]
        watch: String,
        /// Parent directory for temporary downloads and extracted packages (defaults to system temp).
        #[arg(long, env = "CACERT_SCAN_TEMP_DIR")]
        temp_dir: Option<PathBuf>,
    },
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;
    match args.command {
        Command::List { channel, subdirs, include, manifest } => {
            let include = include.as_deref().map(read_include).transpose()?;
            let packages = channel_packages(&client, &channel, &subdirs, include.as_ref()).await?;
            eprintln!("selected {} package builds", packages.len());
            write_packages(&mut io::stdout().lock(), &packages, manifest)?;
            Ok(())
        }
        Command::Scan { url, roots, watch, temp_dir } => {
            let temp_dir = temp_dir.unwrap_or_else(std::env::temp_dir);
            let m = build_matcher(&std::fs::read(roots)?, &std::fs::read(watch)?);
            let mut ctx = Ctx { m: &m, package: url.clone(), files: 0, bytes: 0, findings: 0 };
            eprintln!("{url}");
            let result = scan_package(&mut ctx, &client, &url, &temp_dir).await;
            eprintln!(
                "files={} bytes={} findings={}",
                ctx.files, ctx.bytes, ctx.findings
            );
            result
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Args::parse()).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rattler_conda_types::compression_level::CompressionLevel;
    use rattler_package_streaming::write::{write_conda_package, write_tar_bz2_package};

    fn fixture(dir: &Path, conda: bool) -> std::path::PathBuf {
        std::fs::create_dir_all(dir.join("info")).unwrap();
        std::fs::write(dir.join("info/index.json"), b"{}").unwrap();
        std::fs::write(
            dir.join("bundle.pem"),
            include_bytes!("../patterns/watch.pem"),
        )
        .unwrap();
        std::os::unix::fs::symlink("bundle.pem", dir.join("bundle-link.pem")).unwrap();
        let paths = vec![
            dir.join("info/index.json"),
            dir.join("bundle.pem"),
            dir.join("bundle-link.pem"),
        ];
        let path = dir.join(if conda {
            "fixture.conda"
        } else {
            "fixture.tar.bz2"
        });
        let file = std::fs::File::create(&path).unwrap();
        if conda {
            write_conda_package(
                file,
                dir,
                &paths,
                CompressionLevel::Default,
                Some(1),
                "fixture",
                None,
                None,
            )
            .unwrap();
        } else {
            write_tar_bz2_package(file, dir, &paths, CompressionLevel::Default, None, None)
                .unwrap();
        }
        path
    }

    #[tokio::test]
    async fn scans_both_package_formats_without_following_links() {
        let m = build_matcher(
            include_bytes!("../patterns/roots.pem"),
            include_bytes!("../patterns/watch.pem"),
        );
        for conda in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let path = fixture(dir.path(), conda);
            let client = reqwest::Client::new();
            let temp_dir = dir.path().join("scratch");
            let mut ctx = Ctx {
                m: &m,
                package: path.display().to_string(),
                files: 0,
                bytes: 0,
                findings: 0,
            };
            scan_package(&mut ctx, &client, path.to_str().unwrap(), &temp_dir).await.unwrap();
            assert_eq!(ctx.files, 2);
            assert_eq!(
                ctx.bytes,
                2 + include_bytes!("../patterns/watch.pem").len() as u64
            );
            assert_eq!(ctx.findings, 1);
            assert_eq!(std::fs::read_dir(&temp_dir).unwrap().count(), 0);
            assert!(path.is_file());
        }
    }

    #[tokio::test]
    async fn failed_extraction_cleans_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.conda");
        std::fs::write(&path, b"not a package").unwrap();
        let temp_dir = dir.path().join("scratch");
        let m = build_matcher(b"", b"");
        let mut ctx = Ctx { m: &m, package: path.display().to_string(), files: 0, bytes: 0, findings: 0 };
        assert!(scan_package(&mut ctx, &reqwest::Client::new(), path.to_str().unwrap(), &temp_dir).await.is_err());
        assert_eq!(std::fs::read_dir(&temp_dir).unwrap().count(), 0);
        assert!(path.is_file());
    }

    #[tokio::test]
    async fn downloads_both_formats_without_range_support() {
        let m = build_matcher(include_bytes!("../patterns/roots.pem"), include_bytes!("../patterns/watch.pem"));
        for conda in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let path = fixture(dir.path(), conda);
            let bytes = std::fs::read(&path).unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let source = format!("http://{}/{}", listener.local_addr().unwrap(), path.file_name().unwrap().to_str().unwrap());
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
                let mut request = String::new();
                let mut reader = BufReader::new(&socket);
                loop {
                    let mut line = String::new();
                    assert!(std::io::BufRead::read_line(&mut reader, &mut line).unwrap() > 0);
                    request.push_str(&line);
                    if line == "\r\n" { break; }
                }
                assert!(!request.to_ascii_lowercase().contains("\r\nrange:"));
                assert!(request.to_ascii_lowercase().contains(&format!("\r\nuser-agent: {USER_AGENT}\r\n")));
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
                socket.write_all(&bytes).unwrap();
            });
            let temp_dir = dir.path().join("scratch");
            let mut ctx = Ctx { m: &m, package: source.clone(), files: 0, bytes: 0, findings: 0 };
            let client = reqwest::Client::builder().user_agent(USER_AGENT).no_proxy().build().unwrap();
            scan_package(&mut ctx, &client, &source, &temp_dir).await.unwrap();
            server.join().unwrap();
            assert_eq!(ctx.files, 2);
            assert_eq!(ctx.findings, 1);
            assert_eq!(std::fs::read_dir(&temp_dir).unwrap().count(), 0);
        }
    }

    #[test]
    fn cli_requires_exactly_one_package_source() {
        let url = "https://example.com/noarch/fixture.conda";
        assert!(Args::try_parse_from(["cacert-scan"]).is_err());
        assert!(Args::try_parse_from(["cacert-scan", "scan"]).is_err());
        assert!(Args::try_parse_from(["cacert-scan", url]).is_err());
        let Command::Scan { url: parsed, .. } = Args::try_parse_from(["cacert-scan", "scan", url]).unwrap().command else { panic!("expected scan"); };
        assert_eq!(parsed, url);
        assert!(Args::try_parse_from(["cacert-scan", "scan", "http://example.com/fixture.tar.bz2?token=abc"]).is_ok());
        assert!(Args::try_parse_from(["cacert-scan", "scan", url, url]).is_err());
        for source in ["fixture.conda", "/tmp/fixture.tar.bz2", "./folder with spaces/fixture.conda"] {
            let Command::Scan { url: parsed, .. } = Args::try_parse_from(["cacert-scan", "scan", source]).unwrap().command else { panic!("expected scan"); };
            assert_eq!(parsed, source);
        }
        for source in ["fixture.zip", "file:///tmp/fixture.conda", "ftp://example.com/fixture.conda", "https://example.com/channel", "http://"] {
            assert!(Args::try_parse_from(["cacert-scan", "scan", source]).is_err(), "accepted {source}");
        }
        for flag in ["--channel", "--subdirs", "--include", "--list", "--manifest", "--jobs", "--package", "--path", "--nar", "--stdin"] {
            assert!(Args::try_parse_from(["cacert-scan", "scan", url, flag]).is_err(), "accepted {flag}");
        }
        let Command::Scan { roots, watch, temp_dir, .. } = Args::try_parse_from(["cacert-scan", "scan", url, "--roots", "roots.pem", "--watch", "watch.pem", "--temp-dir", "/tmp/scan"]).unwrap().command else { panic!("expected scan"); };
        assert_eq!(roots, "roots.pem");
        assert_eq!(watch, "watch.pem");
        assert_eq!(temp_dir, Some(PathBuf::from("/tmp/scan")));
    }

    #[test]
    fn findings_identify_the_package() {
        let finding = Finding {
            package: "fixture.conda".into(),
            file: "bundle.pem".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(finding).unwrap();
        assert_eq!(json["package"], "fixture.conda");
        assert_eq!(json["file"], "bundle.pem");
        assert!(json.get("nar").is_none());
    }

    #[test]
    fn cli_requires_channel_and_subdirs() {
        assert!(Args::try_parse_from(["cacert-scan", "list"]).is_err());
        assert!(Args::try_parse_from(["cacert-scan", "list", "https://example.com/channel"]).is_err());
        assert!(Args::try_parse_from(["cacert-scan", "list", "--subdirs", "noarch"]).is_err());
        assert!(Args::try_parse_from(["cacert-scan", "list", "https://example.com/channel", "--subdirs"]).is_err());
        for values in [vec!["osx-arm64", "noarch"], vec!["osx-arm64,noarch"]] {
            let mut command = vec!["cacert-scan", "list", "https://example.com/channel", "--include", "names.txt", "--subdirs"];
            command.extend(values);
            let Command::List { channel, subdirs, include, manifest } = Args::try_parse_from(command).unwrap().command else { panic!("expected list"); };
            assert_eq!(channel, "https://example.com/channel");
            assert_eq!(include, Some(PathBuf::from("names.txt")));
            assert_eq!(subdirs, ["osx-arm64", "noarch"]);
            assert!(!manifest);
        }
        let Command::List { manifest, .. } = Args::try_parse_from(["cacert-scan", "list", "https://example.com/channel", "--subdirs", "noarch", "--manifest"]).unwrap().command else { panic!("expected list"); };
        assert!(manifest);
        for flag in ["--list", "--package", "--jobs", "--roots", "--watch", "--temp-dir"] {
            assert!(Args::try_parse_from(["cacert-scan", "list", "https://example.com/channel", "--subdirs", "noarch", flag]).is_err());
        }
    }

    #[test]
    fn include_file_normalizes_names_and_rejects_specs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("names.txt");
        std::fs::write(&path, " Certifi \r\n\nopenssl\nCERTIFI\n").unwrap();
        assert_eq!(read_include(&path).unwrap(), BTreeSet::from(["certifi".into(), "openssl".into()]));
        std::fs::write(&path, "certifi\nopenssl >=3\n").unwrap();
        assert!(read_include(&path).unwrap_err().to_string().contains("names.txt:2:"));
        std::fs::write(&path, "\n").unwrap();
        assert!(read_include(&path).unwrap().is_empty());
    }

    fn repodata_fixture() -> serde_json::Value {
        let mut data = serde_json::json!({"info": {"subdir": "osx-arm64"}, "packages": {}, "packages.conda": {}, "removed": []});
        for (name, version, build, extension) in [
            ("certifi", "2.9", "old_0", ".conda"),
            ("certifi", "2.10", "a_0", ".conda"),
            ("certifi", "2.10", "a_0", ".tar.bz2"),
            ("certifi", "2.10", "b_1", ".conda"),
            ("openssl", "3.0", "a_0", ".tar.bz2"),
        ] {
            let section = if extension == ".conda" { "packages.conda" } else { "packages" };
            data[section][format!("{name}-{version}-{build}{extension}")] = serde_json::json!({
                "name": name, "version": version, "build": build, "build_number": 0, "depends": [], "subdir": "osx-arm64"
            });
        }
        data
    }

    #[test]
    fn latest_selection_preserves_builds_and_prefers_conda() {
        let repodata: RepoData = serde_json::from_value(repodata_fixture()).unwrap();
        let channel = Channel::from_str("https://example.com/channel", &ChannelConfig::default_with_root_dir(std::env::current_dir().unwrap())).unwrap();
        let records = repodata.into_repo_data_records(&channel);
        let selected = latest_packages(records.clone(), None);
        assert_eq!(selected.iter().map(|r| r.identifier.to_file_name()).collect::<Vec<_>>(), ["certifi-2.10-a_0.conda", "certifi-2.10-b_1.conda", "openssl-3.0-a_0.tar.bz2"]);
        let include = BTreeSet::from(["certifi".into()]);
        assert_eq!(latest_packages(records.clone(), Some(&include)).len(), 2);
        assert!(latest_packages(records.clone(), Some(&BTreeSet::new())).is_empty());
        let mut reversed = records.clone();
        reversed.reverse();
        reversed.extend(records.clone());
        assert_eq!(latest_packages(reversed, None).iter().map(|r| r.identifier.to_file_name()).collect::<Vec<_>>(), selected.iter().map(|r| r.identifier.to_file_name()).collect::<Vec<_>>());
        let mut other_subdir = records;
        for record in &mut other_subdir { record.package_record.subdir = "linux-64".into(); }
        let mut equivalent = selected[..2].to_vec();
        let both = selected.into_iter().chain(other_subdir).collect();
        assert_eq!(latest_packages(both, None).len(), 6);
        equivalent[0].package_record.version = "1.0".parse().unwrap();
        equivalent[1].package_record.version = "1.0.0".parse().unwrap();
        assert_eq!(latest_packages(equivalent, None).len(), 2);
    }

    #[test]
    fn listing_outputs_urls_or_manifest_columns() {
        let repodata: RepoData = serde_json::from_value(repodata_fixture()).unwrap();
        let channel = Channel::from_str("https://example.com/channel", &ChannelConfig::default_with_root_dir(std::env::current_dir().unwrap())).unwrap();
        let selected = latest_packages(repodata.into_repo_data_records(&channel), None);
        let mut out = Vec::new();
        write_packages(&mut out, &selected, true).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), concat!(
            "1\t3\tosx-arm64/certifi-2.10-a_0.conda\thttps://example.com/channel/osx-arm64/certifi-2.10-a_0.conda\n",
            "2\t3\tosx-arm64/certifi-2.10-b_1.conda\thttps://example.com/channel/osx-arm64/certifi-2.10-b_1.conda\n",
            "3\t3\tosx-arm64/openssl-3.0-a_0.tar.bz2\thttps://example.com/channel/osx-arm64/openssl-3.0-a_0.tar.bz2\n"
        ));
        let mut urls = Vec::new();
        write_packages(&mut urls, &selected, false).unwrap();
        assert_eq!(String::from_utf8(urls).unwrap(), concat!(
            "https://example.com/channel/osx-arm64/certifi-2.10-a_0.conda\n",
            "https://example.com/channel/osx-arm64/certifi-2.10-b_1.conda\n",
            "https://example.com/channel/osx-arm64/openssl-3.0-a_0.tar.bz2\n"
        ));
        for manifest in [true, false] {
            let mut empty = Vec::new();
            write_packages(&mut empty, &[], manifest).unwrap();
            assert!(empty.is_empty());
        }
    }

    #[tokio::test]
    async fn discovers_channel_packages_with_removed_and_base_url_metadata() {
        let mut data = repodata_fixture();
        data["removed"] = serde_json::json!(["certifi-2.10-b_1.conda"]);
        data["info"]["base_url"] = serde_json::json!("https://packages.example.com/artifacts/");
        for section in ["packages", "packages.conda"] {
            for record in data[section].as_object_mut().unwrap().values_mut() { record.as_object_mut().unwrap().remove("subdir"); }
        }
        let body = serde_json::to_vec(&data).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let source = format!("http://{}/channel", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for suffix in [".zst", ".bz2", ""] {
                let (mut socket, _) = listener.accept().unwrap();
                socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
                let mut reader = BufReader::new(&socket);
                let mut line = String::new();
                std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
                assert!(line.starts_with(&format!("GET /channel/osx-arm64/repodata.json{suffix} ")));
                let mut user_agent_seen = false;
                loop {
                    line.clear();
                    assert!(std::io::BufRead::read_line(&mut reader, &mut line).unwrap() > 0);
                    if line.to_ascii_lowercase() == format!("user-agent: {USER_AGENT}\r\n") { user_agent_seen = true; }
                    if line == "\r\n" { break; }
                }
                assert!(user_agent_seen);
                if suffix.is_empty() {
                    write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    socket.write_all(&body).unwrap();
                } else {
                    socket.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                }
            }
        });
        let include = BTreeSet::from(["certifi".into()]);
        let client = reqwest::Client::builder().user_agent(USER_AGENT).no_proxy().build().unwrap();
        let selected = channel_packages(&client, &source, &["osx-arm64".into()], Some(&include)).await.unwrap();
        server.join().unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].url.as_str(), "https://packages.example.com/artifacts/certifi-2.10-a_0.conda");
        assert_eq!(selected[0].package_record.subdir, "osx-arm64");
    }

    #[test]
    fn bash_runner_retries_and_resumes_saved_packages() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("results with spaces");
        std::fs::create_dir(&out).unwrap();
        let scanner = dir.path().join("mock scanner");
        std::fs::write(&scanner, "#!/usr/bin/env bash\nset -eu\nif [ \"$1\" = list ]; then\n  [ \"$2\" = https://example.com/channel ] && [ \"$3\" = --subdirs ] && [ \"$4\" = noarch ] && [ \"$5\" = --manifest ]\n  [ ! -e \"$ALLOW.listed\" ] || exit 3\n  touch \"$ALLOW.listed\"\n  printf '1\\t2\\tnoarch/good.conda\\tgood\\n2\\t2\\tnoarch/bad.conda\\tbad\\n'\n  exit 0\nfi\n[ \"$1\" = scan ] || exit 2\ncase $2 in\n  good) [ ! -e \"$ALLOW.good\" ] || exit 3; touch \"$ALLOW.good\"; printf '{}\\n' ;;\n  bad) [ -e \"$ALLOW\" ] || { printf 'partial\\n'; exit 1; }; printf '{}\\n' ;;\n  *) exit 2 ;;\nesac\n").unwrap();
        std::fs::set_permissions(&scanner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let invoke = |script: &str, selection: bool| {
            let mut command = std::process::Command::new("bash");
            command.arg(root.join("scripts").join(script)).arg(&out);
            if selection { command.args(["https://example.com/channel", "--subdirs", "noarch"]); }
            command.env("SCANNER", &scanner).env("JOBS", "2").env("ALLOW", dir.path().join("allow"))
                .env_remove("CACERT_SCAN_TEMP_DIR").output().unwrap()
        };
        assert!(!invoke("run.sh", true).status.success());
        assert!(dir.path().join("allow.listed").exists());
        assert_eq!(std::fs::read_to_string(out.join("packages.tsv")).unwrap(), "1\t2\tnoarch/good.conda\tgood\n2\t2\tnoarch/bad.conda\tbad\n");
        assert!(out.join("done/1").exists());
        assert!(!out.join("done/2").exists());
        assert_eq!(std::fs::read_to_string(out.join("res/2.jsonl")).unwrap(), "partial\n");
        assert_eq!(std::fs::read_to_string(out.join("failed")).unwrap(), "2\t2\tnoarch/bad.conda\tbad\n");
        std::fs::write(dir.path().join("allow"), b"").unwrap();
        assert!(invoke("retry-failed.sh", false).status.success());
        assert!(out.join("done/2").exists());
        assert_eq!(std::fs::read_to_string(out.join("res/2.jsonl")).unwrap(), "{}\n");
        assert!(!out.join("failed").exists());
        assert!(invoke("run.sh", true).status.success());
    }

}
