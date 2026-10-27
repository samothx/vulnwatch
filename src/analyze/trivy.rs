//! Container images: `trivy sbom` over the CycloneDX SBOM the collector sent.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use opskit::Severity;
use serde::Deserialize;

use crate::inventory::Image;
use crate::model::{Kind, Vuln};

#[derive(Deserialize)]
struct TrivyReport {
    #[serde(rename = "Results", default)]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Class", default)]
    class: String,
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Vulnerabilities", default)]
    vulns: Option<Vec<TrivyVuln>>,
}

#[derive(Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    id: String,
    #[serde(rename = "PkgName", default)]
    pkg: String,
    #[serde(rename = "InstalledVersion", default)]
    installed: String,
    #[serde(rename = "FixedVersion", default)]
    fixed: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Severity", default)]
    severity: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "PrimaryURL", default)]
    url: String,
}

pub struct Trivy {
    pub bin: PathBuf,
    pub cache: PathBuf,
    pub tmp: PathBuf,
    pub offline: bool,
    /// The DB is updated on the first scan of a run only.
    db_checked: std::cell::Cell<bool>,
}

impl Trivy {
    pub fn new(bin: PathBuf, cache: PathBuf, tmp: PathBuf, offline: bool) -> Self {
        Self { bin, cache, tmp, offline, db_checked: std::cell::Cell::new(false) }
    }

    pub fn available(&self) -> bool {
        self.bin.is_file()
    }

    pub fn scan(&self, host: &str, img: &Image) -> Result<Vec<Vuln>> {
        let Some(sbom) = &img.sbom else { return Ok(Vec::new()) };
        std::fs::create_dir_all(&self.tmp).with_context(|| format!("creating {}", self.tmp.display()))?;
        let input = self.tmp.join(format!("{host}-{}.cdx.json", short_id(&img.id)));
        let output = input.with_extension("vulns.json");
        std::fs::write(&input, serde_json::to_vec(sbom)?)?;
        let mut argv: Vec<std::ffi::OsString> = vec![
            self.bin.clone().into(),
            "sbom".into(),
            "--quiet".into(),
            "--disable-telemetry".into(),
            "--skip-version-check".into(),
            "--scanners".into(),
            "vuln".into(),
            "--cache-dir".into(),
            self.cache.clone().into(),
            "--format".into(),
            "json".into(),
            "--output".into(),
            output.clone().into(),
        ];
        if self.offline || self.db_checked.get() {
            argv.push("--skip-db-update".into());
        }
        argv.push(input.clone().into());
        let res = crate::collect::run(&argv, Duration::from_secs(900));
        self.db_checked.set(true);
        let _ = std::fs::remove_file(&input);
        res?;
        let text = std::fs::read(&output).with_context(|| format!("reading {}", output.display()))?;
        let _ = std::fs::remove_file(&output);
        parse(host, &img.reference, &text)
    }
}

impl Trivy {
    /// Scans an image straight from its registry (`repo@sha256:…`) without docker: used to see
    /// what a newer published build still ships. Layers are analyzed once (Trivy's cache).
    pub fn scan_remote(&self, reference: &str) -> Result<Vec<Vuln>> {
        std::fs::create_dir_all(&self.tmp).with_context(|| format!("creating {}", self.tmp.display()))?;
        let safe: String = reference.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
        let output = self.tmp.join(format!("remote-{}.vulns.json", safe.chars().take(120).collect::<String>()));
        let mut argv: Vec<std::ffi::OsString> = vec![
            self.bin.clone().into(),
            "image".into(),
            "--quiet".into(),
            "--disable-telemetry".into(),
            "--skip-version-check".into(),
            "--image-src".into(),
            "remote".into(),
            "--platform".into(),
            format!("linux/{}", go_arch()).into(),
            "--scanners".into(),
            "vuln".into(),
            "--cache-dir".into(),
            self.cache.clone().into(),
            "--format".into(),
            "json".into(),
            "--output".into(),
            output.clone().into(),
        ];
        if self.offline || self.db_checked.get() {
            argv.push("--skip-db-update".into());
        }
        argv.push(reference.into());
        let res = crate::collect::run(&argv, Duration::from_secs(900));
        self.db_checked.set(true);
        res?;
        let text = std::fs::read(&output).with_context(|| format!("reading {}", output.display()))?;
        let _ = std::fs::remove_file(&output);
        parse("upstream", reference, &text)
    }
}

fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn is_kernel_pkg(name: &str) -> bool {
    ["linux-libc-dev", "linux-headers", "linux-image", "linux-modules", "linux-kbuild", "kernel-headers", "linux-lts", "linux-virt"]
        .iter()
        .any(|p| name.starts_with(p))
}

fn short_id(id: &str) -> String {
    id.trim_start_matches("sha256:").chars().take(12).collect()
}

pub fn parse(host: &str, image: &str, json: &[u8]) -> Result<Vec<Vuln>> {
    let rep: TrivyReport = serde_json::from_slice(json).context("parsing trivy JSON")?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in rep.results {
        let os_layer = r.class == "os-pkgs";
        for t in r.vulns.unwrap_or_default() {
            // Kernel packages inside an image are never the running kernel (linux-libc-dev alone
            // carries thousands of kernel CVEs).
            if os_layer && is_kernel_pkg(&t.pkg) {
                continue;
            }
            // The same package often appears in several node_modules copies.
            if !seen.insert((t.pkg.clone(), t.installed.clone(), t.id.clone())) {
                continue;
            }
            let fix_available = t.status == "fixed" && !t.fixed.is_empty();
            let base = t.severity.parse::<Severity>().unwrap_or(Severity::Medium);
            let title = if t.title.is_empty() { opskit::truncate(t.description.lines().next().unwrap_or(""), 200) } else { opskit::truncate(&t.title, 200) };
            let mut v = Vuln {
                id: t.id,
                aliases: Vec::new(),
                host: host.to_string(),
                kind: Kind::Image,
                component: image.to_string(),
                package: if r.kind.is_empty() { t.pkg } else { format!("{} ({})", t.pkg, r.kind) },
                installed: t.installed,
                fixed: (!t.fixed.is_empty()).then_some(t.fixed),
                fix_available,
                base_severity: base,
                severity: base,
                title,
                url: t.url,
                source: if os_layer { "trivy-os" } else { "trivy-lang" }.into(),
                kev: false,
                epss: None,
                new: false,
                fingerprint: String::new(),
                note: String::new(),
            };
            v.make_fingerprint();
            out.push(v);
        }
    }
    Ok(out)
}

pub fn tmp_dir(state: &Path) -> PathBuf {
    state.join("tmp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_dedupes() {
        let j = br#"{"Results":[
          {"Target":"x (alpine 3.22.2)","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[
            {"VulnerabilityID":"CVE-1","PkgName":"openssl","InstalledVersion":"3.5.1-r0","FixedVersion":"3.5.4-r0","Status":"fixed","Severity":"HIGH","Title":"t"},
            {"VulnerabilityID":"CVE-k","PkgName":"linux-libc-dev","InstalledVersion":"6.1-1","FixedVersion":"6.2-1","Status":"fixed","Severity":"HIGH","Title":"k"}]},
          {"Target":"Node.js","Class":"lang-pkgs","Type":"node-pkg","Vulnerabilities":[
            {"VulnerabilityID":"CVE-2025-68613","PkgName":"n8n","InstalledVersion":"1.121.0","FixedVersion":"1.120.4, 1.121.1","Status":"fixed","Severity":"CRITICAL","Title":"rce"},
            {"VulnerabilityID":"CVE-2025-68613","PkgName":"n8n","InstalledVersion":"1.121.0","FixedVersion":"1.120.4, 1.121.1","Status":"fixed","Severity":"CRITICAL","Title":"rce"},
            {"VulnerabilityID":"CVE-3","PkgName":"lodash","InstalledVersion":"4.17.20","FixedVersion":"","Status":"affected","Severity":"UNKNOWN","Description":"d\nmore"}]},
          {"Target":"bin","Class":"lang-pkgs","Type":"gobinary"}
        ]}"#;
        let v = parse("anubis", "n8nio/n8n:1.121.0", j).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[1].package, "n8n (node-pkg)");
        assert_eq!((v[0].source.as_str(), v[1].source.as_str()), ("trivy-os", "trivy-lang"));
        assert!(v[1].fix_available && v[1].base_severity == Severity::Critical);
        assert!(!v[2].fix_available && v[2].base_severity == Severity::Medium && v[2].title == "d");
    }
}
