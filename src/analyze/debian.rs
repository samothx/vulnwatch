//! Debian: installed source packages vs the security tracker's per-release status.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use opskit::Severity;
use serde::Deserialize;

use crate::inventory::Inventory;
use crate::model::{Kind, Vuln};
use crate::version::deb_cmp;

#[derive(Deserialize)]
pub struct CveEntry {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub releases: HashMap<String, Release>,
}

#[derive(Deserialize)]
pub struct Release {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub repositories: BTreeMap<String, String>,
    #[serde(default)]
    pub fixed_version: Option<String>,
    #[serde(default)]
    pub urgency: String,
    #[serde(default)]
    pub nodsa: Option<String>,
}

/// source package → CVE → entry
pub type Tracker = HashMap<String, HashMap<String, CveEntry>>;

pub fn load(path: &Path) -> Result<Tracker> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parsing the Debian security tracker JSON")
}

pub fn matches(inv: &Inventory, tracker: &Tracker) -> Vec<Vuln> {
    let suite = inv.os.codename.as_str();
    let mut out = Vec::new();
    // One entry per source package (binaries of the same source share the version).
    let mut sources: BTreeMap<&str, (&str, Vec<&str>)> = BTreeMap::new();
    for p in &inv.packages {
        let src = if p.source.is_empty() { p.name.as_str() } else { p.source.as_str() };
        let ver = if p.source_version.is_empty() { p.version.as_str() } else { p.source_version.as_str() };
        let e = sources.entry(src).or_insert((ver, Vec::new()));
        // Mixed versions mid-upgrade: keep the oldest (the vulnerable one).
        if deb_cmp(ver, e.0).is_lt() {
            e.0 = ver;
        }
        e.1.push(p.name.as_str());
    }
    for (src, (installed, bins)) in sources {
        let Some(cves) = tracker.get(src) else { continue };
        for (cve, entry) in cves {
            let Some(rel) = entry.releases.get(suite) else { continue };
            if rel.urgency == "unimportant" || rel.status == "undetermined" {
                continue;
            }
            let (fixed, fix_available) = match (rel.status.as_str(), rel.fixed_version.as_deref()) {
                ("resolved", Some("0")) => continue, // never affected
                ("resolved", Some(f)) => {
                    if deb_cmp(installed, f).is_ge() {
                        continue;
                    }
                    // Fixed in the tracker, but is it in a repository yet (security or point release)?
                    let available = rel.repositories.values().any(|v| deb_cmp(v, f).is_ge());
                    (Some(f.to_string()), available)
                }
                ("open", _) => (None, false),
                _ => continue,
            };
            let base = match rel.urgency.trim_end_matches('*') {
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                "end-of-life" => Severity::Low,
                // "not yet assigned": a fix exists, so it is worth installing.
                _ => {
                    if fix_available {
                        Severity::Medium
                    } else {
                        Severity::Low
                    }
                }
            };
            let mut title = opskit::truncate(entry.description.trim(), 220);
            if let Some(reason) = &rel.nodsa {
                title = format!("{title} [no DSA: {reason}]");
            }
            let mut v = Vuln {
                id: cve.clone(),
                aliases: Vec::new(),
                host: inv.host.clone(),
                kind: Kind::Os,
                component: "Debian packages".into(),
                package: if bins.len() == 1 && bins[0] == src { src.to_string() } else { format!("{src} ({})", short_list(&bins)) },
                installed: installed.to_string(),
                fixed,
                fix_available,
                base_severity: base,
                severity: base,
                title,
                url: format!("https://security-tracker.debian.org/tracker/{cve}"),
                source: "debian-tracker".into(),
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
    out
}

fn short_list(bins: &[&str]) -> String {
    let mut b: Vec<&str> = bins.to_vec();
    b.sort_unstable();
    b.dedup();
    if b.len() > 3 { format!("{}, … {} binaries", b[..3].join(", "), b.len()) } else { b.join(", ") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Os, Package};

    #[test]
    fn matches_trixie_status() {
        let tracker: Tracker = serde_json::from_str(
            r#"{"openssl": {
                "CVE-1": {"description":"fixed in security","releases":{"trixie":{"status":"resolved","repositories":{"trixie":"3.5.6-1~deb13u2","trixie-security":"3.5.7-1~deb13u3"},"fixed_version":"3.5.7-1~deb13u3","urgency":"high"}}},
                "CVE-2": {"description":"already fixed","releases":{"trixie":{"status":"resolved","repositories":{},"fixed_version":"3.5.0-1","urgency":"medium"}}},
                "CVE-3": {"description":"open","releases":{"trixie":{"status":"open","repositories":{},"urgency":"not yet assigned","nodsa":"Minor issue"}}},
                "CVE-4": {"description":"unimportant","releases":{"trixie":{"status":"open","repositories":{},"urgency":"unimportant"}}},
                "CVE-5": {"description":"not affected","releases":{"trixie":{"status":"resolved","repositories":{},"fixed_version":"0","urgency":"low"}}},
                "CVE-6": {"description":"fix not yet in a repo","releases":{"trixie":{"status":"resolved","repositories":{"trixie":"3.5.6-1~deb13u2"},"fixed_version":"3.5.8-1","urgency":"not yet assigned"}}},
                "CVE-7": {"description":"other release only","releases":{"bookworm":{"status":"open","repositories":{},"urgency":"high"}}}
            }}"#,
        )
        .unwrap();
        let inv = Inventory {
            host: "anubis".into(),
            os: Os { id: "debian".into(), codename: "trixie".into(), ..Default::default() },
            packages: vec![
                Package { name: "libssl3t64".into(), version: "3.5.6-1~deb13u2".into(), source: "openssl".into(), source_version: "3.5.6-1~deb13u2".into() },
                Package { name: "openssl".into(), version: "3.5.6-1~deb13u2".into(), source: "openssl".into(), source_version: "3.5.6-1~deb13u2".into() },
            ],
            ..Default::default()
        };
        let mut v = matches(&inv, &tracker);
        v.sort_by(|a, b| a.id.cmp(&b.id));
        let ids: Vec<&str> = v.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-1", "CVE-3", "CVE-6"]);
        assert!(v[0].fix_available && v[0].base_severity == Severity::High);
        assert!(!v[1].fix_available && v[1].fixed.is_none() && v[1].title.contains("no DSA"));
        assert!(!v[2].fix_available && v[2].fixed.as_deref() == Some("3.5.8-1"));
        assert_eq!(v[0].package, "openssl (libssl3t64, openssl)");
    }
}
