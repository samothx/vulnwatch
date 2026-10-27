//! Source trees vs. what runs: a lockfile on a dev notebook is a checkout, not a service. With
//! `[[host]] deployed_as` (lockfile glob → image glob) each lockfile vulnerability is compared
//! with the package versions inside the deployed image's SBOM:
//!
//! - the image reports the same vulnerability itself → the image finding covers it (capped here),
//! - the image runs another version of the package and is not affected → stale checkout (capped),
//! - the image runs the same version → kept (the image scanner may simply not know the advisory),
//! - the package is not in the image → kept (build/dev dependency, or bundled into JS chunks).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::config::Config;
use crate::inventory::{Image, Inventory};
use crate::model::{Finding, Kind, Vuln};

use super::glob;

#[derive(Debug, Default, Clone)]
pub struct Deployed {
    /// deployed_as pattern, if one matched the lockfile.
    pub pattern: Option<String>,
    /// "host: image (containers)" of every matching running image.
    pub images: Vec<String>,
    pub duplicate: usize,
    pub stale: usize,
    pub same: usize,
    pub missing: usize,
}

impl Deployed {
    pub fn describe(&self, f: &Finding) -> String {
        let mut s = format!("Source tree on {}: a checkout, not a running service.", f.host);
        match &self.pattern {
            None => s.push_str(" Map it to its image with `[[host]] deployed_as` to compare it with what runs."),
            Some(p) if self.images.is_empty() => {
                let _ = write!(s, " deployed_as `{p}` matches no running image.");
            }
            Some(_) => {
                let _ = write!(s, " Deployed as {}.", self.images.join("; "));
                let mut parts = Vec::new();
                if self.stale > 0 {
                    parts.push(format!("{} older than the deployed version (not affected there)", self.stale));
                }
                if self.duplicate > 0 {
                    parts.push(format!("{} reported under the image itself", self.duplicate));
                }
                if self.same > 0 {
                    parts.push(format!("{} at the deployed version", self.same));
                }
                if self.missing > 0 {
                    parts.push(format!("{} not in the image (build/dev dependency, or bundled)", self.missing));
                }
                if !parts.is_empty() {
                    let _ = write!(s, " Of its vulnerabilities: {}. The first two kinds are capped here.", parts.join(", "));
                }
            }
        }
        s
    }
}

/// purl type for an OSV lockfile ecosystem.
fn purl_type(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "npm" => Some("npm"),
        "crates.io" => Some("cargo"),
        "PyPI" => Some("pypi"),
        "Go" => Some("golang"),
        "Packagist" => Some("composer"),
        _ => None,
    }
}

/// `pkg:npm/%40scope/name@1.2.3?x=y` → ("npm", "@scope/name", "1.2.3").
pub fn parse_purl(p: &str) -> Option<(String, String, String)> {
    let rest = p.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next()?;
    let (ty, path) = rest.split_once('/')?;
    let (name, version) = path.rsplit_once('@')?;
    let name = name.replace("%40", "@").replace("%2F", "/").replace("%2f", "/");
    Some((ty.to_ascii_lowercase(), name, version.to_string()))
}

/// (purl type, package) → versions in one image's SBOM.
type SbomPackages = BTreeMap<(String, String), BTreeSet<String>>;

fn sbom_packages(img: &Image) -> SbomPackages {
    let mut out = SbomPackages::new();
    let comps = img.sbom.as_ref().and_then(|s| s["components"].as_array());
    for c in comps.into_iter().flatten() {
        if let Some((ty, name, ver)) = c["purl"].as_str().and_then(parse_purl) {
            out.entry((ty, name)).or_default().insert(ver);
        }
    }
    out
}

fn ids(v: &Vuln) -> impl Iterator<Item = &str> {
    std::iter::once(v.id.as_str()).chain(v.aliases.iter().map(String::as_str))
}

fn base_pkg(p: &str) -> &str {
    p.split(' ').next().unwrap_or(p)
}

/// Caps stale/duplicate lockfile vulnerabilities and returns, per (host, lockfile), what was found.
pub fn compare(cfg: &Config, inventories: &[Inventory], vulns: &mut [Vuln]) -> BTreeMap<(String, String), Deployed> {
    let mut out: BTreeMap<(String, String), Deployed> = BTreeMap::new();
    // Image vulnerabilities by (host, image) → (package, id) keys, for the duplicate check.
    let mut image_vulns: BTreeMap<(String, String), BTreeSet<(String, String)>> = BTreeMap::new();
    for v in vulns.iter().filter(|v| v.kind == Kind::Image) {
        let e = image_vulns.entry((v.host.clone(), v.component.clone())).or_default();
        for id in ids(v) {
            e.insert((base_pkg(&v.package).to_string(), id.to_string()));
        }
    }
    let mut sboms: BTreeMap<(String, String), SbomPackages> = BTreeMap::new();

    for v in vulns.iter_mut().filter(|v| v.kind == Kind::Lockfile) {
        let key = (v.host.clone(), v.component.clone());
        let hc = cfg.host_cfg(&v.host);
        let pattern = hc.deployed_as.iter().find(|(lock, _)| glob(lock, &v.component)).map(|(_, img)| img.clone());
        let ecosystem = inventories
            .iter()
            .filter(|i| i.host == v.host)
            .flat_map(|i| &i.lockfiles)
            .find(|l| l.path == v.component)
            .map(|l| l.ecosystem.clone())
            .unwrap_or_default();
        let images: Vec<(&str, &Image)> = match &pattern {
            Some(p) => inventories
                .iter()
                .flat_map(|i| i.images.iter().map(move |img| (i.host.as_str(), img)))
                .filter(|(_, img)| {
                    glob(p, &img.reference) || img.containers.iter().any(|c| glob(p, c)) || (!img.configured.is_empty() && glob(p, &img.configured))
                })
                .collect(),
            None => Vec::new(),
        };
        let d = out.entry(key).or_insert_with(|| Deployed {
            pattern: pattern.clone(),
            images: images.iter().map(|(h, img)| format!("{h}: {} ({})", img.reference, img.containers.join(", "))).collect(),
            ..Default::default()
        });
        if images.is_empty() {
            continue;
        }
        let Some(ty) = purl_type(&ecosystem) else {
            continue;
        };

        let mut duplicate_in = None;
        let mut versions: BTreeSet<String> = BTreeSet::new();
        for (h, img) in &images {
            let ik = (h.to_string(), img.reference.clone());
            if let Some(keys) = image_vulns.get(&ik)
                && ids(v).any(|id| keys.contains(&(v.package.clone(), id.to_string())))
            {
                duplicate_in = Some(format!("{h}: {}", img.reference));
            }
            let pk = sboms.entry(ik).or_insert_with(|| sbom_packages(img));
            if let Some(vs) = pk.get(&(ty.to_string(), v.package.clone())) {
                versions.extend(vs.iter().cloned());
            }
        }
        if let Some(img) = duplicate_in {
            d.duplicate += 1;
            v.severity = v.severity.min(cfg.analyze.lockfile_stale_max);
            v.note = format!("the deployed copy is reported under image {img}");
        } else if versions.is_empty() {
            d.missing += 1;
            v.note = "not in the deployed image (build/dev dependency, or bundled)".into();
        } else if versions.contains(&v.installed) {
            d.same += 1;
            v.note = "the deployed image runs this version too".into();
        } else {
            d.stale += 1;
            v.severity = v.severity.min(cfg.analyze.lockfile_stale_max);
            v.note = format!("stale checkout: the deployed image runs {} {} (not affected)", v.package, versions.into_iter().collect::<Vec<_>>().join(", "));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Lockfile;
    use opskit::Severity;

    #[test]
    fn purls() {
        assert_eq!(parse_purl("pkg:npm/next@16.4.2"), Some(("npm".into(), "next".into(), "16.4.2".into())));
        assert_eq!(parse_purl("pkg:npm/%40next/env@16.4.2?x=1"), Some(("npm".into(), "@next/env".into(), "16.4.2".into())));
        assert_eq!(parse_purl("pkg:cargo/serde@1.0.0"), Some(("cargo".into(), "serde".into(), "1.0.0".into())));
        assert_eq!(parse_purl("nope"), None);
    }

    fn vuln(kind: Kind, host: &str, comp: &str, pkg: &str, ver: &str, id: &str) -> Vuln {
        Vuln {
            id: id.into(),
            aliases: vec![],
            host: host.into(),
            kind,
            component: comp.into(),
            package: pkg.into(),
            installed: ver.into(),
            fixed: Some("99".into()),
            fix_available: true,
            base_severity: Severity::Critical,
            severity: Severity::Critical,
            title: String::new(),
            url: String::new(),
            source: "osv".into(),
            kev: false,
            epss: None,
            new: false,
            fingerprint: String::new(),
            note: String::new(),
        }
    }

    #[test]
    fn stale_duplicate_same_missing() {
        let lock = "/home/t/develop/shop/package-lock.json";
        let mut cfg = Config::default();
        let mut hc = crate::config::HostCfg { name: "zeno".into(), ..Default::default() };
        hc.deployed_as.insert("*/shop/package-lock.json".into(), "registry.example/shop:*".into());
        cfg.hosts.push(hc);
        let sbom = serde_json::json!({"components": [
            {"purl": "pkg:npm/next@16.4.2"}, {"purl": "pkg:npm/sharp@0.34.0"}, {"purl": "pkg:npm/undici@7.0.0"}]});
        let invs = vec![
            Inventory {
                host: "anubis".into(),
                images: vec![Image {
                    reference: "registry.example/shop:prod".into(),
                    containers: vec!["gmc".into()],
                    sbom: Some(sbom),
                    ..Default::default()
                }],
                ..Default::default()
            },
            Inventory { host: "zeno".into(), lockfiles: vec![Lockfile { path: lock.into(), ecosystem: "npm".into(), packages: vec![] }], ..Default::default() },
        ];
        let mut vs = vec![
            vuln(Kind::Image, "anubis", "registry.example/shop:prod", "undici (node-pkg)", "7.0.0", "GHSA-u"),
            vuln(Kind::Lockfile, "zeno", lock, "next", "16.3.4", "GHSA-n"),
            vuln(Kind::Lockfile, "zeno", lock, "undici", "7.0.0", "GHSA-u"),
            vuln(Kind::Lockfile, "zeno", lock, "sharp", "0.34.0", "GHSA-s"),
            vuln(Kind::Lockfile, "zeno", lock, "eslint", "9.0.0", "GHSA-e"),
        ];
        let d = compare(&cfg, &invs, &mut vs);
        assert_eq!(vs[1].severity, Severity::Low, "stale next");
        assert!(vs[1].note.contains("16.4.2"));
        assert_eq!(vs[2].severity, Severity::Low, "reported under the image");
        assert_eq!(vs[3].severity, Severity::Critical, "same version stays");
        assert_eq!(vs[4].severity, Severity::Critical, "not in image stays");
        let x = &d[&("zeno".to_string(), lock.to_string())];
        assert_eq!((x.stale, x.duplicate, x.same, x.missing), (1, 1, 1, 1));
    }
}
