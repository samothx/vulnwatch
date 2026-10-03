//! Arch Linux and derivatives (CachyOS): pacman packages vs security.archlinux.org AVGs.
//!
//! Coverage caveat (reported in the notes): the Arch tracker is maintained by volunteers and
//! lags; CachyOS-only packages (linux-cachyos, …) are not in it at all. The watch list and
//! lockfiles fill some of that gap.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use opskit::Severity;
use serde::Deserialize;

use crate::inventory::Inventory;
use crate::model::{Kind, Vuln};
use crate::version::alpm_cmp;

#[derive(Deserialize)]
pub struct Avg {
    pub name: String,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub affected: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub issues: Vec<String>,
}

pub fn load(path: &Path) -> Result<Vec<Avg>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parsing the Arch security tracker JSON")
}

pub fn matches(inv: &Inventory, avgs: &[Avg]) -> Vec<Vuln> {
    let installed: HashMap<&str, &str> = inv.packages.iter().map(|p| (p.name.as_str(), p.version.as_str())).collect();
    let mut out = Vec::new();
    for a in avgs {
        if a.status == "Not affected" {
            continue;
        }
        for pkg in &a.packages {
            let Some(ver) = installed.get(pkg.as_str()) else { continue };
            let (fixed, fix_available) = match a.fixed.as_deref() {
                Some(f) if alpm_cmp(ver, f).is_ge() => continue,
                Some(f) => (Some(f.to_string()), true),
                // No fix yet: only if the tracker says still vulnerable and we are not older
                // than the first affected version it knows (older ones are long gone).
                None if a.status == "Vulnerable" => {
                    if let Some(aff) = a.affected.as_deref()
                        && alpm_cmp(ver, aff).is_lt()
                    {
                        continue;
                    }
                    (None, false)
                }
                None => continue,
            };
            let base = a.severity.parse::<Severity>().unwrap_or(Severity::Medium);
            let cves: Vec<String> = a.issues.iter().filter(|i| i.starts_with("CVE-")).cloned().collect();
            let title = if cves.is_empty() {
                format!("{} ({})", a.kind, pkg)
            } else {
                format!("{} ({}): {}", a.kind, pkg, short(&cves))
            };
            let mut v = Vuln {
                id: a.name.clone(),
                aliases: cves,
                host: inv.host.clone(),
                kind: Kind::Os,
                component: "Arch packages".into(),
                package: pkg.clone(),
                installed: ver.to_string(),
                fixed,
                fix_available,
                base_severity: base,
                severity: base,
                title,
                url: format!("https://security.archlinux.org/{}", a.name),
                source: "arch-tracker".into(),
                kev: false,
                epss: None,
                new: false,
                fingerprint: String::new(),
            };
            v.make_fingerprint();
            out.push(v);
        }
    }
    out
}

fn short(ids: &[String]) -> String {
    if ids.len() > 4 { format!("{} … (+{})", ids[..4].join(", "), ids.len() - 4) } else { ids.join(", ") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Package;

    #[test]
    fn matches_fixed_and_open() {
        let avgs: Vec<Avg> = serde_json::from_str(
            r#"[
              {"name":"AVG-1","packages":["vim"],"status":"Fixed","severity":"High","type":"arbitrary code execution","affected":"9.0-1","fixed":"9.1-1","issues":["CVE-9"]},
              {"name":"AVG-2","packages":["vim"],"status":"Fixed","severity":"Low","type":"x","affected":"8.0-1","fixed":"8.1-1","issues":[]},
              {"name":"AVG-3","packages":["curl"],"status":"Vulnerable","severity":"Medium","type":"y","affected":"8.10-1","fixed":null,"issues":["CVE-8"]},
              {"name":"AVG-4","packages":["curl"],"status":"Not affected","severity":"High","type":"z","affected":"1-1","fixed":null,"issues":[]},
              {"name":"AVG-5","packages":["gone"],"status":"Vulnerable","severity":"High","type":"z","affected":"1-1","fixed":null,"issues":[]}
            ]"#,
        )
        .unwrap();
        let inv = Inventory {
            host: "zeno".into(),
            packages: vec![
                Package { name: "vim".into(), version: "9.0.2-1".into(), ..Default::default() },
                Package { name: "curl".into(), version: "8.16.0-1".into(), ..Default::default() },
            ],
            ..Default::default()
        };
        let v = matches(&inv, &avgs);
        assert_eq!(v.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(), vec!["AVG-1", "AVG-3"]);
        assert!(v[0].fix_available && v[0].aliases == vec!["CVE-9"]);
        assert!(!v[1].fix_available);
    }
}
