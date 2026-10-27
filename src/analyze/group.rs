//! Vulnerabilities → one finding per thing you act on (a host's OS packages, an image, a
//! lockfile, a product). Without a fix nothing can be done, so those only feed counts.

use std::collections::BTreeMap;

use opskit::Severity;

use crate::model::{Finding, Kind, SevCounts, UnfixedSummary, Vuln};

pub fn group(vulns: Vec<Vuln>, pkg_manager: &BTreeMap<String, String>) -> (Vec<Finding>, Vec<UnfixedSummary>) {
    let mut buckets: BTreeMap<(String, Kind, String), (Vec<Vuln>, SevCounts)> = BTreeMap::new();
    for v in vulns {
        let e = buckets.entry((v.host.clone(), v.kind, v.component.clone())).or_default();
        if v.fix_available || v.kev {
            e.0.push(v);
        } else {
            e.1.add(v.base_severity);
        }
    }
    let mut findings = Vec::new();
    let mut unfixed = Vec::new();
    for ((host, kind, component), (mut vs, counts)) in buckets {
        if counts.total() > 0 {
            unfixed.push(UnfixedSummary { host: host.clone(), kind, component: component.clone(), counts });
        }
        // Informational only (RustSec "unsound"/"unmaintained" notes): nothing to act on.
        if vs.is_empty() || vs.iter().all(|v| v.severity == Severity::Info) {
            continue;
        }
        vs.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.kev.cmp(&a.kev))
                .then(b.epss.partial_cmp(&a.epss).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.package.cmp(&b.package))
                .then(a.id.cmp(&b.id))
        });
        let severity = vs.iter().map(|v| v.severity).max().unwrap_or(Severity::Info);
        let new_count = vs.iter().filter(|v| v.new).count();
        let (title, action) = describe(&host, kind, &component, &vs, pkg_manager.get(&host).map(String::as_str));
        findings.push(Finding {
            fingerprint: format!("{host}|{kind:?}|{component}"),
            host,
            kind,
            component,
            severity,
            title,
            action,
            vulns: vs,
            unfixed: counts,
            detail: String::new(),
            new_count,
            remind: false,
            exposure: None,
        });
    }
    (findings, unfixed)
}

fn describe(host: &str, kind: Kind, component: &str, vs: &[Vuln], mgr: Option<&str>) -> (String, String) {
    let n = vs.len();
    let pkgs = {
        let mut p: Vec<&str> = vs.iter().map(|v| v.package.split(' ').next().unwrap_or(&v.package)).collect();
        p.sort_unstable();
        p.dedup();
        p.len()
    };
    match kind {
        Kind::Os => {
            let cmd = match mgr {
                Some("pacman") => "pacman -Syu",
                _ => "apt upgrade",
            };
            (format!("{n} fixable vulnerabilities in {pkgs} OS package(s)"), format!("`{cmd}` on {host} (then restart affected services / reboot for the kernel)"))
        }
        Kind::Image => (format!("{n} fixable vulnerabilities in image {component}"), format!("pull/rebuild a newer {component} and recreate its containers on {host}")),
        Kind::Lockfile => {
            let tool = if component.ends_with("Cargo.lock") { "cargo update" } else { "npm update / npm audit fix" };
            (format!("{n} vulnerable dependencies in source tree {component}"), format!("`{tool}` in {} on {host}, then rebuild/redeploy", parent(component)))
        }
        Kind::Watch => {
            let installed = vs.first().map(|v| v.installed.as_str()).unwrap_or("?");
            let target = vs.iter().filter_map(|v| v.fixed.as_deref()).max_by(|a, b| crate::version::loose_cmp(a, b)).unwrap_or("a fixed release");
            (format!("{component} {installed}: {n} known vulnerabilities"), format!("upgrade {component} on {host} to ≥ {target}"))
        }
        Kind::Outdated | Kind::Health => (component.to_string(), String::new()),
    }
}

fn parent(p: &str) -> &str {
    p.rsplit_once('/').map(|(d, _)| d).unwrap_or(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(id: &str, kind: Kind, comp: &str, sev: Severity, fix: bool) -> Vuln {
        let mut v = Vuln {
            id: id.into(),
            aliases: vec![],
            host: "anubis".into(),
            kind,
            component: comp.into(),
            package: "n8n (node-pkg)".into(),
            installed: "1.121.0".into(),
            fixed: fix.then(|| "1.121.3".into()),
            fix_available: fix,
            base_severity: sev,
            severity: sev,
            title: String::new(),
            url: String::new(),
            source: "t".into(),
            kev: false,
            epss: None,
            new: true,
            fingerprint: String::new(),
            note: String::new(),
        };
        v.make_fingerprint();
        v
    }

    #[test]
    fn groups_and_counts_unfixed() {
        let (f, u) = group(
            vec![
                v("A", Kind::Image, "n8nio/n8n:1.121.0", Severity::High, true),
                v("B", Kind::Image, "n8nio/n8n:1.121.0", Severity::Critical, true),
                v("C", Kind::Image, "n8nio/n8n:1.121.0", Severity::Critical, false),
                v("D", Kind::Image, "nginx:alpine", Severity::Low, false),
            ],
            &BTreeMap::new(),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].vulns[0].id, "B");
        assert_eq!(f[0].new_count, 2);
        assert_eq!(f[0].unfixed.critical, 1);
        assert_eq!(u.len(), 2);
        assert!(f[0].action.contains("n8nio/n8n:1.121.0"));
    }
}
