//! `vulnwatch run`: inbox inventories → matches → policy → findings → diff → report.

pub mod arch;
pub mod cvss;
pub mod debian;
pub mod group;
pub mod osv;
pub mod outdated;
pub mod policy;
pub mod trivy;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::Result;
use chrono::Local;
use opskit::Severity;

use crate::config::{Config, Exposure};
use crate::feeds::{self, Fetcher};
use crate::inventory::Inventory;
use crate::model::{Finding, HostSummary, Kind, Report, Vuln};
use crate::state::State;

pub struct Options {
    pub offline: bool,
}

/// Every inventory in the inbox (`<host>.json.gz`, file name must match the host inside).
pub fn load_inbox(cfg: &Config, errors: &mut Vec<String>) -> Vec<Inventory> {
    let dir = cfg.state_path(&cfg.analyze.inbox);
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        errors.push(format!("inbox {} not readable", dir.display()));
        return out;
    };
    let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(".json.gz")).collect();
    files.sort();
    for p in files {
        let stem = p.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".json.gz")).unwrap_or("").to_string();
        match Inventory::read(&p) {
            Ok(inv) if inv.host == stem => out.push(inv),
            Ok(inv) => errors.push(format!("{}: inventory says host '{}', file name says '{stem}'; ignored", p.display(), inv.host)),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    out
}

pub fn run(cfg: &Config, opts: &Options, state: &mut State) -> Result<Report> {
    let now = Local::now();
    let mut errors = Vec::new();
    let mut notes = Vec::new();
    let feeds_dir = cfg.state_path(std::path::Path::new("feeds"));
    let fetcher = Fetcher::new(feeds_dir.clone(), cfg.analyze.feeds_max_age_hours, cfg.analyze.http_timeout_secs, opts.offline);
    let inventories = load_inbox(cfg, &mut errors);

    // Feeds are loaded only if some inventory needs them.
    let need_debian = inventories.iter().any(|i| i.pkg_manager == "dpkg");
    let need_arch = inventories.iter().any(|i| i.pkg_manager == "pacman");
    let debian = if need_debian { load_feed(&fetcher, &feeds::DEBIAN, debian::load, &mut errors) } else { None };
    let arch = if need_arch { load_feed(&fetcher, &feeds::ARCH, arch::load, &mut errors) } else { None };
    let mut intel = policy::Intel::default();
    match fetcher.get(&feeds::KEV, &mut errors) {
        Ok(p) => {
            if let Err(e) = intel.load_kev(&p) {
                errors.push(format!("KEV: {e:#}"));
            }
        }
        Err(e) => errors.push(format!("KEV: {e:#}")),
    }
    match fetcher.get(&feeds::EPSS, &mut errors) {
        Ok(p) => {
            if let Err(e) = intel.load_epss(&p) {
                errors.push(format!("EPSS: {e:#}"));
            }
        }
        Err(e) => errors.push(format!("EPSS: {e:#}")),
    }

    let trivy = trivy::Trivy::new(
        cfg.analyze.trivy.clone(),
        cfg.state_path(&cfg.analyze.trivy_cache),
        trivy::tmp_dir(&cfg.general.state_dir),
        opts.offline,
    );
    let osv = osv::Osv::new(fetcher.agent(), osv::cache_dir(&feeds_dir));
    let gh_token = (!cfg.analyze.github_token_file.as_os_str().is_empty())
        .then(|| opskit::secret::read("VULNWATCH_GITHUB_TOKEN", &cfg.analyze.github_token_file))
        .transpose()
        .unwrap_or_else(|e| {
            errors.push(format!("github token: {e:#}"));
            None
        });
    let github = outdated::GitHub::new(fetcher.agent(), gh_token, feeds_dir.join("github"), cfg.analyze.feeds_max_age_hours, opts.offline);

    let mut vulns: Vec<Vuln> = Vec::new();
    let mut extra: Vec<Finding> = Vec::new();
    let mut covered: BTreeSet<(String, Kind)> = BTreeSet::new();
    let mut hosts = Vec::new();
    let mut pkg_managers = BTreeMap::new();

    for inv in &inventories {
        let hc = cfg.host_cfg(&inv.host);
        pkg_managers.insert(inv.host.clone(), inv.pkg_manager.clone());
        hosts.push(HostSummary {
            name: inv.host.clone(),
            collected_at: inv.collected_at,
            os: inv.os.pretty_name.clone(),
            packages: inv.packages.len(),
            images: inv.images.len(),
            lockfiles: inv.lockfiles.len(),
            watched: inv.watched.len(),
            collector_errors: inv.errors.clone(),
        });
        let mut host_vulns = Vec::new();

        // OS packages
        match inv.pkg_manager.as_str() {
            "dpkg" if inv.os.is("debian") && !inv.os.codename.is_empty() => {
                if let Some(t) = &debian {
                    host_vulns.extend(debian::matches(inv, t));
                    covered.insert((inv.host.clone(), Kind::Os));
                }
            }
            "dpkg" => notes.push(format!("{}: dpkg on '{}' is not Debian; OS packages not checked", inv.host, inv.os.id)),
            "pacman" => {
                if let Some(a) = &arch {
                    host_vulns.extend(arch::matches(inv, a));
                    covered.insert((inv.host.clone(), Kind::Os));
                }
                if inv.os.id != "arch" {
                    notes.push(format!(
                        "{}: {} packages are matched against the Arch tracker; distribution-specific builds (e.g. linux-cachyos) are not covered there",
                        inv.host, inv.os.id
                    ));
                }
            }
            _ => {}
        }

        // Images
        if !inv.images.is_empty() {
            if trivy.available() {
                let mut ok = true;
                for img in &inv.images {
                    if img.sbom.is_none() {
                        notes.push(format!("{}: image {} has no SBOM (collector without trivy?)", inv.host, img.reference));
                        ok = false;
                        continue;
                    }
                    match trivy.scan(&inv.host, img) {
                        Ok(v) => host_vulns.extend(v),
                        Err(e) => {
                            ok = false;
                            errors.push(format!("trivy {} {}: {e:#}", inv.host, img.reference));
                        }
                    }
                }
                if ok {
                    covered.insert((inv.host.clone(), Kind::Image));
                }
            } else {
                errors.push(format!("trivy not found at {}; {} image(s) of {} not scanned", cfg.analyze.trivy.display(), inv.images.len(), inv.host));
            }
        }

        // Lockfiles + watch list via OSV
        let queries = osv::queries(inv);
        if !queries.is_empty() {
            if opts.offline {
                notes.push(format!("{}: OSV lookups skipped (--offline)", inv.host));
            } else {
                match osv.matches(&queries, &mut errors) {
                    Ok(v) => {
                        host_vulns.extend(v);
                        covered.insert((inv.host.clone(), Kind::Lockfile));
                        covered.insert((inv.host.clone(), Kind::Watch));
                    }
                    Err(e) => errors.push(format!("osv {}: {e:#}", inv.host)),
                }
            }
        }

        // Policy
        for v in host_vulns.iter_mut() {
            intel.annotate(v);
            let exp = exposure_for(inv, v, &hc);
            policy::apply(v, exp, &cfg.analyze);
        }
        vulns.extend(host_vulns);

        // Outdated releases
        let mut seen = BTreeSet::new();
        for w in inv.watched.iter().filter(|w| !w.github.is_empty()) {
            if !seen.insert((w.name.clone(), w.version.clone())) {
                continue;
            }
            match github.latest(&w.github, w.same_major.then_some(w.version.as_str())) {
                Ok(Some(latest)) => {
                    let (newer, major) = outdated::compare(&w.version, &latest);
                    if newer {
                        let sev = if major { Severity::Medium } else { Severity::Low };
                        extra.push(Finding {
                            host: inv.host.clone(),
                            kind: Kind::Outdated,
                            component: w.name.clone(),
                            severity: sev,
                            title: format!("{} {} → {} available{}", w.name, w.version, latest, if major { " (new major version)" } else { "" }),
                            action: format!("plan an upgrade of {} on {}", w.name, inv.host),
                            vulns: Vec::new(),
                            unfixed: Default::default(),
                            detail: format!("https://github.com/{}/releases", w.github),
                            new_count: 0,
                            remind: false,
                            fingerprint: format!("{}|Outdated|{}|{}|{}", inv.host, w.name, w.version, latest),
                        });
                    }
                }
                Ok(None) => {}
                Err(e) => errors.push(format!("releases {}: {e:#}", w.github)),
            }
        }

        // Collector problems
        if !inv.errors.is_empty() {
            extra.push(health(&inv.host, Severity::Low, format!("collector reported {} problem(s)", inv.errors.len()), inv.errors.join("\n- "), "collector-errors"));
        }
    }

    // Stale or missing inventories
    for h in &cfg.hosts {
        let inv = inventories.iter().find(|i| i.host == h.name);
        let age_days = inv.and_then(|i| i.collected_at).map(|t| (now - t).num_hours() as f64 / 24.0);
        match age_days {
            None => {
                hosts.push(HostSummary {
                    name: h.name.clone(),
                    collected_at: None,
                    os: String::new(),
                    packages: 0,
                    images: 0,
                    lockfiles: 0,
                    watched: 0,
                    collector_errors: Vec::new(),
                });
                extra.push(health(&h.name, Severity::Medium, "no inventory received yet".into(), String::new(), "missing"));
            }
            Some(d) if d > f64::from(h.stale_days) => {
                extra.push(health(&h.name, Severity::Medium, format!("inventory is {d:.1} days old (limit {})", h.stale_days), String::new(), "stale"));
            }
            _ => {}
        }
    }

    let resolved = state.diff_vulns(&mut vulns, &covered, now.timestamp());
    let (mut findings, unfixed) = group::group(vulns, &pkg_managers);
    // Image findings: which containers run it (untagged images are otherwise just a digest).
    for f in findings.iter_mut().filter(|f| f.kind == Kind::Image) {
        if let Some(img) = inventories.iter().filter(|i| i.host == f.host).flat_map(|i| &i.images).find(|i| i.reference == f.component) {
            f.detail = format!("Containers: {}", img.containers.join(", "));
            if img.repo_tags.is_empty() {
                f.title = format!("{} (untagged image of {})", f.title, img.containers.join(", "));
            }
        }
    }
    findings.extend(extra);
    // Worst first: severity, new items, exploited, then how much is critical/high.
    findings.sort_by(|a, b| {
        let (ca, cb) = (a.counts(), b.counts());
        b.severity
            .cmp(&a.severity)
            .then(b.new_count.cmp(&a.new_count))
            .then(b.kev_count().cmp(&a.kev_count()))
            .then(cb.critical.cmp(&ca.critical))
            .then(cb.high.cmp(&ca.high))
            .then(a.host.cmp(&b.host))
            .then(a.title.cmp(&b.title))
    });
    state.diff_findings(&mut findings, cfg.notify.min_severity, cfg.analyze.remind_days, now.timestamp());
    state.last_run = Some(now.timestamp());

    Ok(Report {
        generated: now,
        version: env!("CARGO_PKG_VERSION").into(),
        hosts,
        findings,
        unfixed,
        resolved,
        summary: None,
        notes,
        errors,
    })
}

fn load_feed<T>(fetcher: &Fetcher, feed: &feeds::Feed, parse: fn(&std::path::Path) -> Result<T>, errors: &mut Vec<String>) -> Option<T> {
    match fetcher.get(feed, errors).and_then(|p| parse(&p)) {
        Ok(t) => Some(t),
        Err(e) => {
            errors.push(format!("{}: {e:#}", feed.name));
            None
        }
    }
}

/// A watch entry's own exposure, or the host's lockfile_exposure, wins over the host default.
fn exposure_for(inv: &Inventory, v: &Vuln, host: &crate::config::HostCfg) -> Exposure {
    if v.kind == Kind::Watch
        && let Some(w) = inv.watched.iter().find(|w| w.name == v.component)
        && let Ok(e) = w.exposure.parse()
    {
        return e;
    }
    if v.kind == Kind::Lockfile
        && let Some(e) = host.lockfile_exposure
    {
        return e;
    }
    host.exposure
}

fn health(host: &str, sev: Severity, title: String, detail: String, key: &str) -> Finding {
    Finding {
        host: host.to_string(),
        kind: Kind::Health,
        component: title.clone(),
        severity: sev,
        title,
        action: String::new(),
        vulns: Vec::new(),
        unfixed: Default::default(),
        detail: if detail.is_empty() { detail } else { format!("- {detail}") },
        new_count: 0,
        remind: false,
        fingerprint: format!("{host}|Health|{key}"),
    }
}
