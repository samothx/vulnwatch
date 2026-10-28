//! `vulnwatch run`: inbox inventories → matches → policy → findings → diff → report.

pub mod arch;
pub mod cvss;
pub mod debian;
pub mod group;
pub mod osv;
pub mod outdated;
pub mod policy;
pub mod trivy;
pub mod upstream;

mod deployed;

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
use upstream::Upstream;

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
    let registry = upstream::Registry::new(fetcher.agent(), opts.offline);
    // (host, image reference) → is a newer build published, and what does it still ship?
    let mut upstreams: BTreeMap<(String, String), Upstream> = BTreeMap::new();
    // (host, kind, component) → exposure used by the policy (most exposed vuln of the component).
    let mut exposures: BTreeMap<(String, Kind, String), Exposure> = BTreeMap::new();
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

        // Upstream check, only for images that have something fixable to report
        let vulnerable: BTreeSet<&str> = host_vulns.iter().filter(|v| v.kind == Kind::Image && v.fix_available).map(|v| v.component.as_str()).collect();
        for img in inv.images.iter().filter(|i| vulnerable.contains(i.reference.as_str())) {
            let up = upstream_for(img, &registry, &trivy, cfg, &feeds_dir.join("upstream"), &mut errors);
            upstreams.insert((inv.host.clone(), img.reference.clone()), up);
        }

        // Policy
        for v in host_vulns.iter_mut() {
            intel.annotate(v);
            let exp = exposure_for(inv, v, &hc);
            let up = (v.kind == Kind::Image).then(|| upstreams.get(&(inv.host.clone(), v.component.clone()))).flatten();
            let waiting = up.is_some_and(|u| u.waiting(v));
            if waiting && up.is_some_and(|u| !u.status.is_current()) {
                v.note = "the newest published build still ships it".into();
            }
            policy::apply(v, exp, waiting, &cfg.analyze);
            let e = exposures.entry((v.host.clone(), v.kind, v.component.clone())).or_insert(exp);
            *e = (*e).max(exp);
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
                            exposure: None,
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

    // Source trees vs. what is deployed, then human triage; both only lower severities.
    let deployed = deployed::compare(cfg, &inventories, &mut vulns);
    triage(cfg, &mut vulns, &inventories, now.date_naive(), &mut notes);

    let resolved = state.diff_vulns(&mut vulns, &covered, now.timestamp());
    let (mut findings, unfixed) = group::group(vulns, &pkg_managers);
    for f in findings.iter_mut() {
        f.exposure = exposures.get(&(f.host.clone(), f.kind, f.component.clone())).copied();
    }
    // Image findings: which containers run it (untagged images are otherwise just a digest), and
    // whether pulling would change anything.
    for f in findings.iter_mut().filter(|f| f.kind == Kind::Image) {
        let Some(img) = inventories.iter().filter(|i| i.host == f.host).flat_map(|i| &i.images).find(|i| i.reference == f.component) else { continue };
        f.detail = format!("Containers: {}", img.containers.join(", "));
        if img.repo_tags.is_empty() {
            let was = if img.configured.is_empty() { String::new() } else { format!(", started as {}", img.configured) };
            f.title = format!("{} (untagged image of {}{was})", f.title, img.containers.join(", "));
        }
        if let Some(up) = upstreams.get(&(f.host.clone(), f.component.clone())) {
            f.detail = format!("{}\n\n{}", f.detail, up.describe());
            f.action = up.action(f, img);
        }
    }
    for f in findings.iter_mut().filter(|f| f.kind == Kind::Lockfile) {
        if let Some(d) = deployed.get(&(f.host.clone(), f.component.clone())) {
            f.detail = d.describe(f);
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

/// Registry check for one image; for an untagged image (tag pulled again since) the tag the
/// containers were started with is checked. A newer build is scanned to see what it still ships.
fn upstream_for(img: &crate::inventory::Image, registry: &upstream::Registry, trivy: &trivy::Trivy, cfg: &Config, cache: &std::path::Path, errors: &mut Vec<String>) -> Upstream {
    let recreate = img.repo_tags.is_empty() && !img.configured.is_empty();
    let probe = if recreate { crate::inventory::Image { reference: img.configured.clone(), ..img.clone() } } else { img.clone() };
    let status = registry.status(&probe);
    let tag = probe.reference.clone();
    let mut up = Upstream { status, tag, recreate, still: None, scan_error: None };
    if let upstream::Status::Newer { digest } = &up.status
        && cfg.analyze.upstream_scan
        && trivy.available()
        && !trivy.offline
    {
        match upstream::still_ships(trivy, probe.repository(), digest, cache, cfg.analyze.feeds_max_age_hours) {
            Ok(set) => up.still = Some(set),
            Err(e) => {
                errors.push(format!("upstream scan {}: {e:#}", probe.reference));
                up.scan_error = Some(format!("{e:#}"));
            }
        }
    }
    up
}

/// `[[triage]]`: caps matching vulnerabilities and says why. Exploited ones (KEV) only with an
/// `until` date and never below medium, so they stay visible until the next re-check.
fn triage(cfg: &Config, vulns: &mut [Vuln], inventories: &[Inventory], today: chrono::NaiveDate, notes: &mut Vec<String>) {
    let active: Vec<&crate::config::Triage> = cfg.triage.iter().filter(|t| !t.expired(today)).collect();
    for t in cfg.triage.iter().filter(|t| t.expired(today)) {
        notes.push(format!("triage of {} expired on {}: re-check it, then extend or remove the entry", t.id, t.until));
    }
    if active.is_empty() {
        return;
    }
    let mut kev_without_until = std::collections::BTreeSet::new();
    for v in vulns.iter_mut() {
        let containers: Vec<&str> = if v.kind == Kind::Image {
            inventories.iter().filter(|i| i.host == v.host).flat_map(|i| &i.images).filter(|i| i.reference == v.component).flat_map(|i| i.containers.iter().map(String::as_str)).collect()
        } else {
            Vec::new()
        };
        let pkg = v.package.split(' ').next().unwrap_or(&v.package).to_string();
        let hit = active.iter().find(|t| {
            (t.id == v.id || v.aliases.contains(&t.id))
                && (t.host.is_empty() || t.host == v.host)
                && (t.package.is_empty() || glob(&t.package, &pkg) || glob(&t.package, &v.package))
                && (t.component.is_empty() || glob(&t.component, &v.component) || containers.iter().any(|c| glob(&t.component, c)))
        });
        if let Some(t) = hit {
            let mut max = t.max.unwrap_or(Severity::Low);
            if v.kev {
                if t.until.is_empty() {
                    kev_without_until.insert(t.id.clone());
                    continue;
                }
                max = max.max(Severity::Medium);
            }
            v.severity = v.severity.min(max);
            let until = if t.until.is_empty() { String::new() } else { format!(" (until {})", t.until) };
            let kev = if v.kev { "; exploited in the wild, kept at medium or above" } else { "" };
            v.note = format!("triaged: {}{until}{kev}", t.reason.trim());
        }
    }
    for id in kev_without_until {
        notes.push(format!("triage of {id} not applied: it is exploited in the wild (KEV), which needs an `until` date"));
    }
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

/// A watch entry's own exposure, the host's lockfile_exposure, or a matching image_exposure entry
/// wins over the host default.
fn exposure_for(inv: &Inventory, v: &Vuln, host: &crate::config::HostCfg) -> Exposure {
    if v.kind == Kind::Image
        && let Some(e) = image_exposure(inv, &v.component, host)
    {
        return e;
    }
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

/// Exposure of an image from `image_exposure`: an entry for the image reference sets the default
/// for its containers, an entry for a container name overrides it for that container, and the
/// image is as exposed as its most exposed container (unlisted containers keep the host default).
/// None when no entry matches at all.
fn image_exposure(inv: &Inventory, reference: &str, host: &crate::config::HostCfg) -> Option<Exposure> {
    if host.image_exposure.is_empty() {
        return None;
    }
    let containers = inv.images.iter().find(|i| i.reference == reference).map(|i| i.containers.as_slice()).unwrap_or_default();
    let matching = |name: &str| host.image_exposure.iter().filter(|(pat, _)| glob(pat, name)).map(|(_, e)| *e).max();
    let by_ref = matching(reference);
    if by_ref.is_none() && !containers.iter().any(|c| matching(c).is_some()) {
        return None;
    }
    let base = by_ref.unwrap_or(host.exposure);
    containers.iter().map(|c| matching(c).unwrap_or(base)).max().or(Some(base))
}

/// `*` matches any run of characters; everything else literally.
pub(crate) fn glob(pat: &str, s: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == s;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if s.len() < first.len() + last.len() || !s.starts_with(first) || !s.ends_with(last) {
        return false;
    }
    let mut rest = &s[first.len()..s.len() - last.len()];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
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
        exposure: None,
        fingerprint: format!("{host}|Health|{key}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Image;

    #[test]
    fn triage_kev_needs_until_and_keeps_medium() {
        let mut cfg = Config::default();
        let t = |until: &str| crate::config::Triage { id: "CVE-1".into(), reason: "not reachable".into(), until: until.into(), ..Default::default() };
        let mk = |kev: bool| Vuln {
            id: "CVE-1".into(), aliases: vec![], host: "h".into(), kind: Kind::Image, component: "c".into(),
            package: "p".into(), installed: "1".into(), fixed: None, fix_available: true,
            base_severity: Severity::Critical, severity: Severity::High, title: String::new(), url: String::new(),
            source: "trivy-os".into(), kev, epss: None, new: false, fingerprint: String::new(), note: String::new(),
        };
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 28).unwrap();
        let mut notes = Vec::new();
        cfg.triage = vec![t("")];
        let mut v = vec![mk(true), mk(false)];
        triage(&cfg, &mut v, &[], today, &mut notes);
        assert_eq!(v[0].severity, Severity::High, "KEV without until: not applied");
        assert_eq!(v[1].severity, Severity::Low);
        assert!(notes.iter().any(|n| n.contains("needs an `until` date")));
        cfg.triage = vec![t("2026-12-31")];
        let mut v = vec![mk(true)];
        triage(&cfg, &mut v, &[], today, &mut notes);
        assert_eq!(v[0].severity, Severity::Medium, "KEV triage never below medium");
        assert!(v[0].note.contains("exploited in the wild"));
    }

    #[test]
    fn globs() {
        assert!(glob("postgres:*", "postgres:15-alpine"));
        assert!(glob("*umami*", "docker.umami.is/umami-software/umami:latest"));
        assert!(glob("umami-db", "umami-db"));
        assert!(!glob("umami-db", "umami"));
        assert!(!glob("a*a", "a"));
        assert!(glob("*", ""));
    }

    #[test]
    fn image_exposure_by_reference_or_container() {
        let inv = Inventory {
            images: vec![Image { reference: "postgres:15-alpine".into(), containers: vec!["umami-db".into(), "other-db".into()], ..Default::default() }],
            ..Default::default()
        };
        let mut hc = crate::config::HostCfg::default();
        assert_eq!(image_exposure(&inv, "postgres:15-alpine", &hc), None);
        hc.image_exposure.insert("umami-db".into(), Exposure::Local);
        assert_eq!(image_exposure(&inv, "postgres:15-alpine", &hc), Some(Exposure::Public), "unlisted other-db keeps the host default");
        hc.image_exposure.insert("other-*".into(), Exposure::Vpn);
        assert_eq!(image_exposure(&inv, "postgres:15-alpine", &hc), Some(Exposure::Vpn), "most exposed container wins");
        hc.image_exposure.insert("postgres:*".into(), Exposure::Trusted);
        hc.image_exposure.remove("other-*");
        assert_eq!(image_exposure(&inv, "postgres:15-alpine", &hc), Some(Exposure::Trusted), "reference entry is the default for its containers");
        assert_eq!(image_exposure(&inv, "nginx:alpine", &hc), None);
    }
}
