//! OSV.dev: lockfile dependencies and watch-list products (`querybatch`, then `vulns/{id}`,
//! cached by id + modified timestamp).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use opskit::Severity;
use serde::Deserialize;
use serde_json::{Value, json};

use super::cvss;
use crate::model::{Kind, Vuln};
use crate::version::loose_cmp;

const API: &str = "https://api.osv.dev/v1";
const BATCH: usize = 1000;

/// One thing to look up, with where it came from.
#[derive(Debug, Clone)]
pub struct Query {
    pub host: String,
    pub kind: Kind,
    pub component: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Deserialize)]
struct BatchResp {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<IdMod>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize, Clone)]
struct IdMod {
    id: String,
    #[serde(default)]
    modified: String,
}

pub struct Osv<'a> {
    agent: &'a ureq::Agent,
    cache: PathBuf,
}

impl<'a> Osv<'a> {
    pub fn new(agent: &'a ureq::Agent, cache: PathBuf) -> Self {
        Self { agent, cache }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let mut resp = self.agent.post(format!("{API}/{path}")).send_json(body).map_err(|e| anyhow!("POST {path}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().with_config().limit(64 * 1024 * 1024).read_to_string()?;
        if !(200..300).contains(&status) {
            bail!("OSV {path}: HTTP {status} {}", opskit::truncate(&text, 300));
        }
        Ok(serde_json::from_str(&text)?)
    }

    fn detail(&self, im: &IdMod) -> Result<Value> {
        let safe: String = im.id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
        let path = self.cache.join(format!("{safe}.json"));
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(v) = serde_json::from_str::<Value>(&text)
            && v["modified"].as_str() == Some(im.modified.as_str())
        {
            return Ok(v);
        }
        let mut resp = self.agent.get(format!("{API}/vulns/{}", im.id)).call().map_err(|e| anyhow!("GET vulns/{}: {e}", im.id))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().with_config().limit(16 * 1024 * 1024).read_to_string()?;
        if !(200..300).contains(&status) {
            bail!("OSV vulns/{}: HTTP {status}", im.id);
        }
        std::fs::create_dir_all(&self.cache).ok();
        let _ = std::fs::write(&path, &text);
        Ok(serde_json::from_str(&text)?)
    }

    pub fn matches(&self, queries: &[Query], errors: &mut Vec<String>) -> Result<Vec<Vuln>> {
        let mut out = Vec::new();
        for chunk in queries.chunks(BATCH) {
            let body = json!({ "queries": chunk.iter().map(|q| json!({
                "package": {"name": q.name, "ecosystem": q.ecosystem}, "version": q.version
            })).collect::<Vec<_>>() });
            let resp: BatchResp = serde_json::from_value(self.post("querybatch", &body)?).context("OSV querybatch response")?;
            for (q, mut r) in chunk.iter().zip(resp.results) {
                // Rare: more results than one page. Re-query this package alone.
                while let Some(tok) = r.next_page_token.take() {
                    let more: BatchResp = serde_json::from_value(self.post(
                        "querybatch",
                        &json!({"queries": [{"package": {"name": q.name, "ecosystem": q.ecosystem}, "version": q.version, "page_token": tok}]}),
                    )?)?;
                    let next = more.results.into_iter().next().unwrap_or_default();
                    r.vulns.extend(next.vulns);
                    r.next_page_token = next.next_page_token;
                }
                let mut found = Vec::new();
                for im in &r.vulns {
                    match self.detail(im) {
                        Ok(d) => {
                            if let Some(v) = to_vuln(q, &d) {
                                found.push(v);
                            }
                        }
                        Err(e) => errors.push(format!("osv {}: {e:#}", im.id)),
                    }
                }
                out.extend(merge_aliases(found));
            }
        }
        Ok(out)
    }
}

pub fn to_vuln(q: &Query, d: &Value) -> Option<Vuln> {
    if d.get("withdrawn").and_then(Value::as_str).is_some() {
        return None;
    }
    let id = d["id"].as_str()?.to_string();
    let aliases: Vec<String> = d["aliases"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let affected: Vec<&Value> = d["affected"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|x| {
                    x["package"]["name"].as_str() == Some(q.name.as_str())
                        && x["package"]["ecosystem"].as_str().is_some_and(|e| e.eq_ignore_ascii_case(&q.ecosystem))
                })
                .collect()
        })
        .unwrap_or_default();
    // RustSec "informational" advisories (unmaintained, unsound) are not vulnerabilities.
    let informational = affected.iter().any(|a| a["database_specific"]["informational"].is_string())
        || d["database_specific"]["informational"].is_string();
    let fixed = fixed_version(&affected, &q.version);
    let base = if informational { Severity::Info } else { severity(d) };
    let summary = d["summary"].as_str().filter(|s| !s.is_empty()).or_else(|| d["details"].as_str()).unwrap_or("");
    let mut v = Vuln {
        id: id.clone(),
        aliases,
        host: q.host.clone(),
        kind: q.kind,
        component: q.component.clone(),
        package: q.name.clone(),
        installed: q.version.clone(),
        fix_available: fixed.is_some(),
        fixed,
        base_severity: base,
        severity: base,
        title: opskit::truncate(summary.lines().next().unwrap_or("").trim(), 200),
        url: format!("https://osv.dev/vulnerability/{id}"),
        source: "osv".into(),
        kev: false,
        epss: None,
        new: false,
        fingerprint: String::new(),
        note: String::new(),
    };
    v.make_fingerprint();
    Some(v)
}

/// GHSA label first (reviewed), then a CVSS v3 vector, else medium.
pub fn severity(d: &Value) -> Severity {
    if let Some(s) = d["database_specific"]["severity"].as_str()
        && let Ok(s) = s.parse::<Severity>()
    {
        return s;
    }
    let mut best: Option<f64> = None;
    for s in d["severity"].as_array().into_iter().flatten() {
        if let Some(score) = s["score"].as_str().and_then(cvss::v3_base_score) {
            best = Some(best.map_or(score, |b: f64| b.max(score)));
        }
    }
    best.map(Severity::from_cvss).unwrap_or(Severity::Medium)
}

/// The `fixed` event of the range that contains `installed`; else the lowest fixed > installed.
pub fn fixed_version(affected: &[&Value], installed: &str) -> Option<String> {
    let mut candidates = Vec::new();
    for a in affected {
        for r in a["ranges"].as_array().into_iter().flatten() {
            if r["type"].as_str() == Some("GIT") {
                continue;
            }
            let mut introduced: Option<&str> = None;
            for ev in r["events"].as_array().into_iter().flatten() {
                if let Some(i) = ev["introduced"].as_str() {
                    introduced = Some(i);
                }
                if let Some(f) = ev["fixed"].as_str() {
                    let in_range = introduced.is_none_or(|i| i == "0" || loose_cmp(installed, i).is_ge()) && loose_cmp(installed, f).is_lt();
                    if in_range {
                        return Some(f.to_string());
                    }
                    if loose_cmp(f, installed).is_gt() {
                        candidates.push(f.to_string());
                    }
                }
            }
        }
    }
    candidates.sort_by(|a, b| loose_cmp(a, b));
    candidates.into_iter().next()
}

/// GHSA-x and RUSTSEC-y for the same bug (shared alias or listing each other) → one entry with
/// the union of aliases and the worse severity. GHSA is preferred as the primary id.
pub fn merge_aliases(mut vs: Vec<Vuln>) -> Vec<Vuln> {
    vs.sort_by(|a, b| rank(&a.id).cmp(&rank(&b.id)).then(a.id.cmp(&b.id)));
    let mut out: Vec<Vuln> = Vec::new();
    for v in vs {
        let keys: BTreeSet<&str> = std::iter::once(v.id.as_str()).chain(v.aliases.iter().map(String::as_str)).collect();
        if let Some(e) = out.iter_mut().find(|e| {
            std::iter::once(e.id.as_str()).chain(e.aliases.iter().map(String::as_str)).any(|k| keys.contains(k))
        }) {
            let mut all: BTreeSet<String> = e.aliases.iter().cloned().collect();
            all.extend(keys.iter().map(|s| s.to_string()));
            all.remove(&e.id);
            e.aliases = all.into_iter().collect();
            if v.base_severity > e.base_severity {
                e.base_severity = v.base_severity;
                e.severity = v.severity;
            }
            if e.fixed.is_none() {
                e.fixed = v.fixed;
                e.fix_available = v.fix_available;
            }
        } else {
            out.push(v);
        }
    }
    out
}

fn rank(id: &str) -> u8 {
    match id.split('-').next() {
        Some("GHSA") => 0,
        Some("CVE") => 1,
        Some("RUSTSEC") => 2,
        _ => 3,
    }
}

/// Queries for lockfiles and OSV-mapped watch entries of one inventory.
pub fn queries(inv: &crate::inventory::Inventory) -> Vec<Query> {
    let mut q = Vec::new();
    for l in &inv.lockfiles {
        for d in &l.packages {
            q.push(Query {
                host: inv.host.clone(),
                kind: Kind::Lockfile,
                component: l.path.clone(),
                ecosystem: l.ecosystem.clone(),
                name: d.name.clone(),
                version: d.version.clone(),
            });
        }
    }
    let mut seen = BTreeMap::new();
    for w in &inv.watched {
        if let Some(o) = &w.osv
            && seen.insert((w.name.clone(), w.version.clone()), ()).is_none()
        {
            q.push(Query {
                host: inv.host.clone(),
                kind: Kind::Watch,
                component: w.name.clone(),
                ecosystem: o.ecosystem.clone(),
                name: o.name.clone(),
                version: w.version.clone(),
            });
        }
    }
    q
}

pub fn cache_dir(feeds: &Path) -> PathBuf {
    feeds.join("osv")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> Query {
        Query {
            host: "anubis".into(),
            kind: Kind::Watch,
            component: "n8n".into(),
            ecosystem: "npm".into(),
            name: "n8n".into(),
            version: "1.121.0".into(),
        }
    }

    #[test]
    fn ghsa_detail_to_vuln() {
        let d: Value = serde_json::from_str(
            r#"{"id":"GHSA-v364-rw7m-3263","summary":"n8n Vulnerable to RCE via Arbitrary File Write","aliases":["CVE-2026-21877"],
                "database_specific":{"severity":"CRITICAL"},
                "affected":[{"package":{"ecosystem":"npm","name":"n8n"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.123.0"},{"fixed":"1.121.3"}]}]}]}"#,
        )
        .unwrap();
        let v = to_vuln(&q(), &d).unwrap();
        assert_eq!(v.base_severity, Severity::Critical);
        assert_eq!(v.fixed.as_deref(), Some("1.121.3"));
        assert_eq!(v.cves().collect::<Vec<_>>(), vec!["CVE-2026-21877"]);
    }

    #[test]
    fn cvss_fallback_and_multiple_ranges() {
        let d: Value = serde_json::from_str(
            r#"{"id":"X-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected":[{"package":{"ecosystem":"npm","name":"n8n"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.120.4"},{"introduced":"1.121.0"},{"fixed":"1.121.1"}]}]}]}"#,
        )
        .unwrap();
        let v = to_vuln(&q(), &d).unwrap();
        assert_eq!(v.base_severity, Severity::Critical);
        assert_eq!(v.fixed.as_deref(), Some("1.121.1"));
    }

    #[test]
    fn informational_and_withdrawn() {
        let info: Value = serde_json::from_str(
            r#"{"id":"RUSTSEC-1","affected":[{"package":{"ecosystem":"crates.io","name":"n8n"},"database_specific":{"informational":"unmaintained"},"ranges":[]}]}"#,
        )
        .unwrap();
        let mut qq = q();
        qq.ecosystem = "crates.io".into();
        assert_eq!(to_vuln(&qq, &info).unwrap().base_severity, Severity::Info);
        let w: Value = serde_json::from_str(r#"{"id":"G-1","withdrawn":"2026-01-01T00:00:00Z","affected":[]}"#).unwrap();
        assert!(to_vuln(&q(), &w).is_none());
    }

    #[test]
    fn merges_ghsa_and_rustsec() {
        let mk = |id: &str, aliases: &[&str], s: Severity| {
            let mut v = to_vuln(&q(), &json!({"id": id, "affected": []})).unwrap();
            v.aliases = aliases.iter().map(|s| s.to_string()).collect();
            v.base_severity = s;
            v.severity = s;
            v
        };
        let m = merge_aliases(vec![
            mk("RUSTSEC-2026-1", &["CVE-2026-5", "GHSA-aaaa"], Severity::Medium),
            mk("GHSA-aaaa", &["CVE-2026-5"], Severity::High),
            mk("GHSA-bbbb", &[], Severity::Low),
        ]);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].id, "GHSA-aaaa");
        assert_eq!(m[0].aliases, vec!["CVE-2026-5", "RUSTSEC-2026-1"]);
        assert_eq!(m[0].severity, Severity::High);
    }
}
