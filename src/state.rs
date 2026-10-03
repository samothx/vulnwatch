//! What the previous runs saw: `<state_dir>/state.json`. Drives "new", "resolved" and reminders.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Result;
use opskit::Severity;
use serde::{Deserialize, Serialize};

use crate::model::{Finding, Kind, Resolved, Vuln};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub last_run: Option<i64>,
    /// Vulnerability fingerprint → last known state.
    pub vulns: BTreeMap<String, SeenVuln>,
    /// Finding fingerprint → push / mail bookkeeping.
    pub findings: BTreeMap<String, SeenFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeenVuln {
    pub first: i64,
    pub last: i64,
    pub severity: Severity,
    pub fix: bool,
    pub host: String,
    pub kind: Kind,
    pub component: String,
    pub id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SeenFinding {
    pub first: i64,
    pub last: i64,
    pub alerted: Option<i64>,
    pub emailed: Option<i64>,
}

impl State {
    pub fn load(dir: &Path) -> Result<Self> {
        opskit::state::load(&dir.join("state.json"))
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        opskit::state::save(&dir.join("state.json"), self)
    }

    /// Marks vulns new (unseen, worse, or newly fixable) and records them. Vulns of `covered`
    /// (host, kind) pairs that are gone are returned as resolved and forgotten; others are kept
    /// (a host whose inventory is missing this run must not look "fixed").
    pub fn diff_vulns(&mut self, vulns: &mut [Vuln], covered: &BTreeSet<(String, Kind)>, now: i64) -> Vec<Resolved> {
        let mut current = BTreeSet::new();
        for v in vulns.iter_mut() {
            current.insert(v.fingerprint.clone());
            match self.vulns.get_mut(&v.fingerprint) {
                None => {
                    v.new = true;
                    self.vulns.insert(
                        v.fingerprint.clone(),
                        SeenVuln {
                            first: now,
                            last: now,
                            severity: v.severity,
                            fix: v.fix_available,
                            host: v.host.clone(),
                            kind: v.kind,
                            component: v.component.clone(),
                            id: v.id.clone(),
                        },
                    );
                }
                Some(s) => {
                    v.new = v.severity > s.severity || (v.fix_available && !s.fix);
                    s.last = now;
                    s.severity = v.severity;
                    s.fix = v.fix_available;
                }
            }
        }
        let gone: Vec<String> = self
            .vulns
            .iter()
            .filter(|(fp, s)| !current.contains(*fp) && covered.contains(&(s.host.clone(), s.kind)))
            .map(|(fp, _)| fp.clone())
            .collect();
        let mut resolved = Vec::new();
        for fp in gone {
            if let Some(s) = self.vulns.remove(&fp)
                && s.fix
            {
                resolved.push(Resolved { host: s.host, component: s.component, id: s.id, severity: s.severity });
            }
        }
        resolved.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.host.cmp(&b.host)).then(a.id.cmp(&b.id)));
        resolved
    }

    /// For findings without vulns (outdated, health): new when the fingerprint is unseen.
    /// For all findings: the reminder flag.
    pub fn diff_findings(&mut self, findings: &mut [Finding], remind_min: Severity, remind_days: u32, now: i64) {
        let window = i64::from(remind_days.max(1)) * 86_400;
        let current: BTreeSet<String> = findings.iter().map(|f| f.fingerprint.clone()).collect();
        for f in findings.iter_mut() {
            let e = self.findings.entry(f.fingerprint.clone()).or_insert_with(|| SeenFinding { first: now, last: now, ..Default::default() });
            if f.vulns.is_empty() && e.first == now {
                f.new_count = 1;
            }
            e.last = now;
            f.remind = f.new_count == 0 && f.severity >= remind_min && e.alerted.is_some_and(|t| now - t >= window);
        }
        self.findings.retain(|fp, _| current.contains(fp));
    }

    pub fn mark_alerted(&mut self, fps: &[String], now: i64) {
        for fp in fps {
            if let Some(e) = self.findings.get_mut(fp) {
                e.alerted = Some(now);
            }
        }
    }

    pub fn mark_emailed(&mut self, fps: &[String], now: i64) {
        for fp in fps {
            if let Some(e) = self.findings.get_mut(fp) {
                e.emailed = Some(now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(id: &str, sev: Severity, fix: bool) -> Vuln {
        let mut v = Vuln {
            id: id.into(),
            aliases: vec![],
            host: "anubis".into(),
            kind: Kind::Os,
            component: "Debian packages".into(),
            package: "openssl".into(),
            installed: "1".into(),
            fixed: None,
            fix_available: fix,
            base_severity: sev,
            severity: sev,
            title: String::new(),
            url: String::new(),
            source: "t".into(),
            kev: false,
            epss: None,
            new: false,
            fingerprint: String::new(),
        };
        v.make_fingerprint();
        v
    }

    #[test]
    fn new_changed_resolved() {
        let mut st = State::default();
        let covered: BTreeSet<_> = [("anubis".to_string(), Kind::Os)].into();
        let mut run1 = vec![v("CVE-1", Severity::Low, false), v("CVE-2", Severity::High, true)];
        assert!(st.diff_vulns(&mut run1, &covered, 1).is_empty());
        assert!(run1.iter().all(|x| x.new));
        let mut run2 = vec![v("CVE-1", Severity::Medium, true), v("CVE-3", Severity::Low, true)];
        let res = st.diff_vulns(&mut run2, &covered, 2);
        assert!(run2[0].new, "became fixable + worse");
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, "CVE-2");
        let mut run3 = vec![v("CVE-1", Severity::Medium, true), v("CVE-3", Severity::Low, true)];
        st.diff_vulns(&mut run3, &covered, 3);
        assert!(run3.iter().all(|x| !x.new));
        // Host not covered this run: nothing resolves.
        let mut empty: Vec<Vuln> = vec![];
        assert!(st.diff_vulns(&mut empty, &BTreeSet::new(), 4).is_empty());
        assert_eq!(st.vulns.len(), 2);
    }
}
