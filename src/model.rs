//! Matched vulnerabilities, grouped into actionable findings, and the run report.

use chrono::{DateTime, Local};
use opskit::Severity;
use serde::{Deserialize, Serialize};

/// Where a vulnerable component lives; findings are grouped by (host, kind, component).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// OS package (Debian source package / Arch package).
    Os,
    /// Contents of a container image (Trivy).
    Image,
    /// A project lockfile.
    Lockfile,
    /// A watch-list product.
    Watch,
    /// A newer upstream release exists.
    Outdated,
    /// Inventory missing/old, or collector errors.
    Health,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Os => "OS packages",
            Kind::Image => "image",
            Kind::Lockfile => "source tree",
            Kind::Watch => "watched",
            Kind::Outdated => "outdated",
            Kind::Health => "inventory",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vuln {
    /// Primary id: CVE-…, GHSA-…, RUSTSEC-…, AVG-…
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub host: String,
    pub kind: Kind,
    /// Grouping key: "Debian packages", image reference, lockfile path, product name.
    pub component: String,
    /// The affected package inside the component.
    pub package: String,
    pub installed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    pub fix_available: bool,
    /// Severity from the source, before policy.
    pub base_severity: Severity,
    /// After policy (unfixed cap, exposure, EPSS, KEV).
    pub severity: Severity,
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// debian-tracker | arch-tracker | osv | trivy | github
    pub source: String,
    #[serde(default)]
    pub kev: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    /// Set by the state diff: first seen in this run, or got worse / became fixable.
    #[serde(default)]
    pub new: bool,
    pub fingerprint: String,
    /// Why the policy changed its severity beyond the usual rules (stale lockfile, triage, …).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl Vuln {
    pub fn cves(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.id.as_str()).chain(self.aliases.iter().map(String::as_str)).filter(|i| i.starts_with("CVE-"))
    }

    pub fn make_fingerprint(&mut self) {
        // Not the installed version: an upgrade that is still vulnerable is not a new finding.
        self.fingerprint = format!("{}|{:?}|{}|{}|{}", self.host, self.kind, self.component, self.package, self.id);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub host: String,
    pub kind: Kind,
    pub component: String,
    pub severity: Severity,
    pub title: String,
    /// What to do: "apt upgrade on anubis", "update image n8nio/n8n:1.121.0", …
    pub action: String,
    /// Fixable vulnerabilities, worst first (all of them; the Markdown shows the top N).
    pub vulns: Vec<Vuln>,
    /// Vulnerabilities without a fix, counted per severity (awareness only).
    #[serde(default)]
    pub unfixed: SevCounts,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub new_count: usize,
    /// Unresolved ≥ notify.min_severity and not pushed for remind_days.
    #[serde(default)]
    pub remind: bool,
    pub fingerprint: String,
    /// Who can reach it (image/lockfile/watch findings).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<crate::config::Exposure>,
}

impl Finding {
    pub fn kev_count(&self) -> usize {
        self.vulns.iter().filter(|v| v.kev).count()
    }

    pub fn counts(&self) -> SevCounts {
        let mut c = SevCounts::default();
        for v in &self.vulns {
            c.add(v.severity);
        }
        c
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SevCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SevCounts {
    pub fn add(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// "2 crit · 5 high · 1 med", empty parts omitted.
    pub fn short(&self) -> String {
        let parts: Vec<String> = [(self.critical, "crit"), (self.high, "high"), (self.medium, "med"), (self.low, "low"), (self.info, "info")]
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, l)| format!("{n} {l}"))
            .collect();
        if parts.is_empty() { "none".into() } else { parts.join(" · ") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSummary {
    pub name: String,
    pub collected_at: Option<DateTime<Local>>,
    pub os: String,
    pub packages: usize,
    pub images: usize,
    pub lockfiles: usize,
    pub watched: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collector_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnfixedSummary {
    pub host: String,
    pub kind: Kind,
    pub component: String,
    pub counts: SevCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolved {
    pub host: String,
    pub component: String,
    pub id: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub generated: DateTime<Local>,
    pub version: String,
    pub hosts: Vec<HostSummary>,
    pub findings: Vec<Finding>,
    /// Vulnerabilities without an available fix, per component (awareness; by source severity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unfixed: Vec<UnfixedSummary>,
    /// Fixed since the previous run (fingerprint gone).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved: Vec<Resolved>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Coverage gaps worth knowing (e.g. CachyOS-only packages the Arch tracker can't see).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl Report {
    pub fn count_at(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }

    pub fn new_vulns(&self) -> usize {
        self.findings.iter().map(|f| f.new_count).sum()
    }
}
