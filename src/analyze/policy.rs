//! Threat intel (CISA KEV, EPSS) and the severity policy applied to every match.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use opskit::Severity;
use serde::Deserialize;

use crate::config::{Analyze, Exposure};
use crate::model::{Kind, Vuln};

#[derive(Default)]
pub struct Intel {
    /// CVE → known ransomware use ("Known" / "Unknown").
    pub kev: HashMap<String, String>,
    /// CVE → EPSS probability (0..1).
    pub epss: HashMap<String, f64>,
}

#[derive(Deserialize)]
struct KevFile {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    ransomware: String,
}

impl Intel {
    pub fn load_kev(&mut self, path: &Path) -> Result<()> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let f: KevFile = serde_json::from_slice(&bytes).context("parsing CISA KEV JSON")?;
        self.kev = f.vulnerabilities.into_iter().map(|e| (e.cve, e.ransomware)).collect();
        Ok(())
    }

    /// `#model_version…` comment, `cve,epss,percentile` header, then one row per CVE.
    pub fn load_epss(&mut self, path: &Path) -> Result<()> {
        let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let r = BufReader::new(GzDecoder::new(f));
        for line in r.lines() {
            let line = line.context("reading EPSS CSV")?;
            if line.starts_with('#') || line.starts_with("cve,") {
                continue;
            }
            let mut it = line.split(',');
            if let (Some(cve), Some(score)) = (it.next(), it.next())
                && let Ok(s) = score.parse::<f64>()
            {
                self.epss.insert(cve.to_string(), s);
            }
        }
        Ok(())
    }

    pub fn annotate(&self, v: &mut Vuln) {
        let kev = v.cves().any(|c| self.kev.contains_key(c));
        let epss = v.cves().filter_map(|c| self.epss.get(c).copied()).reduce(f64::max);
        v.kev = kev;
        v.epss = epss;
    }
}

/// Order matters: exposure and EPSS adjust the source severity, then findings without a fix,
/// OS packages inside images and images with nothing newer to pull (`upstream_current`) are
/// capped, and finally KEV (exploited in the wild) overrides everything.
pub fn apply(v: &mut Vuln, exposure: Exposure, upstream_current: bool, cfg: &Analyze) {
    let mut s = v.base_severity;
    if s > Severity::Info {
        if exposure == Exposure::Local {
            s = s.lowered().max(Severity::Low);
        }
        if v.epss.is_some_and(|e| e >= cfg.epss_raise) {
            s = s.raised();
        }
        if !v.fix_available {
            s = s.min(cfg.unfixed_max);
        }
        let hot = v.epss.is_some_and(|e| e >= cfg.epss_raise);
        if v.kind == Kind::Image && v.source == "trivy-os" && !hot {
            s = s.min(cfg.image_os_max);
        }
        if v.kind == Kind::Image && upstream_current {
            s = s.min(cfg.image_current_max);
        }
    }
    if v.kev {
        s = s.max(if v.fix_available { Severity::Critical } else { Severity::High });
    }
    v.severity = s;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(base: Severity, fix: bool) -> Vuln {
        Vuln {
            id: "CVE-1".into(),
            aliases: vec![],
            host: "h".into(),
            kind: Kind::Os,
            component: "c".into(),
            package: "p".into(),
            installed: "1".into(),
            fixed: None,
            fix_available: fix,
            base_severity: base,
            severity: base,
            title: String::new(),
            url: String::new(),
            source: "t".into(),
            kev: false,
            epss: None,
            new: false,
            fingerprint: String::new(),
        }
    }

    #[test]
    fn policy_order() {
        let cfg = Analyze::default();
        let mut v = vuln(Severity::High, true);
        apply(&mut v, Exposure::Public, false, &cfg);
        assert_eq!(v.severity, Severity::High);
        apply(&mut v, Exposure::Local, false, &cfg);
        assert_eq!(v.severity, Severity::Medium);
        v.epss = Some(0.5);
        apply(&mut v, Exposure::Public, false, &cfg);
        assert_eq!(v.severity, Severity::Critical);
        let mut u = vuln(Severity::Critical, false);
        apply(&mut u, Exposure::Public, false, &cfg);
        assert_eq!(u.severity, Severity::Low, "unfixed is capped");
        u.kev = true;
        apply(&mut u, Exposure::Local, false, &cfg);
        assert_eq!(u.severity, Severity::High, "KEV beats cap and exposure");
        let mut img = vuln(Severity::Critical, true);
        img.kind = Kind::Image;
        img.source = "trivy-os".into();
        apply(&mut img, Exposure::Public, false, &cfg);
        assert_eq!(img.severity, Severity::Medium, "image OS layer capped");
        img.source = "trivy-lang".into();
        apply(&mut img, Exposure::Public, false, &cfg);
        assert_eq!(img.severity, Severity::Critical, "app layer not capped");
        apply(&mut img, Exposure::Public, true, &cfg);
        assert_eq!(img.severity, Severity::Low, "nothing newer to pull: wait for upstream");
        img.kev = true;
        apply(&mut img, Exposure::Public, true, &cfg);
        assert_eq!(img.severity, Severity::Critical, "KEV still shouts");
        let mut i = vuln(Severity::Info, true);
        i.epss = Some(0.9);
        apply(&mut i, Exposure::Public, false, &cfg);
        assert_eq!(i.severity, Severity::Info);
    }

    #[test]
    fn intel_matches_aliases() {
        let mut intel = Intel::default();
        intel.kev.insert("CVE-2".into(), "Unknown".into());
        intel.epss.insert("CVE-2".into(), 0.3);
        let mut v = vuln(Severity::Medium, true);
        v.id = "GHSA-x".into();
        v.aliases = vec!["CVE-2".into()];
        intel.annotate(&mut v);
        assert!(v.kev && v.epss == Some(0.3));
    }
}
