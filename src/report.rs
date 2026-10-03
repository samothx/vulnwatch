//! Markdown rendering of a run and report storage (`<state>/reports/<stamp>.{md,json}`).
//!
//! Advisory titles are upstream-controlled text: they are kept on one line and never put into
//! raw HTML (the mail renderer escapes HTML anyway).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Local;
use opskit::Severity;

use crate::model::{Finding, Kind, Report, Vuln};

pub fn markdown(r: &Report, max_items: usize) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# vulnwatch: {}", r.generated.format("%Y-%m-%d %H:%M"));
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "**{} finding(s)**: {} critical · {} high · {} medium · {} low. {} new vulnerabilities, {} resolved since the last run.",
        r.findings.len(),
        r.count_at(Severity::Critical),
        r.count_at(Severity::High),
        r.count_at(Severity::Medium),
        r.count_at(Severity::Low),
        r.new_vulns(),
        r.resolved.len()
    );

    if let Some(sum) = &r.summary {
        let _ = writeln!(s, "\n## Summary (AI)\n\n{}", sum.trim());
    }

    let _ = writeln!(s, "\n## Hosts\n");
    let _ = writeln!(s, "| Host | Inventory | OS | Packages | Images | Lockfiles | Watched |");
    let _ = writeln!(s, "|---|---|---|---|---|---|---|");
    for h in &r.hosts {
        let age = h.collected_at.map(|t| human_age(Local::now().signed_duration_since(t).num_minutes())).unwrap_or_else(|| "missing".into());
        let _ = writeln!(s, "| {} | {} | {} | {} | {} | {} | {} |", h.name, age, cell(&h.os), h.packages, h.images, h.lockfiles, h.watched);
    }

    if !r.findings.is_empty() {
        let _ = writeln!(s, "\n## Action list\n");
        let _ = writeln!(s, "| Severity | Host | What | Action | Fixable | New | KEV |");
        let _ = writeln!(s, "|---|---|---|---|---|---|---|");
        for f in &r.findings {
            let fixable = if f.vulns.is_empty() { "–".to_string() } else { f.counts().short() };
            let mark = if f.remind { " ⏰" } else { "" };
            let _ = writeln!(
                s,
                "| {}{mark} | {} | {} | {} | {} | {} | {} |",
                f.severity.to_string().to_uppercase(),
                f.host,
                cell(&f.title),
                cell(&f.action),
                fixable,
                f.new_count,
                f.kev_count()
            );
        }
        let _ = writeln!(s, "\n## Details");
        for f in &r.findings {
            finding_md(&mut s, f, max_items);
        }
    }

    if !r.resolved.is_empty() {
        let _ = writeln!(s, "\n## Resolved since the last run\n");
        for x in r.resolved.iter().take(40) {
            let _ = writeln!(s, "- {} {} · {} · {}", x.severity, x.id, x.host, x.component);
        }
        if r.resolved.len() > 40 {
            let _ = writeln!(s, "- … and {} more", r.resolved.len() - 40);
        }
    }

    if !r.unfixed.is_empty() {
        let _ = writeln!(s, "\n## No fix available yet (awareness)\n");
        let _ = writeln!(s, "Counted by the source's severity; they are reported once a fix ships, or right away if exploited in the wild (KEV).\n");
        for u in &r.unfixed {
            let _ = writeln!(s, "- {} · {} {}: {}", u.host, u.kind.label(), u.component, u.counts.short());
        }
    }

    if !r.notes.is_empty() {
        let _ = writeln!(s, "\n## Coverage notes\n");
        for n in &r.notes {
            let _ = writeln!(s, "- {n}");
        }
    }
    if !r.errors.is_empty() {
        let _ = writeln!(s, "\n## Errors\n");
        for e in &r.errors {
            let _ = writeln!(s, "- {}", one_line(e));
        }
    }
    let _ = writeln!(s, "\n---\nvulnwatch {} · JSON report has every item.", r.version);
    s
}

fn finding_md(s: &mut String, f: &Finding, max_items: usize) {
    let new = if f.new_count > 0 { format!(" ({} new)", f.new_count) } else { String::new() };
    let _ = writeln!(s, "\n### [{}] {} · {}{new}\n", f.severity.to_string().to_uppercase(), f.host, one_line(&f.title));
    if !f.action.is_empty() {
        let _ = writeln!(s, "**Action:** {}\n", one_line(&f.action));
    }
    if !f.detail.is_empty() {
        let _ = writeln!(s, "{}\n", f.detail.trim());
    }
    for v in f.vulns.iter().take(max_items) {
        let _ = writeln!(s, "- {}", vuln_line(v));
    }
    if f.vulns.len() > max_items {
        let rest = &f.vulns[max_items..];
        let new_rest = rest.iter().filter(|v| v.new).count();
        let _ = writeln!(s, "- … {} more ({} new), see the JSON report", rest.len(), new_rest);
    }
    if f.kind != Kind::Os && f.unfixed.total() > 0 {
        let _ = writeln!(s, "\nWithout a fix yet: {}", f.unfixed.short());
    }
}

pub fn vuln_line(v: &Vuln) -> String {
    let mut tags = Vec::new();
    if v.new {
        tags.push("NEW".to_string());
    }
    if v.kev {
        tags.push("KEV".to_string());
    }
    if let Some(e) = v.epss
        && e >= 0.01
    {
        tags.push(format!("EPSS {:.0}%", e * 100.0));
    }
    let tags = if tags.is_empty() { String::new() } else { format!(" **{}**", tags.join(" · ")) };
    let fix = match &v.fixed {
        Some(f) => format!("{} → {}", v.installed, f),
        None => v.installed.clone(),
    };
    let link = if v.url.is_empty() { v.id.clone() } else { format!("[{}]({})", v.id, v.url) };
    format!("{} {link}{tags} · `{}` {fix} · {}", v.severity, one_line(&v.package), one_line(&v.title))
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Table cells: no pipes or newlines.
fn cell(s: &str) -> String {
    one_line(s).replace('|', "/")
}

pub fn human_age(minutes: i64) -> String {
    match minutes {
        m if m < 0 => "in the future?".into(),
        m if m < 90 => format!("{m} min ago"),
        m if m < 48 * 60 => format!("{} h ago", m / 60),
        m => format!("{} days ago", m / 1440),
    }
}

/// Writes `<stamp>.md/.json` and `latest.*`, prunes old reports. Returns the Markdown path.
pub fn store(dir: &Path, r: &Report, md: &str, retention_days: u32) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let stamp = r.generated.format("%Y-%m-%d_%H%M").to_string();
    let md_path = dir.join(format!("{stamp}.md"));
    std::fs::write(&md_path, md)?;
    let json = serde_json::to_vec_pretty(r)?;
    std::fs::write(dir.join(format!("{stamp}.json")), &json)?;
    std::fs::write(dir.join("latest.md"), md)?;
    std::fs::write(dir.join("latest.json"), &json)?;
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(u64::from(retention_days.max(1)) * 86_400);
    for e in std::fs::read_dir(dir)?.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("latest.") {
            continue;
        }
        if e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < cutoff) {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(md_path)
}

pub fn load(dir: &Path, which: &str) -> Result<Report> {
    let p = dir.join(format!("{which}.json"));
    let bytes = std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", p.display()))
}
