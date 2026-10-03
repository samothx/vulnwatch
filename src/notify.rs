//! Push (ntfy-dispatcher) and mail decisions for a run.

use opskit::notify::Message;
use opskit::{Severity, truncate};

use crate::model::{Finding, Report};

pub const EVENT_ALERT: &str = "vulnwatch.alert";
pub const EVENT_DIGEST: &str = "vulnwatch.digest";
pub const EVENT_ERROR: &str = "vulnwatch.error";

/// Findings to push: at/above min severity with something new, or due for a reminder.
pub fn select_alerts(r: &Report, min: Severity) -> Vec<&Finding> {
    r.findings.iter().filter(|f| f.severity >= min && (f.new_count > 0 || f.remind)).collect()
}

/// Findings that make a mail worth sending: at/above min severity with something new.
pub fn select_mail(r: &Report, min: Severity) -> Vec<&Finding> {
    r.findings.iter().filter(|f| f.severity >= min && f.new_count > 0).collect()
}

fn label(f: &Finding) -> String {
    let what = if f.new_count > 0 && !f.vulns.is_empty() {
        format!(" ({} new)", f.new_count)
    } else if f.remind {
        " (still open)".into()
    } else {
        String::new()
    };
    let kev = if f.kev_count() > 0 { format!(" · {} KEV", f.kev_count()) } else { String::new() };
    format!("{} {}: {}{what}{kev}", f.severity.to_string().to_uppercase(), f.host, f.title)
}

pub fn alert_message(alerts: &[&Finding], report_path: &str) -> Message {
    let max = alerts.iter().map(|f| f.severity).max().unwrap_or(Severity::High);
    let mut body = String::new();
    for f in alerts.iter().take(10) {
        body.push_str(&format!("• {}\n", truncate(&label(f), 200)));
        if !f.action.is_empty() {
            body.push_str(&format!("  → {}\n", truncate(&f.action, 160)));
        }
    }
    if alerts.len() > 10 {
        body.push_str(&format!("… and {} more\n", alerts.len() - 10));
    }
    body.push_str(&format!("\nReport: {report_path}"));
    Message {
        event: EVENT_ALERT,
        title: format!("{} vulnerability finding(s), max {max}", alerts.len()),
        body,
        priority: Some(if max >= Severity::Critical { 5 } else { 4 }),
    }
}

pub fn digest_message(r: &Report, report_path: &str, mailed_to: Option<&str>) -> Message {
    let mut body = format!(
        "critical {} · high {} · medium {} · low {}\n{} new · {} resolved\n",
        r.count_at(Severity::Critical),
        r.count_at(Severity::High),
        r.count_at(Severity::Medium),
        r.count_at(Severity::Low),
        r.new_vulns(),
        r.resolved.len()
    );
    for h in &r.hosts {
        let n = r.findings.iter().filter(|f| f.host == h.name).count();
        let age = h.collected_at.map(|t| crate::report::human_age(chrono::Local::now().signed_duration_since(t).num_minutes())).unwrap_or_else(|| "no inventory".into());
        body.push_str(&format!("{}: {n} finding(s), inventory {age}\n", h.name));
    }
    let top: Vec<&Finding> = r.findings.iter().filter(|f| f.severity >= Severity::Medium).take(6).collect();
    if !top.is_empty() {
        body.push('\n');
        for f in top {
            body.push_str(&format!("• {}\n", truncate(&label(f), 160)));
        }
    }
    if !r.errors.is_empty() {
        body.push_str(&format!("\n{} error(s), see report\n", r.errors.len()));
    }
    body.push_str(&format!("\nReport: {report_path}"));
    if let Some(to) = mailed_to {
        body.push_str(&format!("\nFull report mailed to {to}"));
    }
    Message { event: EVENT_DIGEST, title: "daily vulnerability digest".into(), body, priority: None }
}

pub fn error_message(what: &str) -> Message {
    Message { event: EVENT_ERROR, title: "vulnwatch problem".into(), body: truncate(what, 3000), priority: None }
}

pub fn mail_subject(r: &Report, new_findings: usize) -> String {
    let counts: Vec<String> = [Severity::Critical, Severity::High, Severity::Medium]
        .iter()
        .filter_map(|s| {
            let n = r.count_at(*s);
            (n > 0).then(|| format!("{n} {s}"))
        })
        .collect();
    let what = if counts.is_empty() { "no findings".to_string() } else { counts.join(", ") };
    let new = if new_findings > 0 { format!(" ({new_findings} with new items)") } else { String::new() };
    format!("[vulnwatch] {what}{new}")
}
