//! Watch-list probes: the version of a binary (`version_cmd`) or of a running image.

use std::time::Duration;

use crate::config::WatchEntry;
use crate::inventory::{Image, Watched};
use crate::version::looks_like_version;

pub fn collect(entries: &[WatchEntry], images: &[Image], timeout: Duration, errors: &mut Vec<String>) -> Vec<Watched> {
    let mut out = Vec::new();
    for w in entries {
        let found = if !w.image.is_empty() {
            image_versions(w, images)
        } else {
            match probe(w, timeout) {
                Ok(Some(v)) => vec![(v, "cmd")],
                Ok(None) => Vec::new(),
                Err(e) => {
                    errors.push(format!("watch {}: {e}", w.name));
                    Vec::new()
                }
            }
        };
        for (version, by) in found {
            out.push(Watched {
                name: w.name.clone(),
                version,
                found_by: by.into(),
                osv: w.osv.clone(),
                github: w.github.clone(),
                exposure: w.exposure.clone(),
                same_major: w.same_major,
            });
        }
    }
    out
}

/// Not installed (command missing) is silently skipped: watch lists are shared between hosts.
fn probe(w: &WatchEntry, timeout: Duration) -> Result<Option<String>, String> {
    let re = compile(&w.version_regex).map_err(|e| format!("version_regex: {e}"))?;
    let out = match super::run(&w.version_cmd, timeout) {
        Ok(o) => o,
        Err(e) if format!("{e:#}").contains("starting") => return Ok(None),
        Err(e) => return Err(format!("{e:#}")),
    };
    match re(&out) {
        Some(v) => Ok(Some(v)),
        None => Err(format!("version_regex matched nothing in: {}", opskit::truncate(out.trim(), 200))),
    }
}

/// One version per running image of this repository: the tag if it looks like a version,
/// else the OCI version label.
fn image_versions(w: &WatchEntry, images: &[Image]) -> Vec<(String, &'static str)> {
    let mut v: Vec<(String, &'static str)> = images
        .iter()
        .filter(|i| repo_matches(i.repository(), &w.image))
        .filter_map(|i| {
            let tag = i.tag().filter(|t| looks_like_version(t)).map(|t| t.trim_start_matches(['v', 'V']).to_string());
            let label = (!i.version_label.is_empty()).then(|| i.version_label.trim_start_matches(['v', 'V']).to_string());
            let ver = tag.or(label)?;
            Some((ver, "image"))
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// `n8nio/n8n` matches `n8nio/n8n`, `docker.io/n8nio/n8n`; `postgres` matches `library/postgres`.
fn repo_matches(repo: &str, want: &str) -> bool {
    let norm = |r: &str| {
        let r = r.strip_prefix("docker.io/").unwrap_or(r);
        r.strip_prefix("library/").unwrap_or(r).to_string()
    };
    norm(repo) == norm(want)
}

/// Compiled `version_regex`: returns the first capture group of the first match.
type Extract = Box<dyn Fn(&str) -> Option<String>>;

fn compile(pattern: &str) -> Result<Extract, String> {
    let re = regex::Regex::new(pattern).map_err(|e| e.to_string())?;
    if re.captures_len() < 2 {
        return Err("needs one capture group".into());
    }
    Ok(Box::new(move |s: &str| re.captures(s).and_then(|c| c.get(1)).map(|m| m.as_str().to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_versions_from_tag_or_label() {
        let w = WatchEntry { name: "n8n".into(), image: "n8nio/n8n".into(), ..Default::default() };
        let imgs = vec![
            Image { reference: "n8nio/n8n:1.121.0".into(), ..Default::default() },
            Image { reference: "docker.io/n8nio/n8n:latest".into(), version_label: "2.29.1".into(), ..Default::default() },
            Image { reference: "other/n8n:9".into(), ..Default::default() },
        ];
        assert_eq!(image_versions(&w, &imgs), vec![("1.121.0".to_string(), "image"), ("2.29.1".to_string(), "image")]);
        assert!(repo_matches("postgres", "library/postgres"));
    }

    #[test]
    fn probe_missing_binary_is_skipped() {
        let w = WatchEntry {
            name: "x".into(),
            version_cmd: vec!["/nonexistent/bin".into()],
            version_regex: r"(\d+)".into(),
            ..Default::default()
        };
        assert_eq!(probe(&w, Duration::from_secs(1)), Ok(None));
        let e = WatchEntry { version_cmd: vec!["echo".into(), "tool v2.3.4 linux".into()], version_regex: r"v(\d+\.\d+\.\d+)".into(), ..w };
        assert_eq!(probe(&e, Duration::from_secs(5)), Ok(Some("2.3.4".into())));
    }
}
