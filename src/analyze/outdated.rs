//! Newer upstream release than what runs (GitHub releases, cached per repo).

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;

use crate::version::{loose_cmp, loose_major, looks_like_version};

#[derive(Deserialize, Clone)]
struct Release {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}

pub struct GitHub<'a> {
    agent: &'a ureq::Agent,
    token: Option<String>,
    cache: PathBuf,
    max_age: Duration,
    offline: bool,
}

impl<'a> GitHub<'a> {
    pub fn new(agent: &'a ureq::Agent, token: Option<String>, cache: PathBuf, max_age_hours: u64, offline: bool) -> Self {
        Self { agent, token, cache, max_age: Duration::from_secs(max_age_hours * 3600), offline }
    }

    fn releases(&self, repo: &str) -> Result<Vec<Release>> {
        if !repo.split('/').count().eq(&2) || !repo.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c)) {
            bail!("invalid github repo '{repo}' (owner/name)");
        }
        let path = self.cache.join(format!("{}.json", repo.replace('/', "__")));
        let fresh = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|a| a < self.max_age);
        if (fresh || self.offline)
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            return Ok(serde_json::from_str(&text)?);
        }
        if self.offline {
            bail!("{repo}: not cached and --offline");
        }
        let mut req = self.agent.get(format!("https://api.github.com/repos/{repo}/releases?per_page=40")).header("Accept", "application/vnd.github+json");
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let mut resp = req.call().map_err(|e| anyhow!("GitHub {repo}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().with_config().limit(32 * 1024 * 1024).read_to_string()?;
        if !(200..300).contains(&status) {
            bail!("GitHub {repo}: HTTP {status} {}", opskit::truncate(&text, 200));
        }
        let rel: Vec<Release> = serde_json::from_str(&text)?;
        std::fs::create_dir_all(&self.cache).ok();
        let _ = std::fs::write(&path, serde_json::to_vec(&rel.iter().map(|r| serde_json::json!({"tag_name": r.tag_name, "prerelease": r.prerelease, "draft": r.draft})).collect::<Vec<_>>())?);
        Ok(rel)
    }

    /// Highest stable release, optionally on the installed major line.
    pub fn latest(&self, repo: &str, same_major_as: Option<&str>) -> Result<Option<String>> {
        let rel = self.releases(repo)?;
        Ok(pick_latest(&rel.iter().filter(|r| !r.prerelease && !r.draft).map(|r| r.tag_name.as_str()).collect::<Vec<_>>(), same_major_as))
    }
}

/// "n8n@2.29.1" → "2.29.1", "v1.2.3" → "1.2.3". Tags with a pre-release suffix are skipped.
pub fn tag_version(tag: &str) -> Option<String> {
    let t = tag.rsplit('@').next().unwrap_or(tag).trim_start_matches(['v', 'V']);
    if !looks_like_version(t) || t.contains(['-', '~']) {
        return None;
    }
    Some(t.to_string())
}

pub fn pick_latest(tags: &[&str], same_major_as: Option<&str>) -> Option<String> {
    tags.iter()
        .filter_map(|t| tag_version(t))
        .filter(|v| same_major_as.is_none_or(|m| loose_major(m) == loose_major(v)))
        .max_by(|a, b| loose_cmp(a, b))
}

/// (is newer, major version(s) behind).
pub fn compare(installed: &str, latest: &str) -> (bool, bool) {
    let newer = loose_cmp(latest, installed).is_gt();
    (newer, newer && loose_major(latest) != loose_major(installed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_stable_latest() {
        let tags = ["n8n@2.30.0-beta.1", "n8n@2.29.1", "n8n@1.123.17", "v0.9", "nightly"];
        assert_eq!(pick_latest(&tags, None).as_deref(), Some("2.29.1"));
        assert_eq!(pick_latest(&tags, Some("1.121.0")).as_deref(), Some("1.123.17"));
        assert_eq!(compare("1.121.0", "2.29.1"), (true, true));
        assert_eq!(compare("2.29.0", "2.29.1"), (true, false));
        assert_eq!(compare("2.29.1", "2.29.1"), (false, false));
    }
}
