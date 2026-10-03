//! Cached downloads with conditional GET (ETag / Last-Modified) under `<state>/feeds/`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

pub struct Feed {
    pub name: &'static str,
    pub url: &'static str,
    pub file: &'static str,
}

pub const DEBIAN: Feed = Feed { name: "debian-tracker", url: "https://security-tracker.debian.org/tracker/data/json", file: "debian.json" };
pub const ARCH: Feed = Feed { name: "arch-tracker", url: "https://security.archlinux.org/issues/all.json", file: "arch.json" };
pub const KEV: Feed = Feed {
    name: "cisa-kev",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    file: "kev.json",
};
pub const EPSS: Feed = Feed { name: "epss", url: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", file: "epss.csv.gz" };

pub const ALL: [&Feed; 4] = [&DEBIAN, &ARCH, &KEV, &EPSS];

const MAX_BODY: u64 = 256 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
struct Meta {
    etag: Option<String>,
    last_modified: Option<String>,
    fetched: Option<i64>,
}

pub struct Fetcher {
    pub dir: PathBuf,
    agent: ureq::Agent,
    max_age: Duration,
    /// Never touch the network; use whatever is cached.
    pub offline: bool,
}

impl Fetcher {
    pub fn new(dir: PathBuf, max_age_hours: u64, timeout_secs: u64, offline: bool) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(timeout_secs)))
            .timeout_connect(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .user_agent(concat!("vulnwatch/", env!("CARGO_PKG_VERSION"), " (+https://etnur.net)"))
            .build()
            .into();
        Self { dir, agent, max_age: Duration::from_secs(max_age_hours * 3600), offline }
    }

    pub fn agent(&self) -> &ureq::Agent {
        &self.agent
    }

    /// Path of the cached file, refreshed if older than max_age. A failed refresh falls back to
    /// the cached copy (with a warning pushed to `warnings`).
    pub fn get(&self, feed: &Feed, warnings: &mut Vec<String>) -> Result<PathBuf> {
        let path = self.dir.join(feed.file);
        if self.offline || fresh(&path, self.max_age) {
            if path.exists() {
                return Ok(path);
            }
            if self.offline {
                bail!("{}: not cached and --offline", feed.name);
            }
        }
        match self.fetch(feed, &path) {
            Ok(()) => Ok(path),
            Err(e) if path.exists() => {
                warnings.push(format!("{}: refresh failed, using cached copy: {e:#}", feed.name));
                Ok(path)
            }
            Err(e) => Err(e),
        }
    }

    fn fetch(&self, feed: &Feed, path: &Path) -> Result<()> {
        std::fs::create_dir_all(&self.dir).with_context(|| format!("creating {}", self.dir.display()))?;
        let meta_path = path.with_extension("meta.json");
        let meta: Meta = if path.exists() { opskit::state::load(&meta_path).unwrap_or_default() } else { Meta::default() };
        let mut req = self.agent.get(feed.url);
        if let Some(e) = &meta.etag {
            req = req.header("If-None-Match", e);
        }
        if let Some(lm) = &meta.last_modified {
            req = req.header("If-Modified-Since", lm);
        }
        let mut resp = req.call().map_err(|e| anyhow!("GET {}: {e}", feed.url))?;
        let status = resp.status().as_u16();
        let header = |n: &str| resp.headers().get(n).and_then(|v| v.to_str().ok()).map(String::from);
        let etag = header("etag");
        let last_modified = header("last-modified");
        if status == 304 {
            touch(path)?;
            return save_meta(&meta_path, meta.etag, meta.last_modified);
        }
        if !(200..300).contains(&status) {
            bail!("GET {}: HTTP {status}", feed.url);
        }
        let mut body = Vec::new();
        resp.body_mut().with_config().limit(MAX_BODY).reader().take(MAX_BODY).read_to_end(&mut body).with_context(|| format!("reading {}", feed.url))?;
        if body.is_empty() {
            bail!("GET {}: empty body", feed.url);
        }
        let tmp = path.with_extension("part");
        std::fs::write(&tmp, &body).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path)?;
        save_meta(&meta_path, etag, last_modified)
    }

    /// (name, age) of every cached feed, for `feeds status`.
    pub fn status(&self) -> Vec<(String, Option<Duration>, u64)> {
        ALL.iter()
            .map(|f| {
                let p = self.dir.join(f.file);
                let md = std::fs::metadata(&p).ok();
                let age = md.as_ref().and_then(|m| m.modified().ok()).and_then(|t| SystemTime::now().duration_since(t).ok());
                (f.name.to_string(), age, md.map(|m| m.len()).unwrap_or(0))
            })
            .collect()
    }
}

fn fresh(path: &Path, max_age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < max_age)
}

fn touch(path: &Path) -> Result<()> {
    let f = std::fs::File::options().append(true).open(path)?;
    f.set_modified(SystemTime::now())?;
    Ok(())
}

fn save_meta(path: &Path, etag: Option<String>, last_modified: Option<String>) -> Result<()> {
    opskit::state::save(path, &Meta { etag, last_modified, fetched: Some(chrono::Local::now().timestamp()) })
}
