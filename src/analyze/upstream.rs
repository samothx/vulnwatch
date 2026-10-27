//! Is there anything newer to pull? Compares a running image's repo digest with the digest the
//! registry currently serves for its tag (anonymous `HEAD /v2/<repo>/manifests/<tag>`).
//!
//! When they are equal, `docker pull` cannot fix anything: the vulnerabilities are waiting for
//! upstream, and the policy caps them (`image_current_max`) instead of paging every day.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};

use crate::inventory::Image;

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, \
                      application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json";

/// What a newer published build still ships: (package, vulnerability id) pairs as Trivy names
/// them for the running image, so they can be compared one to one. Cached per digest.
pub fn still_ships(trivy: &super::trivy::Trivy, repository: &str, digest: &str, cache_dir: &Path, max_age_hours: u64) -> Result<BTreeSet<(String, String)>> {
    let hex: String = digest.trim_start_matches("sha256:").chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() != 64 {
        bail!("unexpected digest {digest}");
    }
    let path = cache_dir.join(format!("{hex}.json"));
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .is_ok_and(|t| SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(max_age_hours * 3600));
    if fresh
        && let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(set) = serde_json::from_str::<BTreeSet<(String, String)>>(&text)
    {
        return Ok(set);
    }
    let vulns = trivy.scan_remote(&format!("{repository}@{digest}")).with_context(|| format!("scanning the newer build {repository}@{}", short(digest)))?;
    let set: BTreeSet<(String, String)> = vulns.into_iter().map(|v| (v.package, v.id)).collect();
    std::fs::create_dir_all(cache_dir).ok();
    let _ = std::fs::write(&path, serde_json::to_vec(&set)?);
    Ok(set)
}

/// Everything the analyzer knows about pulling a newer build of one image.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub status: Status,
    /// The tag that was checked (`nginx:alpine`).
    pub tag: String,
    /// The containers run an older build of a tag that was pulled again since (untagged now).
    pub recreate: bool,
    /// `Newer` only: (package, id) pairs the newer build still ships; None = not scanned.
    pub still: Option<BTreeSet<(String, String)>>,
    pub scan_error: Option<String>,
}

impl Upstream {
    /// No pull/recreate can fix this vulnerability yet.
    pub fn waiting(&self, v: &crate::model::Vuln) -> bool {
        match &self.status {
            Status::Current { .. } => true,
            Status::Newer { .. } => self.still.as_ref().is_some_and(|s| s.contains(&(v.package.clone(), v.id.clone()))),
            Status::Unknown(_) => false,
        }
    }

    pub fn describe(&self) -> String {
        let mut s = self.status.describe(&self.tag);
        if self.recreate {
            s.push_str(&format!("; the containers still run an older build of `{}` that was replaced locally", self.tag));
        }
        if let Some(still) = &self.still {
            s.push_str(&format!("; that build was scanned: {} vulnerabilit(ies) still in it", still.len()));
        }
        if let Some(e) = &self.scan_error {
            s.push_str(&format!("; scanning it failed ({})", crate::report::one_line(e)));
        }
        s
    }

    /// What to do about a finding of this image.
    pub fn action(&self, f: &crate::model::Finding, img: &Image) -> String {
        let n = f.vulns.iter().filter(|v| v.fix_available).count();
        let fixed_by_newer = f.vulns.iter().filter(|v| v.fix_available && !self.waiting(v)).count();
        let containers = img.containers.join(", ");
        match &self.status {
            Status::Current { .. } => format!(
                "nothing to do yet: no newer {} is published (checked daily; alerts again once upstream ships a new build)",
                self.tag
            ),
            Status::Newer { .. } if self.still.is_some() && fixed_by_newer == 0 => format!(
                "nothing to do yet: the newest published {} still ships all {n} (scanned); alerts again once upstream fixes them",
                self.tag
            ),
            Status::Newer { .. } => {
                let how_many = if self.still.is_some() { format!(" (fixes {fixed_by_newer} of {n})") } else { String::new() };
                if self.recreate {
                    format!("recreate {containers} on {}: still running an older build of {}{how_many}; pull it first if the local tag is not the newest", f.host, self.tag)
                } else {
                    format!("a newer {} is published{how_many}: pull it and recreate {containers} on {}", self.tag, f.host)
                }
            }
            Status::Unknown(why) if why.contains("locally built") => format!(
                "rebuild {} (fresh base image + OS package upgrade) and recreate {containers} on {}",
                f.component, f.host
            ),
            Status::Unknown(_) if self.recreate => format!("recreate {containers} on {}: still running an older build of {}", f.host, self.tag),
            Status::Unknown(_) => format!("pull/rebuild a newer {} and recreate {containers} on {}", f.component, f.host),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// The registry serves the digest that is running: nothing newer to pull.
    Current { digest: String },
    /// The tag now points elsewhere: a pull brings a different build.
    Newer { digest: String },
    /// Locally built, private registry, digest-pinned, offline, …
    Unknown(String),
}

impl Status {
    pub fn is_current(&self) -> bool {
        matches!(self, Status::Current { .. })
    }

    /// One line for the finding's detail.
    pub fn describe(&self, tag: &str) -> String {
        match self {
            Status::Current { digest } => {
                format!("Upstream: no newer build of `{tag}` (registry digest = running digest {}); waiting for upstream", short(digest))
            }
            Status::Newer { digest } => format!("Upstream: a newer build of `{tag}` is published ({})", short(digest)),
            Status::Unknown(why) => format!("Upstream: not checked ({why})"),
        }
    }
}

fn short(d: &str) -> &str {
    let end = d.find(':').map_or(0, |i| i + 1) + 12;
    &d[..end.min(d.len())]
}

/// Where to ask: (registry host, repository path) for `Image::repository()`.
pub fn locate(repository: &str) -> (String, String) {
    let (first, rest) = repository.split_once('/').unwrap_or(("", repository));
    if !first.is_empty() && (first.contains('.') || first.contains(':') || first == "localhost") {
        let host = if first == "docker.io" { "registry-1.docker.io" } else { first };
        let path = if first == "docker.io" && !rest.contains('/') { format!("library/{rest}") } else { rest.to_string() };
        return (host.to_string(), path);
    }
    let path = if repository.contains('/') { repository.to_string() } else { format!("library/{repository}") };
    ("registry-1.docker.io".into(), path)
}

/// Digests the local image was pulled as (`RepoDigests` entries for its own repository).
pub fn local_digests(img: &Image) -> Vec<&str> {
    let repo = img.repository();
    img.repo_digests.iter().filter_map(|d| d.split_once('@')).filter(|(name, _)| *name == repo).map(|(_, d)| d).collect()
}

pub struct Registry<'a> {
    agent: &'a ureq::Agent,
    offline: bool,
    cache: std::cell::RefCell<HashMap<String, Status>>,
}

impl<'a> Registry<'a> {
    pub fn new(agent: &'a ureq::Agent, offline: bool) -> Self {
        Self { agent, offline, cache: Default::default() }
    }

    pub fn status(&self, img: &Image) -> Status {
        let key = format!("{}|{}", img.reference, img.repo_digests.join(","));
        if let Some(s) = self.cache.borrow().get(&key) {
            return s.clone();
        }
        let s = self.check(img);
        self.cache.borrow_mut().insert(key, s.clone());
        s
    }

    fn check(&self, img: &Image) -> Status {
        let Some(tag) = img.tag() else { return Status::Unknown("no tag".into()) };
        let local = local_digests(img);
        if local.is_empty() {
            return Status::Unknown("no repo digest (locally built?)".into());
        }
        if self.offline {
            return Status::Unknown("--offline".into());
        }
        let (host, path) = locate(img.repository());
        match self.remote_digest(&host, &path, tag) {
            Ok(d) if local.contains(&d.as_str()) => Status::Current { digest: d },
            Ok(d) => Status::Newer { digest: d },
            Err(e) => Status::Unknown(format!("{e:#}")),
        }
    }

    fn remote_digest(&self, host: &str, path: &str, tag: &str) -> Result<String> {
        let url = format!("https://{host}/v2/{path}/manifests/{tag}");
        let resp = self.agent.head(&url).header("Accept", ACCEPT).call().map_err(|e| anyhow!("{host}: {e}"))?;
        let resp = if resp.status().as_u16() == 401 {
            let challenge = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let token = self.token(&challenge, path)?;
            self.agent.head(&url).header("Accept", ACCEPT).header("Authorization", format!("Bearer {token}")).call().map_err(|e| anyhow!("{host}: {e}"))?
        } else {
            resp
        };
        let status = resp.status().as_u16();
        if status != 200 {
            bail!("{host}/{path}:{tag}: HTTP {status}");
        }
        let d = resp.headers().get("docker-content-digest").and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_string();
        if !d.starts_with("sha256:") {
            bail!("{host}: no Docker-Content-Digest header");
        }
        Ok(d)
    }

    /// Anonymous pull token from the realm the registry names (https only).
    fn token(&self, challenge: &str, path: &str) -> Result<String> {
        let p = parse_challenge(challenge).ok_or_else(|| anyhow!("unauthorized, no bearer challenge"))?;
        if !p.realm.starts_with("https://") {
            bail!("token realm is not https: {}", p.realm);
        }
        let scope = p.scope.unwrap_or_else(|| format!("repository:{path}:pull"));
        let mut req = self.agent.get(&p.realm).query("scope", &scope);
        if let Some(s) = &p.service {
            req = req.query("service", s);
        }
        let mut resp = req.call().map_err(|e| anyhow!("token: {e}"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            bail!("token: HTTP {status} (private image?)");
        }
        let v: serde_json::Value = serde_json::from_str(&resp.body_mut().with_config().limit(1024 * 1024).read_to_string()?)?;
        v.get("token").or_else(|| v.get("access_token")).and_then(|t| t.as_str()).map(str::to_string).ok_or_else(|| anyhow!("token: no token in response"))
    }
}

struct Challenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

/// `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:x:pull"`
fn parse_challenge(h: &str) -> Option<Challenge> {
    let rest = h.trim().strip_prefix("Bearer ").or_else(|| h.trim().strip_prefix("bearer "))?;
    let mut kv = HashMap::new();
    for part in rest.split("\",") {
        if let Some((k, v)) = part.split_once('=') {
            kv.insert(k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
        }
    }
    Some(Challenge { realm: kv.remove("realm")?, service: kv.remove("service"), scope: kv.remove("scope") })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(reference: &str, digests: &[&str]) -> Image {
        Image { reference: reference.into(), repo_digests: digests.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn locates_registries() {
        assert_eq!(locate("postgres"), ("registry-1.docker.io".into(), "library/postgres".into()));
        assert_eq!(locate("n8nio/n8n"), ("registry-1.docker.io".into(), "n8nio/n8n".into()));
        assert_eq!(locate("docker.io/nginx"), ("registry-1.docker.io".into(), "library/nginx".into()));
        assert_eq!(locate("docker.umami.is/umami-software/umami"), ("docker.umami.is".into(), "umami-software/umami".into()));
        assert_eq!(locate("localhost:5000/app"), ("localhost:5000".into(), "app".into()));
    }

    #[test]
    fn local_digests_of_own_repo_only() {
        let i = img("postgres:15-alpine", &["postgres@sha256:aa", "mirror.example/postgres@sha256:bb"]);
        assert_eq!(local_digests(&i), vec!["sha256:aa"]);
        let u = img("docker.umami.is/umami-software/umami:latest", &["docker.umami.is/umami-software/umami@sha256:cc"]);
        assert_eq!(local_digests(&u), vec!["sha256:cc"]);
    }

    #[test]
    fn parses_challenges() {
        let c = parse_challenge(r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:umami-software/umami:pull""#).unwrap();
        assert_eq!(c.realm, "https://ghcr.io/token");
        assert_eq!(c.service.as_deref(), Some("ghcr.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:umami-software/umami:pull"));
        assert!(parse_challenge(r#"Basic realm="x""#).is_none());
    }

    #[test]
    fn unknown_without_digest_or_offline() {
        let agent = ureq::Agent::new_with_defaults();
        let r = Registry::new(&agent, true);
        assert!(matches!(r.status(&img("statamic-app:latest", &[])), Status::Unknown(_)));
        assert!(matches!(r.status(&img("postgres:15-alpine", &["postgres@sha256:aa"])), Status::Unknown(w) if w == "--offline"));
        assert!(matches!(r.status(&img("sha256:abc", &["x@sha256:aa"])), Status::Unknown(_)));
    }
}
