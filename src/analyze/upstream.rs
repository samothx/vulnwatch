//! Is there anything newer to pull? Compares a running image's repo digest with the digest the
//! registry currently serves for its tag (anonymous `HEAD /v2/<repo>/manifests/<tag>`).
//!
//! When they are equal, `docker pull` cannot fix anything: the vulnerabilities are waiting for
//! upstream, and the policy caps them (`image_current_max`) instead of paging every day.

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};

use crate::inventory::Image;

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, \
                      application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json";

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
