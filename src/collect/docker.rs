//! Images of running containers, each with a CycloneDX SBOM from Trivy (no vulnerability DB
//! needed on the collector; matching happens on the analyzer).

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::Collect;
use crate::inventory::Image;

#[derive(Deserialize)]
struct ImageInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "RepoDigests", default)]
    repo_digests: Option<Vec<String>>,
    #[serde(rename = "Config", default)]
    config: Option<ImageConfig>,
}

#[derive(Deserialize, Default)]
struct ImageConfig {
    #[serde(rename = "Labels", default)]
    labels: Option<BTreeMap<String, String>>,
}

pub fn collect(cfg: &Collect, timeout: Duration, errors: &mut Vec<String>) -> Result<Vec<Image>> {
    let docker = cfg.docker_bin.as_os_str();
    let ps = match super::run(&[docker, "ps".as_ref(), "--format".as_ref(), "{{.ID}}".as_ref()], timeout) {
        Ok(o) => o,
        // No docker on this host (zeno) is not an error.
        Err(e) if format!("{e:#}").contains("starting") => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let ids: Vec<&str> = ps.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    // Container → (name, image id, image as configured).
    let mut argv: Vec<&std::ffi::OsStr> = vec![docker, "inspect".as_ref(), "--format".as_ref(), "{{.Name}}\t{{.Image}}\t{{.Config.Image}}".as_ref()];
    argv.extend(ids.iter().map(|s| std::ffi::OsStr::new(*s)));
    let out = super::run(&argv, timeout)?;
    let mut by_image: BTreeMap<String, (Vec<String>, String)> = BTreeMap::new();
    for l in out.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() == 3 {
            let e = by_image.entry(f[1].to_string()).or_insert_with(|| (Vec::new(), f[2].to_string()));
            e.0.push(f[0].trim_start_matches('/').to_string());
        }
    }

    let mut images = Vec::new();
    for (id, (containers, configured)) in by_image {
        let raw = super::run(&[docker, "image".as_ref(), "inspect".as_ref(), id.as_ref()], timeout)
            .with_context(|| format!("inspecting image {id}"))?;
        let parsed: Vec<ImageInspect> = serde_json::from_str(&raw).context("docker image inspect output")?;
        let Some(ii) = parsed.into_iter().next() else { continue };
        let repo_tags = ii.repo_tags.unwrap_or_default();
        // Prefer the reference the container was started with when it is still a tag of the image.
        let (reference, configured) = if repo_tags.contains(&configured) {
            (configured, String::new())
        } else {
            // Kept only for untagged images (the tag was pulled again since), and only if it is a
            // real tag, not an id or digest the container was started with.
            let real_tag = !configured.starts_with("sha256:") && !configured.contains('@') && !ii.id.contains(&configured);
            let keep = if repo_tags.is_empty() && real_tag { configured } else { String::new() };
            (repo_tags.first().cloned().unwrap_or_else(|| ii.id.clone()), keep)
        };
        let version_label = ii.config.and_then(|c| c.labels).and_then(|l| l.get("org.opencontainers.image.version").cloned()).unwrap_or_default();
        let mut img = Image {
            reference,
            id: ii.id,
            repo_tags,
            repo_digests: ii.repo_digests.unwrap_or_default(),
            containers,
            configured,
            version_label,
            sbom: None,
        };
        if !cfg.trivy.as_os_str().is_empty() {
            match sbom(cfg, &img.id, timeout) {
                Ok(s) => img.sbom = Some(s),
                Err(e) => errors.push(format!("sbom {}: {e:#}", img.reference)),
            }
        }
        images.push(img);
    }
    Ok(images)
}

fn sbom(cfg: &Collect, image_id: &str, timeout: Duration) -> Result<serde_json::Value> {
    let out = super::run(
        &[
            cfg.trivy.as_os_str(),
            "image".as_ref(),
            "--quiet".as_ref(),
            "--disable-telemetry".as_ref(),
            "--skip-version-check".as_ref(),
            "--image-src".as_ref(),
            "docker".as_ref(),
            "--cache-dir".as_ref(),
            cfg.trivy_cache.as_os_str(),
            "--format".as_ref(),
            "cyclonedx".as_ref(),
            image_id.as_ref(),
        ],
        timeout,
    )?;
    serde_json::from_str(&out).context("trivy output is not JSON")
}
