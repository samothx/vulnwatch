//! What a collector reports: one gzipped JSON document per host (`<host>.json.gz`).

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;
/// Refuse to inflate more than this (an upload is attacker-reachable input on the analyzer).
pub const MAX_INFLATED: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Inventory {
    pub schema: u32,
    pub host: String,
    pub collected_at: Option<DateTime<Local>>,
    pub collector_version: String,
    pub os: Os,
    pub kernel: String,
    /// "dpkg", "pacman" or "" (no OS packages collected).
    pub pkg_manager: String,
    pub packages: Vec<Package>,
    pub images: Vec<Image>,
    pub lockfiles: Vec<Lockfile>,
    pub watched: Vec<Watched>,
    /// Non-fatal collector problems (trivy missing, unreadable lockfile, …).
    pub errors: Vec<String>,
}

/// From /etc/os-release.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Os {
    pub id: String,
    pub id_like: Vec<String>,
    pub version_id: String,
    pub codename: String,
    pub pretty_name: String,
}

impl Os {
    pub fn is(&self, family: &str) -> bool {
        self.id == family || self.id_like.iter().any(|l| l == family)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// Debian source package and its version (binNMU suffixes removed); empty on Arch.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Image {
    /// First repo tag (`n8nio/n8n:1.121.0`), or the image id when untagged.
    pub reference: String,
    pub id: String,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    /// Running containers using this image.
    pub containers: Vec<String>,
    /// The image the containers were started with, when it no longer names this image (the tag
    /// was pulled again since, so the containers run an older, now untagged build).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub configured: String,
    /// `org.opencontainers.image.version` label, if set.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_label: String,
    /// CycloneDX SBOM from `trivy image --format cyclonedx` (no vulnerability data).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom: Option<serde_json::Value>,
}

impl Image {
    /// The tag part of the reference, if it is not a digest/id.
    pub fn tag(&self) -> Option<&str> {
        let r = &self.reference;
        if r.starts_with("sha256:") {
            return None;
        }
        let last = r.rsplit('/').next().unwrap_or(r);
        last.split_once(':').map(|(_, t)| t)
    }

    /// Repository without tag (`n8nio/n8n`).
    pub fn repository(&self) -> &str {
        let r = &self.reference;
        match r.rfind(':') {
            Some(i) if !r[i..].contains('/') => &r[..i],
            _ => r,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Lockfile {
    pub path: String,
    /// OSV ecosystem: "crates.io" or "npm".
    pub ecosystem: String,
    pub packages: Vec<Dep>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dep {
    pub name: String,
    pub version: String,
}

/// A product from the watch list with the version found on this host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Watched {
    pub name: String,
    pub version: String,
    /// "cmd" (version_cmd) or "image" (tag / label of a running image).
    pub found_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osv: Option<OsvPackage>,
    /// owner/repo for the latest-release check.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub github: String,
    /// public | vpn | local; empty = the host's default.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub exposure: String,
    /// Only compare against releases with the same major (e.g. an LTS line).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub same_major: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

impl Inventory {
    pub fn to_gz(&self) -> Result<Vec<u8>> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        serde_json::to_writer(&mut enc, self)?;
        Ok(enc.finish()?)
    }

    pub fn from_gz(bytes: &[u8]) -> Result<Self> {
        let mut text = Vec::new();
        GzDecoder::new(bytes).take(MAX_INFLATED + 1).read_to_end(&mut text).context("inflating inventory")?;
        if text.len() as u64 > MAX_INFLATED {
            bail!("inventory inflates to more than {} MiB", MAX_INFLATED / 1024 / 1024);
        }
        let inv: Inventory = serde_json::from_slice(&text).context("inventory is not valid JSON")?;
        if inv.schema != SCHEMA {
            bail!("inventory schema {} (this vulnwatch reads {SCHEMA})", inv.schema);
        }
        if !valid_host(&inv.host) {
            bail!("invalid host name in inventory: {:?}", inv.host);
        }
        Ok(inv)
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_gz(&bytes).with_context(|| path.display().to_string())
    }

    /// Atomic write (tmp + rename) so the analyzer never reads a half-written file.
    pub fn write(&self, path: &Path) -> Result<()> {
        let bytes = self.to_gz()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }
}

/// Short host names only: they become file names and upload paths.
pub fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 63 && h.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') && !h.starts_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_gz() {
        let inv = Inventory { schema: SCHEMA, host: "zeno".into(), pkg_manager: "pacman".into(), ..Default::default() };
        let back = Inventory::from_gz(&inv.to_gz().unwrap()).unwrap();
        assert_eq!(back.host, "zeno");
        let bad = Inventory { schema: SCHEMA, host: "../x".into(), ..Default::default() };
        assert!(Inventory::from_gz(&bad.to_gz().unwrap()).is_err());
        let old = Inventory { schema: 99, host: "a".into(), ..Default::default() };
        assert!(Inventory::from_gz(&old.to_gz().unwrap()).is_err());
    }

    #[test]
    fn image_tag_and_repo() {
        let i = Image { reference: "registry.etnur.net:5000/samothx/cvz-web:prod".into(), ..Default::default() };
        assert_eq!(i.tag(), Some("prod"));
        assert_eq!(i.repository(), "registry.etnur.net:5000/samothx/cvz-web");
        let j = Image { reference: "localhost:5000/x".into(), ..Default::default() };
        assert_eq!(j.tag(), None);
        assert_eq!(j.repository(), "localhost:5000/x");
        assert!(valid_host("anubis") && !valid_host("Anubis") && !valid_host(""));
    }
}
