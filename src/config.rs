//! `/etc/vulnwatch/config.toml` (collector and analyzer) plus `watch.d/*.toml`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use opskit::Severity;
use serde::{Deserialize, Serialize};

use crate::inventory::{OsvPackage, valid_host};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub collect: Collect,
    pub analyze: Analyze,
    #[serde(rename = "host")]
    pub hosts: Vec<HostCfg>,
    pub notify: Notify,
    pub email: Email,
    pub llm: Llm,
    /// Loaded from `collect.watch_dir`, not from this file.
    #[serde(skip)]
    pub watch: Vec<WatchEntry>,
    #[serde(skip)]
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// Short host name used in inventories; empty = first label of the kernel hostname.
    pub host: String,
    pub state_dir: PathBuf,
    pub report_retention_days: u32,
}

impl Default for General {
    fn default() -> Self {
        Self { host: String::new(), state_dir: PathBuf::from("/var/lib/vulnwatch"), report_retention_days: 90 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Collect {
    /// auto | dpkg | pacman | none
    pub packages: String,
    pub docker: bool,
    pub docker_bin: PathBuf,
    /// Empty = skip image SBOMs (images are still listed).
    pub trivy: PathBuf,
    pub trivy_cache: PathBuf,
    pub lockfile_roots: Vec<PathBuf>,
    pub lockfile_max_depth: usize,
    /// Directory names never descended into.
    pub lockfile_skip_dirs: Vec<String>,
    pub watch_dir: PathBuf,
    /// Where `collect` writes when no upload URL is set (the analyzer's inbox on anubis).
    pub out: PathBuf,
    /// https://inv.services.etnur.net:8443/upload ; the file name `<host>.json.gz` is appended.
    pub upload_url: String,
    pub token_file: PathBuf,
    pub command_timeout_secs: u64,
}

impl Default for Collect {
    fn default() -> Self {
        Self {
            packages: "auto".into(),
            docker: true,
            docker_bin: PathBuf::from("docker"),
            trivy: PathBuf::from("/usr/local/bin/trivy"),
            trivy_cache: PathBuf::from("/var/cache/vulnwatch/trivy"),
            lockfile_roots: Vec::new(),
            lockfile_max_depth: 5,
            lockfile_skip_dirs: ["node_modules", "target", ".git", ".next", "dist", "vendor"].map(String::from).to_vec(),
            watch_dir: PathBuf::from("watch.d"),
            out: PathBuf::new(),
            upload_url: String::new(),
            token_file: PathBuf::from("/etc/vulnwatch/upload-token"),
            command_timeout_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Analyze {
    /// Relative to state_dir.
    pub inbox: PathBuf,
    pub trivy: PathBuf,
    /// Relative to state_dir. The vulnerability DB lives here (~1.5 GiB).
    pub trivy_cache: PathBuf,
    /// Feeds older than this are refetched (conditional GET).
    pub feeds_max_age_hours: u64,
    pub github_token_file: PathBuf,
    /// Findings without an available fix are capped at this severity (KEV excepted).
    pub unfixed_max: Severity,
    /// OS-package vulnerabilities inside container images are capped at this (KEV and high
    /// EPSS excepted): stale base images carry hundreds, the fix is a re-pull, not a page.
    pub image_os_max: Severity,
    /// EPSS probability at or above which a finding is raised one level.
    pub epss_raise: f64,
    /// Re-alert unresolved findings ≥ notify.min_severity after this many days.
    pub remind_days: u32,
    /// Max vulnerabilities listed per finding in the Markdown report (all are in the JSON).
    pub report_max_items: usize,
    pub http_timeout_secs: u64,
}

impl Default for Analyze {
    fn default() -> Self {
        Self {
            inbox: PathBuf::from("inbox"),
            trivy: PathBuf::from("/usr/local/bin/trivy"),
            trivy_cache: PathBuf::from("trivy-cache"),
            feeds_max_age_hours: 20,
            github_token_file: PathBuf::new(),
            unfixed_max: Severity::Low,
            image_os_max: Severity::Medium,
            epss_raise: 0.1,
            remind_days: 7,
            report_max_items: 15,
            http_timeout_secs: 120,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    Local,
    Vpn,
    #[default]
    Public,
}

impl std::str::FromStr for Exposure {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "local" => Self::Local,
            "vpn" => Self::Vpn,
            "public" => Self::Public,
            o => bail!("unknown exposure '{o}' (local | vpn | public)"),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostCfg {
    pub name: String,
    pub exposure: Exposure,
    /// Report the host when its newest inventory is older than this.
    pub stale_days: u32,
    /// Free text for the LLM summary ("public web server", "notebook", …).
    pub context: String,
    /// Exposure for lockfile findings when they differ from the host's own: the lockfiles on a
    /// dev notebook belong to apps that run publicly elsewhere.
    pub lockfile_exposure: Option<Exposure>,
}

impl Default for HostCfg {
    fn default() -> Self {
        Self { name: String::new(), exposure: Exposure::Public, stale_days: 2, context: String::new(), lockfile_exposure: None }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Notify {
    pub enabled: bool,
    pub command: PathBuf,
    pub min_severity: Severity,
    pub digest: bool,
}

impl Default for Notify {
    fn default() -> Self {
        Self { enabled: false, command: PathBuf::from("/usr/local/bin/ntfy-dispatcher"), min_severity: Severity::High, digest: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Email {
    pub enabled: bool,
    pub to: Vec<String>,
    pub from: String,
    pub sendmail: PathBuf,
    /// A new finding at or above this severity triggers a mail.
    pub min_severity: Severity,
    pub on_errors: bool,
    pub html: bool,
}

impl Default for Email {
    fn default() -> Self {
        Self {
            enabled: false,
            to: Vec::new(),
            from: String::new(),
            sendmail: PathBuf::from("/usr/sbin/sendmail"),
            min_severity: Severity::Medium,
            on_errors: true,
            html: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Llm {
    pub enabled: bool,
    pub provider: String,
    pub base_url: String,
    pub model: String,
    /// Relative names are looked up in $CREDENTIALS_DIRECTORY first; $VULNWATCH_API_KEY overrides.
    pub api_key_file: PathBuf,
    pub timeout_secs: u64,
    pub max_tokens: u32,
    pub json_mode: bool,
    /// Findings handed to the model (highest severity first).
    pub max_findings: usize,
    pub extra_body: toml::Table,
}

impl Default for Llm {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "venice".into(),
            base_url: "https://api.venice.ai/api/v1".into(),
            model: "deepseek-v4-flash".into(),
            api_key_file: PathBuf::from("/etc/vulnwatch/llm-api-key"),
            timeout_secs: 300,
            max_tokens: 4000,
            json_mode: true,
            max_findings: 40,
            extra_body: toml::Table::new(),
        }
    }
}

/// One product on the watch list (`watch.d/*.toml`, `[[watch]]`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WatchEntry {
    pub name: String,
    /// argv, no shell. The first regex capture of its output is the version.
    pub version_cmd: Vec<String>,
    pub version_regex: String,
    /// Docker repository (`n8nio/n8n`); version = tag, or the OCI version label.
    pub image: String,
    pub osv: Option<OsvPackage>,
    pub github: String,
    pub exposure: String,
    pub same_major: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchFile {
    #[serde(default)]
    watch: Vec<WatchEntry>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.path = path.to_path_buf();
        let wd = cfg.resolve(&cfg.collect.watch_dir.clone());
        cfg.watch = load_watch(&wd)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Relative paths are relative to the config file's directory.
    pub fn resolve(&self, p: &Path) -> PathBuf {
        if p.is_absolute() || p.as_os_str().is_empty() {
            return p.to_path_buf();
        }
        self.path.parent().unwrap_or(Path::new(".")).join(p)
    }

    /// Relative paths below state_dir.
    pub fn state_path(&self, p: &Path) -> PathBuf {
        if p.is_absolute() { p.to_path_buf() } else { self.general.state_dir.join(p) }
    }

    pub fn host_name(&self) -> String {
        if !self.general.host.is_empty() {
            return self.general.host.clone();
        }
        opskit::hostname().split('.').next().unwrap_or("localhost").to_ascii_lowercase()
    }

    pub fn host_cfg(&self, name: &str) -> HostCfg {
        self.hosts.iter().find(|h| h.name == name).cloned().unwrap_or_else(|| HostCfg { name: name.to_string(), ..HostCfg::default() })
    }

    fn validate(&self) -> Result<()> {
        if !valid_host(&self.host_name()) {
            bail!("general.host '{}' must be a lowercase short name ([a-z0-9-])", self.host_name());
        }
        if !["auto", "dpkg", "pacman", "none"].contains(&self.collect.packages.as_str()) {
            bail!("collect.packages must be auto | dpkg | pacman | none");
        }
        let mut seen = BTreeMap::new();
        for h in &self.hosts {
            if !valid_host(&h.name) {
                bail!("[[host]] name '{}' must be a lowercase short name", h.name);
            }
            if seen.insert(h.name.clone(), ()).is_some() {
                bail!("[[host]] '{}' defined twice", h.name);
            }
        }
        for w in &self.watch {
            if w.name.is_empty() {
                bail!("watch entry without name");
            }
            if w.version_cmd.is_empty() == w.image.is_empty() {
                bail!("watch '{}': set exactly one of version_cmd or image", w.name);
            }
            if !w.version_cmd.is_empty() && w.version_regex.is_empty() {
                bail!("watch '{}': version_cmd needs version_regex", w.name);
            }
            if !w.exposure.is_empty() {
                w.exposure.parse::<Exposure>().with_context(|| format!("watch '{}'", w.name))?;
            }
            if w.osv.is_none() && w.github.is_empty() {
                bail!("watch '{}': set osv and/or github, otherwise nothing is checked", w.name);
            }
        }
        if self.email.enabled && (self.email.to.is_empty() || self.email.from.is_empty()) {
            bail!("[email] enabled but to/from missing");
        }
        Ok(())
    }
}

fn load_watch(dir: &Path) -> Result<Vec<WatchEntry>> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return Ok(out) };
    let mut files: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "toml")).collect();
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
        let wf: WatchFile = toml::from_str(&text).with_context(|| format!("parsing {}", f.display()))?;
        out.extend(wf.watch);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_config_and_watch_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("watch.d")).unwrap();
        std::fs::write(
            dir.path().join("watch.d/10-apps.toml"),
            r#"
[[watch]]
name = "n8n"
image = "n8nio/n8n"
osv = { ecosystem = "npm", name = "n8n" }
github = "n8n-io/n8n"

[[watch]]
name = "syncthing"
version_cmd = ["syncthing", "--version"]
version_regex = 'v(\d+\.\d+\.\d+)'
github = "syncthing/syncthing"
exposure = "local"
"#,
        )
        .unwrap();
        let p = dir.path().join("config.toml");
        std::fs::write(&p, "[general]\nhost = \"anubis\"\n[[host]]\nname = \"zeno\"\nexposure = \"local\"\nstale_days = 7\n").unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.watch.len(), 2);
        assert_eq!(c.host_cfg("zeno").exposure, Exposure::Local);
        assert_eq!(c.host_cfg("balrog").stale_days, 2);
        std::fs::write(&p, "[general]\nhost = \"x\"\nbogus = 1\n").unwrap();
        assert!(Config::load(&p).is_err());
    }
}
