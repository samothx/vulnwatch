//! PUT the gzipped inventory to the analyzer's nginx endpoint (`<upload_url>/<host>.json.gz`).

use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use crate::config::Collect;

pub fn upload(cfg: &Collect, host: &str, body: &[u8]) -> Result<String> {
    let token = opskit::secret::read("VULNWATCH_UPLOAD_TOKEN", &cfg.token_file)?;
    let url = format!("{}/{host}.json.gz", cfg.upload_url.trim_end_matches('/'));
    if !url.starts_with("https://") {
        bail!("upload_url must be https:// (the token is a bearer secret)");
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(300)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .http_status_as_error(false)
        .user_agent(concat!("vulnwatch/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut resp = agent
        .put(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/gzip")
        .send(body)
        .map_err(|e| anyhow!("PUT {url}: {e}"))?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        bail!("PUT {url}: HTTP {status} {}", opskit::truncate(text.trim(), 300));
    }
    Ok(url)
}
