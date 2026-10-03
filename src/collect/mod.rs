//! `vulnwatch collect`: build this host's inventory. Read-only on the host; needs the docker
//! group (root-equivalent) only for image SBOMs.

pub mod docker;
pub mod lockfiles;
pub mod packages;
pub mod upload;
pub mod watch;

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Local;

use crate::config::Config;
use crate::inventory::{Inventory, Os, SCHEMA};

pub fn collect(cfg: &Config) -> Inventory {
    let mut inv = Inventory {
        schema: SCHEMA,
        host: cfg.host_name(),
        collected_at: Some(Local::now()),
        collector_version: env!("CARGO_PKG_VERSION").into(),
        os: os_release(Path::new("/etc/os-release")),
        kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default(),
        ..Default::default()
    };
    let timeout = Duration::from_secs(cfg.collect.command_timeout_secs);

    match packages::collect(&cfg.collect.packages, &inv.os, timeout) {
        Ok((mgr, pkgs)) => {
            inv.pkg_manager = mgr;
            inv.packages = pkgs;
        }
        Err(e) => inv.errors.push(format!("packages: {e:#}")),
    }
    if cfg.collect.docker {
        match docker::collect(&cfg.collect, timeout, &mut inv.errors) {
            Ok(images) => inv.images = images,
            Err(e) => inv.errors.push(format!("docker: {e:#}")),
        }
    }
    let roots: Vec<_> = cfg.collect.lockfile_roots.iter().map(|r| cfg.resolve(r)).collect();
    inv.lockfiles = lockfiles::collect(&roots, cfg.collect.lockfile_max_depth, &cfg.collect.lockfile_skip_dirs, &mut inv.errors);
    inv.watched = watch::collect(&cfg.watch, &inv.images, timeout, &mut inv.errors);
    inv
}

pub fn os_release(path: &Path) -> Os {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut os = Os::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
        match k.trim() {
            "ID" => os.id = v,
            "ID_LIKE" => os.id_like = v.split_whitespace().map(String::from).collect(),
            "VERSION_ID" => os.version_id = v,
            "VERSION_CODENAME" => os.codename = v,
            "PRETTY_NAME" => os.pretty_name = v,
            _ => {}
        }
    }
    os
}

/// Runs argv (no shell) with a timeout; returns stdout. Non-zero exit is an error with stderr.
pub fn run(argv: &[impl AsRef<std::ffi::OsStr>], timeout: Duration) -> Result<String> {
    let Some((prog, args)) = argv.split_first() else { bail!("empty command") };
    let name = Path::new(prog.as_ref()).display().to_string();
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C")
        .spawn()
        .with_context(|| format!("starting {name}"))?;
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = out.read_to_end(&mut s);
        s
    });
    let ereader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = err.read_to_end(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{name} timed out after {}s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&ereader.join().unwrap_or_default()).into_owned();
    if !status.success() {
        bail!("{name} failed ({status}): {}", opskit::truncate(stderr.trim(), 500));
    }
    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_release() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("os-release");
        std::fs::write(&p, "PRETTY_NAME=\"CachyOS\"\nID=cachyos\nID_LIKE=arch\n").unwrap();
        let os = os_release(&p);
        assert!(os.is("arch") && os.id == "cachyos" && !os.is("debian"));
    }

    #[test]
    fn run_times_out_and_reports_failure() {
        assert_eq!(run(&["echo", "hi"], Duration::from_secs(5)).unwrap(), "hi\n");
        assert!(run(&["sleep", "5"], Duration::from_millis(200)).unwrap_err().to_string().contains("timed out"));
        assert!(run(&["false"], Duration::from_secs(5)).is_err());
    }
}
