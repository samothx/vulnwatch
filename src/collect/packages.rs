//! Installed OS packages: dpkg (Debian) or pacman (Arch, CachyOS, …).

use std::time::Duration;

use anyhow::{Result, bail};

use crate::inventory::{Os, Package};

pub fn collect(mode: &str, os: &Os, timeout: Duration) -> Result<(String, Vec<Package>)> {
    let mode = match mode {
        "auto" if os.is("debian") => "dpkg",
        "auto" if os.is("arch") => "pacman",
        "auto" => return Ok((String::new(), Vec::new())),
        m => m,
    };
    match mode {
        "dpkg" => {
            let out = super::run(
                &["dpkg-query", "-W", "-f", "${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n"],
                timeout,
            )?;
            Ok(("dpkg".into(), parse_dpkg(&out)))
        }
        "pacman" => Ok(("pacman".into(), parse_pacman(&super::run(&["pacman", "-Q"], timeout)?))),
        "none" => Ok((String::new(), Vec::new())),
        m => bail!("unknown package mode {m}"),
    }
}

/// Only installed packages ("ii"); deduplicated over multiarch (same name, version).
pub fn parse_dpkg(out: &str) -> Vec<Package> {
    let mut v: Vec<Package> = out
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 5 || !f[0].starts_with("ii") {
                return None;
            }
            let name = f[1].split(':').next().unwrap_or(f[1]).to_string();
            Some(Package { name, version: f[2].into(), source: f[3].into(), source_version: f[4].into() })
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    v.dedup();
    v
}

pub fn parse_pacman(out: &str) -> Vec<Package> {
    out.lines()
        .filter_map(|l| {
            let (n, v) = l.trim().split_once(' ')?;
            Some(Package { name: n.into(), version: v.into(), ..Default::default() })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_lines() {
        let out = "ii \tlibssl3t64:amd64\t3.5.6-1~deb13u2\topenssl\t3.5.6-1~deb13u2\n\
                   ii \tlibssl3t64:i386\t3.5.6-1~deb13u2\topenssl\t3.5.6-1~deb13u2\n\
                   rc \told\t1.0\told\t1.0\n\
                   ii \tbash\t5.2.37-2+b5\tbash\t5.2.37-2\n";
        let p = parse_dpkg(out);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "bash");
        assert_eq!(p[0].source_version, "5.2.37-2");
        assert_eq!(p[1].source, "openssl");
    }

    #[test]
    fn pacman_lines() {
        let p = parse_pacman("linux-cachyos 6.17.1-2\nsyncthing 2.0.10-1\n");
        assert_eq!(p[1], Package { name: "syncthing".into(), version: "2.0.10-1".into(), ..Default::default() });
    }
}
