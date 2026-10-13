//! Dependency lockfiles of own projects: Cargo.lock (crates.io), package-lock.json and
//! pnpm-lock.yaml (npm).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::inventory::{Dep, Lockfile};

const LOCKFILES: &[&str] = &["Cargo.lock", "package-lock.json", "pnpm-lock.yaml"];

pub fn collect(roots: &[PathBuf], max_depth: usize, skip: &[String], errors: &mut Vec<String>) -> Vec<Lockfile> {
    let mut found = Vec::new();
    for r in roots {
        walk(r, 0, max_depth, skip, &mut found);
    }
    found.sort();
    let mut out = Vec::new();
    for p in found {
        let res = match p.file_name().and_then(|n| n.to_str()) {
            Some("Cargo.lock") => cargo(&p).map(|d| ("crates.io", d)),
            Some("package-lock.json") => npm(&p).map(|d| ("npm", d)),
            Some("pnpm-lock.yaml") => pnpm(&p).map(|d| ("npm", d)),
            _ => continue,
        };
        match res {
            Ok((eco, packages)) if !packages.is_empty() => {
                out.push(Lockfile { path: p.display().to_string(), ecosystem: eco.into(), packages });
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("lockfile {}: {e:#}", p.display())),
        }
    }
    out
}

fn walk(dir: &Path, depth: usize, max: usize, skip: &[String], found: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let name = e.file_name();
        let name = name.to_string_lossy();
        if ft.is_dir() {
            if depth < max && !skip.iter().any(|s| s == name.as_ref()) && !name.starts_with('.') {
                walk(&e.path(), depth + 1, max, skip, found);
            }
        } else if ft.is_file() && LOCKFILES.contains(&name.as_ref()) {
            found.push(e.path());
        }
    }
}

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPkg>,
}

#[derive(Deserialize)]
struct CargoPkg {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

/// Registry packages only; path and git dependencies are the projects themselves or forks.
pub fn cargo(p: &Path) -> Result<Vec<Dep>> {
    let text = std::fs::read_to_string(p)?;
    let lock: CargoLock = toml::from_str(&text).context("parsing Cargo.lock")?;
    let set: BTreeSet<Dep> = lock
        .package
        .into_iter()
        .filter(|c| c.source.as_deref().is_some_and(|s| s.starts_with("registry+") || s.starts_with("sparse+")))
        .map(|c| Dep { name: c.name, version: c.version })
        .collect();
    Ok(set.into_iter().collect())
}

/// lockfileVersion 2/3 (`packages`) and 1 (`dependencies`, nested).
pub fn npm(p: &Path) -> Result<Vec<Dep>> {
    let text = std::fs::read_to_string(p)?;
    let v: serde_json::Value = serde_json::from_str(&text).context("parsing package-lock.json")?;
    let mut set = BTreeSet::new();
    if let Some(pkgs) = v["packages"].as_object() {
        for (path, meta) in pkgs {
            if path.is_empty() || meta["link"].as_bool() == Some(true) {
                continue;
            }
            let name = meta["name"].as_str().map(String::from).unwrap_or_else(|| {
                let tail = path.rsplit("node_modules/").next().unwrap_or(path);
                tail.to_string()
            });
            if let Some(ver) = meta["version"].as_str()
                && !name.is_empty()
            {
                set.insert(Dep { name, version: ver.into() });
            }
        }
    } else if let Some(deps) = v["dependencies"].as_object() {
        fn rec(deps: &serde_json::Map<String, serde_json::Value>, set: &mut BTreeSet<Dep>) {
            for (name, meta) in deps {
                if let Some(ver) = meta["version"].as_str()
                    && !ver.starts_with("file:")
                {
                    set.insert(Dep { name: name.clone(), version: ver.into() });
                }
                if let Some(sub) = meta["dependencies"].as_object() {
                    rec(sub, set);
                }
            }
        }
        rec(deps, &mut set);
    }
    Ok(set.into_iter().collect())
}

/// pnpm-lock.yaml v5.x, v6 and v9: the keys of the top-level `packages:` map name every
/// resolved package. Parsed line by line (no YAML dependency); a file may hold several
/// documents (pnpm 10 puts config dependencies in a leading one), each with its own map.
pub fn pnpm(p: &Path) -> Result<Vec<Dep>> {
    let text = std::fs::read_to_string(p)?;
    let mut set = BTreeSet::new();
    let mut slash_keys = false;
    let mut in_packages = false;
    let mut seen_version = false;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            in_packages = line.trim_end() == "packages:";
            if let Some(v) = line.strip_prefix("lockfileVersion:") {
                let v = v.trim().trim_matches(|c| c == '\'' || c == '"');
                // 5.x keys are `/name/1.2.3_peers`, 6+ use `/name@1.2.3(peers)`
                slash_keys = v.split('.').next().and_then(|m| m.parse::<u32>().ok()).is_some_and(|m| m < 6);
                seen_version = true;
            }
            continue;
        }
        if !in_packages || line.starts_with("   ") {
            continue;
        }
        let Some(key) = line.trim().strip_suffix(':').or_else(|| line.trim().strip_suffix(": {}")) else {
            continue;
        };
        if let Some(d) = pnpm_key(key.trim_matches(|c| c == '\'' || c == '"'), slash_keys) {
            set.insert(d);
        }
    }
    if !seen_version {
        anyhow::bail!("parsing pnpm-lock.yaml: no lockfileVersion");
    }
    Ok(set.into_iter().collect())
}

/// Registry packages only: tarball, git, `file:` and `link:` entries have no semver version.
fn pnpm_key(key: &str, slash_keys: bool) -> Option<Dep> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let (name, version) = if slash_keys {
        let (name, ver) = key.rsplit_once('/')?;
        (name, ver.split('_').next()?)
    } else {
        let key = key.split('(').next()?;
        let at = key.rfind('@').filter(|&i| i > 0)?;
        (&key[..at], &key[at + 1..])
    };
    if name.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some(Dep { name: name.into(), version: version.into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_parses_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("rust/app");
        std::fs::create_dir_all(proj.join("target/debug")).unwrap();
        std::fs::write(
            proj.join("Cargo.lock"),
            r#"version = 4
[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "fork"
version = "0.2.0"
source = "git+https://example.org/fork#abc"
"#,
        )
        .unwrap();
        std::fs::write(proj.join("target/debug/Cargo.lock"), "garbage").unwrap();
        let web = dir.path().join("web");
        std::fs::create_dir_all(&web).unwrap();
        std::fs::write(
            web.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{"name":"web"},"node_modules/next":{"version":"15.5.2"},
               "node_modules/@scope/x/node_modules/y":{"version":"1.0.0"},"node_modules/linked":{"link":true}}}"#,
        )
        .unwrap();
        let mut errs = Vec::new();
        let l = collect(&[dir.path().to_path_buf()], 5, &["target".into()], &mut errs);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].packages, vec![Dep { name: "tokio".into(), version: "1.0.0".into() }]);
        assert_eq!(l[1].ecosystem, "npm");
        assert_eq!(l[1].packages.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), vec!["next", "y"]);
    }

    #[test]
    fn npm_v1() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("package-lock.json");
        std::fs::write(&p, r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}"#).unwrap();
        assert_eq!(npm(&p).unwrap().len(), 2);
    }

    fn deps(v: &[Dep]) -> Vec<String> {
        v.iter().map(|d| format!("{}@{}", d.name, d.version)).collect()
    }

    #[test]
    fn pnpm_v9() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pnpm-lock.yaml");
        std::fs::write(
            &p,
            r#"lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      next:
        specifier: 15.5.2
        version: 15.5.2(react@19.1.0)

packages:

  '@next/env@15.5.2':
    resolution: {integrity: sha512-x}

  next@15.5.2:
    resolution: {integrity: sha512-y}
    engines: {node: '>=18'}
    peerDependencies:
      react: ^19

  gitdep@https://codeload.github.com/o/r/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/o/r/tar.gz/abc}
    version: 1.0.0

snapshots:

  next@15.5.2(react@19.1.0):
    dependencies:
      '@next/env': 15.5.2

  ignored@9.9.9: {}
"#,
        )
        .unwrap();
        assert_eq!(deps(&pnpm(&p).unwrap()), vec!["@next/env@15.5.2", "next@15.5.2"]);
    }

    #[test]
    fn pnpm_v6_and_v5() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pnpm-lock.yaml");
        std::fs::write(
            &p,
            "lockfileVersion: '6.0'\n\npackages:\n\n  /@scope/a@1.2.3(react@18.2.0):\n    resolution: {integrity: x}\n  /b@2.0.0:\n    dev: false\n",
        )
        .unwrap();
        assert_eq!(deps(&pnpm(&p).unwrap()), vec!["@scope/a@1.2.3", "b@2.0.0"]);
        std::fs::write(
            &p,
            "lockfileVersion: 5.4\n\npackages:\n\n  /@scope/a/1.2.3_react@18.2.0:\n    resolution: {integrity: x}\n  /b/2.0.0:\n    dev: false\n",
        )
        .unwrap();
        assert_eq!(deps(&pnpm(&p).unwrap()), vec!["@scope/a@1.2.3", "b@2.0.0"]);
        std::fs::write(&p, "not: a lockfile\n").unwrap();
        assert!(pnpm(&p).is_err());
    }
}
