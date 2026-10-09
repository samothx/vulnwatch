# vulnwatch

Daily vulnerability digest for a handful of hosts, built from **what is actually installed**
rather than from news feeds filtered by keywords.

```
every host                               analyzer host (anubis)
vulnwatch collect   (timer 06:45)  ──▶   inbox/<host>.json.gz  (nginx PUT, per-host token, VPN only)
  dpkg-query / pacman -Q                 vulnwatch run   (timer 07:30, user vulnwatch)
  running images → trivy SBOM              Debian security tracker   → OS packages (Debian)
  Cargo.lock / package-lock.json           Arch security tracker     → OS packages (Arch, CachyOS)
  watch list: version_cmd / image tag      OSV.dev                   → lockfiles, watch list
                                           trivy sbom                → image contents
                                           GitHub releases           → newer version available
                                           CISA KEV + EPSS           → exploited / likely exploited
                                         policy → findings → diff vs state → report, ntfy, mail
                                         optional LLM summary (prose only, cannot change findings)
```

## What you get

One **finding per thing you act on**: a host's OS packages (`apt upgrade on anubis`), an image
(`pull/rebuild n8nio/n8n:1.121.0`), a lockfile (`cargo update in …`), a watched product
(`upgrade crowdsec to ≥ 1.8.2`), a newer release, or a missing/stale inventory. Each finding
lists its vulnerabilities, worst first, with fix version, KEV and EPSS.

- **New vs. known:** vulnerabilities are remembered by host + component + package + id. Only new
  ones, worse ones, or ones that just became fixable count as new. A second run on the same day
  pushes nothing.
- **Resolved:** listed once when they disappear (only for hosts and sources that were checked in
  that run; a missing inventory never looks like "fixed").
- **Reminders:** unresolved findings ≥ `notify.min_severity` are pushed again after `remind_days`.
- **Without a fix:** counted per component under "No fix available yet". They show up as findings
  once a fix ships, or immediately if they are on the KEV list.

## Severity policy

Applied to every vulnerability, in this order:

1. Source severity: Debian urgency, Arch severity, GHSA label or CVSS v3 score, Trivy.
2. `exposure = "local"` (host, watch entry, `lockfile_exposure` or `image_exposure`) lowers it one level.
3. EPSS ≥ `epss_raise` (default 0.1) raises it one level.
4. No fix available: capped at `unfixed_max` (low).
5. OS packages *inside images* are capped at `image_os_max` (medium) unless EPSS is high. Stale
   base images carry hundreds of them, and the fix is a re-pull, not a page.
6. Images whose registry still serves the running build for their tag are capped at
   `image_current_max` (low): `docker pull` would change nothing, so the finding waits for upstream
   instead of alerting daily. Once the tag points to a new build the cap lifts, the severity rises,
   and the finding counts as new again (push). Locally built or private images are "not checked".
7. CISA KEV (exploited in the wild): at least high, critical when a fix exists.

The upstream check is an anonymous `HEAD /v2/<repo>/manifests/<tag>` against the image's registry
(bearer token from the registry's own https realm), compared with the image's `RepoDigests`. It runs
on the analyzer, only for images with findings, and is skipped with `--offline`.

Per-image exposure, by image reference or container name (`*` wildcard; the most exposed match wins):

```toml
[[host]]
name = "balrog"
exposure = "public"
image_exposure = { "umami-db" = "local", "postgres:*" = "local" }
```

Kernel packages inside images (`linux-libc-dev` …) are ignored: they are never the running kernel.

## Coverage and limits

- **Debian:** source package + version against the tracker's per-release status. Packages from
  third-party repos (Docker, NodeSource, CrowdSec) are not in the tracker. Watch them in `watch.d`.
- **Arch/CachyOS:** the Arch tracker lags behind, and CachyOS-only builds (`linux-cachyos`) aren't in it.
  The report says so; the watch list fills some of the gap.
- **Images:** whatever Trivy finds in the SBOM (OS packages, node_modules, Go binaries, …).
- **Lockfiles:** `Cargo.lock` (registry crates only) and `package-lock.json` v1–v3.
- Trivy runs with `--disable-telemetry --skip-version-check`.

## CLI

```
vulnwatch [--config /etc/vulnwatch/config.toml] [--state-dir DIR] <command>

collect [--out FILE] [--print] [--dry-run]   # build + upload/write this host's inventory
run [--dry-run] [--print] [--no-llm] [--offline]
feeds update|status
inventory list | show <host>
config check
show [latest|2026-10-03_0730]
explain <id|text>                            # full JSON of matching findings (latest report)
mail [latest]                                # mail a stored report now
```

Trying things without touching the real state (as any user who can read the inbox):

```bash
vulnwatch --state-dir /tmp/vw run --dry-run --print --no-llm | less
```

## Watch list (`watch.d/*.toml`)

```toml
[[watch]]
name = "crowdsec"
version_cmd = ["dpkg-query", "-W", "-f", "${Version}", "crowdsec"]   # argv, no shell
version_regex = '^(\d+\.\d+\.\d+)'                                    # first capture = version
osv = { ecosystem = "Go", name = "github.com/crowdsecurity/crowdsec" }
github = "crowdsecurity/crowdsec"     # newer-release check
exposure = "public"                   # optional, else the host's
same_major = false                    # true: compare with releases on the installed major only

[[watch]]
name = "n8n"
image = "n8nio/n8n"                   # version = tag, or the OCI version label
osv = { ecosystem = "npm", name = "n8n" }
github = "n8n-io/n8n"
```

A missing command or image is skipped silently, so one list serves all hosts.

## Install

`dist/package.sh` → `target/bundle/vulnwatch-<ver>-x86_64-linux.tar.gz` (static musl binary, units,
defaults, `install.sh`). Trivy is downloaded by `install.sh` (pinned version, sha256 checked).

```bash
# analyzer (also collects itself), with upload tokens for two remote collectors
sudo ./install.sh --role analyzer --config my-config.toml --collectors "balrog zeno"
# collector
sudo ./install.sh --role collector --upload-url https://inv.services.etnur.net:8443/upload \
                  --token-file ./zeno.token --lockfile-root /home/thomas/develop --no-trivy
```

Files: `/etc/vulnwatch/{config.toml,watch.d/,upload-token,tokens/,llm-api-key}`,
`/var/lib/vulnwatch/{inbox/,feeds/,trivy-cache/,reports/,state.json}`, `/var/cache/vulnwatch/trivy`.
ntfy events: `vulnwatch.alert` (≥ high, new or reminder), `vulnwatch.digest`, `vulnwatch.error`.
