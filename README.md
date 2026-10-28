# vulnwatch

Daily vulnerability digest for a handful of hosts, built from **what is actually installed**
rather than from news feeds filtered by keywords.

```
every host                               analyzer host (anubis)
vulnwatch collect   (timer 06:45)  ──▶   inbox/<host>.json.gz  (nginx PUT, per-host token, VPN only)
  dpkg-query / pacman -Q                 vulnwatch run   (timer 07:30, user vulnwatch)
  running images → trivy SBOM              Debian security tracker   → OS packages (Debian)
  Cargo.lock / package-lock / pnpm-lock    Arch security tracker     → OS packages (Arch, CachyOS)
  watch list: version_cmd / image tag      OSV.dev                   → lockfiles, watch list
                                           trivy sbom                → image contents
                                           GitHub releases           → newer version available
                                           CISA KEV + EPSS           → exploited / likely exploited
                                         policy → findings → diff vs state → report, ntfy, mail
                                         optional LLM summary (ranks + explains findings, cannot change them)
```

## What you get

One **finding per thing you act on**: a host's OS packages (`apt upgrade on anubis`), an image
(`pull n8nio/n8n:1.121.0`, or `nothing to do yet` when no published build fixes it), a source
tree's lockfile (`cargo update in …`), a watched product
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
2. EPSS ≥ `epss_raise` (default 0.1) raises it one level.
3. No fix available: capped at `unfixed_max` (low).
4. OS packages *inside images* are capped at `image_os_max` (medium); a high EPSS lifts them one
   level above that at most. Stale base images carry hundreds of them, the fix is a re-pull, not a
   page, and EPSS rates the library bug in general, not whether this image ever feeds it attacker
   input (brotli pulled in by curl ≠ nginx decoding requests).
5. Image vulnerabilities **no pull can fix yet** are capped at `image_current_max` (low): the
   registry still serves the running build for the tag, or it serves a newer build that still
   ships the same package version (see below). The finding then says "nothing to do yet" and
   waits for upstream instead of alerting daily; once a fixing build is published the cap lifts and
   the vulnerability counts as new again (push). Locally built or private images are "not checked".
6. Exposure of what is affected (host `exposure`, watch entry, `lockfile_exposure`,
   `image_exposure`): `local` lowers the result one level (min low), `vpn` caps it at `vpn_max`
   (medium), `trusted` (the admin plus a named outside party, e.g. a VPN customer) at
   `trusted_max` (low).
7. Source trees (lockfiles) deployed as an image (`deployed_as`): capped at `lockfile_stale_max`
   (low) where the deployed image runs another version and isn't affected, or reports the same
   vulnerability itself (see below).
8. CISA KEV (exploited in the wild): at least high; critical only when it is public and pulling a newer
   build fixes it today. When the newest published build still ships it, the action says to rebuild on top
   of the tag with an OS package upgrade instead of "nothing to do yet".
9. `[[triage]]`: a human decision caps one vulnerability, shown with its reason. A KEV one only with an
   `until` date and never below medium.

**Upstream check.** An anonymous `HEAD /v2/<repo>/manifests/<tag>` against the image's registry
(bearer token from the registry's own https realm), compared with the image's `RepoDigests`. When
the tag points to a newer build, that build is scanned straight from the registry
(`trivy image --image-src remote`, `upstream_scan = true`; result cached per digest), and every
vulnerability it still ships counts as "waiting for upstream". The action then says how many a pull
fixes ("fixes 15 of 64") or "nothing to do yet". Containers still running an older, now untagged
build of a tag that was pulled since are checked against the tag they were started with, and the
action is "recreate". Runs on the analyzer, only for images with fixable findings; skipped with
`--offline`.

Per-image exposure, by image reference (default for its containers) or container name (overrides
for that container), `*` wildcard. An image is as exposed as its most exposed container; containers
without an entry keep the host's exposure:

```toml
[[host]]
name = "anubis"
exposure = "public"
image_exposure = { "umami-db" = "local", "postgres:*" = "vpn", "customer-*" = "trusted" }
```

**Source trees.** Lockfiles are checkouts, not services ("source tree" in the report). Map them to
the image they are deployed as and each vulnerability is compared with that image's SBOM:

```toml
[[host]]
name = "zeno"
exposure = "local"
lockfile_exposure = "public"
deployed_as = { "*/shop/package-lock.json" = "registry.example/shop:*" }
```

Reported under the image itself or older than the deployed version → capped; same version, or not
in the image (build/dev dependency, or bundled into JS chunks) → kept, with a note.

**Triage.** For what no rule can know (reachability):

```toml
[[triage]]
id = "CVE-2026-111497"
package = "brotli-libs"          # glob, optional
component = "nginx:*"            # image reference, container or lockfile glob, optional
host = ""                        # optional
max = "low"                      # default low
reason = "only via curl/freetype; nothing decodes attacker-supplied brotli"
until = "2026-12-31"             # optional; after that the entry is ignored and noted
```

Kernel packages inside images (`linux-libc-dev` …) are ignored: they are never the running kernel.

## AI summary (optional, `[llm]`)

The model gets the findings as numbered references (F1, F2, …) with host, kind (container image /
source tree / OS packages), containers, exposure, packages and the action, and answers only with
up to six picks `{"finding": "F3", "why": "…"}` plus one "can wait" sentence. vulnwatch prints the
host, target, containers and action next to each "why", so the model cannot move a vulnerability
onto a container that doesn't have it. Each sentence is checked against its own finding and
dropped (noted under "Coverage notes") when it cites an id or version that isn't in that finding,
or names another finding's container, image, project or package (`next.js` counts as `next`).

## Coverage and limits

- **Debian:** source package + version against the tracker's per-release status. Packages from
  third-party repos (Docker, NodeSource, CrowdSec) are not in the tracker. Watch them in `watch.d`.
- **Arch/CachyOS:** the Arch tracker lags behind, and CachyOS-only builds (`linux-cachyos`) aren't in it.
  The report says so; the watch list fills some of the gap.
- **Images:** whatever Trivy finds in the SBOM (OS packages, node_modules, Go binaries, …).
- **Lockfiles:** `Cargo.lock` (registry crates only) and `package-lock.json` v1–v3 and `pnpm-lock.yaml` v5.x/v6/v9 (registry packages only).
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

## License

MIT, see [LICENSE](LICENSE).
