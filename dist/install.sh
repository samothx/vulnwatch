#!/usr/bin/env bash
#
# install.sh: install or upgrade vulnwatch. Idempotent; run as root from an unpacked bundle:
#
#   sudo ./install.sh --role collector|analyzer [options]
#
# Roles:
#   collector   every host: daily `vulnwatch collect` (root), uploads to the analyzer
#   analyzer    one host: collector (writing straight into the inbox) + daily `vulnwatch run`
#               as user vulnwatch, upload tokens for the other collectors, ntfy rules
#
# Options:
#   --config FILE         install this config.toml (from your repo; authoritative)
#   --watch FILE          extra watch.d file (repeatable; authoritative)
#   --host NAME           short host name for a generated config (default: hostname -s)
#   --upload-url URL      collector: analyzer endpoint, e.g. https://inv.services.etnur.net:8443/upload
#   --token-file FILE     collector: upload token to install as /etc/vulnwatch/upload-token
#   --lockfile-root DIR   collector: search Cargo.lock / package-lock.json below DIR (repeatable)
#   --collectors "a b"    analyzer: remote collectors that get an upload token (kept if present)
#   --no-trivy            don't install Trivy (no image SBOMs on this collector)
#   --no-first-run        don't run once at the end (timers are still enabled)
#   --bin PATH            binary to install (default: ./vulnwatch from the bundle)
#
# Never touches an existing config.toml unless --config is given. Shipped watch.d files that were
# edited locally are kept; the new version lands next to them as *.new.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root: sudo $0" >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
ETC=/etc/vulnwatch
STATE=/var/lib/vulnwatch
UNITS=/etc/systemd/system
DISPATCH_CFG=/etc/ntfy-dispatcher/config.toml
NGINX_MAP=/etc/nginx/conf.d/vulnwatch-upload-map.conf
BIN="$HERE/vulnwatch"
TRIVY_VERSION=0.75.0
TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ROLE=""
CONFIG=""
HOST="$(hostname -s | tr '[:upper:]' '[:lower:]')"
UPLOAD_URL=""
TOKEN_FILE=""
COLLECTORS=""
TRIVY=1
FIRST_RUN=1
WATCH=()
ROOTS=()
EXTRA_GROUPS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --watch) WATCH+=("$2"); shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --upload-url) UPLOAD_URL="$2"; shift 2 ;;
    --token-file) TOKEN_FILE="$2"; shift 2 ;;
    --lockfile-root) ROOTS+=("$2"); shift 2 ;;
    --collectors) COLLECTORS="$2"; shift 2 ;;
    --no-trivy) TRIVY=0; shift ;;
    --no-first-run) FIRST_RUN=0; shift ;;
    --bin) BIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

case "$ROLE" in collector|analyzer) ;; *) echo "--role collector|analyzer is required" >&2; exit 1 ;; esac
[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 1; }
[ -d "$HERE/systemd" ] && [ -d "$HERE/defaults/watch.d" ] || { echo "bundle incomplete" >&2; exit 1; }
[[ "$HOST" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "host name '$HOST' must be [a-z0-9-]" >&2; exit 1; }

BACKUPS="/var/backups/vulnwatch-$STAMP"
stash() { install -d -m 0700 "$BACKUPS"; cp -a "$1" "$BACKUPS/"; echo "  backup: $BACKUPS/$(basename "$1")"; }
install_local() {  # SRC DST MODE: files from your repo are authoritative
  if [ -e "$2" ] && cmp -s "$1" "$2"; then echo "  unchanged $2"; return; fi
  [ -e "$2" ] && stash "$2"
  install -o root -g root -m "${3:-0644}" "$1" "$2"; echo "  installed $2"
}

echo "=== vulnwatch install ($ROLE) on $(hostname) ($("$BIN" --version)) ==="

# --- binary + docs ---------------------------------------------------------------------------
[ -e /usr/local/bin/vulnwatch ] && ! cmp -s "$BIN" /usr/local/bin/vulnwatch && stash /usr/local/bin/vulnwatch
install -o root -g root -m 0755 "$BIN" /usr/local/bin/vulnwatch
install -d -m 0755 /usr/local/share/doc/vulnwatch
[ -f "$HERE/README.md" ] && install -m 0644 "$HERE/README.md" /usr/local/share/doc/vulnwatch/README.md

# --- Trivy (pinned, checksum verified) ---------------------------------------------------------
NEED_TRIVY=0
[ "$ROLE" = analyzer ] && NEED_TRIVY=1
command -v docker >/dev/null && NEED_TRIVY=1
if [ "$TRIVY" -eq 1 ] && [ "$NEED_TRIVY" -eq 1 ]; then
  if /usr/local/bin/trivy --version 2>/dev/null | grep -q "Version: $TRIVY_VERSION\$"; then
    echo "  trivy $TRIVY_VERSION already installed"
  else
    [ "$(uname -m)" = x86_64 ] || { echo "only x86_64 Trivy is pinned here; install it yourself or use --no-trivy" >&2; exit 1; }
    TMP="$(mktemp -d)"
    curl -fsSL -o "$TMP/trivy.tgz" "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    echo "$TRIVY_SHA256_AMD64  $TMP/trivy.tgz" | sha256sum -c --quiet
    tar -xzf "$TMP/trivy.tgz" -C "$TMP" trivy
    [ -e /usr/local/bin/trivy ] && stash /usr/local/bin/trivy
    install -o root -g root -m 0755 "$TMP/trivy" /usr/local/bin/trivy
    rm -rf "$TMP"
    echo "  installed trivy $TRIVY_VERSION (sha256 verified)"
  fi
fi

# --- config + watch list ------------------------------------------------------------------------
install -d -o root -g root -m 0755 "$ETC" "$ETC/watch.d"
for f in "$HERE"/defaults/watch.d/*.toml; do
  dst="$ETC/watch.d/$(basename "$f")"
  if [ ! -e "$dst" ]; then install -m 0644 "$f" "$dst"; echo "  installed $dst"
  elif cmp -s "$f" "$dst"; then echo "  unchanged $dst"
  else install -m 0644 "$f" "$dst.new"; echo "  KEPT $dst (differs from the shipped version: $dst.new; merge by hand)"; fi
done
for f in "${WATCH[@]}"; do install_local "$f" "$ETC/watch.d/$(basename "$f")"; done
if [ -n "$CONFIG" ]; then
  install_local "$CONFIG" "$ETC/config.toml"
elif [ -e "$ETC/config.toml" ]; then
  echo "  kept existing $ETC/config.toml"
else
  roots=""
  for r in "${ROOTS[@]}"; do roots+="\"$r\", "; done
  sed -e "s|^host = \"\" .*|host = \"$HOST\"|" \
      -e "s|^upload_url = \"\" .*|upload_url = \"$UPLOAD_URL\"|" \
      -e "s|^lockfile_roots = \[\] .*|lockfile_roots = [${roots%, }]|" \
      "$HERE/defaults/config.toml" > "$ETC/config.toml"
  # No Trivy on this collector: list images without SBOMs ([collect] only).
  [ "$TRIVY" -eq 0 ] && sed -i '/^\[collect\]/,/^\[/ s|^trivy = "[^"]*"|trivy = ""|' "$ETC/config.toml"
  chmod 0644 "$ETC/config.toml"
  echo "  generated $ETC/config.toml (host $HOST)"
fi
/usr/local/bin/vulnwatch --config "$ETC/config.toml" config check | sed -n 1,2p  # not head: closing the pipe early + pipefail aborts the install

# --- collector upload token ------------------------------------------------------------------------
if [ -n "$TOKEN_FILE" ]; then
  install -o root -g root -m 0600 "$TOKEN_FILE" "$ETC/upload-token"
  echo "  installed $ETC/upload-token (root 0600)"
fi
if grep -q '^upload_url = "https' "$ETC/config.toml" && [ ! -s "$ETC/upload-token" ]; then
  echo "  WARNING: upload_url is set but $ETC/upload-token is missing (copy it from the analyzer)"
fi

# --- analyzer: user, state, tokens, dispatcher -------------------------------------------------------
if [ "$ROLE" = analyzer ]; then
  if ! id vulnwatch >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$STATE" --no-create-home \
            --shell /usr/sbin/nologin --comment "vulnwatch analyzer" vulnwatch
    echo "  created system user vulnwatch"
  fi
  EXTRA_GROUPS=()
  for g in ntfy-senders msmtp; do getent group "$g" >/dev/null && EXTRA_GROUPS+=("$g"); done
  [ ${#EXTRA_GROUPS[@]} -gt 0 ] && usermod -aG "$(IFS=,; echo "${EXTRA_GROUPS[*]}")" vulnwatch
  echo "  vulnwatch groups: $(id -nG vulnwatch)"
  # adm members (thomas) may read reports. o+x (no read): nginx (www-data) must traverse to the inbox;
  # everything inside keeps its own modes (reports/state 0640/0750 vulnwatch:adm).
  install -d -o vulnwatch -g adm -m 2751 "$STATE"
  # Inbox: nginx (www-data) writes uploads, root writes the local inventory, vulnwatch reads.
  WEB=www-data; id "$WEB" >/dev/null 2>&1 || WEB=root
  install -d -o "$WEB" -g vulnwatch -m 2750 "$STATE/inbox"
  # nginx upload temp files live here so that renamed uploads keep group vulnwatch (see the vhost).
  install -d -o "$WEB" -g vulnwatch -m 2750 "$STATE/inbox/.upload-tmp"
  [ -e "$ETC/llm-api-key" ] && chown root:vulnwatch "$ETC/llm-api-key" && chmod 0640 "$ETC/llm-api-key" && echo "  $ETC/llm-api-key present (root:vulnwatch 0640)"

  # One random token per remote collector; nginx gets a map of "Bearer <token>|<upload path>".
  install -d -o root -g root -m 0700 "$ETC/tokens"
  for c in $COLLECTORS; do
    [[ "$c" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "bad collector name '$c'" >&2; exit 1; }
    if [ ! -s "$ETC/tokens/$c" ]; then
      (umask 077; head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > "$ETC/tokens/$c")
      echo "  generated upload token for $c: $ETC/tokens/$c (copy to $c:/etc/vulnwatch/upload-token)"
    fi
  done
  if [ -d /etc/nginx/conf.d ] && compgen -G "$ETC/tokens/*" >/dev/null; then
    TMPMAP="$(mktemp)"
    {
      echo "# Written by vulnwatch install.sh ($STAMP). Secrets: root 0600, never commit."
      echo "# Keys (\"Bearer <token>|/upload/<host>.json.gz\") are ~75 bytes: above the default bucket of 64."
      echo "map_hash_bucket_size 128;"
      echo "map \"\$http_authorization|\$request_uri\" \$vulnwatch_upload_ok {"
      echo "    default 0;"
      for t in "$ETC"/tokens/*; do
        echo "    \"Bearer $(cat "$t")|/upload/$(basename "$t").json.gz\" 1;"
      done
      echo "}"
    } > "$TMPMAP"
    if [ -e "$NGINX_MAP" ] && cmp -s "$TMPMAP" "$NGINX_MAP"; then
      rm -f "$TMPMAP"; echo "  unchanged $NGINX_MAP"
    else
      PREV=""
      if [ -e "$NGINX_MAP" ]; then stash "$NGINX_MAP"; PREV="$BACKUPS/$(basename "$NGINX_MAP")"; fi
      install -o root -g root -m 0600 "$TMPMAP" "$NGINX_MAP"; rm -f "$TMPMAP"
      if nginx -t 2>/dev/null; then
        systemctl reload nginx; echo "  $NGINX_MAP installed, nginx reloaded"
      else
        echo "nginx -t failed with the new upload map:" >&2; nginx -t || true
        # Never leave nginx with a config that doesn't load: put the previous state back.
        if [ -n "$PREV" ]; then cp -a "$PREV" "$NGINX_MAP"; else rm -f "$NGINX_MAP"; fi
        nginx -t 2>/dev/null && echo "  restored the previous nginx state" >&2
        exit 1
      fi
    fi
  fi

  if [ -f "$DISPATCH_CFG" ] && command -v ntfy-dispatcher >/dev/null && ! grep -q 'id = "vulnwatch_alert"' "$DISPATCH_CFG"; then
    stash "$DISPATCH_CFG"
    cat "$HERE/dispatcher-rules.toml" >> "$DISPATCH_CFG"
    if ! ntfy-dispatcher config check >/dev/null; then
      echo "dispatcher config check failed; restoring $DISPATCH_CFG" >&2
      cp -a "$BACKUPS/$(basename "$DISPATCH_CFG")" "$DISPATCH_CFG"; exit 1
    fi
    echo "  added dispatcher rules vulnwatch_alert / vulnwatch_digest / vulnwatch_error"
  fi
fi

# --- units + host drop-ins -------------------------------------------------------------------------
UNIT_LIST=(vulnwatch-collect.service vulnwatch-collect.timer)
[ "$ROLE" = analyzer ] && UNIT_LIST+=(vulnwatch.service vulnwatch.timer)
for u in "${UNIT_LIST[@]}"; do
  [ -e "$UNITS/$u" ] && ! cmp -s "$HERE/systemd/$u" "$UNITS/$u" && stash "$UNITS/$u"
  install -o root -g root -m 0644 "$HERE/systemd/$u" "$UNITS/$u"
done
HANDLER=""
for h in ntfy-job-failed@.service ntfy-unit-failed@.service; do
  if [ -e "$UNITS/$h" ] || [ -e "/usr/lib/systemd/system/$h" ] || [ -e "/lib/systemd/system/$h" ]; then HANDLER="${h%@.service}@%N.service"; break; fi
done
for svc in vulnwatch-collect vulnwatch; do
  [ -e "$UNITS/$svc.service" ] || continue
  install -d -m 0755 "$UNITS/$svc.service.d"
  {
    echo "# Written by vulnwatch install.sh for $(hostname) on $STAMP."
    echo "[Unit]"
    [ -n "$HANDLER" ] && echo "OnFailure=$HANDLER"
    if [ "$svc" = vulnwatch ] && [ ${#EXTRA_GROUPS[@]} -gt 0 ]; then
      echo "[Service]"
      echo "SupplementaryGroups=${EXTRA_GROUPS[*]}"
    fi
  } > "$UNITS/$svc.service.d/10-host.conf"
done
systemctl daemon-reload
systemd-analyze verify --man=no "${UNIT_LIST[@]}" 2>&1 | grep -v '^$' || true

# --- verify + first run --------------------------------------------------------------------------
echo "--- collect --dry-run ---"
/usr/local/bin/vulnwatch --config "$ETC/config.toml" collect --dry-run || true
if [ "$FIRST_RUN" -eq 1 ]; then
  echo "--- first run: vulnwatch-collect.service ---"
  systemctl start vulnwatch-collect.service || echo "  vulnwatch-collect.service failed, see journal"
  journalctl -u vulnwatch-collect.service -n 4 --no-pager -o cat
  if [ "$ROLE" = analyzer ]; then
    echo "--- first run: vulnwatch.service (downloads feeds + Trivy DB, a few minutes) ---"
    systemctl start vulnwatch.service || echo "  vulnwatch.service failed, see journal"
    journalctl -u vulnwatch.service -n 8 --no-pager -o cat
  fi
fi
systemctl enable --now vulnwatch-collect.timer
[ "$ROLE" = analyzer ] && systemctl enable --now vulnwatch.timer
systemctl list-timers 'vulnwatch*' --no-pager | head -4
echo "=== done ==="
