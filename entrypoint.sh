#!/bin/sh
# Edge Proxy entrypoint — frps + nginx + lego lifecycle
# POSIX sh only — the runtime image carries no bash.
set -eu

# --- lifecycle helpers -------------------------------------------------------
# Defined before startup so scripts/test-entrypoint.sh can source this file
# (EDGE_PROXY_LIB_ONLY=1) and exercise them without starting any service.
CERT_DIR=/certs
WEBROOT=/var/www/acme
# Renewal-liveness marker consumed by the Dockerfile HEALTHCHECK (7-day
# freshness window). Touch ONLY on a fully successful install_cert cycle.
RENEW_MARKER=/tmp/nginx/renewed
# Stream-map include consumed by nginx.conf: the t-* (wss control) route is
# GATED on a CA-signed certificate. Written before nginx starts and rewritten
# by install_cert before its reload — see write_tunnel_route below.
ROUTE_FILE=/tmp/nginx/tunnel-route.conf

# True iff the PEM in $1 is signed by a CA (issuer != subject). The
# per-container placeholder is the only self-signed cert this entrypoint ever
# mints, so this is exactly "real cert, not placeholder" — the gate the sidecar
# trust contract needs: a self-signed cert must never reach a TLS client, or
# the sidecar is forced into a TOFU decision (see Dockerfile header).
cert_is_ca_signed() {
  _issuer=$(openssl x509 -in "$1" -noout -issuer 2>/dev/null) || return 1
  _subject=$(openssl x509 -in "$1" -noout -subject 2>/dev/null) || return 1
  [ "${_issuer#issuer=}" != "${_subject#subject=}" ]
}

# write_tunnel_route open|closed — generate the nginx stream-map include that
# decides where the wss control channel lands. open: the wss terminator at
# :7444. closed: a dead loopback port (nothing binds port 1), so the client
# connection is refused before any TLS handshake — the placeholder cert is
# never served.
# The map key is the exact DOMAIN, case-insensitive and anchored — NOT a t-*
# prefix match: a customer's app hostname may itself start with t-, and a
# prefix match would hijack it to the wss terminator, which answers with the
# DOMAIN cert and breaks that app's TLS. DOMAIN is validated to the
# [A-Za-z0-9.-] charset at startup, so escaping the dots makes it regex-safe.
# The map body lives here (not in nginx.conf) because it is the only
# runtime-state-dependent piece of the nginx config; everything else is static.
write_tunnel_route() {
  mkdir -p "$(dirname "$ROUTE_FILE")"
  _domain_re=$(printf '%s' "$DOMAIN" | sed 's/\./\\./g')
  case "$1" in
    open)   printf '~*^%s$  127.0.0.1:7444;\n' "$_domain_re" > "$ROUTE_FILE" ;;
    closed) printf '~*^%s$  127.0.0.1:1;\n'    "$_domain_re" > "$ROUTE_FILE" ;;
    *) return 1 ;;
  esac
}

# Install the issued cert/key into the nginx-served pair and hot-reload.
# Callers run `if issue && install_cert`, which suppresses set -e — every step
# is chained so a failed copy or reload propagates as failure, and RENEW_MARKER
# is touched only after the reload succeeded. Touching it unconditionally would
# let a full/drifted /certs mount pin nginx to a stale cert while the
# HEALTHCHECK stays green — defeating the marker's whole purpose.
# write_tunnel_route runs BEFORE the reload so the gate opens atomically with
# the cert swap: a reload that sees the new cert must also see the open route.
# `nginx -t` preflight BEFORE the reload: `nginx -s reload` exits 0 once SIGHUP
# is delivered to the master — a config the master then REJECTS (corrupt or
# mismatched t.crt/t.key on the operator-managed /certs mount) keeps the old
# workers running while the reload "succeeded". Without the preflight that is
# a self-sustaining wedge: every later 12h cycle "succeeds" (lego no-op,
# signal deliverable), the marker stays fresh, and the failure branch — the
# one that closes the gate on an expired served cert — never runs. A failed
# preflight instead propagates as a cycle failure, engaging exactly that
# branch and leaving the marker untouched so the HEALTHCHECK can see the wedge.
install_cert() {
  install -m 644 "$CERT_DIR/certificates/$DOMAIN.crt" "$CERT_DIR/t.crt" &&
  install -m 600 "$CERT_DIR/certificates/$DOMAIN.key" "$CERT_DIR/t.key" &&
  write_tunnel_route open &&
  nginx -t &&
  nginx -s reload &&
  touch "$RENEW_MARKER"
}

# close_gate_if_cert_expired — the runtime half of the gate invariant. Startup
# closes the t-* route when the cert on disk is missing or expired, but a cert
# can also expire WHILE RUNNING if issuance keeps failing past notAfter;
# without this check nginx would serve the expired cert with the gate open
# until the healthcheck's 7-day marker staleness forced a restart. The renewal
# loop calls this after every failed cycle: an expired (or unreadable/missing)
# served cert closes the gate — refused beats a handshake that must fail — and
# install_cert reopens it on the next successful cycle. Only called after a
# FAILED cycle: a successful one re-copies a cert lego just considered
# current, so t.crt cannot be expired. Returns nonzero when the gate should be
# closed but closing failed (route write or reload); the caller logs and the
# untouched renewal marker leaves the healthcheck as the backstop.
close_gate_if_cert_expired() {
  if openssl x509 -in "$CERT_DIR/t.crt" -noout -checkend 0 2>/dev/null; then
    return 0
  fi
  echo "[entrypoint] served certificate expired — closing the tunnel gate until renewal succeeds" >&2
  # Same preflight as install_cert: a rejected reload would leave the gate
  # open on the expired cert while reporting success.
  write_tunnel_route closed && nginx -t && nginx -s reload
}

# Certificate issuance + ARI-driven renewal.
# lego v5: a single `run` command obtains a certificate when none exists and
# renews it when due. Renewal consults the ARI renewalInfo endpoint by default
# (opt-out is --ari-disable; there is no --ari flag, so a stray --ari fails
# flag parsing — fail-closed before any ACME traffic). The ARI wait duration
# defaults to 0, so lego never sleeps into a future renewal window: when
# nothing is due, `run` exits 0 without ACME traffic and the check-before-
# sleep 12h loop below remains the outer loop.
# timeout 300: a wedged TLS connection or hung DNS lookup to the ACME directory
# must not stall the renewal loop forever — a hang turns into rc=124, the 12h
# loop retries, and the HEALTHCHECK's renewal-marker freshness check turns the
# container unhealthy (→ restart) if cycles keep failing for 7 days.
lego_run() {
  timeout 300 /usr/local/bin/lego run --path "$CERT_DIR" \
      --accept-tos --email "$ACME_EMAIL" \
      --domains "$DOMAIN" \
      --http --http.webroot "$WEBROOT"
}

issue() {
  lego_rc=0
  lego_out=$(lego_run 2>&1) || lego_rc=$?
  printf '%s\n' "$lego_out" >&2
  if [ "$lego_rc" -eq 0 ]; then
    return 0
  fi
  # lego v5 wedges where v4 retried: when the FIRST registration fails, the
  # locally saved account keeps registration=null, and every later `run` then
  # tries to recover that account by key — which fails with accountDoesNotExist
  # because the account was never created server-side (v4 simply re-registered).
  # Break the wedge: this image manages exactly one ACME account, so a 400
  # accountDoesNotExist proves the local account is stale — drop it (key
  # included; it was never bound server-side) and retry once. The retry's exit
  # status IS the function's status: a successful recovery must report success
  # so install_cert runs in the same cycle, not 12h later. Any other failure is
  # surfaced unchanged and the 12h loop retries as before.
  if printf '%s' "$lego_out" | grep -q accountDoesNotExist; then
    echo "[entrypoint] stale ACME account (never registered server-side) — clearing and retrying" >&2
    rm -rf "$CERT_DIR/accounts"
    lego_run && return 0
  fi
  return 1
}

# Unit-test hook: with EDGE_PROXY_LIB_ONLY set, stop here — the helpers above
# are loaded and nothing below (validation, config writes, services) runs.
if [ -n "${EDGE_PROXY_LIB_ONLY:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

# --- startup -----------------------------------------------------------------

: "${DOMAIN:?    set DOMAIN     (t-<customer-id>.<integrator-domain>)}"
: "${ACME_EMAIL:?set ACME_EMAIL (LE registration contact)}"

# DOMAIN is operator-supplied but interpolated into `openssl -subj "/CN=$DOMAIN"`,
# into cert file paths in install_cert(), and names the SNI map key in
# nginx.conf (only the exact DOMAIN routes to the wss terminator — anything
# else silently falls through to the app passthrough). Restrict to the
# hostname charset with the t- prefix: a "/" would path-traverse the install
# target, an "=" would inject subject components. Fail closed before anything
# is written.
case "$DOMAIN" in
  *[!A-Za-z0-9.-]*|*..*|.*|*.|*-)
    echo "[entrypoint] refuse to start: DOMAIN is not a plain hostname ([A-Za-z0-9.-], no leading/trailing/consecutive dots, no trailing hyphen): $DOMAIN" >&2
    exit 1 ;;
esac
case "$DOMAIN" in
  t-*) ;;
  *)
    echo "[entrypoint] refuse to start: DOMAIN must start with t- (the SNI map routes t-* to the wss terminator; anything else falls through to the app passthrough): $DOMAIN" >&2
    exit 1 ;;
esac

# /tmp must be a tmpfs mount (--tmpfs /tmp): frps.toml (0600, token at rest) and
# nginx pid/temp state live there — on a writable overlay they would persist in
# the container layer after stop. With a bare `docker run` (no tmpfs)
# this would silently "work" while degrading the security model, so refuse to
# start: fail closed, not open.
if ! awk '$2 == "/tmp" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts; then
  echo "[entrypoint] refuse to start: /tmp is not a tmpfs mount — run with --tmpfs /tmp (see docker-compose.yml)" >&2
  exit 1
fi

# FRP_TOKEN is a secret — file only. env is exposed via `docker inspect`
# and /proc/*/environ, so refuse to start if the token was passed with -e.
if [ -n "${FRP_TOKEN:-}" ]; then
  echo "[entrypoint] refuse to start: FRP_TOKEN is set in the environment — unset it; pass the token as a file (FRP_TOKEN_FILE, default /run/secrets/frp_token)" >&2
  exit 1
fi
FRP_TOKEN_FILE="${FRP_TOKEN_FILE:-/run/secrets/frp_token}"
if [ ! -f "$FRP_TOKEN_FILE" ]; then
  echo "[entrypoint] refuse to start: token file missing: $FRP_TOKEN_FILE (bind-mount it read-only, root:10001 mode 640)" >&2
  exit 1
fi
if [ ! -r "$FRP_TOKEN_FILE" ]; then
  echo "[entrypoint] refuse to start: token file unreadable by uid $(id -u): $FRP_TOKEN_FILE (host: chgrp 10001 && chmod 640)" >&2
  exit 1
fi
FRP_TOKEN="$(cat "$FRP_TOKEN_FILE")"
if [ -z "$FRP_TOKEN" ]; then
  echo "[entrypoint] refuse to start: token file is empty: $FRP_TOKEN_FILE" >&2
  exit 1
fi
# The token is interpolated into frps.toml as a TOML basic string. A " or \ in
# the token could close the string and inject keys (e.g. bindAddr = "0.0.0.0",
# moving the control port off localhost). Validate the charset instead of
# escaping it: frp tokens are opaque ASCII, anything outside this set is
# refused fail-closed before any config is written.
case "$FRP_TOKEN" in
  *[!A-Za-z0-9._~+/=:@-]*)
    echo "[entrypoint] refuse to start: token in $FRP_TOKEN_FILE has characters outside [A-Za-z0-9._~+/=:@-]" >&2
    exit 1 ;;
esac
# Entropy floor: the token is the only credential on the wss control channel.
# nginx throttles handshakes on :7444 (limit_req zone=tunnel), but a short
# token is still a brute-force target. Note frp's token login is
# md5(token||timestamp) — if a login frame ever leaks (legacy wire protocol /
# known-plaintext), it is an offline oracle on the token, so entropy matters.
# The 32-char floor is a LENGTH floor, NOT an entropy estimate — generate the
# token randomly (Dockerfile header: `openssl rand -base64 32`), never as a
# passphrase. The distinct-character check below only rules out trivial
# repeated-pattern tokens ("aaaaaaaa..."); it is not an entropy estimator.
if [ "${#FRP_TOKEN}" -lt 32 ]; then
  echo "[entrypoint] refuse to start: token in $FRP_TOKEN_FILE is shorter than 32 characters — generate at least 128 bits of entropy" >&2
  exit 1
fi
distinct_chars=$(printf '%s' "$FRP_TOKEN" | fold -w 1 | sort -u | wc -l)
if [ "$distinct_chars" -lt 8 ]; then
  echo "[entrypoint] refuse to start: token in $FRP_TOKEN_FILE has fewer than 8 distinct characters — use a randomly generated token (openssl rand -base64 32)" >&2
  exit 1
fi

# Everything below that touches secrets or key material gets 0600/0700;
# /tmp is tmpfs at run time (--tmpfs /tmp) so none of it reaches a persisted layer.
umask 077

# /tmp/nginx holds nginx.pid; the *_temp paths match nginx.conf. nginx must find
# them writable — same uid (10001) that created them.
mkdir -p "$WEBROOT/.well-known/acme-challenge" \
         /tmp/nginx /tmp/nginx-body /tmp/nginx-proxy \
         /tmp/nginx-fcgi /tmp/nginx-uwsgi /tmp/nginx-scgi
# Seed the renewal-liveness marker (touched again by install_cert on every
# successful cycle) so the HEALTHCHECK's 7-day freshness window starts at boot.
touch "$RENEW_MARKER"

# 1) Placeholder cert + initial tunnel-gate state.
# nginx's config needs cert files at load, so a per-container self-signed
# placeholder is minted when /certs/t.crt is missing or expired. The placeholder
# is NEVER served: the t-* route stays closed (write_tunnel_route closed —
# connection refused at :443) until a CA-signed cert is installed. This removes
# the pre-issuance TOFU decision from the sidecar entirely: before first
# issuance a well-configured sidecar sees a refused connection, not a
# self-signed cert it must decide to trust (see Dockerfile header).
# Regenerate when missing OR expired: /certs is a persistent bind mount, so
# after 7 days of failed issuance an expired cert would otherwise be served
# forever. Replacing an expired cert with a placeholder is client-equivalent —
# both are rejected — and it CLOSES the gate (cert_is_ca_signed fails), which
# is strictly better than serving an expired cert: refused beats a handshake
# that must fail. install_cert reopens the gate on the next successful renewal.
if [ ! -f "$CERT_DIR/t.crt" ] || ! openssl x509 -in "$CERT_DIR/t.crt" -noout -checkend 0 2>/dev/null; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
    -keyout "$CERT_DIR/t.key" -out "$CERT_DIR/t.crt" \
    -subj "/CN=$DOMAIN" 2>/dev/null
fi
# Restart case: a valid CA-signed cert from a previous run is already in place
# — open the gate immediately so the sidecar reconnects without waiting for the
# renewal loop. A fresh placeholder keeps it closed.
if cert_is_ca_signed "$CERT_DIR/t.crt"; then
  write_tunnel_route open
else
  write_tunnel_route closed
fi

# 2) frps config — control port localhost-only; wss terminated by nginx at :7444.
# allowPorts fail-closed: the token is a per-customer shared secret, so
# without this any token holder could claim ANY remote port on 127.0.0.1 —
# including 7443 (the :443 app passthrough) and 8080 (the ACME relay) whenever
# the legit sidecar is not bound — and hijack or blackhole edge traffic.
# Restricted to exactly the ports the sidecar owns (the two nginx proxies in
# nginx.conf); extend deliberately, never open up.
# proxyBindAddr is pinned explicitly (it merely defaults to bindAddr upstream):
# the two remote-port listeners must never silently move off loopback if
# bindAddr is edited or the upstream default ever changes — on 0.0.0.0 they
# would sit on the docker bridge, bypassing nginx's SNI map and rate limits.
# detailedErrorsToClient=false: frps defaults to true and leaks internal error
# strings to UNAUTHENTICATED wss callers (token-mismatch reasons, port policy,
# "client_id already online"). Generic errors only.
# umask 077 ⇒ mode 0600 owned by the runtime uid; on tmpfs, gone at `docker rm`.
cat > /tmp/frps.toml <<EOF
bindAddr = "127.0.0.1"
bindPort = 7000
proxyBindAddr = "127.0.0.1"
allowPorts = [
  { single = 7443 },
  { single = 8080 }
]
auth.method = "token"
auth.token = "$FRP_TOKEN"
detailedErrorsToClient = false
EOF
unset FRP_TOKEN   # token now lives only in frps.toml (0600) and frps' memory

# 3) Start services.
/usr/local/bin/frps -c /tmp/frps.toml &
FRPS_PID=$!
nginx -g 'daemon off;' &
NGINX_PID=$!

trap 'kill "$FRPS_PID" "$NGINX_PID" 2>/dev/null || true' TERM INT

# 4) Certificate issuance + ARI-driven renewal loop — via the
# install_cert/lego_run/issue helpers defined at the top of this file.

# lego v4 -> v5 storage migration (one-time; see Dockerfile header). v5 changed
# the storage layout and the JSON schemas: `lego migrate` rewrites account and
# certificate files in place and skips files already migrated (origin marker).
# Trigger on precise v4 markers, NOT mere directory existence: a v5 account
# file saved by a FAILED first registration carries no origin marker, and
# migrating it would error (it looks for a v4-only keys/ subdir) — so detect
# the v4 layout itself:
#   - accounts/<server>/<account>/keys/   v4 stores the account key there; v5
#     puts it next to account.json and removes the directory.
#   - certificates/<domain>.json without an "origin" field — the v4 resource
#     schema; every v5 resource records origin. The probe matches the quoted
#     JSON key ("origin":) — a bare grep for origin would false-positive on a
#     domain whose NAME merely contains the word, silently skipping a needed
#     migration (fail-closed outage). (A v5 account saved before a
#     failed registration self-heals: `lego run` re-registers and stamps
#     origin itself — no migration needed, no crash loop.)
# The migrate prompt reads stdin: an empty line answers yes, EOF would abort —
# hence the piped newline. It runs with CWD=/tmp so the optional suggested-
# config file it writes lands on tmpfs, never on the read-only rootfs. On
# failure, refuse to start: fail closed, not open.
v4_keys=$(find "$CERT_DIR/accounts" -type d -name keys 2>/dev/null | head -n 1)
v4_cert=""
for f in "$CERT_DIR"/certificates/*.json; do
  [ -f "$f" ] || continue
  if ! grep -q '"origin":' "$f" 2>/dev/null; then
    v4_cert="$f"
    break
  fi
done
if [ -n "$v4_keys" ] || [ -n "$v4_cert" ]; then
  echo "[entrypoint] lego v4 storage detected — migrating to v5 layout ..."
  ( cd /tmp && printf '\n' | timeout 300 /usr/local/bin/lego migrate --path "$CERT_DIR" ) \
    || { echo "[entrypoint] lego storage migration failed — refusing to continue" >&2; exit 1; }
fi

if [ ! -f "$CERT_DIR/certificates/$DOMAIN.crt" ]; then
  echo "[entrypoint] first issuance for $DOMAIN ..."
  # Bounded short-backoff retries: a transient failure (rate limit, DNS not
  # propagated yet) must not leave the edge idle on the 7-day placeholder
  # cert for the full 12h cycle. After 5 attempts (~15 min total) the renewal
  # loop below takes over at its 12h cadence.
  delay=60
  attempt=1
  while [ "$attempt" -le 5 ]; do
    if issue && install_cert; then
      echo "[entrypoint] certificate installed"
      break
    fi
    if [ "$attempt" -lt 5 ]; then
      echo "[entrypoint] first issuance failed; retrying in ${delay}s" >&2
      sleep "$delay"
      delay=$((delay * 2))
    fi
    attempt=$((attempt + 1))
  done
fi

# Renewal loop: check FIRST, sleep after. A restart with an expired
# certificate must re-issue immediately instead of serving the stale cert
# for up to 12h (client rejections + MITM window). At steady state lego
# exits 0 without ACME traffic (ARI: nothing due), so the cost is one no-op
# poll + reload per 12h. A failed cycle also closes the gate if the served
# cert has expired (see close_gate_if_cert_expired) — an expired cert is
# never served longer than one cycle.
while true; do
  if issue && install_cert; then
    echo "[entrypoint] certificate in place (renewed if it was due)"
  else
    echo "[entrypoint] renewal attempt failed; retrying next cycle" >&2
    close_gate_if_cert_expired \
      || echo "[entrypoint] gate close failed; healthcheck restart is the backstop" >&2
  fi
  sleep 43200   # 12h; ARI decides the actual renewal window
done &

RENEW_PID=$!
trap 'kill "$FRPS_PID" "$NGINX_PID" "$RENEW_PID" 2>/dev/null || true' TERM INT

# If frps or nginx dies, the container must restart (restart policy on host).
# POSIX sh has no `wait -n`; poll both pids so either one exiting ends the wait.
while kill -0 "$FRPS_PID" 2>/dev/null && kill -0 "$NGINX_PID" 2>/dev/null; do
  sleep 1
done
echo "[entrypoint] a core service exited — terminating" >&2
exit 1
