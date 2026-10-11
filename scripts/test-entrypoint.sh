#!/bin/sh
# Unit tests for entrypoint.sh's lifecycle helpers (install_cert, issue).
# scripts/smoke-test.sh cannot reach these paths: it blackholes the ACME
# directory hosts, so install_cert never runs and issue()'s stale-account
# retry never triggers. These tests source the entrypoint with
# EDGE_PROXY_LIB_ONLY=1 (helpers load, startup does not run) and drive the
# helpers directly with stubbed external commands.
#
#   scripts/test-entrypoint.sh [path/to/entrypoint.sh]
#
# Regression targets:
#   - install_cert must report failure and must NOT touch the renewal-liveness
#     marker when the cert copy, the `nginx -t` preflight, or the nginx reload
#     fails (the marker is what the Dockerfile HEALTHCHECK trusts to decide
#     "renewal is alive"; a reload's exit code only proves SIGHUP delivery —
#     without the preflight a rejected config wedges renewal invisibly).
#   - install_cert must open the t-* tunnel gate (write_tunnel_route) only
#     together with a successful cert install + reload: a failed cycle must
#     leave the route as it was (closed on a fresh container), or the
#     placeholder could reach a TLS client.
#   - cert_is_ca_signed must distinguish the self-signed placeholder (gate
#     closed) from a CA-signed cert (gate open) — it is the only thing
#     standing between the placeholder and the sidecar's TOFU decision.
#   - close_gate_if_cert_expired must close the t-* gate when the served cert
#     expires mid-run (issuance failing past notAfter) — an expired cert must
#     not be served with the gate open until the healthcheck restart.
#   - issue() must return 0 when the accountDoesNotExist wedge-break retry
#     succeeds (so install_cert runs in the same cycle, not 12h later).
set -eu

ENTRYPOINT=${1:-entrypoint.sh}
case "$ENTRYPOINT" in
  /*) ;;
  *) ENTRYPOINT=$PWD/$ENTRYPOINT ;;   # `.` resolves bare names via PATH — make it absolute
esac

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Fixtures for cert_is_ca_signed: a self-signed placeholder (issuer == subject,
# exactly what entrypoint.sh mints) and a CA-signed leaf (issuer != subject).
# openssl is already a runtime dependency of the entrypoint, so this adds no
# new tooling requirement.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$TMP/self.key" -out "$TMP/self.crt" -subj "/CN=t-ci.example" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$TMP/ca.key" -out "$TMP/ca.crt" -subj "/CN=test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" -subj "/CN=t-ci.example" 2>/dev/null
openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" \
  -CAcreateserial -days 2 -out "$TMP/leaf.crt" 2>/dev/null
printf 'not a certificate\n' > "$TMP/garbage"

# --- stubs for the external commands install_cert/issue invoke ----------------
# install -m MODE SRC DST — a controllable stand-in for coreutils/busybox install
INSTALL_FAIL=${INSTALL_FAIL:-0}
install() {
  [ "$INSTALL_FAIL" -eq 0 ] || return 1
  [ "$1" = "-m" ] || fail "install stub: unexpected args: $*"
  cp "$3" "$4" && chmod "$2" "$4"
}

# nginx — `-t` (config preflight) and `-s reload` are used by the helpers;
# NGINX_T_FAIL fails only the preflight, NGINX_FAIL fails both.
NGINX_FAIL=${NGINX_FAIL:-0}
NGINX_T_FAIL=${NGINX_T_FAIL:-0}
nginx() {
  if [ "$1" = "-t" ] && [ "$NGINX_T_FAIL" -ne 0 ]; then
    return 1
  fi
  [ "$NGINX_FAIL" -eq 0 ] || return 1
  return 0
}

# lego_run — replaced below with a mode-driven stub after sourcing
lego_run() { fail "lego_run stub not installed"; }

# --- load helpers from the entrypoint, without starting anything -------------
EDGE_PROXY_LIB_ONLY=1
. "$ENTRYPOINT"

# Redirect all state the helpers touch into the sandbox.
CERT_DIR=$TMP/certs
WEBROOT=$TMP/webroot
RENEW_MARKER=$TMP/renewed
ROUTE_FILE=$TMP/nginx/tunnel-route.conf
DOMAIN=t-ci.example
ACME_EMAIL=ci@example.com
mkdir -p "$CERT_DIR/certificates"

# Mode-driven lego_run stub. The wedge path in issue() removes
# $CERT_DIR/accounts before retrying, so keying on that directory gives the
# first-call-fails / second-call-succeeds sequence without a call counter
# (issue() captures the first call in a subshell).
#   ok         — always succeeds
#   fail       — always fails with a non-wedge error
#   wedge-ok   — accountDoesNotExist while accounts/ exists, then succeeds
#   wedge-fail — accountDoesNotExist while accounts/ exists, then keeps failing
lego_run() {
  case "${LEGO_MODE:-ok}" in
    ok) return 0 ;;
    fail) printf '%s\n' 'acme: some transient error'; return 1 ;;
    wedge-ok)
      if [ -d "$CERT_DIR/accounts" ]; then
        printf '%s\n' 'acme: accountDoesNotExist'
        return 1
      fi
      return 0 ;;
    wedge-fail)
      if [ -d "$CERT_DIR/accounts" ]; then
        printf '%s\n' 'acme: accountDoesNotExist'
        return 1
      fi
      printf '%s\n' 'acme: still failing'
      return 1 ;;
    *) fail "unknown LEGO_MODE: $LEGO_MODE" ;;
  esac
}

echo "$DOMAIN-real" > "$CERT_DIR/certificates/$DOMAIN.crt"
echo "$DOMAIN-real" > "$CERT_DIR/certificates/$DOMAIN.key"

# --- install_cert: success ---------------------------------------------------
rm -f "$RENEW_MARKER" "$CERT_DIR/t.crt" "$CERT_DIR/t.key"
write_tunnel_route closed || fail "could not seed closed route"
INSTALL_FAIL=0 NGINX_FAIL=0
install_cert || fail "install_cert failed on the happy path"
[ "$(cat "$CERT_DIR/t.crt")" = "$DOMAIN-real" ] || fail "t.crt not installed"
[ "$(stat -c '%a' "$CERT_DIR/t.key")" = "600" ] || fail "t.key mode is not 600"
[ -f "$RENEW_MARKER" ] || fail "renewal marker missing after successful install_cert"
grep -q '127.0.0.1:7444' "$ROUTE_FILE" || fail "tunnel gate not opened by successful install_cert"
pass "install_cert: success installs cert/key, opens the gate, touches the marker"

# --- install_cert: failed copy must not touch the marker or open the gate (F3) -
rm -f "$RENEW_MARKER" "$CERT_DIR/t.crt" "$CERT_DIR/t.key"
write_tunnel_route closed || fail "could not seed closed route"
INSTALL_FAIL=1
if install_cert; then
  fail "install_cert reported success despite a failed cert copy"
fi
[ ! -f "$RENEW_MARKER" ] || fail "renewal marker touched despite a failed cert copy — the HEALTHCHECK would report renewal alive"
grep -q '127.0.0.1:1' "$ROUTE_FILE" || fail "tunnel gate opened despite a failed cert copy — placeholder state would be routable"
pass "install_cert: failed copy reports failure, leaves marker and gate untouched"
INSTALL_FAIL=0

# --- install_cert: failed reload must not touch the marker (F3) ---------------
# The route file is written before the reload (the reload must see both the new
# cert and the open route in one config load), so a failed reload leaves the
# FILE open — but nginx never reloaded, so the running config is unchanged and
# the gate stays closed in practice. The invariant that matters is the marker.
rm -f "$RENEW_MARKER" "$CERT_DIR/t.crt" "$CERT_DIR/t.key"
INSTALL_FAIL=0 NGINX_FAIL=1
if install_cert; then
  fail "install_cert reported success despite a failed nginx reload"
fi
[ ! -f "$RENEW_MARKER" ] || fail "renewal marker touched despite a failed reload — the HEALTHCHECK would report renewal alive"
pass "install_cert: failed reload reports failure and leaves the marker untouched"
NGINX_FAIL=0

# --- install_cert: failed config preflight must not reload or touch the marker
# `nginx -s reload` exit 0 only proves SIGHUP delivery — a config the master
# rejects keeps the old cert served. The `nginx -t` preflight turns that into
# a cycle failure: marker untouched, failure branch (gate close) reachable.
rm -f "$RENEW_MARKER" "$CERT_DIR/t.crt" "$CERT_DIR/t.key"
write_tunnel_route closed || fail "could not seed closed route"
INSTALL_FAIL=0 NGINX_T_FAIL=1
if install_cert; then
  fail "install_cert reported success despite a failed nginx -t preflight"
fi
[ ! -f "$RENEW_MARKER" ] || fail "renewal marker touched despite a failed preflight — a rejected config would wedge renewal while the HEALTHCHECK stays green"
pass "install_cert: failed nginx -t preflight reports failure and leaves the marker untouched"
NGINX_T_FAIL=0

# --- cert_is_ca_signed: the gate's only criterion -----------------------------
# Self-signed placeholder (issuer == subject): gate must stay closed.
if cert_is_ca_signed "$TMP/self.crt"; then
  fail "cert_is_ca_signed accepted a self-signed cert — the placeholder would be routable"
fi
pass "cert_is_ca_signed: rejects the self-signed placeholder"

# CA-signed leaf (issuer != subject): gate may open.
cert_is_ca_signed "$TMP/leaf.crt" || fail "cert_is_ca_signed rejected a CA-signed cert"
pass "cert_is_ca_signed: accepts a CA-signed cert"

# Garbage / missing input: fail closed.
if cert_is_ca_signed "$TMP/does-not-exist.crt"; then
  fail "cert_is_ca_signed accepted a missing cert file"
fi
if cert_is_ca_signed "$TMP/garbage"; then
  fail "cert_is_ca_signed accepted non-certificate input"
fi
pass "cert_is_ca_signed: fails closed on missing/garbage input"

# --- write_tunnel_route: state encoding ---------------------------------------
# The key must be the exact DOMAIN (anchored, case-insensitive, dots escaped)
# — never a t-* prefix, which would hijack customer app hostnames starting
# with t- to the wss terminator.
write_tunnel_route closed
grep -qF '~*^t-ci\.example$  127.0.0.1:1;' "$ROUTE_FILE" \
  || fail "closed route does not pin DOMAIN to the dead port: $(cat "$ROUTE_FILE")"
write_tunnel_route open
grep -qF '~*^t-ci\.example$  127.0.0.1:7444;' "$ROUTE_FILE" \
  || fail "open route does not pin DOMAIN to the wss terminator: $(cat "$ROUTE_FILE")"
grep -q 't-\.\*' "$ROUTE_FILE" \
  && fail "route uses a t-* prefix match — app hostnames starting with t- would be hijacked"
if write_tunnel_route bogus; then
  fail "write_tunnel_route accepted an unknown state"
fi
pass "write_tunnel_route: encodes open/closed on the exact DOMAIN, refuses unknown states"

# --- close_gate_if_cert_expired: the gate tracks cert validity at runtime ----
# openssl is stubbed to control the checkend verdict (minting a truly expired
# cert needs faketime or a CA with backdating); the missing-file case below
# exercises real openssl. Regression target: a cert that expires WHILE RUNNING
# (issuance failing past notAfter) must close the gate in the renewal loop,
# not be served until the healthcheck restart.
openssl() {
  [ "${OPENSSL_CHECKEND_FAIL:-0}" -eq 0 ] || return 1
  return 0
}

# Valid served cert: no-op — the route file must be left exactly as it was.
write_tunnel_route open || fail "could not seed open route"
OPENSSL_CHECKEND_FAIL=0
close_gate_if_cert_expired || fail "close_gate_if_cert_expired failed on a valid cert"
grep -q '127.0.0.1:7444' "$ROUTE_FILE" || fail "gate touched despite a valid served cert"
pass "close_gate_if_cert_expired: valid cert leaves the gate as it is"

# Expired served cert: gate closes (route rewritten + reload).
OPENSSL_CHECKEND_FAIL=1 NGINX_FAIL=0
close_gate_if_cert_expired || fail "close_gate_if_cert_expired failed to close the gate on an expired cert"
grep -q '127.0.0.1:1' "$ROUTE_FILE" || fail "gate left open for an expired served cert"
pass "close_gate_if_cert_expired: expired cert closes the gate"

# Expired cert but the reload fails: must report failure so the caller warns
# and the (untouched) renewal marker leaves the healthcheck as the backstop.
NGINX_FAIL=1
if close_gate_if_cert_expired; then
  fail "close_gate_if_cert_expired reported success despite a failed reload"
fi
pass "close_gate_if_cert_expired: failed reload reports failure"
NGINX_FAIL=0 OPENSSL_CHECKEND_FAIL=0
unset -f openssl

# Missing served cert (real openssl): fail closed — gate closes.
rm -f "$CERT_DIR/t.crt"
write_tunnel_route open || fail "could not seed open route"
close_gate_if_cert_expired || fail "close_gate_if_cert_expired failed on a missing served cert"
grep -q '127.0.0.1:1' "$ROUTE_FILE" || fail "gate left open with no served cert at all"
pass "close_gate_if_cert_expired: missing cert fails closed"

# --- issue: plain success ----------------------------------------------------
rm -rf "$CERT_DIR/accounts"; mkdir -p "$CERT_DIR/accounts"
LEGO_MODE=ok
issue || fail "issue failed on plain success"
[ -d "$CERT_DIR/accounts" ] || fail "issue removed the ACME account on plain success"
pass "issue: success returns 0 and keeps the account"

# --- issue: non-wedge failure keeps the account ------------------------------
rm -rf "$CERT_DIR/accounts"; mkdir -p "$CERT_DIR/accounts"
LEGO_MODE=fail
if issue; then
  fail "issue reported success on a lego failure"
fi
[ -d "$CERT_DIR/accounts" ] || fail "issue removed the ACME account on a non-wedge failure"
pass "issue: non-wedge failure returns 1 and keeps the account"

# --- issue: wedge-break retry success must report success (F4) ---------------
rm -rf "$CERT_DIR/accounts"; mkdir -p "$CERT_DIR/accounts"
LEGO_MODE=wedge-ok
issue || fail "issue returned failure after a SUCCESSFUL wedge-break retry — install_cert would be skipped for 12h"
[ ! -d "$CERT_DIR/accounts" ] || fail "stale account not cleared before the retry"
pass "issue: successful wedge-break retry returns 0 and clears the stale account"

# --- issue: wedge-break retry failure reports failure ------------------------
rm -rf "$CERT_DIR/accounts"; mkdir -p "$CERT_DIR/accounts"
LEGO_MODE=wedge-fail
if issue; then
  fail "issue reported success after a FAILED wedge-break retry"
fi
[ ! -d "$CERT_DIR/accounts" ] || fail "stale account not cleared before the retry"
pass "issue: failed wedge-break retry returns 1 and clears the stale account"

echo "test-entrypoint: all checks passed ($ENTRYPOINT)"
