#!/bin/sh
# Smoke test for a freshly built edge-proxy image. Run after every build so a
# version/pin bump that silently breaks the artifact fails the pipeline instead
# of reaching production.
#
#   scripts/smoke-test.sh <image-ref> [path/to/Dockerfile]
#
# Groups of checks:
#   contract   — the built artifact itself: uid/gid 10001, no curl/bash, no
#                baked-in bootstrap key, frps/lego match the pinned ARG versions
#   failclosed — entrypoint refuses unsafe invocations (no /tmp tmpfs,
#                FRP_TOKEN passed via environment, DOMAIN outside the
#                hostname charset / t-* prefix)
#   runtime    — full start with the compose-documented flags: container turns
#                healthy, :80 serves ONLY the ACME webroot, token at rest is
#                0600 on tmpfs, and the t-* gate behaves in both states:
#                  closed  — cold start, no CA-signed cert: t-* is refused at
#                            :443 before any TLS handshake (the per-container
#                            placeholder must never reach a client)
#                  open    — CA-signed cert in place (simulating install_cert):
#                            t-* routes to the wss terminator and a VERIFYING
#                            client (--cacert, hostname-checked) completes the
#                            wss upgrade to frps — the sidecar's view, enacted
#
# No outbound ACME traffic: the Let's Encrypt directory hosts are blackholed to
# a dead loopback address via --add-host, so the first-issuance attempt fails
# fast and the container runs on its per-container placeholder cert — the same
# state entrypoint.sh guarantees on any host before first issuance.
set -eu

IMAGE=${1:?usage: smoke-test.sh <image-ref> [Dockerfile]}
DOCKERFILE=${2:-Dockerfile}
DOMAIN=t-ci.example

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

CID=""
TMP=""
cleanup() {
  [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1 || true
  [ -z "$TMP" ] && return 0
  if ! rm -rf "$TMP" 2>/dev/null; then
    # Mount dirs end up owned by uid 10001 — remove them via a throwaway
    # container as root, then the host-side rmdir succeeds.
    docker run --rm --user 0 --entrypoint rm -v "$TMP:/m" "$IMAGE" \
      -rf /m/webroot /m/certs /m/frp_token >/dev/null 2>&1 || true
    rm -rf "$TMP" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# --- contract: the artifact itself -------------------------------------------

ids=$(docker run --rm --entrypoint sh "$IMAGE" -c 'echo "$(id -u):$(id -g)"')
[ "$ids" = "10001:10001" ] || fail "expected uid:gid 10001:10001, got $ids"
pass "runs as uid:gid 10001:10001"

docker run --rm --entrypoint sh "$IMAGE" \
  -c '! command -v curl >/dev/null && ! command -v bash >/dev/null' \
  || fail "curl or bash present in the runtime image"
pass "no curl/bash in the runtime image"

# A bootstrap key baked into the image would let anyone who pulls it MITM the
# control channel before first issuance (Dockerfile header) — it must only ever
# be generated per container at run time.
docker run --rm --entrypoint sh "$IMAGE" \
  -c 'test ! -e /certs/t.crt && test ! -e /certs/t.key' \
  || fail "bootstrap key/cert baked into the image (/certs/t.*)"
pass "no bootstrap key material in the image"

# Expected versions come from the Dockerfile ARGs — single source of truth, so
# a version bump needs no test edit and a binary/version mismatch still fails.
want_frps=$(sed -n 's/^ARG FRPS_VERSION=\([0-9.]*\).*/\1/p' "$DOCKERFILE")
want_lego=$(sed -n 's/^ARG LEGO_VERSION=\([0-9.]*\).*/\1/p' "$DOCKERFILE")
[ -n "$want_frps" ] && [ -n "$want_lego" ] || fail "could not parse version ARGs from $DOCKERFILE"
docker run --rm --entrypoint /usr/local/bin/frps "$IMAGE" --version \
  | grep -qF "$want_frps" || fail "frps is not the pinned $want_frps"
docker run --rm --entrypoint /usr/local/bin/lego "$IMAGE" --version \
  | grep -qF "$want_lego" || fail "lego is not the pinned $want_lego"
pass "frps=$want_frps and lego=$want_lego match the Dockerfile pins"

# --- fail-closed: entrypoint refuses unsafe invocations ----------------------

# No --tmpfs /tmp: token at rest would persist in the overlay layer.
if out=$(docker run --rm -e DOMAIN="$DOMAIN" -e ACME_EMAIL=ci@example.com "$IMAGE" 2>&1); then
  fail "container started without --tmpfs /tmp"
fi
echo "$out" | grep -q "not a tmpfs" || fail "refusal for missing tmpfs not logged; got: $out"
pass "refuses to start without --tmpfs /tmp"

# FRP_TOKEN in the environment: exposed via docker inspect and /proc/*/environ.
if out=$(docker run --rm --tmpfs /tmp -e DOMAIN="$DOMAIN" -e ACME_EMAIL=ci@example.com \
      -e FRP_TOKEN=should-be-refused "$IMAGE" 2>&1); then
  fail "container started with FRP_TOKEN in the environment"
fi
echo "$out" | grep -q "FRP_TOKEN is set" || fail "refusal for env token not logged; got: $out"
pass "refuses FRP_TOKEN via environment"

# Short token: the wss control channel is a brute-force oracle for anything
# guessable, so the entrypoint enforces a 32-char floor.
SHORTTOK=$(mktemp)
printf 'short-token' > "$SHORTTOK"
chmod 644 "$SHORTTOK"   # readable by the container uid 10001
if out=$(docker run --rm --tmpfs /tmp -e DOMAIN="$DOMAIN" -e ACME_EMAIL=ci@example.com \
      -v "$SHORTTOK:/run/secrets/frp_token:ro" "$IMAGE" 2>&1); then
  rm -f "$SHORTTOK"
  fail "container started with a token shorter than 32 characters"
fi
rm -f "$SHORTTOK"
echo "$out" | grep -q "shorter than 32" || fail "refusal for short token not logged; got: $out"
pass "refuses a token shorter than 32 characters"

# Low-entropy token: length alone is not entropy — a repeated-pattern 32-char
# token passes the length floor but is trivially guessable; the entrypoint
# requires at least 8 distinct characters.
LOWTOK=$(mktemp)
printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > "$LOWTOK"
chmod 644 "$LOWTOK"   # readable by the container uid 10001
if out=$(docker run --rm --tmpfs /tmp -e DOMAIN="$DOMAIN" -e ACME_EMAIL=ci@example.com \
      -v "$LOWTOK:/run/secrets/frp_token:ro" "$IMAGE" 2>&1); then
  rm -f "$LOWTOK"
  fail "container started with a repeated-pattern token"
fi
rm -f "$LOWTOK"
echo "$out" | grep -q "fewer than 8 distinct" || fail "refusal for low-entropy token not logged; got: $out"
pass "refuses a repeated-pattern (low-entropy) token"

# DOMAIN outside the hostname charset / t-* prefix: a "/" in it path-traverses
# the install_cert target, "=" injects openssl -subj components, and a non-t-*
# DOMAIN silently falls through the SNI map to the app passthrough.
if out=$(docker run --rm --tmpfs /tmp -e DOMAIN='../evil' -e ACME_EMAIL=ci@example.com "$IMAGE" 2>&1); then
  fail "container started with a path-traversal DOMAIN"
fi
echo "$out" | grep -q "DOMAIN is not a plain hostname" || fail "refusal for bad DOMAIN not logged; got: $out"
pass "refuses a DOMAIN outside the hostname charset"

# --- runtime: full start with the documented flags ---------------------------

TMP=$(mktemp -d)
mkdir -p "$TMP/webroot/.well-known/acme-challenge" "$TMP/certs"
printf 'ci-smoke-token-0123456789abcdef0123456789' > "$TMP/frp_token"
printf 'challenge-ok' > "$TMP/webroot/.well-known/acme-challenge/ci-token"
chmod 400 "$TMP/frp_token"
chmod 700 "$TMP/certs"
# Host-side chown would need sudo; chown through the image itself instead —
# uid 0 entrypoint override, same result on runners and dev machines.
docker run --rm --user 0 --entrypoint chown -v "$TMP:/m" "$IMAGE" \
  -R 10001:10001 /m/webroot /m/certs /m/frp_token

CID=$(docker run -d \
  --read-only --tmpfs /tmp:noexec,nosuid \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  -e DOMAIN="$DOMAIN" -e ACME_EMAIL=ci@example.com \
  --add-host acme-v02.api.letsencrypt.org:127.0.0.2 \
  --add-host acme-staging-v02.api.letsencrypt.org:127.0.0.2 \
  -p 127.0.0.1::80 -p 127.0.0.1::443 \
  -v "$TMP/webroot:/var/www/acme" \
  -v "$TMP/certs:/certs" \
  -v "$TMP/frp_token:/run/secrets/frp_token:ro" \
  "$IMAGE")

# First healthcheck runs at interval=30s; 90s covers slow CI runners.
i=0; status=""
while [ "$i" -lt 90 ]; do
  status=$(docker inspect -f '{{.State.Health.Status}}' "$CID")
  [ "$status" = "healthy" ] && break
  [ "$status" = "unhealthy" ] && { docker logs "$CID" >&2; fail "container reported unhealthy"; }
  sleep 3; i=$((i + 3))
done
[ "$status" = "healthy" ] || { docker logs "$CID" >&2; fail "container not healthy within 90s"; }
pass "container healthy (nginx + frps alive)"

mode=$(docker exec "$CID" stat -c '%a' /tmp/frps.toml)
[ "$mode" = "600" ] || fail "frps.toml (token at rest) mode is $mode, expected 600"
pass "token at rest is mode 0600 on tmpfs"

docker exec "$CID" grep -q allowPorts /tmp/frps.toml \
  || fail "frps.toml lost its allowPorts remote-port restriction"
pass "frps remote ports restricted (allowPorts present)"

docker exec "$CID" grep -q 'proxyBindAddr = "127.0.0.1"' /tmp/frps.toml \
  || fail "frps.toml lost its explicit proxyBindAddr=127.0.0.1 (remote ports would bind 0.0.0.0)"
pass "frps remote-port listeners pinned to loopback (proxyBindAddr)"

docker exec "$CID" grep -q 'detailedErrorsToClient = false' /tmp/frps.toml \
  || fail "frps.toml lost detailedErrorsToClient=false (error detail leaks to unauthenticated callers)"
pass "frps error detail disabled (detailedErrorsToClient=false)"

# The renewal-liveness marker must exist from boot — the HEALTHCHECK fails on
# it going stale, so a missing file would mean perpetual unhealthy.
docker exec "$CID" test -f /tmp/nginx/renewed \
  || fail "renewal-liveness marker /tmp/nginx/renewed missing"
pass "renewal-liveness marker present"

P80=$(docker port "$CID" 80/tcp | sed 's/.*://')
P443=$(docker port "$CID" 443/tcp | sed 's/.*://')

body=$(curl -sf "http://127.0.0.1:$P80/.well-known/acme-challenge/ci-token") \
  || fail "ACME webroot did not serve the challenge file"
[ "$body" = "challenge-ok" ] || fail "challenge body mismatch: $body"
pass ":80 serves the ACME webroot"

code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P80/")
[ "$code" = "404" ] || fail ":80 served / with $code, expected 404 (ACME-only port)"
pass ":80 refuses everything outside the ACME path"

# --- gate CLOSED: cold start, no CA-signed cert -------------------------------
# The t-* route must be refused at the TCP layer: a TLS client must never see
# the self-signed placeholder (that would force the sidecar into a TOFU
# decision). "no peer certificate" on an aborted handshake is the signal —
# same probe shape as the non-t-* check below.
if echo | timeout 5 openssl s_client -connect "127.0.0.1:$P443" -servername "$DOMAIN" 2>/dev/null \
     | grep -q 'BEGIN CERTIFICATE'; then
  fail "t-* SNI received a TLS handshake before issuance — placeholder would reach the sidecar"
fi
pass ":443 t-* SNI refused while no CA-signed cert is installed (gate closed)"

# Any other SNI → frps remotePort (:7443), where nothing listens until a client
# tunnel registers one: the stream must be refused, never answered with TLS.
if echo | timeout 5 openssl s_client -connect "127.0.0.1:$P443" -servername other.example 2>/dev/null \
     | grep -q 'BEGIN CERTIFICATE'; then
  fail "non-t-* SNI received a TLS handshake — SNI map is leaking the control channel"
fi
pass ":443 non-t-* SNI is refused"

# --- gate OPEN: CA-signed cert installed --------------------------------------
# Simulate install_cert's output: a CA-signed pair at /certs/t.{crt,key}. The
# entrypoint must detect issuer != subject at restart and route t-* to the wss
# terminator. The wss probe verifies with --cacert (host name checked) — the
# exact check a correctly configured sidecar performs, so a regression that
# re-introduces the placeholder fails here rather than in production.
echo "building test CA + leaf for $DOMAIN"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$TMP/ca.key" -out "$TMP/ca.crt" -subj "/CN=edge-proxy smoke CA" 2>/dev/null
printf 'subjectAltName=DNS:%s\n' "$DOMAIN" > "$TMP/leaf.ext"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" \
  -subj "/CN=$DOMAIN" 2>/dev/null
openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" \
  -CAcreateserial -days 2 -extfile "$TMP/leaf.ext" -out "$TMP/leaf.crt" 2>/dev/null
# $TMP/certs is mode 700 owned by uid 10001 — write through the image as root,
# same trick as the chown above, then hand ownership back to the runtime uid so
# nginx (10001) can read t.key at config load.
docker run --rm --user 0 --entrypoint sh -v "$TMP:/m" "$IMAGE" -c \
  'install -m 644 /m/leaf.crt /m/certs/t.crt && install -m 600 /m/leaf.key /m/certs/t.key && chown 10001:10001 /m/certs/t.crt /m/certs/t.key'
docker restart "$CID" >/dev/null

# Restart re-runs the entrypoint: it must reopen the gate on the CA-signed
# pair without waiting for lego (whose directory is blackholed).
i=0; status=""
while [ "$i" -lt 90 ]; do
  status=$(docker inspect -f '{{.State.Health.Status}}' "$CID")
  [ "$status" = "healthy" ] && break
  [ "$status" = "unhealthy" ] && { docker logs "$CID" >&2; fail "container unhealthy after cert install"; }
  sleep 3; i=$((i + 3))
done
[ "$status" = "healthy" ] || { docker logs "$CID" >&2; fail "container not healthy within 90s after cert install"; }

# docker restart re-randomizes published host ports (-p 127.0.0.1::443) —
# re-read them, the pre-restart values are stale.
P80=$(docker port "$CID" 80/tcp | sed 's/.*://')
P443=$(docker port "$CID" 443/tcp | sed 's/.*://')

subj=$(echo | openssl s_client -connect "127.0.0.1:$P443" -servername "$DOMAIN" 2>/dev/null \
       | openssl x509 -noout -subject) \
  || fail "TLS handshake with t-* SNI failed after cert install"
echo "$subj" | grep -q "CN.*=.*$DOMAIN" \
  || fail "served cert subject mismatch: $subj"
pass ":443 t-* SNI routes to the wss terminator (serves the installed cert)"

# A t-* SNI that is NOT the DOMAIN must fall through to the app passthrough
# (frps remotePort 7443 — unbound here, no sidecar), never to the terminator:
# a t-* prefix match would hijack customer app hostnames starting with t- and
# answer them with the DOMAIN cert. Same probe shape as above: any TLS
# handshake means the name reached the terminator.
if echo | timeout 5 openssl s_client -connect "127.0.0.1:$P443" -servername "t-app.other.example" 2>/dev/null \
     | grep -q 'BEGIN CERTIFICATE'; then
  fail "non-DOMAIN t-* SNI reached the wss terminator — prefix match hijacks t-* app hostnames"
fi
pass "non-DOMAIN t-* SNI falls through to the app passthrough (no hijack)"

# wss control channel end-to-end, as a verifying client: a websocket Upgrade on
# frp's ws path (/~!frp — frps auto-multiplexes ws and raw frp on bindPort by
# sniffing this prefix) must be answered 101 by frps through the nginx
# terminator. Proves the whole chain the handshake check above cannot: SNI
# map → gate open → :7444 TLS termination → ws reverse proxy → frps control
# listener. frp's ws handler is x/net/websocket.Handler, whose default
# handshake REFUSES a missing Origin header with 403 (real frpc clients send
# one), so the probe must carry a parseable Origin. curl exits nonzero once
# the upgraded connection stalls, hence || true; the 101 is already captured.
# --cacert + hostname match = the sidecar trust contract, enacted (no -k).
wscode=$(curl -s --max-time 10 --http1.1 -o /dev/null -w '%{http_code}' \
  --cacert "$TMP/ca.crt" \
  --resolve "$DOMAIN:$P443:127.0.0.1" \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Origin: http://localhost/' \
  "https://$DOMAIN:$P443/~!frp" 2>/dev/null || true)
[ "$wscode" = "101" ] || fail "wss control channel did not upgrade to frps (got ${wscode:-no response}, expected 101)"
pass "wss control channel reaches frps with a verifying client (HTTP 101 upgrade)"

echo "smoke test: all checks passed ($IMAGE)"
