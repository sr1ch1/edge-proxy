# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Frontend pinned by digest (mutable tags would run arbitrary build logic as root).
# To bump: pull docker/dockerfile:1, re-inspect, re-pin — same policy as the base image.
# Edge Proxy — single-image reference implementation
#
# The image runs as uid/gid 10001 (USER below) — no root at run time. Bind mounts
# must be writable/readable by that uid: on the host `chown 10001:10001` the acme
# webroot and certs dir, and make the token file root:10001 mode 640 (see below).
#
# Runtime parameters (secrets must never enter image layers — never as ARG/ENV):
#   DOMAIN       env  t-<customer-id>.<integrator-domain> (control hostname; its A record
#                must already point at this host before first start — lego HTTP-01)
#   ACME_EMAIL   env  Let's Encrypt registration contact
#   FRP_TOKEN    file per-customer shared secret — generate it
#                RANDOMLY, never as a passphrase:
#                  openssl rand -base64 32
#                The entrypoint enforces a 32-character length floor (a LENGTH
#                floor, not an entropy estimate) plus a distinct-character
#                floor that only rules out trivial repeated-pattern tokens.
#                frp's token login is md5(token||timestamp) — an offline oracle
#                if a login frame ever leaks — so token entropy is load-bearing.
#                Rotate by writing a new token file and restarting this
#                container and the sidecar together. Bind-mount it read-only at
#                /run/secrets/frp_token — readable by the runtime uid only:
#                root-owned, group 10001, mode 640 (or 10001:10001 mode 400).
#                entrypoint.sh reads the token from FRP_TOKEN_FILE (default
#                /run/secrets/frp_token) and refuses to start if FRP_TOKEN is present
#                in the environment — env is exposed via `docker inspect` and
#                /proc/*/environ.
#
# docker-compose.yml in this repo encodes every flag below (plus --read-only,
# --cap-drop ALL --cap-add NET_BIND_SERVICE, no-new-privileges) as enforced
# configuration — it is the only supported way to run this image.
#
# Required run-time mounts (no VOLUME declared on purpose — anonymous volumes would
# persist private keys in dangling volumes after `docker rm`):
#   --tmpfs /tmp                  REQUIRED with --read-only: nginx pid/temp state and
#                                 the 0600 frps.toml (token at rest) live on tmpfs —
#                                 never on a persisted layer. tmpfs /tmp is mode 1777,
#                                 writable by the runtime uid; /run is not writable.
#                                 entrypoint.sh refuses to start if /tmp is not tmpfs
#                                 (a bare `docker run` would otherwise silently
#                                 "work" while persisting the token in the layer).
#   -v <acme-webroot>:/var/www/acme   HTTP-01 challenge webroot (uid 10001:10001)
#   -v <certs-dir>:/certs         lego account key + domain key (uid 10001:10001, mode 700)
#   -v <token-file>:/run/secrets/frp_token:ro
#
# Sidecar (frpc) trust contract — REQUIRED. The wss control channel has no
# server-authentication mechanism beyond TLS, and frp 0.71 defaults defeat it
# (verified in frp source: pkg/transport/tls.go). The sidecar MUST be
# configured as follows:
#   - Verify this endpoint's certificate:
#       transport.tls.serverName     = DOMAIN
#       transport.tls.trustedCaFile  = <system CA bundle, e.g.
#                                     /etc/ssl/certs/ca-certificates.crt>
#     frp's client TLS sets InsecureSkipVerify=true whenever trustedCaFile is
#     unset — with sidecar defaults an on-path attacker can impersonate the
#     terminator (blackhole or relay the tunnel) even AFTER Let's Encrypt
#     issuance. The LE cert only helps if the sidecar actually validates it.
#   - Speak wire protocol v2 — EXPLICITLY (`transport.wireProtocol = "v2"`).
#     frp's client still defaults to v1 (verified in frp 0.71 source:
#     pkg/config/v1/client.go — util.EmptyOr(c.WireProtocol, "v1")) although
#     v2 shipped in 0.52. v1's message framing is unauthenticated and frp's
#     token login is md5(token||timestamp) with no server-side freshness check
#     — replayable if a login frame ever becomes readable. Never configure a
#     legacy/v1 downgrade. See examples/frpc.toml for the full contract.
#   - Before first issuance there is nothing to verify and nothing to TOFU:
#     the control route is CLOSED (entrypoint.sh writes a stream-map include
#     that pins the exact DOMAIN — not a t-* prefix — to a dead port at :443)
#     until a CA-signed cert is installed. The
#     per-container placeholder below only lets nginx start; it is never
#     routed to a client. The gate opens automatically on the first successful
#     lego issuance (install_cert), so bring the sidecar up once t.crt is
#     CA-signed (issuer != subject — the placeholder is the only self-signed
#     cert the entrypoint ever mints).
#
# The image implements the wss layout: one public 443, SNI-multiplexed;
# the wss control channel is TLS-terminated by the in-container nginx at 127.0.0.1:7444.

# Base pinned by digest — tags are mutable. To bump: pull, re-inspect, re-pin.
# lego v5 notes:
#   - Renewal: `run` consults the ARI renewalInfo endpoint by default
#     (opt-out: --ari-disable). The ARI wait duration defaults to 0 — lego
#     never sleeps into a future renewal window; when nothing is due it exits 0
#     without ACME traffic, so the 12h poll in entrypoint.sh stays the outer
#     loop.
#   - Upgrade (v4 -> v5): storage layout and JSON schemas changed. entrypoint.sh
#     migrates /certs on startup only when it detects a v4 layout (details in
#     entrypoint.sh) and refuses to start if migration fails. Before deploying
#     an image built with lego >= 5 over an existing deployment, back up /certs
#     on the host: `cp -a certs certs.bak-<date>`.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS fetch

# Pin; bump deliberately: new version -> new checksums -> rebuild -> re-pin base digest.
ARG FRPS_VERSION=0.71.0      # MUST support wss control channel
ARG LEGO_VERSION=5.5.2       # MUST support ARI. v5 CLI: unified `run`
                             # (obtain+renew) — entrypoint.sh handles this, plus a
                             # one-time idempotent storage migration (see header).
ARG TARGETARCH

# apk packages pinned (bump deliberately; see policy note in the runtime stage).
# frps/lego sha256s from upstream frp_sha256_checksums.txt / lego_5.5.2_checksums.txt
# (note: the lego asset is NOT v-prefixed). Update together with the version pins above.
# The expected digests are literals, NOT ARG: a --build-arg must never be able to swap
# the expected checksum and defeat verify-before-extract. Verify BEFORE extracting;
# fail closed on unknown arch.
RUN apk add --no-cache 'curl=8.22.0-r0' 'ca-certificates=20260909-r0' \
 && case "${TARGETARCH}" in \
      amd64) frps_sha="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716" \
             lego_sha="2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef" ;; \
      arm64) frps_sha="f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266" \
             lego_sha="15b14ec2ab14fde69cc8396eb0204c5ce4327e31a486953225a6059b26db3e8c" ;; \
      *) echo >&2 "unsupported TARGETARCH: ${TARGETARCH}"; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/frps.tar.gz \
      "https://github.com/fatedier/frp/releases/download/v${FRPS_VERSION}/frp_${FRPS_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && echo "${frps_sha}  /tmp/frps.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/frps.tar.gz -C /usr/local/bin --strip-components=1 \
      "frp_${FRPS_VERSION}_linux_${TARGETARCH}/frps" \
 && curl -fsSL -o /tmp/lego.tar.gz \
      "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && echo "${lego_sha}  /tmp/lego.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/lego.tar.gz -C /usr/local/bin lego \
 && chmod 0755 /usr/local/bin/frps /usr/local/bin/lego \
 && rm -f /tmp/frps.tar.gz /tmp/lego.tar.gz

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# apk packages pinned to exact versions — same deliberate-bump policy as the
# FRPS/LEGO pins above: a rebuild must not silently change what goes into the
# image. Alpine drops superseded .apks from the index, so if a pin 404s, bump it
# in the same reviewed change (and re-run the build/smoke tests).
# No curl and no bash in the runtime image (asserted by the smoke test) — curl
# is outbound fetch tooling and bash an extra interpreter; both are
# post-compromise second-stage material. Busybox applets (incl. wget) remain —
# busybox IS /bin/sh; trimming it would cost the shell entrypoint.sh needs.
# entrypoint.sh itself performs no network fetches (lego is the only client).
# openssl stays: it mints the per-container throwaway bootstrap
# cert (entrypoint.sh). A build-time shared bootstrap key baked into the image
# would let anyone who pulls the image MITM the t-* control channel before first
# issuance — per-container generation is the safer trade.
# BuildKit is required (COPY --chmod, TARGETARCH, checksum gating).
# nginx-mod-stream: Alpine builds `stream` as a dynamic module — loaded explicitly in
# nginx.conf (no include-glob, nothing else gets loaded). The error.log symlink silences
# nginx's pre-config open of its compile-time default log (unwritable for uid 10001 and
# under --read-only; the real log is /dev/stderr per nginx.conf).
# Numeric uid/gid 10001: no setuid tooling needed to drop privileges — USER does it.
# The token file is NOT baked in: the image ships only /run/secrets as the mount
# point, so a forgotten token mount fails closed as "token file missing".
RUN apk add --no-cache 'nginx=1.30.4-r1' 'nginx-mod-stream=1.30.4-r1' \
        'openssl=3.5.9-r0' 'ca-certificates=20260909-r0' \
 && addgroup -S -g 10001 edge \
 && adduser -S -D -H -u 10001 -G edge -s /sbin/nologin edge \
 && mkdir -p /run/secrets /var/www/acme /certs \
 && ln -sf /dev/stderr /var/lib/nginx/logs/error.log \
 && chmod 755 /var/lib/nginx \
 && chown -R edge:edge /var/www/acme /certs

COPY --from=fetch --chown=0:0 /usr/local/bin/frps /usr/local/bin/frps
COPY --from=fetch --chown=0:0 /usr/local/bin/lego /usr/local/bin/lego
COPY nginx.conf    /etc/nginx/nginx.conf
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh

# Non-root (uid 10001) end to end: frps, nginx and lego all drop the ability to
# re-escalate via --security-opt no-new-privileges, and nginx binds :80/:443 only
# via the NET_BIND_SERVICE capability granted at run time (file caps are inert
# under no-new-privileges; --cap-drop ALL --cap-add NET_BIND_SERVICE is required).
# Per D12 the container is still explicitly NOT claimed as a security boundary.
USER 10001:10001
EXPOSE 80 443

# The last clause covers the renewal loop: install_cert touches
# /tmp/nginx/renewed on every successful cycle (12h cadence) and entrypoint.sh
# seeds it at boot. A wedged lego (guarded by `timeout 300`) or a dead renewal
# subshell leaves frps/nginx healthy while renewal silently stops — after 7
# days without a successful cycle the marker goes stale, the container turns
# unhealthy, and the host restart policy is the recovery path. 7 days (not
# hours) keeps transient ACME outages from causing restart churn: a 90-day
# cert renewed at the ARI window has weeks of runway.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["sh", "-c", "test -s /tmp/nginx/nginx.pid && kill -0 \"$(cat /tmp/nginx/nginx.pid)\" && kill -0 $(pidof frps) && [ -n \"$(find /tmp/nginx/renewed -mmin -10080 2>/dev/null)\" ]"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
