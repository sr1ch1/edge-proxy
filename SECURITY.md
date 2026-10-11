# Security Policy

edge-proxy terminates public internet traffic on customer edge hosts and relays it into customer networks — security bugs in this image are high-impact. Thank you for reporting them responsibly.

## Supported Versions

Only the latest published image tag (`ghcr.io/sr1ch1/edge-proxy:latest`) and the `main` branch receive security fixes. Images are cosign-signed; verify signatures when pulling.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for anything security-sensitive.**

Report privately via GitHub's private vulnerability reporting:

> https://github.com/sr1ch1/edge-proxy/security/advisories/new

Please include:

- Affected component (nginx SNI stream, wss terminator, `entrypoint.sh`, frps/frpc integration, ACME/lego handling, CI/release pipeline)
- Image tag or commit hash
- Reproduction steps, ideally with a minimal `docker-compose.yml` override
- Impact assessment (RCE, auth bypass, tunnel hijack, sandbox escape, cert issuance abuse)
- Suggested mitigation, if any

## What to Expect

- Acknowledgment within 72 hours
- Assessment and severity rating within 7 days
- Fix or mitigation prioritized by impact; a fix for critical issues in the next image release
- Credit in the release notes / advisory (opt-in; anonymous reports respected)

## Scope

In scope:

- Everything in this repository: `Dockerfile`, `entrypoint.sh`, `nginx.conf`, `docker-compose.yml`, CI workflows, release/signing pipeline
- Default deployment as described in the README (compose file, non-root, capability-dropped, read-only rootfs)

Out of scope:

- Misconfiguration (weakened compose settings, exposed `:7000`/`7443`/`8080` on public interfaces — these must stay loopback/firewalled)
- Vulnerabilities in upstream pinned dependencies themselves (report upstream; we track and patch pin bumps)
- Customer-side `frpc` configuration outside the documented reference setup
- Attacks requiring physical access or compromise of the edge host itself
- Denial of service against a single-host edge

## Safe Harbor

Good-faith research against your own deployments is welcome. Do not test against hosts you do not own, and avoid privacy violations, data destruction, and downtime.
