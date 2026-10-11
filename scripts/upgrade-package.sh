#!/bin/sh
# Bump one pinned dependency in the Dockerfile, per the repo's deliberate-bump
# policy: fetch upstream, verify integrity, edit the pin, re-read to confirm.
#
#   scripts/upgrade-package.sh <name> <version>
#
# <name> must be one of the NAMEs printed by scripts/sbom.sh. Per class:
#
#   frps / lego         Downloads BOTH arch tarballs from the GitHub release
#                       plus the upstream checksums file, verifies each tarball
#                       against it (fail closed on 404 or mismatch), then
#                       updates the ARG version and the two per-arch sha256
#                       literals. A nonexistent version never touches the file.
#   nginx, nginx-mod-stream, openssl, ca-certificates, curl
#                       <version> must be the exact version-release (e.g.
#                       1.30.4-r1) currently served by the Alpine branch repo —
#                       verified against APKINDEX before editing. Updates every
#                       stage that pins the package (ca-certificates is pinned
#                       in both).
#   alpine              <version> is a tag (e.g. 3.24.3). The digest is resolved
#                       from Docker Hub and both FROM lines are re-pinned.
#                       Warns if the major.minor branch moved: apk pins resolve
#                       against the branch repo and likely need bumps too.
#   dockerfile-frontend <version> is the syntax tag (e.g. 1). Re-pins the
#                       digest the tag serves today.
#
# After ANY bump: docker compose build && scripts/smoke-test.sh &&
# scripts/check-image-pins.sh. For lego over an existing deployment, back up
# /certs on the host first (see Dockerfile header).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/pins-lib.sh"
trap pins_cleanup EXIT

die() { echo >&2 "error: $*"; exit 1; }

[ $# -eq 2 ] || die "usage: $0 <name> <version>  (names: $PIN_NAMES)"
name=$1 ver=$2
case " $PIN_NAMES " in *" $name "*) ;; *) die "unknown package '$name' (names: $PIN_NAMES)" ;; esac
[ -f "$DOCKERFILE" ] || die "Dockerfile not found: $DOCKERFILE"

# --- frps / lego: GitHub release binaries -----------------------------------

upgrade_gh_binary() {
  echo "$ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || die "version must be x.y.z, got '$ver'"
  case $name in
    frps) repo=fatedier/frp;  var=FRPS_VERSION; key=frps_sha
          sums=frp_sha256_checksums.txt;        asset_fmt='frp_%s_linux_%s.tar.gz' ;;
    lego) repo=go-acme/lego;  var=LEGO_VERSION; key=lego_sha
          sums="lego_${ver}_checksums.txt"      # checksums file is NOT v-prefixed
          asset_fmt='lego_v%s_linux_%s.tar.gz' ;;
  esac
  base="https://github.com/$repo/releases/download/v$ver"

  tmp=$(pins_tmp); mkdir -p "$tmp.d"
  echo "fetching $base/$sums"
  curl -fsSL --max-time 60 "$base/$sums" -o "$tmp.d/$sums" \
    || die "release v$ver not found (no checksums file) — nothing changed"
  for arch in amd64 arm64; do
    asset=$(printf "$asset_fmt" "$ver" "$arch")
    echo "fetching $asset"
    curl -fsSL --max-time 300 "$base/$asset" -o "$tmp.d/$asset" \
      || die "asset $asset missing from release v$ver — nothing changed"
    ( cd "$tmp.d" && grep "[[:space:]]${asset}\$" "$sums" | sha256sum -c - >/dev/null ) \
      || die "checksum verification failed for $asset — nothing changed"
    eval "${arch}_sha=\$(awk -v a=\"\$asset\" '\$2==a{print \$1}' \"\$tmp.d/\$sums\")"
  done

  sed -i "s/^ARG ${var}=[0-9.]*/ARG ${var}=${ver}/" "$DOCKERFILE"
  sed -i "/amd64)/,/;;/ s/\(${key}=\"\)[0-9a-f]\{64\}\"/\1${amd64_sha}\"/" "$DOCKERFILE"
  sed -i "/arm64)/,/;;/ s/\(${key}=\"\)[0-9a-f]\{64\}\"/\1${arm64_sha}\"/" "$DOCKERFILE"
  grep -q "$amd64_sha" "$DOCKERFILE" && grep -q "$arm64_sha" "$DOCKERFILE" \
    || die "post-edit check failed: sha literals not updated"
  echo "verified: both tarballs match upstream checksums"
}

# --- apk packages ------------------------------------------------------------

upgrade_apk() {
  echo "$ver" | grep -qE '^[0-9][0-9A-Za-z._]*-r[0-9]+$' \
    || die "apk version must be a full version-release (e.g. 1.30.4-r1), got '$ver'"
  served=$(apk_index_version "$name")
  [ -n "$served" ] || die "package '$name' not in Alpine v$(alpine_branch) main index"
  [ "$served" = "$ver" ] \
    || die "Alpine v$(alpine_branch) serves '$name=$served', not '$ver' — nothing changed"
  sed -i "s|'${name}=[0-9][^']*'|'${name}=${ver}'|g" "$DOCKERFILE"
}

# --- image references --------------------------------------------------------

upgrade_alpine() {
  echo "$ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || die "version must be a tag like 3.24.3"
  digest=$(hub_tag_digest library/alpine "$ver")
  [ -n "$digest" ] || die "tag alpine:$ver not found on Docker Hub — nothing changed"
  old_branch=$(alpine_branch)
  sed -i "s|alpine:[0-9][0-9.]*@sha256:[0-9a-f]\{64\}|alpine:${ver}@${digest}|g" "$DOCKERFILE"
  [ "${ver%.*}" = "$old_branch" ] \
    || echo "WARNING: branch moved v$old_branch -> v${ver%.*}; apk pins resolve against the branch repo — re-run scripts/sbom.sh and bump them"
}

upgrade_frontend() {
  digest=$(hub_tag_digest docker/dockerfile "$ver")
  [ -n "$digest" ] || die "tag docker/dockerfile:$ver not found on Docker Hub — nothing changed"
  sed -i "s|^# syntax=docker/dockerfile:[^[:space:]@]*@sha256:[0-9a-f]\{64\}|# syntax=docker/dockerfile:${ver}@${digest}|" "$DOCKERFILE"
}

# --- dispatch ----------------------------------------------------------------

case $name in
  frps|lego)                                             upgrade_gh_binary ;;
  ca-certificates|curl|nginx|nginx-mod-stream|openssl)   upgrade_apk ;;
  alpine)                                                upgrade_alpine ;;
  dockerfile-frontend)                                   upgrade_frontend ;;
esac

now=$(current_version "$name" || true)
echo "updated: $name -> $ver  (Dockerfile now pins: $now)"
echo "next:    docker compose build && scripts/smoke-test.sh && scripts/check-image-pins.sh"
[ "$name" = lego ] && echo "note:    back up /certs on the host before deploying (Dockerfile header)" || :
