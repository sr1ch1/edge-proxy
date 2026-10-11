#!/bin/sh
# Tag/digest drift check for every image reference in the Dockerfile
# (the `# syntax=` frontend pin and all FROM lines). Each reference is written
# name:tag@sha256:<digest> — the tag is mutable, the digest is the security
# gate. This script re-resolves each tag against the registry and fails if the
# digest it serves today differs from the pin: someone bumped the tag text
# without re-pinning, or the tag was re-published upstream. Also fails on any
# reference missing a digest entirely (unpinned base image).
#
# Legitimate bump procedure (per the Dockerfile header): pull, re-inspect,
# re-pin — then this check goes green again.
#
# Usage: scripts/check-image-pins.sh [path/to/Dockerfile]
set -eu

DOCKERFILE=${1:-Dockerfile}

# syntax directive + every FROM (both build stages), deduplicated.
refs=$({ sed -n 's/^# syntax=\([^[:space:]]*\).*/\1/p' "$DOCKERFILE";
        awk '/^FROM / { print $2 }' "$DOCKERFILE"; } | sort -u)

rc=0
for ref in $refs; do
  case "$ref" in
    *@sha256:*) ;;
    *) echo "UNPINNED  $ref (no @sha256: digest)"; rc=1; continue ;;
  esac
  name=${ref%%@*}
  want=${ref##*@}
  # --raw prints the exact manifest/index bytes the registry serves for the
  # tag; their sha256 is the content digest — the same value `docker pull`
  # verifies when resolving name@sha256:...
  got=$(docker buildx imagetools inspect "$name" --raw | sha256sum | cut -d' ' -f1)
  if [ "sha256:$got" = "$want" ]; then
    echo "OK        $name == $want"
  else
    echo "DRIFT     $name"
    echo "          pinned:   $want"
    echo "          registry: sha256:$got"
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo >&2 "pin drift detected — re-inspect and re-pin deliberately; do not mass-update digests"
fi
exit "$rc"
