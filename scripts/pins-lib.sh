#!/bin/sh
# Shared pin registry for sbom.sh and upgrade-package.sh — the single list of
# pinned products and the parsers/lookups for their current and available
# versions. Sourced, not executed. DOCKERFILE may be overridden (env) for
# testing against a copy; defaults to the repo-root Dockerfile.
#
# Product-name <-> Dockerfile-location map:
#   alpine              FROM lines (both stages), tag + digest
#   dockerfile-frontend # syntax= directive, tag + digest
#   frps / lego         ARG <TOOL>_VERSION + per-arch sha256 literals (fetch stage)
#   curl, ca-certificates, nginx, nginx-mod-stream, openssl
#                       apk '<pkg>=<version-release>' pins (fetch and/or runtime)

set -u

DOCKERFILE=${DOCKERFILE:-"$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/Dockerfile"}

PIN_NAMES="alpine ca-certificates curl dockerfile-frontend frps lego nginx nginx-mod-stream openssl"

# --- temp-file bookkeeping (callers: trap pins_cleanup EXIT) ----------------

_PINS_TMP=
pins_tmp() {
  t=$(mktemp) || return 1
  _PINS_TMP="$_PINS_TMP $t"
  printf '%s\n' "$t"
}
pins_cleanup() { rm -f $_PINS_TMP; }

# --- Dockerfile parsers ------------------------------------------------------

alpine_branch() { # e.g. 3.24 — the apk repo branch the pins resolve against
  current_version alpine | cut -d. -f1,2
}

current_version() { # <name> -> version as pinned in DOCKERFILE
  case $1 in
    frps|lego)
      var=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')_VERSION
      sed -n "s/^ARG ${var}=\([0-9.]*\).*/\1/p" "$DOCKERFILE" ;;
    ca-certificates|curl|nginx|nginx-mod-stream|openssl)
      grep -o "'$1=[0-9][^']*'" "$DOCKERFILE" | head -1 | cut -d= -f2 | tr -d "'" ;;
    alpine)
      awk '/^FROM /{print $2; exit}' "$DOCKERFILE" | sed 's/^alpine:\([0-9.]*\)@.*/\1/' ;;
    dockerfile-frontend)
      sed -n 's/^# syntax=docker\/dockerfile:\([^@]*\)@sha256:\([0-9a-f]*\).*/\1@\2/p' "$DOCKERFILE" |
        awk -F@ '{printf "%s@%s\n", $1, substr($2,1,12)}' ;;
    *) return 1 ;;
  esac
}

# --- network lookups ---------------------------------------------------------

github_latest() { # <owner/repo> -> latest release version, v-prefix stripped
  curl -fsS -o /dev/null --max-time 30 -w '%{redirect_url}' \
    "https://github.com/$1/releases/latest" | sed 's|.*/tag/v\{0,1\}||'
}

hub_tag_digest() { # <repo> <tag> -> sha256:... (empty on 404)
  curl -fsS --max-time 30 "https://hub.docker.com/v2/repositories/$1/tags/$2" 2>/dev/null |
    grep -o '"digest":"sha256:[0-9a-f]\{64\}"' | tail -1 | cut -d'"' -f4
}

# APKINDEX is fetched once per run and cached; main only (every pinned apk
# package lives in main for v3.24 — verified against the repo).
_APKINDEX_TXT=
apk_index() {
  if [ -z "$_APKINDEX_TXT" ]; then
    gz=$(pins_tmp)
    _APKINDEX_TXT=$(pins_tmp)
    curl -fsSL --max-time 60 \
      "https://dl-cdn.alpinelinux.org/alpine/v$(alpine_branch)/main/x86_64/APKINDEX.tar.gz" -o "$gz"
    tar -xzOf "$gz" APKINDEX > "$_APKINDEX_TXT"
  fi
  printf '%s\n' "$_APKINDEX_TXT"
}

apk_index_version() { # <pkg> -> version-release currently served by the branch repo
  awk -v p="P:$1" '$0==p{f=1;next} f&&/^V:/{print substr($0,3);exit}' "$(apk_index)"
}

available_version() { # <name>
  case $1 in
    frps)                  github_latest fatedier/frp ;;
    lego)                  github_latest go-acme/lego ;;
    ca-certificates|curl|nginx|nginx-mod-stream|openssl) apk_index_version "$1" ;;
    alpine)
      br=$(alpine_branch)
      curl -fsS --max-time 30 \
        "https://hub.docker.com/v2/repositories/library/alpine/tags/?name=${br}.&page_size=100" |
        grep -o '"name":"[^"]*"' | cut -d'"' -f4 |
        grep -E "^${br}\.[0-9]+$" | sort -V | tail -1 ;;
    dockerfile-frontend)
      tag=$(sed -n 's/^# syntax=docker\/dockerfile:\([^@]*\)@.*/\1/p' "$DOCKERFILE")
      d=$(hub_tag_digest docker/dockerfile "$tag")
      [ -n "$d" ] && printf '%s@%s\n' "$tag" "$(printf '%s' "$d" | sed 's/^sha256://' | cut -c1-12)" ;;
    *) return 1 ;;
  esac
}
