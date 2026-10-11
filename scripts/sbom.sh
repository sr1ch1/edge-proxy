#!/bin/sh
# SBOM drift report for this project's pinned dependencies (see Dockerfile
# header for the pin policy). Prints one table row per pinned product:
#
#   NAME                product key (accepted by upgrade-package.sh)
#   CURRENT             version pinned in the Dockerfile
#   AVAILABLE           latest version the upstream index serves today
#
# Sources: GitHub releases (frps, lego), the Alpine branch APKINDEX (apk
# packages), Docker Hub (alpine patch tags, dockerfile frontend digest).
# dockerfile-frontend compares digests instead of versions — the moving tag
# `1` has no "newer version", only drift. Read-only: nothing is modified.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/pins-lib.sh"
trap pins_cleanup EXIT

rows=$(pins_tmp)
printf 'NAME\tCURRENT\tAVAILABLE\n' > "$rows"
for name in $PIN_NAMES; do
  cur=$(current_version "$name") || cur='?'
  avail=$(available_version "$name") || avail='?'
  [ -n "$cur" ]   || cur='?'
  [ -n "$avail" ] || avail='?'
  printf '%s\t%s\t%s\n' "$name" "$cur" "$avail" >> "$rows"
done

awk -F'\t' '
  { for (i = 1; i <= 3; i++) if (length($i) > w[i]) w[i] = length($i)
    row[NR] = $0 }
  END {
    for (r = 1; r <= NR; r++) {
      split(row[r], a, "\t")
      printf "%-*s  %-*s  %s\n", w[1], a[1], w[2], a[2], a[3]
      if (r == 1) {
        sep = sprintf("%*s", w[1] + w[2] + w[3] + 4, "")
        gsub(/ /, "-", sep)
        print sep
      }
    }
  }' "$rows"
