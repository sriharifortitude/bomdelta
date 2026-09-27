#!/usr/bin/env bash
# Regenerates npm-before.cdx.json / npm-after.cdx.json from real npm
# resolution (lockfile only, nothing is installed). The "after" side makes
# three real changes a release reviewer should catch: express downgraded
# 4.21.2 -> 4.20.0, tinymce 6.8.5 -> 7.6.0 (the MIT -> GPL-2.0-or-later
# relicensing), and zod added.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

make_sbom() {
  # npm names the SBOM's subject after the directory, not package.json
  local dir="$work/$1/demo-app" deps="$2" out="$3"
  mkdir -p "$dir"
  printf '{"name":"demo-app","version":"%s","private":true,"license":"MIT","dependencies":%s}\n' "$4" "$deps" > "$dir/package.json"
  (cd "$dir" && npm install --package-lock-only --ignore-scripts --silent && npm sbom --sbom-format cyclonedx --package-lock-only --omit dev) > "$out"
}

make_sbom before '{"express":"4.21.2","tinymce":"6.8.5"}' "$here/npm-before.cdx.json" 1.0.0
make_sbom after '{"express":"4.20.0","tinymce":"7.6.0","zod":"3.23.8"}' "$here/npm-after.cdx.json" 1.1.0
