#!/bin/bash
source "$(dirname "$0")/lib.sh"

require SITE_URL
site=$SITE_URL
prefix=${R2_PREFIX:-}
prefix=${prefix%/}

r2_check

release=$(agent_version)
out=dist/agent/$release
for name in "${agent_files[@]}"; do
  if [ ! -f "$out/$name" ]; then
    echo "$out/$name is missing. Run make agent first"
    exit 1
  fi
done
(cd "$out" && shasum -a 256 -c SHA256SUMS >/dev/null) || {
  echo "Checksums in $out/SHA256SUMS do not match. Run make agent again"
  exit 1
}

echo "Uploading rackpulse-agent $release to $site/agent"
r2_setup

for name in "${agent_files[@]}"; do
  put "$out/$name" "agent/$release/$name" "$(content_type "$name")" "public, max-age=31536000, immutable"
done
for name in "${agent_files[@]}"; do
  put "$out/$name" "agent/$name" "$(content_type "$name")" "public, max-age=300"
done
