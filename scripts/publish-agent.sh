#!/bin/bash
source "$(dirname "$0")/lib.sh"

require SITE_URL
site=$SITE_URL
prefix=${R2_PREFIX:-}
prefix=${prefix%/}

r2_check
require_release_key

release=$(agent_version)
out=dist/agent/$release
for name in "${agent_build_files[@]}"; do
  if [ ! -f "$out/$name" ]; then
    echo "$out/$name is missing. Run make agent first"
    exit 1
  fi
done
(cd "$out" && shasum -a 256 -c SHA256SUMS >/dev/null) || {
  echo "Checksums in $out/SHA256SUMS do not match. Run make agent again"
  exit 1
}
sign_agent "$out"

echo "Uploading rackpulse-agent $release to $site/agent"
r2_setup

for name in "${agent_files[@]}"; do
  put "$out/$name" "agent/$release/$name" "$(content_type "$name")" "public, max-age=31536000, immutable"
done
for name in rackpulse-agent-linux-amd64 rackpulse-agent-linux-arm64 SHA256SUMS.sig SHA256SUMS install.sh; do
  put "$out/$name" "agent/$name" "$(content_type "$name")" "public, max-age=300"
done
