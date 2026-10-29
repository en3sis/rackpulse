#!/bin/bash
source "$(dirname "$0")/lib.sh"

release=${AGENT_VERSION:-$(agent_version)}
out=${AGENT_OUT:-dist/agent/$release}
rm -rf "$out"
mkdir -p "$out"

for arch in amd64 arm64; do
  echo "Building rackpulse-agent $release for linux/$arch"
  (cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=$release" -o "../$out/rackpulse-agent-linux-$arch" ./cmd/rackpulse-agent)
done
cp agent/install.sh "$out/install.sh"
if [ -n "${AGENT_URL:-}" ]; then
  sed -i '' "s#:-https://rackpulse.app/agent}#:-$AGENT_URL}#" "$out/install.sh"
  grep -q ":-$AGENT_URL}" "$out/install.sh" || { echo "Could not set $AGENT_URL in install.sh"; exit 1; }
fi
(cd "$out" && shasum -a 256 rackpulse-agent-linux-amd64 rackpulse-agent-linux-arm64 >SHA256SUMS)
ls -l "$out"
