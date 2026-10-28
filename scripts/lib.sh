set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

APP_NAME=${APP_NAME:-Rackpulse}
OUT=${OUT:-dist}
APP=$OUT/$APP_NAME.app
DMG=$OUT/$APP_NAME.dmg
FEED=dist/feed
ICON=${ICON:-macos/Resources/AppIcon}
ENTITLEMENTS=macos/Rackpulse.entitlements

if [ -f .env ]; then
  while IFS='=' read -r key value; do
    case "$key" in
      '' | \#*) continue ;;
    esac
    if [ -z "${!key:-}" ]; then export "$key=$value"; fi
  done <.env
fi
SIGN_ID="${SIGN_ID:--}"

require() {
  local name
  for name in "$@"; do
    if [ -z "${!name:-}" ]; then
      echo "Set $name in .env. See .env.example"
      exit 1
    fi
  done
}

release_dir() {
  echo "dist/Rackpulse-$1"
}

feed_view() {
  local file
  rm -rf "$FEED"
  mkdir -p "$FEED"
  for file in dist/Rackpulse-*/*.dmg dist/Rackpulse-*/*.delta dist/Rackpulse-*/*.md; do
    if [ -f "$file" ]; then ln "$file" "$FEED/"; fi
  done
}

version() {
  tr -d '[:space:]' <VERSION
}

dev_identity() {
  if [ -n "${DEV_SIGN_ID:-}" ]; then
    echo "$DEV_SIGN_ID"
    return
  fi
  local found
  found=$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Apple Development: [^"]*\)".*/\1/p' | head -1)
  echo "${found:--}"
}

r2_check() {
  local name
  for name in R2_ACCOUNT_ID R2_BUCKET; do
    if [ -z "${!name:-}" ]; then
      echo "Set $name in .env"
      exit 1
    fi
  done
}

r2_setup() {
  if [ -n "${R2_ACCESS_KEY_ID:-}" ] && [ -n "${R2_SECRET:-}" ]; then
    echo "Using R2_ACCESS_KEY_ID and R2_SECRET from .env"
    key_id=$R2_ACCESS_KEY_ID
    secret=$R2_SECRET
  else
    local token path
    token=${R2_TOKEN:-${R2_SECRET:-}}
    if [ -z "$token" ]; then
      echo "Set R2_TOKEN, or R2_ACCESS_KEY_ID and R2_SECRET, in .env"
      exit 1
    fi
    key_id=""
    for path in "accounts/$R2_ACCOUNT_ID/tokens/verify" "user/tokens/verify"; do
      key_id=$( (curl -sS -H "Authorization: Bearer $token" "https://api.cloudflare.com/client/v4/$path" 2>/dev/null || true) \
        | sed -n 's/.*"result":{"id":"\([^"]*\)".*/\1/p')
      if [ -n "$key_id" ]; then break; fi
    done
    if [ -z "$key_id" ]; then
      echo "Cloudflare did not accept R2_TOKEN. Check that it is the token value from R2, Manage API tokens"
      exit 1
    fi
    if [ -n "${R2_TOKEN:-}" ] && [ -n "${R2_SECRET:-}" ]; then
      secret=$R2_SECRET
    else
      secret=$(printf %s "$token" | shasum -a 256 | cut -d' ' -f1)
    fi
    echo "Using R2_TOKEN from .env"
  fi
  endpoint=https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com/$R2_BUCKET${prefix:+/$prefix}
}

put() {
  curl -fsS --aws-sigv4 "aws:amz:auto:s3" --user "$key_id:$secret" \
    -H "Content-Type: $3" -H "Cache-Control: $4" -T "$1" "$endpoint/$2" -o /dev/null
  echo "Uploaded $site/$2"
}

submit() {
  local result
  result=$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1)
  echo "$result"
  if ! echo "$result" | grep -q "status: Accepted"; then
    echo "Notarization of $1 was not accepted"
    exit 1
  fi
}

content_type() {
  case "$1" in
    install.sh) echo "text/x-shellscript; charset=utf-8" ;;
    SHA256SUMS) echo "text/plain; charset=utf-8" ;;
    *) echo application/octet-stream ;;
  esac
}

agent_files=(install.sh rackpulse-agent-linux-amd64 rackpulse-agent-linux-arm64 SHA256SUMS)

agent_version() {
  tr -d '[:space:]' <agent/VERSION
}
