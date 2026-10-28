#!/bin/bash
source "$(dirname "$0")/lib.sh"

require SITE_URL
if [ "$SIGN_ID" = "-" ]; then
  echo "Set SIGN_ID in .env, for example: SIGN_ID=Developer ID Application: Your Name (TEAMID)"
  exit 1
fi
notarize=${NOTARIZE:-1}
if [ "$notarize" != 0 ]; then require NOTARY_PROFILE; fi

site=$SITE_URL
prefix=${R2_PREFIX:-}
prefix=${prefix%/}
r2_check
r2_setup

stamp=$(date -u +%Y%m%d%H%M)
commit=$(git rev-parse --short HEAD)
if [ -n "$(git status --porcelain)" ]; then commit="$commit+"; fi

export OUT=dist/dev APP_NAME="Rackpulse Dev" ICON=dist/dev/AppIcon
export BUNDLE_ID=dev.rackpulse.mac.dev FLAVOR=dev COMMIT=$commit
export APP_VERSION=$(version)-dev.$stamp BUILD_NUMBER=$(version).$stamp
export AGENT_VERSION=$(agent_version)-dev.$stamp AGENT_URL=$site/agent/dev AGENT_OUT=dist/dev/agent
APP=$OUT/$APP_NAME.app
DMG=$OUT/$APP_NAME.dmg

rm -rf "$OUT"
mkdir -p "$OUT"
sed -e 's/cx="716" cy="716"/cx="716" cy="308"/' \
  -e 's#</svg>#  <rect x="372" y="790" width="280" height="88" rx="44" fill="\#FF9F0A"/>\
  <text x="512" y="854" text-anchor="middle" font-family="Helvetica Neue, Helvetica, Arial, sans-serif" font-size="60" font-weight="800" fill="\#FFFFFF">DEV</text>\
</svg>#' macos/Resources/AppIcon.svg >"$ICON.svg"
scripts/appicon.sh

scripts/agent.sh
scripts/build.sh
codesign --verify --deep --strict "$APP"

if [ "$notarize" != 0 ]; then
  scripts/dmg.sh
  codesign --force --timestamp --sign "$SIGN_ID" "$DMG"
  submit "$DMG"
  xcrun stapler staple "$DMG"
  spctl --assess --type open --context context:primary-signature -v "$DMG"
fi

for name in "${agent_files[@]}"; do
  put "$AGENT_OUT/$name" "agent/dev/$name" "$(content_type "$name")" "no-cache"
done
if [ "$notarize" != 0 ]; then
  put "$DMG" download/dev/Rackpulse-Dev.dmg application/x-apple-diskimage "no-cache"
fi

echo
echo "Rackpulse Dev $APP_VERSION ($commit), agent $AGENT_VERSION"
echo "App:      open \"$APP\""
if [ "$notarize" != 0 ]; then echo "Download: $site/download/dev/Rackpulse-Dev.dmg"; fi
echo "Agent:    curl -fsSL $site/agent/dev/install.sh | sudo sh -s -- --pair <key>"
echo "          Rackpulse Dev shows the full command with the key"
