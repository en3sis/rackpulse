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

dev_flavor
quit_dev_app
rm -rf "$OUT"
dev_icon

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
echo "$AGENT_VERSION" >"$DEV_AGENT"

open "$APP"

echo
echo "Rackpulse Dev $APP_VERSION ($COMMIT), agent $AGENT_VERSION"
echo "App:      $APP, now open"
if [ "$notarize" != 0 ]; then echo "Download: $site/download/dev/Rackpulse-Dev.dmg"; fi
echo "Agent:    curl -fsSL $site/agent/dev/install.sh | sudo sh -s -- --pair <key>"
echo "          Rackpulse Dev shows the full command with the key"
