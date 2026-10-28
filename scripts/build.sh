#!/bin/bash
source "$(dirname "$0")/lib.sh"

contents=$APP/Contents
build=macos/.build/release

(cd macos && xcrun swift build -c release)
rm -rf "$APP"
mkdir -p "$contents/MacOS" "$contents/Resources" "$contents/Frameworks"
binary=$contents/MacOS/$APP_NAME
plist=$contents/Info.plist
cp "$build/Rackpulse" "$binary"
xcrun vtool -set-build-version macos 14.0 "$(xcrun --show-sdk-version)" -replace -output "$binary" "$binary"
cp macos/Info.plist "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${APP_VERSION:-$(version)}" -c "Set :CFBundleVersion ${BUILD_NUMBER:-$(version)}" \
  -c "Set :CFBundleExecutable '$APP_NAME'" -c "Set :CFBundleName '$APP_NAME'" \
  -c "Add :RackpulseAgentVersion string ${AGENT_VERSION:-$(agent_version)}" "$plist"
if [ -n "${BUNDLE_ID:-}" ]; then /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" "$plist"; fi
if [ -n "${AGENT_URL:-}" ]; then /usr/libexec/PlistBuddy -c "Add :RackpulseAgentURL string $AGENT_URL" "$plist"; fi
if [ -n "${FLAVOR:-}" ]; then
  /usr/libexec/PlistBuddy -c "Add :RackpulseFlavor string $FLAVOR" -c "Add :RackpulseCommit string ${COMMIT:-}" "$plist"
fi
cp -R "$build/Sparkle.framework" "$contents/Frameworks/Sparkle.framework"
cp "$ICON.icns" "$contents/Resources/AppIcon.icns"
scripts/sign.sh
