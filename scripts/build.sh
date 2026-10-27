#!/bin/bash
source "$(dirname "$0")/lib.sh"

contents=$APP/Contents
build=macos/.build/release

(cd macos && xcrun swift build -c release)
rm -rf "$APP"
mkdir -p "$contents/MacOS" "$contents/Resources" "$contents/Frameworks"
cp "$build/Rackpulse" "$contents/MacOS/Rackpulse"
xcrun vtool -set-build-version macos 14.0 "$(xcrun --show-sdk-version)" -replace -output "$contents/MacOS/Rackpulse" "$contents/MacOS/Rackpulse"
cp macos/Info.plist "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(version)" -c "Set :CFBundleVersion $(version)" \
  -c "Add :RackpulseAgentVersion string $(agent_version)" "$contents/Info.plist"
cp -R "$build/Sparkle.framework" "$contents/Frameworks/Sparkle.framework"
cp "$ICON.icns" "$contents/Resources/AppIcon.icns"
scripts/sign.sh
