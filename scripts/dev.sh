#!/bin/bash
source "$(dirname "$0")/lib.sh"

dev_flavor
AGENT_VERSION=$(cat "$DEV_AGENT" 2>/dev/null || agent_version)
quit_dev_app
dev_icon
SIGN_ID=$(dev_identity) DEV_BUILD=1 scripts/build.sh
RACKPULSE_DEV=1 "$APP/Contents/MacOS/$APP_NAME"
