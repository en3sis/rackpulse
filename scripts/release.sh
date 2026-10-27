#!/bin/bash
source "$(dirname "$0")/lib.sh"

bump=${1:-patch}
require SITE_URL

case "$bump" in
  patch | minor | major) ;;
  *)
    echo "BUMP must be patch, minor, or major"
    exit 1
    ;;
esac

if [ "$SIGN_ID" = "-" ]; then
  echo "Set SIGN_ID in .env, for example: SIGN_ID=Developer ID Application: Your Name (TEAMID)"
  exit 1
fi
if [ -n "$(git status --porcelain | grep -v ' VERSION$' || true)" ]; then
  echo "Commit or stash your changes before a release"
  exit 1
fi

current=$(version)
if git rev-parse -q --verify "refs/tags/v$current" >/dev/null; then
  IFS=. read -r major minor patch <<<"$current"
  case "$bump" in
    major) next=$((major + 1)).0.0 ;;
    minor) next=$major.$((minor + 1)).0 ;;
    *) next=$major.$minor.$((patch + 1)) ;;
  esac
  echo "Version $current -> $next"
else
  next=$current
  echo "Version $current has no tag, releasing it"
fi

if ! grep -qx "## $next" CHANGELOG.md; then
  echo "CHANGELOG.md has no section for $next. Add \"## $next\" with the release notes, commit it, and run make release again"
  exit 1
fi

agent=$(agent_version)
if ! curl -fsSI "$SITE_URL/agent/$agent/SHA256SUMS" -o /dev/null; then
  echo "Agent $agent (agent/VERSION) is not published at $SITE_URL/agent/$agent. The app would offer an agent update that does not exist. Run make agent and make publish-agent first"
  exit 1
fi
echo "Agent $agent is published, the app will offer it as the latest agent"

echo "$next" >VERSION
tag=v$next
folder=$(release_dir "$next")

scripts/notarize.sh
scripts/publish.sh

git add VERSION
git diff --cached --quiet || git commit -m "Release $next"
git tag -a "$tag" -m "Rackpulse $next"
git push origin HEAD "$tag"
gh release create "$tag" "$folder/Rackpulse-$next.dmg" --title "Rackpulse $next" --notes-file "$folder/Rackpulse-$next.md"
echo "Released $next: $SITE_URL/download/Rackpulse.dmg"
