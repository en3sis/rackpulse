#!/bin/sh
set -eu

release_key='
'

main() {
  base=${RACKPULSE_AGENT_URL:-https://rackpulse.app/agent}
  installed=/usr/local/bin/rackpulse-agent
  allow_downgrade=no
  for arg do
    shift
    if [ "$arg" = "--allow-downgrade" ]; then
      allow_downgrade=yes
      continue
    fi
    set -- "$@" "$arg"
  done

  if [ "$(uname -s)" != "Linux" ]; then
    echo "The Rackpulse agent runs on Linux servers. Run this command on the server, not on this computer." >&2
    exit 1
  fi

  if [ "$(id -u)" -ne 0 ]; then
    echo "Run this script as root, for example: curl -fsSL $base/install.sh | sudo sh -s -- --pair <key>" >&2
    exit 1
  fi

  machine=$(uname -m)
  case "$machine" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
      echo "Unsupported architecture: $machine. The Rackpulse agent runs on x86_64 and arm64" >&2
      exit 1
      ;;
  esac

  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum is missing. Install coreutils and run the command again" >&2
    exit 1
  fi

  if [ -z "$(printf %s "$release_key" | tr -d '[:space:]')" ]; then
    echo "This install.sh has no release key, so it cannot check the download. Use the install command from Rackpulse" >&2
    exit 1
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is missing. The installer needs it to check the signature of the download. Install it (apt-get install openssl, or apk add openssl) and run the command again" >&2
    exit 1
  fi

  name=rackpulse-agent-linux-$arch
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM

  echo "Downloading $name from $base"
  fetch "$base/$name" "$tmp/rackpulse-agent"
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
  fetch "$base/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig"

  printf '%s\n' "$release_key" >"$tmp/release-key.pem"
  if ! openssl dgst -sha256 -verify "$tmp/release-key.pem" -signature "$tmp/SHA256SUMS.sig" "$tmp/SHA256SUMS" >/dev/null 2>&1; then
    echo "Signature check failed for SHA256SUMS. Nothing was installed. If a new agent was published in the last few minutes, try again in a few minutes. Otherwise the download is incomplete or was not published by Rackpulse" >&2
    exit 1
  fi

  expected=$(awk -v file="$name" '$2 == file || $2 == "*" file { print $1 }' "$tmp/SHA256SUMS")
  actual=$(sha256sum "$tmp/rackpulse-agent" | awk '{ print $1 }')
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "Checksum check failed for $name. The download is incomplete or changed. Try again" >&2
    exit 1
  fi

  chmod 755 "$tmp/rackpulse-agent"
  if [ -e "$installed" ] && [ "$allow_downgrade" != yes ]; then
    new_version=$(agent_version "$tmp/rackpulse-agent")
    old_version=$(agent_version "$installed")
    status=0
    older "$new_version" "$old_version" || status=$?
    case $status in
      0)
        echo "The download is agent ${new_version}, older than the installed ${old_version}. Nothing was installed. To install the older version on purpose, add --allow-downgrade" >&2
        exit 1
        ;;
      1) ;;
      *)
        echo "Cannot compare the installed agent version (${old_version:-unknown}) with the download (${new_version:-unknown}). Nothing was installed. To install it anyway, add --allow-downgrade" >&2
        exit 1
        ;;
    esac
  fi
  "$tmp/rackpulse-agent" install "$@" </dev/null
}

agent_version() {
  "$1" version 2>/dev/null | sed -n 's/^rackpulse-agent //p' | head -n 1 || true
}

older() {
  new=$(printf '%s\n' "$1" | sed -n 's/^\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\)\([-+].*\)\{0,1\}$/\1 \2 \3/p')
  old=$(printf '%s\n' "$2" | sed -n 's/^\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\)\([-+].*\)\{0,1\}$/\1 \2 \3/p')
  if [ -z "$new" ] || [ -z "$old" ]; then
    return 2
  fi
  set -- $new $old
  if [ "$1" -ne "$4" ]; then
    [ "$1" -lt "$4" ] && return 0 || return 1
  fi
  if [ "$2" -ne "$5" ]; then
    [ "$2" -lt "$5" ] && return 0 || return 1
  fi
  [ "$3" -lt "$6" ] && return 0 || return 1
}

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    echo "Install curl or wget and run the command again" >&2
    exit 1
  fi
}

main "$@"
