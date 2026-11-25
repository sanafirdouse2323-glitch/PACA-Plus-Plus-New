#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
JAR="${TLA2TOOLS_JAR:-${TMPDIR:-/tmp}/paca-tla2tools-1.7.4.jar}"
URL="https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"

if [[ ! -s "$JAR" ]]; then
  mkdir -p "$(dirname -- "$JAR")"
  TMP_JAR="${JAR}.tmp.$$"
  trap 'rm -f "$TMP_JAR"' EXIT
  curl --fail --location --silent --show-error "$URL" --output "$TMP_JAR"
  echo "$SHA256  $TMP_JAR" | sha256sum --check --status || {
    echo "TLA+ tools checksum mismatch; refusing to install TLC." >&2
    exit 1
  }
  mv -- "$TMP_JAR" "$JAR"
  trap - EXIT
fi

echo "$SHA256  $JAR" | sha256sum --check --status || {
  echo "TLA+ tools checksum mismatch; refusing to run TLC." >&2
  exit 1
}

cd "$ROOT/models"
java -jar "$JAR" -config PACAAuth.cfg PACAAuth.tla
java -jar "$JAR" -config PACALifecycle.cfg PACALifecycle.tla
java -jar "$JAR" -config PACABroker.cfg PACABroker.tla
java -jar "$JAR" -config PACAGrant.cfg PACAGrant.tla
java -jar "$JAR" -config PACAInfoFlow.cfg PACAInfoFlow.tla
