#!/usr/bin/env bash
# Live cross-SDK interop matrix (packets, receipts, contact requests). See README.md.
#   INTEROP_LANGS=ts,py[,swift]  ACE_INTEROP_SWIFT=/path/to/driver  SKIP_BUILD=1  WORK=/tmp/dir
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK_TS="$ROOT/sdk-ts"
export SDK_PY="${SDK_PY:-$ROOT/sdk-py}"
export PYTHON="${PYTHON:-$SDK_PY/.venv/bin/python}"
[ -x "$PYTHON" ] || { echo "python not found: $PYTHON (set PYTHON=...)" >&2; exit 2; }
case ",${INTEROP_LANGS:-ts}," in *,ts,*)
  node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=18)?0:1)' \
    || { echo "node >= 22.18 is required (type stripping runs ts/driver.ts)" >&2; exit 2; }
  if [ "${SKIP_BUILD:-0}" != 1 ]; then
    echo "==> build sdk-ts (dist/)"
    (cd "$SDK_TS" && { [ -d node_modules ] || npm ci --silent; } && npm run --silent build)
  fi
esac
exec "$PYTHON" -I "$HERE/matrix.py"
