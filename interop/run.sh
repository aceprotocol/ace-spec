#!/usr/bin/env bash
# Live cross-SDK interop matrix for the ACE TypeScript, Python and Swift SDKs.
# Exits non-zero on any mismatch. See README.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"           # the directory holding sdk-ts, sdk-py, sdk-swift
SDK_TS="${SDK_TS:-$ROOT/sdk-ts}"
SDK_PY="${SDK_PY:-$ROOT/sdk-py}"
PYTHON="${PYTHON:-$SDK_PY/.venv/bin/python}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ace-interop.XXXXXX")}"
SKIP_BUILD="${SKIP_BUILD:-0}"

log() { printf '\033[1m==> %s\033[0m\n' "$*"; }

for d in "$SDK_TS" "$SDK_PY" "$ROOT/sdk-swift"; do
  [ -d "$d" ] || { echo "missing SDK checkout: $d" >&2; exit 2; }
done
[ -x "$PYTHON" ] || { echo "python not found: $PYTHON (set PYTHON=...)" >&2; exit 2; }

if [ "$SKIP_BUILD" != 1 ]; then
  log "build sdk-ts (dist/)"
  (cd "$SDK_TS" && { [ -d node_modules ] || npm ci --silent; } && npm run --silent build)
  log "build Swift harness (release)"
  (cd "$HERE/swift" && swift build -c release 2>&1 | tail -n 1)
fi
SWIFT_BIN="$(cd "$HERE/swift" && swift build -c release --show-bin-path)/ACEInterop"
[ -x "$SWIFT_BIN" ] || { echo "Swift harness not built: $SWIFT_BIN" >&2; exit 2; }

# Node >= 22.18 runs .ts directly (type stripping); otherwise fall back to tsx.
if node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=18)?0:1)'; then
  TS_RUN=(node --disable-warning=ExperimentalWarning "$HERE/ts/interop.ts")
else
  TS_RUN=(npx --yes tsx "$HERE/ts/interop.ts")
fi
PY_RUN=("$PYTHON" -X utf8 "$HERE/py/interop.py")
SW_RUN=("$SWIFT_BIN")

run_phase() {
  local phase="$1"
  log "phase $phase"
  "${TS_RUN[@]}" "$phase" "$WORK"
  PYTHONPATH="$SDK_PY" "${PY_RUN[@]}" "$phase" "$WORK"
  "${SW_RUN[@]}" "$phase" "$WORK"
}

echo "work dir: $WORK"
# Every phase runs well inside the 300 s freshness window used by registration requests,
# auth headers and direct Inbox delivery (the slow builds happen before `gen`).
run_phase gen       # 1/3/4: identities, registration files/requests, auth headers
run_phase verify    # 1/3/4: every SDK imports / verifies every other SDK's artifacts
run_phase send1     # 2: text + rfq from every sender to every receiver
log "tamper kemCiphertext"
"$PYTHON" -I "$HERE/compare.py" tamper "$WORK"
run_phase recv1     # 2: receiver parses, rejects tampered copies, replies with an offer
run_phase recv2     # 2: original sender parses the offer
run_phase persist   # 5: Inbox + FileStore receives (replay.json, threads/, peers/, deliveries/)
run_phase load      # 5: every SDK loads every other SDK's store

log "results"
set +e
"$PYTHON" -I "$HERE/compare.py" check "$WORK"
status=$?
set -e
echo "work dir: $WORK"
exit $status
