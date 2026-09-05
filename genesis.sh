#!/usr/bin/env bash
# genesis.sh — admit the Recurse Charter as the first act on its own log.
#
# Usage (from the r5e-kernel directory, with r5e-core as a sibling):
#   ./genesis.sh rehearse    # full dry run: throwaway data dir + port, safe to repeat
#   ./genesis.sh real        # the actual genesis: refuses to run if a log already exists
#
# Rehearsal and real run the SAME code path. Rehearse until boring, then real.
# The script never commits or pushes anything. Those acts are yours.

set -euo pipefail

MODE="${1:-}"
[[ "$MODE" == "rehearse" || "$MODE" == "real" ]] || {
  echo "usage: $0 rehearse|real" >&2; exit 2; }

ACTOR="${R5E_GENESIS_ACTOR:-person:thomas}"
KERNEL_DIR="$(pwd)"
CORE_DIR="$(cd "$KERNEL_DIR/../r5e-core" 2>/dev/null && pwd)" || {
  echo "ABORT: ../r5e-core not found. Run this from r5e-kernel with r5e-core as a sibling." >&2; exit 1; }

CHARTER="$CORE_DIR/CHARTER.md"
STATEMENT="${R5E_SIGNING_STATEMENT:-$CORE_DIR/SIGNING-STATEMENT.md}"

# ---------- prerequisites ----------
for bin in elixir mix curl jq sha256sum; do
  command -v "$bin" >/dev/null || { echo "ABORT: missing dependency: $bin" >&2; exit 1; }
done
[[ -f "$KERNEL_DIR/mix.exs" ]] || { echo "ABORT: not in r5e-kernel (no mix.exs here)." >&2; exit 1; }
[[ -f "$CHARTER" ]]   || { echo "ABORT: charter not found at $CHARTER" >&2; exit 1; }
[[ -f "$STATEMENT" ]] || { echo "ABORT: signing statement not found at $STATEMENT" >&2
                           echo "       (set R5E_SIGNING_STATEMENT=path to override)" >&2; exit 1; }

# The genesis charter must not still be a draft, and must not still carry
# template placeholders. Rehearsal warns; real refuses.
refuse_or_warn() {
  if [[ "$MODE" == "real" ]]; then echo "ABORT: $1" >&2; exit 1; else echo "WARN (rehearsal): $1" >&2; fi
}
grep -qi 'DRAFT' <<<"$(head -5 "$CHARTER")" && refuse_or_warn "charter header still says DRAFT"
grep -q '<CHARTER-CANONICAL-HASH>\|<KEY-FINGERPRINT>' "$STATEMENT" \
  && refuse_or_warn "signing statement still contains template placeholders"

# ---------- mode setup ----------
if [[ "$MODE" == "rehearse" ]]; then
  DATA_DIR="$KERNEL_DIR/.r5e-genesis-rehearsal"
  PORT="${R5E_PORT:-4571}"
  rm -rf "$DATA_DIR"
  echo "== REHEARSAL == throwaway state in $DATA_DIR, port $PORT. Repeat freely."
else
  DATA_DIR="$KERNEL_DIR/.r5e"
  PORT="${R5E_PORT:-4545}"
  # A pre-minted key is expected: you booted once to mint it and pasted its
  # fingerprint into the statement. That boot also wrote the kernel's own
  # bootstrap event (KindDefinition admitting itself) -- one event, idempotent
  # on replay. Genesis is the first act AFTER the kernel's self-bootstrap, so
  # the real guard is checked after boot: no Charter Kind may exist yet.
  echo "== GENESIS == state will land in $DATA_DIR, port $PORT."
fi

BASE="http://localhost:$PORT"

# ---------- start the kernel ----------
echo "-- mix deps.get (quiet) --"
mix deps.get >/dev/null

R5E_DATA_DIR="$DATA_DIR" R5E_PORT="$PORT" mix run --no-halt &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

for i in $(seq 1 60); do
  curl -sf "$BASE/apis" >/dev/null 2>&1 && break
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "ABORT: kernel died during boot." >&2; exit 1; }
  sleep 1
  [[ $i == 60 ]] && { echo "ABORT: kernel not answering on $BASE after 60s." >&2; exit 1; }
done
echo "-- kernel up on $BASE --"

# Genesis happens once. If a Charter Kind is already admitted on this log,
# this is not genesis; it is a re-run, and the log is not a place to pretend.
if curl -sS "$BASE/apis" | jq -e '.kinds[]? | select(.group=="core.r5e.io" and .kind=="Charter")' >/dev/null 2>&1; then
  echo "ABORT: a Charter Kind already exists on this log -- genesis already happened here." >&2
  echo "       Amend the charter through the pipeline (principle 4); do not re-run genesis." >&2
  exit 1
fi
echo "-- no Charter Kind yet: this is genesis --"

# ---------- the key ----------
PUB="$DATA_DIR/keys/node_ed25519.pub"
[[ -f "$PUB" ]] || { echo "ABORT: no public key at $PUB after boot." >&2; exit 1; }
FPR="sha256:$(sha256sum "$PUB" | cut -d' ' -f1)"
CHARTER_SHA="sha256:$(sha256sum "$CHARTER" | cut -d' ' -f1)"

echo
echo "   YOUR KEY (fingerprint): $FPR"
echo "   CHARTER file hash:      $CHARTER_SHA"
echo

if [[ "$MODE" == "real" ]]; then
  grep -q "$CHARTER_SHA" "$STATEMENT" || { echo "ABORT: signing statement does not contain the charter hash $CHARTER_SHA" >&2
    echo "       Paste it in, read it once more, run again." >&2; exit 1; }
  grep -q "$FPR" "$STATEMENT" || { echo "ABORT: signing statement does not contain YOUR key fingerprint $FPR" >&2
    echo "       The key lives under $DATA_DIR/keys/. Paste the fingerprint into the statement — that is part of the act." >&2; exit 1; }
fi

api() { # api METHOD PATH JSON_BODY
  curl -sS -X "$1" "$BASE$2" \
    -H 'content-type: application/json' \
    -H "x-r5e-actor: $ACTOR" \
    -H "x-r5e-key-fingerprint: $FPR" \
    -d "$3"
}

check_admitted() { # check_admitted LABEL RESPONSE_JSON
  local outcome; outcome="$(jq -r '.outcome // .receipt.outcome // empty' <<<"$2")"
  if [[ "$outcome" != "admitted" ]]; then
    echo "ABORT: $1 was not admitted. Full response:" >&2
    jq . <<<"$2" >&2 || echo "$2" >&2
    exit 1
  fi
  echo "-- $1: admitted --"
}

# ---------- 1. define the Charter Kind (explicit scope — genesis must not be 'scope: defaulted') ----------
KIND_BODY=$(jq -n '{spec: {
  group: "core.r5e.io", kind: "Charter", version: "v1", substrate: "resource",
  schema: {
    required: ["title", "version", "content", "signingStatement"],
    properties: {
      title: {type: "string"}, version: {type: "string"},
      sourceFile: {type: "string"}, sourceSha256: {type: "string"},
      content: {type: "string"}, signingStatement: {type: "string"}
    }
  },
  epistemicScope: {
    claims: [
      "this content is the charter text the recorded actor admitted at this version, at the recorded position on the chain",
      "the signing statement travels with the charter whose signature it scopes"
    ],
    doesNotClaim: [
      "finality -- principle 4 governs supersession, in public, never silently",
      "soundness of the principles themselves -- a signature proves who stood behind the words and when, never that the words are right"
    ]
  }
}}')
RESP=$(api POST /apis/core.r5e.io/v1/KindDefinition "$KIND_BODY")
check_admitted "Charter Kind" "$RESP"

# ---------- 2. admit the charter, statement riding with it ----------
INSTANCE_BODY=$(jq -n \
  --rawfile content "$CHARTER" \
  --rawfile statement "$STATEMENT" \
  --arg sha "$CHARTER_SHA" \
  '{name: "charter-v1", spec: {
     title: "The Recurse Charter", version: "1",
     sourceFile: "CHARTER.md", sourceSha256: $sha,
     content: $content, signingStatement: $statement }}')
RESP=$(api POST /apis/core.r5e.io/v1/Charter "$INSTANCE_BODY")
check_admitted "Charter v1" "$RESP"
echo "$RESP" | jq . > "$KERNEL_DIR/genesis-receipt.$MODE.json"

# ---------- 3. the chain, for your eyes ----------
echo "-- the chain so far --"
curl -sS "$BASE/events" | jq -r '.events[] | "\(.seq)  \(.kind)  \(.hash)"' \
  || curl -sS "$BASE/events" | jq .

# ---------- 4. export + offline verification ----------
EXPORT=$(curl -sS -X POST "$BASE/export" -H 'content-type: application/json' -d '{}')
BUNDLE=$(jq -r '.bundle // empty' <<<"$EXPORT")
[[ -n "$BUNDLE" ]] || { echo "ABORT: export returned no bundle path:" >&2; jq . <<<"$EXPORT" >&2; exit 1; }
echo "-- bundle: $BUNDLE --"

cleanup; trap - EXIT   # server down before verifying: the point is offline

VERIFY_OUT="$KERNEL_DIR/genesis-verification.$MODE.txt"
STANDALONE="$CORE_DIR/verifier/recurse_verify"
if [[ -x "$STANDALONE" ]]; then
  "$STANDALONE" "$BUNDLE" | tee "$VERIFY_OUT"
else
  mix r5e.verify "$BUNDLE" | tee "$VERIFY_OUT"
fi

# ---------- summary ----------
echo
echo "================= $MODE complete ================="
echo "  key fingerprint : $FPR"
echo "  charter hash    : $CHARTER_SHA"
echo "  bundle          : $BUNDLE"
echo "  receipt         : $KERNEL_DIR/genesis-receipt.$MODE.json"
echo "  verifier output : $VERIFY_OUT  (read it end to end — the not-checked block is part of the truth)"
if [[ "$MODE" == "real" ]]; then
  cat <<NEXT
  What remains, and it is yours alone:
    1. Back up the private key ($DATA_DIR/keys/node_ed25519.key). It is the only copy on earth.
    2. Copy the bundle + receipt + verifier output into r5e-core/genesis/, review the diff.
    3. Commit. Push. That's the signature landing in public.
NEXT
else
  echo "  Rehearsal state is throwaway: rm -rf $DATA_DIR when done inspecting."
fi
