#!/usr/bin/env sh
# dig-dns Phase 2b HTTP-gateway acceptance (curl).
#
# Proves the gateway contract end-to-end with curl, no installer / OS DNS needed:
#   - origin-form (Host header) AND absolute-form proxy (-x) both resolve a .dig host;
#   - a non-.dig proxy target is refused with 403 (never an open proxy);
#   - the /.dig/ control endpoints answer (resolve-probe 204, proxy.pac 200, health 200);
#   - a syntactically invalid .dig host is a fast 404.
#
# The control + open-proxy checks need NO dig-node (they never fetch store content) and run
# by default. The CONTENT checks (origin/proxy fetch + the pinned-vs-latest proof) need a live
# dig-node holding a store; set STORE_LABEL (and, for the pinned proof, ROOT_LABEL) to run them
# — otherwise they are skipped and the exact curl commands are printed. (The Rust integration
# test `tests/gateway_stub_node.rs` proves all of it deterministically against a stub node.)
#
# Usage:
#   scripts/gateway-acceptance.sh
#   GATEWAY=http://127.0.0.5:80 scripts/gateway-acceptance.sh            # use a running gateway
#   NODE=http://localhost:9778 STORE_LABEL=<52b32> ROOT_LABEL=<52b32> \
#     scripts/gateway-acceptance.sh                                       # full, live node
#
# Env:
#   GATEWAY      base URL of an already-running gateway. If unset, this script starts one
#                unprivileged on 127.0.0.1:$PORT and stops it at the end.
#   PORT         port for the self-started gateway (default 8080; :80 needs elevation).
#   NODE         dig-node endpoint override passed to `dig-dns serve --node`.
#   STORE_LABEL  a 52-char base32 store label to run the content checks.
#   ROOT_LABEL   a 52-char base32 root label to run the pinned-vs-latest proof.
#   TLD          the browsable TLD (default dig).
#   DIG_DNS_BIN  path to the dig-dns binary (default: target/debug/dig-dns).

set -eu

TLD="${TLD:-dig}"
PORT="${PORT:-8080}"
PASS=0
FAIL=0
STARTED_PID=""

log()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$*"; }

# code METHOD_ARGS...  -> prints the HTTP status code for a curl invocation.
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

cleanup() {
  if [ -n "$STARTED_PID" ]; then
    kill "$STARTED_PID" 2>/dev/null || true
    wait "$STARTED_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# --- Bring up a gateway if one was not provided ------------------------------------------
if [ -z "${GATEWAY:-}" ]; then
  BIN="${DIG_DNS_BIN:-target/debug/dig-dns}"
  if [ ! -x "$BIN" ]; then
    log "building dig-dns (release the acceptance from a prebuilt bin via DIG_DNS_BIN=…)"
    cargo build --quiet
    BIN="target/debug/dig-dns"
  fi
  log "starting: $BIN serve on 127.0.0.1:$PORT ${NODE:+(--node $NODE)}"
  DIG_DNS_IP=127.0.0.1 DIG_DNS_HTTP_PORT="$PORT" DIG_DNS_HTTP_FALLBACK_PORT="$PORT" \
    "$BIN" serve ${NODE:+--node "$NODE"} >/dev/null 2>&1 &
  STARTED_PID=$!
  GATEWAY="http://127.0.0.1:$PORT"
  # Wait for the gateway to answer its liveness probe.
  i=0
  while [ "$i" -lt 50 ]; do
    if [ "$(code "$GATEWAY/.dig/resolve-probe")" = "204" ]; then break; fi
    i=$((i + 1)); sleep 0.1
  done
fi

log "gateway: $GATEWAY  tld: .$TLD"
log ""
log "== control + open-proxy safety (no dig-node required) =="

# resolve-probe → 204
[ "$(code "$GATEWAY/.dig/resolve-probe")" = "204" ] \
  && ok "/.dig/resolve-probe → 204" || bad "/.dig/resolve-probe not 204"

# proxy.pac → 200 and advertises the gateway as a PROXY
PAC="$(curl -s "$GATEWAY/.dig/proxy.pac" || true)"
echo "$PAC" | grep -q "PROXY " \
  && ok "/.dig/proxy.pac → advertises a PROXY line" || bad "/.dig/proxy.pac missing PROXY line"

# health → 200 JSON
[ "$(code "$GATEWAY/.dig/health")" = "200" ] \
  && ok "/.dig/health → 200" || bad "/.dig/health not 200"

# absolute-form proxy to a NON-.dig authority → 403 (never an open proxy)
[ "$(code -x "$GATEWAY" "http://example.com/")" = "403" ] \
  && ok "proxy http://example.com/ → 403 (not an open proxy)" \
  || bad "non-.dig proxy target was not 403"

# a syntactically invalid .dig host (origin-form) → fast 404, no node I/O
[ "$(code -H "Host: not-a-valid-label.$TLD" "$GATEWAY/")" = "404" ] \
  && ok "invalid .$TLD host → 404" || bad "invalid host not 404"

log ""
log "== content + pinned-vs-latest (needs a live dig-node with the store) =="
if [ -z "${STORE_LABEL:-}" ]; then
  log "  SKIP  set STORE_LABEL=<52-char base32> (and NODE) to run these. Commands:"
  log "        origin: curl -H 'Host: <STORE_LABEL>.$TLD' $GATEWAY/"
  log "        proxy:  curl -x $GATEWAY http://<STORE_LABEL>.$TLD/"
  log "        pinned: curl -H 'Host: <ROOT_LABEL>.<STORE_LABEL>.$TLD' $GATEWAY/"
else
  HOST="$STORE_LABEL.$TLD"

  # origin-form fetch of /
  [ "$(code -H "Host: $HOST" "$GATEWAY/")" = "200" ] \
    && ok "origin-form GET / (Host: $HOST) → 200" || bad "origin-form fetch not 200"

  # absolute-form proxy fetch of /
  [ "$(code -x "$GATEWAY" "http://$HOST/")" = "200" ] \
    && ok "proxy-form GET http://$HOST/ → 200" || bad "proxy-form fetch not 200"

  # pinned-vs-latest: the pinned host must serve a DIFFERENT body than latest (after advance)
  if [ -n "${ROOT_LABEL:-}" ]; then
    PIN_HOST="$ROOT_LABEL.$STORE_LABEL.$TLD"
    LATEST_BODY="$(curl -s -H "Host: $HOST" "$GATEWAY/" || true)"
    PINNED_BODY="$(curl -s -H "Host: $PIN_HOST" "$GATEWAY/" || true)"
    if [ -n "$PINNED_BODY" ] && [ "$LATEST_BODY" != "$PINNED_BODY" ]; then
      ok "pinned <root>.<store>.$TLD differs from latest <store>.$TLD"
    else
      bad "pinned root did not differ from latest (store may not have advanced, or root absent)"
    fi
  else
    log "  SKIP  set ROOT_LABEL to run the pinned-vs-latest proof"
  fi
fi

log ""
log "result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
