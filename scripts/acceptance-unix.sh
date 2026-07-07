#!/usr/bin/env sh
# dig-dns runtime acceptance for macOS + Linux (curl + dig).
#
# Starts `dig-dns serve` (gateway + DNS) unprivileged on high loopback ports and proves the
# runtime end-to-end, no installer / OS config needed:
#   - `dig-dns doctor` reports a live path (exit 0);
#   - the /.dig/ control endpoints answer (resolve-probe 204, proxy.pac PROXY line, health 200);
#   - an absolute-form proxy to a non-.dig target is refused with 403 (never an open proxy);
#   - a syntactically invalid .dig host is a fast 404;
#   - the DNS responder answers `<name>.dig` → 127.0.0.5 (via `dig` when available, else doctor).
#
# The CONTENT checks (origin/proxy fetch + the pinned-vs-latest proof) need a live dig-node with
# the store: set STORE_LABEL (and, for the pin, ROOT_LABEL) + NODE. Otherwise they are skipped
# and the exact curl commands are printed. The Rust tests prove all of it deterministically.
#
# Env: PORT (gateway, default 18080), DNS_PORT (default 15353), NODE (dig-node override),
#      STORE_LABEL / ROOT_LABEL (52-char base32), TLD (default dig), DIG_DNS_BIN.

set -eu

TLD="${TLD:-dig}"
PORT="${PORT:-18080}"
DNS_PORT="${DNS_PORT:-15353}"
SERVED_IP="127.0.0.1"
GATEWAY="http://127.0.0.1:$PORT"
PASS=0
FAIL=0
SRV_PID=""

log()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$*"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

cleanup() {
  [ -n "$SRV_PID" ] && { kill "$SRV_PID" 2>/dev/null || true; wait "$SRV_PID" 2>/dev/null || true; }
}
trap cleanup EXIT INT TERM

BIN="${DIG_DNS_BIN:-target/debug/dig-dns}"
if [ ! -x "$BIN" ]; then
  log "building dig-dns…"
  cargo build --quiet
  BIN="target/debug/dig-dns"
fi

log "starting: $BIN serve on ${SERVED_IP} (gateway :$PORT, dns :$DNS_PORT) ${NODE:+--node $NODE}"
DIG_DNS_IP="$SERVED_IP" DIG_DNS_HTTP_PORT="$PORT" DIG_DNS_HTTP_FALLBACK_PORT="$PORT" \
  DIG_DNS_DNS_PORT="$DNS_PORT" "$BIN" serve ${NODE:+--node "$NODE"} >/dev/null 2>&1 &
SRV_PID=$!

# Wait for the gateway liveness probe.
i=0
while [ "$i" -lt 60 ]; do
  [ "$(code "$GATEWAY/.dig/resolve-probe")" = "204" ] && break
  i=$((i + 1)); sleep 0.1
done

log ""
log "== doctor =="
if env DIG_DNS_IP="$SERVED_IP" DIG_DNS_HTTP_PORT="$PORT" DIG_DNS_HTTP_FALLBACK_PORT="$PORT" \
     DIG_DNS_DNS_PORT="$DNS_PORT" DIG_DNS_TLD="$TLD" "$BIN" doctor >/tmp/dig-dns-doctor.txt 2>&1; then
  ok "doctor: a .dig URL can load (exit 0)"
else
  bad "doctor reports no live path (see /tmp/dig-dns-doctor.txt)"
fi
sed 's/^/        /' /tmp/dig-dns-doctor.txt 2>/dev/null || true

log ""
log "== control + open-proxy safety =="
[ "$(code "$GATEWAY/.dig/resolve-probe")" = "204" ] && ok "/.dig/resolve-probe → 204" || bad "resolve-probe not 204"
curl -s "$GATEWAY/.dig/proxy.pac" | grep -q "PROXY " && ok "/.dig/proxy.pac advertises a PROXY line" || bad "proxy.pac missing PROXY"
[ "$(code "$GATEWAY/.dig/health")" = "200" ] && ok "/.dig/health → 200" || bad "health not 200"
[ "$(code -x "$GATEWAY" "http://example.com/")" = "403" ] && ok "proxy http://example.com/ → 403" || bad "non-.dig proxy not 403"
[ "$(code -H "Host: not-a-valid-label.$TLD" "$GATEWAY/")" = "404" ] && ok "invalid .$TLD host → 404" || bad "invalid host not 404"

log ""
log "== DNS responder =="
if command -v dig >/dev/null 2>&1; then
  ANS="$(dig @"$SERVED_IP" -p "$DNS_PORT" "probe.$TLD" +short 2>/dev/null | head -1)"
  [ "$ANS" = "127.0.0.5" ] && ok "dig @$SERVED_IP -p $DNS_PORT probe.$TLD → 127.0.0.5" \
    || bad "dig returned '$ANS' (expected 127.0.0.5)"
  if dig @"$SERVED_IP" -p "$DNS_PORT" example.com 2>/dev/null | grep -q "REFUSED"; then
    ok "dig example.com → REFUSED"
  else
    bad "example.com not REFUSED"
  fi
else
  log "  SKIP  \`dig\` not installed — doctor's dns_direct check above covers the responder"
fi

log ""
log "== content + pinned-vs-latest (needs a live dig-node with the store) =="
if [ -z "${STORE_LABEL:-}" ]; then
  log "  SKIP  set STORE_LABEL=<52-char base32> (+ NODE) to run these. Commands:"
  log "        origin: curl -H 'Host: <STORE_LABEL>.$TLD' $GATEWAY/"
  log "        proxy:  curl -x $GATEWAY http://<STORE_LABEL>.$TLD/"
  log "        pinned: curl -H 'Host: <ROOT_LABEL>.<STORE_LABEL>.$TLD' $GATEWAY/"
else
  HOST="$STORE_LABEL.$TLD"
  [ "$(code -H "Host: $HOST" "$GATEWAY/")" = "200" ] && ok "origin-form GET / → 200" || bad "origin fetch not 200"
  [ "$(code -x "$GATEWAY" "http://$HOST/")" = "200" ] && ok "proxy-form GET / → 200" || bad "proxy fetch not 200"
  if [ -n "${ROOT_LABEL:-}" ]; then
    LATEST="$(curl -s -H "Host: $HOST" "$GATEWAY/" || true)"
    PINNED="$(curl -s -H "Host: $ROOT_LABEL.$STORE_LABEL.$TLD" "$GATEWAY/" || true)"
    if [ -n "$PINNED" ] && [ "$LATEST" != "$PINNED" ]; then
      ok "pinned root differs from latest"
    else
      bad "pinned did not differ from latest"
    fi
  fi
fi

log ""
log "result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
