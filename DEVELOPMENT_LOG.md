# dig-dns — development log

High-signal, durable realizations (not a change diary). Keep entries concise + verified.

## TLS: rustls + **ring**, never aws-lc-rs

`release.yml` cross-compiles the `x86_64-apple-darwin` binary on an arm64 macOS runner and
requires every target to build with NO cross C-toolchain. `aws-lc-rs` (rustls 0.23's DEFAULT
provider) needs cmake + a C compiler and cross-compiles poorly to that target; `ring` ships
prebuilt asm and cross-compiles cleanly. So the node transport pins:

- `reqwest = { default-features = false, features = ["json", "rustls-tls-webpki-roots-no-provider"] }`
- `rustls = { default-features = false, features = ["ring", "std", "tls12", "logging"] }`

`cargo tree -i aws-lc-rs` MUST be empty; `-i ring` MUST be present; `-i openssl-sys` empty.

Because the reqwest feature is `*-no-provider`, a rustls `CryptoProvider` MUST be installed
before the FIRST `reqwest::Client` is built or the build panics. `transport::init_crypto()`
installs ring's default provider exactly once (`std::sync::Once`); every client constructor
(`ReqwestNodeClient::{resolve, with_base}`) calls it. Plain-HTTP local tiers still trigger this
(reqwest builds a TLS config eagerly), so it is not optional even for `http://` nodes.

## hyper 1 suppresses the HEAD response body automatically

hyper's http1 server drops the response body for a `HEAD` request and derives `Content-Length`
from the `Full<Bytes>` body's known size. So `serve_store` builds the SAME full response for GET
and HEAD (fetch + decrypt to know the length) and lets hyper strip the bytes — do NOT special-
case HEAD in the response builder. (Unit tests assert the full body; the integration test
asserts the real HEAD-over-socket body is empty.)

## The DIG "decoy" not-found model → SPA vs fail-closed

A dig-node serves a MISS as decoy ciphertext carrying a VALID merkle proof that folds to the
store's real anchored root (all real resources AND decoys are leaves in ONE tree with ONE root
per generation) — the decoy simply fails GCM-SIV decryption under the URN key. Therefore the
gateway maps content outcomes as:

- proof verifies + decrypt succeeds → serve bytes;
- proof verifies + **decrypt fails** (`ContentError::Decrypt`) OR node `-32004`/`-32005` →
  "not found" → SPA catch-all (extensionless → `/index.html`, else 404);
- proof/root/chunk **mismatch** (`RootMismatch`/`ProofFoldMismatch`/`ProofLeafMismatch`/
  `ChunkLenMismatch`) → the node served content inconsistent with the trusted root → **502**,
  fail-closed, never serve unverified bytes.

To reproduce a decoy in a test, put the real leaf AND a non-GCM decoy leaf in the same
`MerkleTree` and prove each to the shared root — a standalone single-leaf decoy tree has a
DIFFERENT root and (correctly) trips the 502 integrity path instead.

## Host forms + the latest-root TOCTOU pin

`<store>.dig` = latest (call `dig.getAnchoredRoot`); `<root>.<store>.dig` = pinned (the LEFTMOST
label is the root; skip `getAnchoredRoot`, use it as the trusted root). For BOTH forms the
gateway passes the resolved/trusted root into `dig.getContent { …, root }` so the served
generation matches the verified root — this pins a latest read against the tip advancing between
the `getAnchoredRoot` and `getContent` calls. Latest responses are `Cache-Control: no-cache`;
pinned (content-hash) responses are `immutable`.

## hyper `Uri` parses a bare host as authority-form

`"abc.dig".parse::<Uri>()` yields `authority = Some("abc.dig")`, `scheme = None` (authority-form,
like a CONNECT target). So an absolute/proxy URL is distinguished by `uri.scheme().is_some()`,
NOT by `authority().is_some()`. `classify` uses `scheme && authority`; `server::split_target`
requires a scheme before treating a `fetch` target as a full URL.

## reqwest honors an explicit `Host` header override

Setting `.header("host", "<label>.dig")` on a reqwest request to the gateway's real
`127.0.0.1:<port>` address sends origin-form with that Host — so Path A (origin-form) is testable
over a real socket without OS DNS. Path B is tested via `reqwest::Proxy::http(gateway)`.

## DNS responder: hand-rolled codec, constant-time wildcard

The `.dig` DNS answer is a constant `A <loopback_ip>` (or NODATA/REFUSED), so a full DNS library
is unnecessary — a single-question parser + a compression-pointer answer suffices and is
byte-level testable. Key details:

- The answer RR name is a compression pointer `0xC0 0x0C` → offset 12 (the question always starts
  right after the 12-byte header), so we never re-encode the name.
- **0x20 case preservation**: echo the request's raw question bytes verbatim (`msg[12..q_end]`)
  into the response — do NOT re-encode from the decoded labels.
- Answer `A` for a `.dig` name of **any base32-label validity** (DNS stays a cheap wildcard; the
  gateway does the 404 for a bad label). "Under the TLD" = the LAST label equals the tld
  (case-insensitive) — so `dig`/`x.dig`/`a.b.dig` match but `digfoo` and `x.com` do not.
- EDNS0 OPT is echoed (root name + type 41). TC only fires when a UDP response exceeds the
  advertised payload size — with our ~tiny answers that never happens for real 512+ clients, so
  TC is tested by crafting a query advertising a sub-response EDNS size.
- DNS-over-TCP is length-prefixed (2-byte big-endian length) and never truncates.

## `doctor`: two-path liveness + cross-OS probes without `#[cfg]`

`doctor` splits DECISION logic (pure `evaluate_*` + `Report::build`, ~100% unit-tested) from the
LIVE probes (bind loopback, DNS query, OS getaddrinfo, gateway probe, browser-policy read, `:80`
holder). Overall outcome = `loopback_up && (path_a || path_b)` — a `.dig` URL loads iff the IP is
up and at least one path is live; individual link fails/warns explain WHY. `path_a` = OS routing
returns the IP (needs the installer's split-DNS, so it WARNs on a dev box); `path_b` = the gateway
answered `/.dig/resolve-probe`.

The OS-specific probes (browser DoH policy, `:80` holder) branch on `std::env::consts::OS` at
RUNTIME and shell out via `std::process::Command` / `std::fs` — deliberately NO `#[cfg]` blocks,
so the code compiles identically on every release target (the `#[cfg(windows)]`/`#[cfg(macos)]`
paths would only be compiled by the release matrix, not ubuntu CI clippy — a runtime branch is
checked everywhere and a missing tool just degrades to "unknown"). Gotcha: a `:80` port-holder
substring match hits `:8000`/`:8080` — require the char after `:{port}` to be a non-digit.

## `dig-dns pac` embeds the ACTUAL bound port

The PAC must advertise the port the gateway actually bound (which may be the `:8053` fallback).
`dig-dns pac` uses `--port` if given, else PROBES the running gateway (`server::probe_gateway_port`
tries `/.dig/resolve-probe` on primary then fallback), else the configured `http_port`. The
running gateway's own `/.dig/proxy.pac` endpoint is the other source (it already knows its bound
port). Windows gotcha: `Invoke-WebRequest` returns `.Content` as BYTES for the PAC's
`application/x-ns-proxy-autoconfig` content-type — use `.RawContent` (always a string) when
grepping PAC output in PowerShell.

## `serve` runs BOTH paths; the DNS bind is non-fatal

`server::run_service` brings up the gateway AND the DNS responder. The two resolution paths are
independent, so a `:53` bind failure (unprivileged run, or `:53` already held) is logged and
`serve` continues **gateway-only** — Path B (the PAC proxy) still serves `.dig`. `/.dig/health`
`paths.dns` reflects whether the responder actually bound. For a local unprivileged run, override
`DIG_DNS_IP=127.0.0.1` + high `DIG_DNS_DNS_PORT`/`DIG_DNS_HTTP_PORT`. (Do NOT smoke-test `serve`
by backgrounding it from the Bash tool on Windows — the process is not reaped and hangs the
shell; the socket integration tests are the real evidence.)
