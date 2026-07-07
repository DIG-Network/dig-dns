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
