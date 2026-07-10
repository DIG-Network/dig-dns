//! # dig-dns — local `*.dig` name resolution
//!
//! `dig-dns` is a standalone OS service that lets a browser open
//! `http://<label>.dig/<path>` on the local machine, where `<label>` is the RFC 4648
//! base32 encoding of a 32-byte DIG store id. It resolves that store's LATEST
//! chain-anchored root and serves its resources (`/index.html` + assets, SPA-style),
//! fetching content from a **dig-node** over the node's public JSON-RPC read surface —
//! `dig-dns` is an RPC client of the node exactly as `digstore` is.
//!
//! Reliability-first: two independent resolution paths (an OS split-DNS responder AND a
//! PAC proxy the browser can be pointed at) plus a `doctor` diagnostic, so a `.dig` URL
//! still loads when one path is blocked (e.g. a browser forcing DNS-over-HTTPS).
//!
//! ## Module map
//! - [`label`] — the base32 DNS-label ↔ 32-byte-storeId codec.
//! - [`host`] — parse a `.dig` request host into a [`host::HostTarget`]: `<storeId>.dig`
//!   (latest root) or `<rootId>.<storeId>.dig` (a pinned-root capsule).
//! - [`content`] — the read path: HTTP path → resource_key → retrieval_key, and the
//!   verify-then-decrypt pipeline (byte-identical to `digstore-core` / `dig-client-wasm`).
//! - [`node`] — the dig-node read contract (PURE): JSON-RPC param builders, response parsing,
//!   windowed-content reassembly, and the §5.3 endpoint-ladder ordering.
//! - [`transport`] — the async dig-node client behind [`node`]: the `reqwest` JSON-RPC client
//!   (`ReqwestNodeClient`) that walks the ladder + pages content, and the [`transport::NodeClient`]
//!   trait the gateway serves against.
//! - [`gateway`] — the HTTP gateway request logic: classify (origin/absolute-proxy/CONNECT/
//!   control), the never-an-open-proxy rules, `/.dig/` control endpoints, and resolve+serve.
//! - [`dns`] — the DNS responder wire codec + answering policy (PURE): `*.<tld>`/apex → `A`
//!   loopback, AAAA/other → NODATA, non-`.<tld>` → REFUSED, EDNS0/TC (SPEC §3).
//! - [`dig_local`] — ensuring `http://dig.local` reaches the local dig-node (SPEC §12, PURE):
//!   the idempotent ensure decision + reverse-proxy target discovery (never `rpc.dig.net`).
//! - [`server`] — the listener glue: bind the gateway (with the `:8053` fallback) + the DNS
//!   responder (`:53`, UDP+TCP) + the ensured `dig.local` reverse proxy, accept, and adapt
//!   hyper requests to [`gateway::handle`].
//! - [`doctor`] — the `doctor` diagnostic (SPEC §9): independent per-link checks of both paths
//!   with fix hints + `--json`, exiting non-zero when a `.dig` URL cannot load.
//! - [`pac`] — Proxy Auto-Config generation for Path B (the PAC control endpoint + CLI).
//! - [`config`] — service configuration: loopback IP / ports / TLD / node endpoint,
//!   with flag → env → file override precedence.
//! - [`cli`] — the `dig-dns` binary's command surface (grows per phase).
//!
//! `doctor` (Phase 4) + the PAC CLI (Phase 5) land in later phases, composing these modules;
//! the binary stays a thin shell over a fully unit-tested library.
//!
//! The contract this library implements is normative in `SPEC.md`.

pub mod cli;
pub mod config;
pub mod content;
pub mod dig_local;
pub mod dns;
pub mod doctor;
pub mod gateway;
pub mod host;
pub mod label;
pub mod node;
pub mod pac;
pub mod server;
pub mod transport;
