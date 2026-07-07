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
//! - [`node`] — the dig-node read contract: JSON-RPC param builders, response parsing,
//!   windowed-content reassembly, and the §5.3 endpoint-ladder ordering.
//! - [`config`] — service configuration: loopback IP / ports / TLD / node endpoint,
//!   with flag → env → file override precedence.
//! - [`cli`] — the `dig-dns` binary's command surface (grows per phase).
//!
//! The HTTP gateway server, DNS responder, `doctor`, and PAC generator land in later phases,
//! composing these modules; the binary stays a thin shell over a fully unit-tested library.
//!
//! The contract this library implements is normative in `SPEC.md`.

pub mod cli;
pub mod config;
pub mod content;
pub mod host;
pub mod label;
pub mod node;
