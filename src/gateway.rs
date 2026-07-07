//! The HTTP gateway request logic: classify a request, enforce the never-an-open-proxy
//! rules, serve the `/.dig/` control endpoints, and resolve + serve store content.
//!
//! This module is transport-agnostic and (given a [`NodeClient`]) fully unit-testable without
//! a socket: [`handle`] maps a `(method, uri, host, range)` tuple to a [`GatewayResponse`]
//! (status + headers + body). The thin [`crate::server`] glue binds the listener and converts
//! hyper's request/response types to and from these plain structs.
//!
//! Contract: SPEC §4 (request forms, resolution, SPA catch-all, headers, control endpoints)
//! and §5 (loopback-only, never an open proxy, no CONNECT, no TLS interception).

use hyper::Uri;
use serde_json::json;

use crate::config::Config;
use crate::content::{
    content_type_for, is_extensionless, resource_key_for_path, retrieval_key_hex,
    verify_and_decrypt, ContentError,
};
use crate::host::{parse_dig_host, HostTarget};
use crate::pac::{self, PAC_CONTENT_TYPE};
use crate::transport::NodeClient;

/// This build's semver, surfaced in `/.dig/health`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A fully-built HTTP response, independent of the server transport. `headers` are
/// lowercase header-name/value pairs; the server glue writes them onto a hyper response and
/// lets hyper derive `Content-Length` (and suppress the body for `HEAD`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers (lowercase names).
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl GatewayResponse {
    /// A `text/plain` response with a short message body (used for errors + probes).
    fn text(status: u16, msg: &str) -> Self {
        GatewayResponse {
            status,
            headers: vec![(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: msg.as_bytes().to_vec(),
        }
    }

    /// A response with an explicit content type + body.
    fn with_type(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        GatewayResponse {
            status,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body,
        }
    }
}

/// Per-server runtime context threaded into request handling (cheap to clone per request).
#[derive(Debug, Clone)]
pub struct Ctx {
    /// The resolved service configuration.
    pub config: Config,
    /// The actually-bound gateway port (primary `:80` or the `:8053` fallback).
    pub bound_port: u16,
    /// Whether the DNS responder is running in this process (Phase 3+); reported in health.
    pub dns_active: bool,
    /// When the server started, for the health uptime field.
    pub started: std::time::Instant,
}

/// The reserved `/.dig/` control endpoints (SPEC §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlEndpoint {
    /// `GET /.dig/health` — machine-readable service state.
    Health,
    /// `GET /.dig/proxy.pac` — the PAC file with the actually-bound port.
    ProxyPac,
    /// `GET /.dig/resolve-probe` — a `204` liveness probe (no store fetch).
    ResolveProbe,
    /// Any other `/.dig/…` path — reserved, `404`.
    Unknown,
}

/// How a request was classified before dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// A `/.dig/…` control endpoint.
    Control(ControlEndpoint),
    /// An absolute-form (proxy) request whose authority is not under the `.<tld>` — refused
    /// with `403`; `dig-dns` is never a general forward proxy (SPEC §4.2/§5).
    NonDigProxy,
    /// The host is not a syntactically valid `<label>.<tld>` — a fast `404`, no node I/O.
    BadHost,
    /// A store content request.
    Store {
        /// The resolved target (latest or pinned root).
        target: HostTarget,
        /// The request path (used for the resource key + SPA catch-all).
        path: String,
    },
}

/// Whether a host string (sans trailing dot / `:port`) is the apex `<tld>` or ends in
/// `.<tld>` (case-insensitive). Used only for the open-proxy authority guard; full label
/// validation happens in [`parse_dig_host`].
fn host_is_under_tld(host: &str, tld: &str) -> bool {
    let h = host.trim().trim_end_matches('.');
    let h = h.split(':').next().unwrap_or(h).to_ascii_lowercase();
    let tld = tld.to_ascii_lowercase();
    h == tld || h.ends_with(&format!(".{tld}"))
}

/// Map a request path to a control endpoint, if it is under the reserved `/.dig/` namespace.
fn control_endpoint_for(path: &str) -> Option<ControlEndpoint> {
    // Compare on the path only (query string already stripped by the caller).
    match path {
        "/.dig/health" => Some(ControlEndpoint::Health),
        "/.dig/proxy.pac" => Some(ControlEndpoint::ProxyPac),
        "/.dig/resolve-probe" => Some(ControlEndpoint::ResolveProbe),
        p if p == "/.dig" || p.starts_with("/.dig/") => Some(ControlEndpoint::Unknown),
        _ => None,
    }
}

/// Classify a request from its URI + `Host` header (CONNECT is handled earlier in [`handle`]).
///
/// Absolute-form (proxy) requests take the host from the URI authority; origin-form takes it
/// from the `Host` header. An absolute-form request to a non-`.dig` authority is refused
/// BEFORE any control routing, so `dig-dns` can never be coerced into touching a foreign
/// origin.
pub fn classify(uri: &Uri, host_header: Option<&str>, tld: &str) -> Classified {
    let is_proxy = uri.scheme().is_some() && uri.authority().is_some();
    let (host, path) = if is_proxy {
        (
            uri.authority().map(|a| a.host().to_string()),
            uri.path().to_string(),
        )
    } else {
        (host_header.map(str::to_string), uri.path().to_string())
    };

    // Open-proxy guard: a proxy request must target a `.<tld>` authority, else 403.
    if is_proxy {
        match &host {
            Some(h) if host_is_under_tld(h, tld) => {}
            _ => return Classified::NonDigProxy,
        }
    }

    // The `/.dig/…` namespace is reserved and answered for any host (a `.dig` host or the
    // bare loopback IP directly), so it is routed before store-host parsing.
    if let Some(ep) = control_endpoint_for(&path) {
        return Classified::Control(ep);
    }

    match host {
        Some(h) => match parse_dig_host(&h, tld) {
            Ok(target) => Classified::Store { target, path },
            Err(_) => Classified::BadHost,
        },
        None => Classified::BadHost,
    }
}

/// Handle a fully-parsed request, returning the response. Generic over the node client so it
/// is unit-tested with an in-memory stub and run with `reqwest` in production.
pub async fn handle<N: NodeClient + ?Sized>(
    client: &N,
    ctx: &Ctx,
    method: &str,
    uri: &Uri,
    host_header: Option<&str>,
    range: Option<&str>,
) -> GatewayResponse {
    // CONNECT is never tunnelled — `dig-dns` does no TLS interception (SPEC §4.2/§5).
    if method.eq_ignore_ascii_case("CONNECT") {
        return GatewayResponse::text(405, "CONNECT is not supported");
    }
    let is_read = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");

    match classify(uri, host_header, &ctx.config.tld) {
        Classified::NonDigProxy => {
            GatewayResponse::text(403, "dig-dns is a .dig-only gateway, not an open proxy")
        }
        Classified::Control(ep) => {
            if !is_read {
                return GatewayResponse::text(405, "method not allowed");
            }
            control_response(ep, ctx, client).await
        }
        Classified::BadHost => GatewayResponse::text(404, "not a valid .dig host"),
        Classified::Store { target, path } => {
            if !is_read {
                return GatewayResponse::text(405, "method not allowed");
            }
            serve_store(client, &target, &path, range).await
        }
    }
}

/// Build a `/.dig/` control-endpoint response.
async fn control_response<N: NodeClient + ?Sized>(
    ep: ControlEndpoint,
    ctx: &Ctx,
    client: &N,
) -> GatewayResponse {
    match ep {
        ControlEndpoint::ResolveProbe => GatewayResponse {
            status: 204,
            headers: Vec::new(),
            body: Vec::new(),
        },
        ControlEndpoint::ProxyPac => GatewayResponse::with_type(
            200,
            PAC_CONTENT_TYPE,
            pac::generate(ctx.config.loopback_ip, ctx.bound_port, &ctx.config.tld).into_bytes(),
        ),
        ControlEndpoint::Health => {
            let reachable = client.healthy().await;
            GatewayResponse::with_type(200, "application/json", health_json(ctx, client, reachable))
        }
        ControlEndpoint::Unknown => GatewayResponse::text(404, "unknown /.dig/ endpoint"),
    }
}

/// The `/.dig/health` JSON body (SPEC §4.7). `reachable` is passed in so the async probe is
/// done by the caller (keeps this pure + directly testable).
fn health_json<N: NodeClient + ?Sized>(ctx: &Ctx, client: &N, reachable: bool) -> Vec<u8> {
    let using_fallback = ctx.bound_port == ctx.config.http_fallback_port
        && ctx.config.http_fallback_port != ctx.config.http_port;
    let dns_listener = if ctx.dns_active {
        json!({ "ip": ctx.config.loopback_ip, "port": ctx.config.dns_port, "transport": "udp+tcp" })
    } else {
        json!(null)
    };
    let body = json!({
        "status": "ok",
        "version": VERSION,
        "uptime_secs": ctx.started.elapsed().as_secs(),
        "loopback_ip": ctx.config.loopback_ip,
        "tld": ctx.config.tld,
        "bound_port": ctx.bound_port,
        "primary_port": ctx.config.http_port,
        "fallback_port": ctx.config.http_fallback_port,
        "using_fallback": using_fallback,
        "listeners": {
            "gateway": { "ip": ctx.config.loopback_ip, "port": ctx.bound_port },
            "dns": dns_listener,
        },
        "node": { "base_url": client.base_url(), "reachable": reachable },
        "paths": { "dns": ctx.dns_active, "gateway": true },
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Resolve + serve a store resource for a request path (SPEC §4.3–§4.6).
async fn serve_store<N: NodeClient + ?Sized>(
    client: &N,
    target: &HostTarget,
    path: &str,
    range: Option<&str>,
) -> GatewayResponse {
    let resource_key = match resource_key_for_path(path) {
        Ok(k) => k,
        Err(_) => return GatewayResponse::text(400, "invalid request path"),
    };

    // Determine the trusted root + whether the host pinned it.
    let (store_hex, trusted_root, pinned) = match target {
        HostTarget::Latest { store_hex } => match client.get_anchored_root(store_hex).await {
            Ok(root) => (store_hex.as_str(), root, false),
            // No anchored root ⇒ the store/site does not exist here: nothing to fall back to.
            Err(e) if e.is_not_found() => return GatewayResponse::text(404, "not found"),
            Err(_) => return GatewayResponse::text(502, "node unreachable resolving root"),
        },
        HostTarget::Pinned {
            store_hex,
            root_hex,
        } => (store_hex.as_str(), root_hex.clone(), true),
    };

    match fetch_and_decrypt(client, store_hex, &resource_key, &trusted_root).await {
        Fetched::Ok(bytes) => ok_body_response(&resource_key, bytes, range, pinned),
        Fetched::NotFound => spa_or_404(client, store_hex, &trusted_root, path, pinned).await,
        Fetched::NodeUnreachable => GatewayResponse::text(502, "node unreachable"),
        Fetched::IntegrityFail => {
            GatewayResponse::text(502, "content failed integrity verification")
        }
    }
}

/// The outcome of fetching + verifying + decrypting one resource.
enum Fetched {
    /// Verified, decrypted plaintext.
    Ok(Vec<u8>),
    /// The resource is not present at this store/root (a decoy/decrypt-fail or a node
    /// `-32004`/`-32005`) — resolved by the SPA catch-all.
    NotFound,
    /// The node could not be reached (transport/malformed) — a `502`, never a `404`.
    NodeUnreachable,
    /// The node served content that FAILED merkle verification against the trusted root — a
    /// misbehaving node; fail-closed with a `502`, never serve unverified bytes.
    IntegrityFail,
}

/// Fetch a resource's ciphertext from the node and verify+decrypt it against `trusted_root`.
async fn fetch_and_decrypt<N: NodeClient + ?Sized>(
    client: &N,
    store_hex: &str,
    resource_key: &str,
    trusted_root: &str,
) -> Fetched {
    let rk = match retrieval_key_hex(store_hex, resource_key) {
        Ok(k) => k,
        // The host already parsed to a 64-hex store id, so this is unreachable in practice.
        Err(_) => return Fetched::IntegrityFail,
    };
    let fetched = match client.get_content(store_hex, &rk, Some(trusted_root)).await {
        Ok(f) => f,
        Err(e) if e.is_not_found() => return Fetched::NotFound,
        Err(_) => return Fetched::NodeUnreachable,
    };
    match verify_and_decrypt(
        store_hex,
        resource_key,
        &fetched.ciphertext,
        &fetched.inclusion_proof_b64,
        trusted_root,
        &fetched.chunk_lens,
    ) {
        Ok(plaintext) => Fetched::Ok(plaintext),
        // A decoy (unknown key) is indistinguishable from a real miss ⇒ "not found" (§8/§4.5).
        Err(ContentError::Decrypt) => Fetched::NotFound,
        // A proof/root/chunk mismatch means the node served content inconsistent with the
        // trusted root — a fail-closed integrity error, not a normal miss.
        Err(_) => Fetched::IntegrityFail,
    }
}

/// SPA catch-all (SPEC §4.5): an extensionless not-found path serves `/index.html` so a
/// client-side route survives a hard reload; an extensioned not-found path is a `404`.
async fn spa_or_404<N: NodeClient + ?Sized>(
    client: &N,
    store_hex: &str,
    trusted_root: &str,
    path: &str,
    pinned: bool,
) -> GatewayResponse {
    if !is_extensionless(path) {
        return GatewayResponse::text(404, "not found");
    }
    // Fall back to index.html.
    match fetch_and_decrypt(client, store_hex, "index.html", trusted_root).await {
        Fetched::Ok(bytes) => ok_body_response("index.html", bytes, None, pinned),
        Fetched::NotFound => GatewayResponse::text(404, "not found"),
        Fetched::NodeUnreachable => GatewayResponse::text(502, "node unreachable"),
        Fetched::IntegrityFail => {
            GatewayResponse::text(502, "content failed integrity verification")
        }
    }
}

/// Build a `200`/`206` body response for verified plaintext, honouring a byte `Range` and the
/// per-root immutability rule (SPEC §4.6): a pinned-root response is immutable; a latest-root
/// response uses `no-cache` so a new generation is picked up promptly.
fn ok_body_response(
    resource_key: &str,
    bytes: Vec<u8>,
    range: Option<&str>,
    pinned: bool,
) -> GatewayResponse {
    let content_type = content_type_for(resource_key).to_string();
    let cache_control = if pinned {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let total = bytes.len() as u64;
    let mut headers = vec![
        ("content-type".to_string(), content_type),
        ("accept-ranges".to_string(), "bytes".to_string()),
        ("cache-control".to_string(), cache_control.to_string()),
    ];

    match range.map(|h| parse_range(h, total)) {
        Some(RangeSpec::Satisfiable { start, end }) => {
            let slice = bytes[start as usize..=end as usize].to_vec();
            headers.push((
                "content-range".to_string(),
                format!("bytes {start}-{end}/{total}"),
            ));
            GatewayResponse {
                status: 206,
                headers,
                body: slice,
            }
        }
        Some(RangeSpec::Unsatisfiable) => {
            headers.push(("content-range".to_string(), format!("bytes */{total}")));
            GatewayResponse {
                status: 416,
                headers,
                body: Vec::new(),
            }
        }
        // No range, malformed range, or multi-range ⇒ serve the whole resource.
        _ => GatewayResponse {
            status: 200,
            headers,
            body: bytes,
        },
    }
}

/// A parsed single-range request.
#[derive(Debug, PartialEq, Eq)]
enum RangeSpec {
    /// Serve `[start, end]` inclusive.
    Satisfiable { start: u64, end: u64 },
    /// A syntactically valid but out-of-bounds range ⇒ `416`.
    Unsatisfiable,
    /// No range / malformed / multi-range ⇒ serve the whole resource.
    Whole,
}

/// Parse a single `Range: bytes=…` header against a known total length. Only a single range
/// is honoured; a malformed or multi-range header falls back to the whole resource.
fn parse_range(header: &str, total: u64) -> RangeSpec {
    let spec = match header.trim().strip_prefix("bytes=") {
        Some(s) if !s.contains(',') => s.trim(),
        _ => return RangeSpec::Whole,
    };
    let (a, b) = match spec.split_once('-') {
        Some(pair) => pair,
        None => return RangeSpec::Whole,
    };

    if a.is_empty() {
        // Suffix range: the last `n` bytes.
        let n: u64 = match b.parse() {
            Ok(n) => n,
            Err(_) => return RangeSpec::Whole,
        };
        if n == 0 || total == 0 {
            return RangeSpec::Unsatisfiable;
        }
        let n = n.min(total);
        RangeSpec::Satisfiable {
            start: total - n,
            end: total - 1,
        }
    } else {
        let start: u64 = match a.parse() {
            Ok(n) => n,
            Err(_) => return RangeSpec::Whole,
        };
        let end: u64 = if b.is_empty() {
            total.saturating_sub(1)
        } else {
            match b.parse::<u64>() {
                Ok(n) => n.min(total.saturating_sub(1)),
                Err(_) => return RangeSpec::Whole,
            }
        };
        if total == 0 || start >= total || start > end {
            RangeSpec::Unsatisfiable
        } else {
            RangeSpec::Satisfiable { start, end }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::retrieval_key_hex;
    use crate::node::{FetchedContent, NodeError};
    use async_trait::async_trait;
    use base64::Engine;
    use digstore_core::codec::Encode;
    use digstore_core::crypto::{derive_decryption_key, encrypt_chunk};
    use digstore_core::{resource_leaf, Bytes32, MerkleTree, Urn, CHAIN};

    const STORE_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn ctx() -> Ctx {
        Ctx {
            config: Config::default(),
            bound_port: 80,
            dns_active: false,
            started: std::time::Instant::now(),
        }
    }

    fn header(resp: &GatewayResponse, name: &str) -> Option<String> {
        resp.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    /// Build a served content window (ciphertext + proof + root) for a resource, exactly as
    /// the node would — the merkle root is the fixture's trusted root.
    fn fixture(store_hex: &str, resource_key: &str, plaintext: &[u8]) -> (String, FetchedContent) {
        let store_id = Bytes32::from_hex(store_hex).unwrap();
        let urn = Urn {
            chain: CHAIN.to_string(),
            store_id,
            root_hash: None,
            resource_key: Some(resource_key.to_string()),
        };
        let key = derive_decryption_key(&urn.canonical(), None);
        let ct = encrypt_chunk(&key, plaintext);
        let lens = vec![ct.len() as u64];
        let leaf = resource_leaf(&ct);
        let tree = MerkleTree::from_leaves(vec![leaf]);
        let root_hex = tree.root().to_hex();
        let proof_b64 =
            base64::engine::general_purpose::STANDARD.encode(tree.prove(0).unwrap().to_bytes());
        (
            root_hex,
            FetchedContent {
                ciphertext: ct,
                root_hex: tree.root().to_hex(),
                inclusion_proof_b64: proof_b64,
                chunk_lens: lens,
            },
        )
    }

    fn b64(bytes: Vec<u8>) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// Build a store whose merkle tree holds the real `index.html` leaf AND a decoy leaf under
    /// ONE shared root — exactly the real decoy model (a miss is served indistinguishable
    /// decoy ciphertext with a valid proof to the store root that simply fails to decrypt).
    /// Returns `(root_hex, index_html_content, decoy_content)`.
    fn fixture_with_decoy() -> (String, FetchedContent, FetchedContent) {
        let store_id = Bytes32::from_hex(STORE_HEX).unwrap();
        let urn = Urn {
            chain: CHAIN.to_string(),
            store_id,
            root_hash: None,
            resource_key: Some("index.html".to_string()),
        };
        let key = derive_decryption_key(&urn.canonical(), None);
        let real_ct = encrypt_chunk(&key, b"APP");
        let real_len = real_ct.len() as u64;
        let real_leaf = resource_leaf(&real_ct);

        let decoy_ct = vec![0x42u8; 40]; // not valid GCM under any key we derive
        let decoy_leaf = resource_leaf(&decoy_ct);

        let tree = MerkleTree::from_leaves(vec![real_leaf, decoy_leaf]);
        let root_hex = tree.root().to_hex();
        let index_fc = FetchedContent {
            ciphertext: real_ct,
            root_hex: root_hex.clone(),
            inclusion_proof_b64: b64(tree.prove(0).unwrap().to_bytes()),
            chunk_lens: vec![real_len],
        };
        let decoy_fc = FetchedContent {
            ciphertext: decoy_ct,
            root_hex: root_hex.clone(),
            inclusion_proof_b64: b64(tree.prove(1).unwrap().to_bytes()),
            chunk_lens: vec![],
        };
        (root_hex, index_fc, decoy_fc)
    }

    /// A configurable in-memory node.
    struct StubNode {
        base: String,
        healthy: bool,
        anchored: Result<String, NodeError>,
        entries: Vec<(String, FetchedContent)>, // (retrieval_key_hex, content)
        miss: Miss,
    }

    #[derive(Clone)]
    enum Miss {
        NotFound,
        Transport,
        Decoy(FetchedContent),
    }

    impl StubNode {
        fn new(anchored: Result<String, NodeError>) -> Self {
            StubNode {
                base: "http://stub-node".to_string(),
                healthy: true,
                anchored,
                entries: Vec::new(),
                miss: Miss::NotFound,
            }
        }
        fn with(mut self, resource_key: &str, fc: FetchedContent) -> Self {
            let rk = retrieval_key_hex(STORE_HEX, resource_key).unwrap();
            self.entries.push((rk, fc));
            self
        }
        fn miss(mut self, m: Miss) -> Self {
            self.miss = m;
            self
        }
    }

    #[async_trait]
    impl NodeClient for StubNode {
        fn base_url(&self) -> &str {
            &self.base
        }
        async fn healthy(&self) -> bool {
            self.healthy
        }
        async fn get_anchored_root(&self, _store_hex: &str) -> Result<String, NodeError> {
            self.anchored.clone()
        }
        async fn get_content(
            &self,
            _store_hex: &str,
            retrieval_key_hex: &str,
            _root_hex: Option<&str>,
        ) -> Result<FetchedContent, NodeError> {
            if let Some((_, fc)) = self.entries.iter().find(|(rk, _)| rk == retrieval_key_hex) {
                return Ok(fc.clone());
            }
            match &self.miss {
                Miss::NotFound => Err(NodeError::Rpc {
                    code: -32004,
                    message: "resource unavailable".into(),
                    data_code: Some("RESOURCE_UNAVAILABLE".into()),
                }),
                Miss::Transport => Err(NodeError::Transport("refused".into())),
                Miss::Decoy(fc) => Ok(fc.clone()),
            }
        }
    }

    fn latest_target() -> HostTarget {
        HostTarget::Latest {
            store_hex: STORE_HEX.to_string(),
        }
    }

    // ---- classify -------------------------------------------------------------------------

    #[test]
    fn classify_origin_form_store() {
        let c = classify(&uri("/assets/app.js"), Some("aaaa.dig"), "dig");
        // `aaaa` is not a valid 52-char label ⇒ BadHost.
        assert_eq!(c, Classified::BadHost);
    }

    #[test]
    fn classify_valid_store_host() {
        let label = "a".repeat(52);
        let c = classify(&uri("/index.html"), Some(&format!("{label}.dig")), "dig");
        assert!(matches!(c, Classified::Store { .. }));
    }

    #[test]
    fn classify_absolute_form_proxy_dig() {
        let label = "a".repeat(52);
        let c = classify(&uri(&format!("http://{label}.dig/app.js")), None, "dig");
        match c {
            Classified::Store { path, .. } => assert_eq!(path, "/app.js"),
            other => panic!("expected Store, got {other:?}"),
        }
    }

    #[test]
    fn classify_absolute_form_non_dig_is_open_proxy_403() {
        let c = classify(&uri("http://example.com/"), None, "dig");
        assert_eq!(c, Classified::NonDigProxy);
    }

    #[test]
    fn classify_control_endpoints() {
        assert_eq!(
            classify(&uri("/.dig/health"), Some("anything"), "dig"),
            Classified::Control(ControlEndpoint::Health)
        );
        assert_eq!(
            classify(&uri("/.dig/proxy.pac"), None, "dig"),
            Classified::Control(ControlEndpoint::ProxyPac)
        );
        assert_eq!(
            classify(&uri("/.dig/resolve-probe"), None, "dig"),
            Classified::Control(ControlEndpoint::ResolveProbe)
        );
        assert_eq!(
            classify(&uri("/.dig/nope"), None, "dig"),
            Classified::Control(ControlEndpoint::Unknown)
        );
    }

    #[test]
    fn classify_control_wins_even_with_bad_host() {
        // Health is answerable directly on the loopback IP (no valid store label).
        assert_eq!(
            classify(&uri("/.dig/health"), Some("127.0.0.5"), "dig"),
            Classified::Control(ControlEndpoint::Health)
        );
    }

    #[test]
    fn classify_missing_host_is_bad_host() {
        assert_eq!(classify(&uri("/x"), None, "dig"), Classified::BadHost);
    }

    #[test]
    fn classify_proxy_to_non_dig_control_path_is_still_forbidden() {
        // A proxy request to a foreign authority is 403 even for a /.dig/ path — never touch
        // a foreign origin.
        assert_eq!(
            classify(&uri("http://example.com/.dig/health"), None, "dig"),
            Classified::NonDigProxy
        );
    }

    // ---- handle: methods + control --------------------------------------------------------

    #[tokio::test]
    async fn connect_is_rejected() {
        let node = StubNode::new(Ok("r".repeat(64)));
        let r = handle(&node, &ctx(), "CONNECT", &uri("/"), None, None).await;
        assert_eq!(r.status, 405);
    }

    #[tokio::test]
    async fn post_to_store_is_405() {
        let label = "a".repeat(52);
        let node = StubNode::new(Ok("r".repeat(64)));
        let r = handle(
            &node,
            &ctx(),
            "POST",
            &uri("/"),
            Some(&format!("{label}.dig")),
            None,
        )
        .await;
        assert_eq!(r.status, 405);
    }

    #[tokio::test]
    async fn resolve_probe_is_204() {
        let node = StubNode::new(Ok("r".repeat(64)));
        let r = handle(
            &node,
            &ctx(),
            "GET",
            &uri("/.dig/resolve-probe"),
            None,
            None,
        )
        .await;
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
    }

    #[tokio::test]
    async fn proxy_pac_embeds_bound_port() {
        let node = StubNode::new(Ok("r".repeat(64)));
        let mut c = ctx();
        c.bound_port = 8053;
        let r = handle(&node, &c, "GET", &uri("/.dig/proxy.pac"), None, None).await;
        assert_eq!(r.status, 200);
        assert_eq!(
            header(&r, "content-type").as_deref(),
            Some(PAC_CONTENT_TYPE)
        );
        let body = String::from_utf8(r.body).unwrap();
        assert!(body.contains("PROXY 127.0.0.5:8053"));
    }

    #[tokio::test]
    async fn health_reports_state() {
        let node = StubNode::new(Ok("r".repeat(64)));
        let r = handle(&node, &ctx(), "GET", &uri("/.dig/health"), None, None).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["version"], VERSION);
        assert_eq!(v["bound_port"], 80);
        assert_eq!(v["loopback_ip"], "127.0.0.5");
        assert_eq!(v["node"]["base_url"], "http://stub-node");
        assert_eq!(v["node"]["reachable"], true);
        assert_eq!(v["paths"]["gateway"], true);
        assert_eq!(v["paths"]["dns"], false);
    }

    #[tokio::test]
    async fn health_reports_fallback_and_dns_active() {
        let node = StubNode {
            healthy: false,
            ..StubNode::new(Ok("r".repeat(64)))
        };
        let mut c = ctx();
        c.bound_port = 8053;
        c.dns_active = true;
        let r = handle(&node, &c, "GET", &uri("/.dig/health"), None, None).await;
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["using_fallback"], true);
        assert_eq!(v["node"]["reachable"], false);
        assert_eq!(v["paths"]["dns"], true);
        assert_eq!(v["listeners"]["dns"]["port"], 53);
    }

    // ---- serve_store: success + headers ---------------------------------------------------

    #[tokio::test]
    async fn latest_serves_index_html_at_root() {
        let (root, fc) = fixture(STORE_HEX, "index.html", b"<h1>hi</h1>");
        let node = StubNode::new(Ok(root)).with("index.html", fc);
        let host = crate::label::store_hex_to_label(STORE_HEX).unwrap();
        let r = handle(
            &node,
            &ctx(),
            "GET",
            &uri("/"),
            Some(&format!("{host}.dig")),
            None,
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"<h1>hi</h1>");
        assert_eq!(
            header(&r, "content-type").as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(header(&r, "cache-control").as_deref(), Some("no-cache"));
        assert_eq!(header(&r, "accept-ranges").as_deref(), Some("bytes"));
    }

    #[tokio::test]
    async fn pinned_root_serves_that_root_and_is_immutable() {
        let (root, fc) = fixture(STORE_HEX, "index.html", b"PINNED");
        let node = StubNode::new(Err(NodeError::Transport("should not be called".into())))
            .with("index.html", fc);
        let target = HostTarget::Pinned {
            store_hex: STORE_HEX.to_string(),
            root_hex: root,
        };
        // Call serve_store directly with a pinned target (host parsing covered elsewhere).
        let r = serve_store(&node, &target, "/", None).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"PINNED");
        assert_eq!(
            header(&r, "cache-control").as_deref(),
            Some("public, max-age=31536000, immutable")
        );
    }

    #[tokio::test]
    async fn spa_catch_all_serves_index_for_extensionless_miss() {
        let (root, idx) = fixture(STORE_HEX, "index.html", b"APP");
        // /about is not present ⇒ miss ⇒ extensionless ⇒ serve index.html.
        let node = StubNode::new(Ok(root)).with("index.html", idx);
        let r = serve_store(&node, &latest_target(), "/about", None).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"APP");
    }

    #[tokio::test]
    async fn extensioned_miss_is_404() {
        let (root, idx) = fixture(STORE_HEX, "index.html", b"APP");
        let node = StubNode::new(Ok(root)).with("index.html", idx);
        let r = serve_store(&node, &latest_target(), "/missing.js", None).await;
        assert_eq!(r.status, 404);
    }

    #[tokio::test]
    async fn decoy_content_is_treated_as_not_found() {
        // index.html present; /about returns a decoy (valid proof to the store root, decrypt
        // fails) ⇒ treated as a miss ⇒ SPA → index.html.
        let (root, idx, decoy_fc) = fixture_with_decoy();
        let node = StubNode::new(Ok(root))
            .with("index.html", idx)
            .miss(Miss::Decoy(decoy_fc));
        let r = serve_store(&node, &latest_target(), "/about", None).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"APP");
    }

    #[tokio::test]
    async fn node_transport_error_is_502() {
        let (root, idx) = fixture(STORE_HEX, "index.html", b"APP");
        let node = StubNode::new(Ok(root))
            .with("index.html", idx)
            .miss(Miss::Transport);
        let r = serve_store(&node, &latest_target(), "/app.js", None).await;
        assert_eq!(r.status, 502);
    }

    #[tokio::test]
    async fn no_anchored_root_is_404() {
        let node = StubNode::new(Err(NodeError::Rpc {
            code: -32005,
            message: "not anchored".into(),
            data_code: Some("ROOT_NOT_ANCHORED".into()),
        }));
        let r = serve_store(&node, &latest_target(), "/", None).await;
        assert_eq!(r.status, 404);
    }

    #[tokio::test]
    async fn anchored_root_transport_error_is_502() {
        let node = StubNode::new(Err(NodeError::Transport("refused".into())));
        let r = serve_store(&node, &latest_target(), "/", None).await;
        assert_eq!(r.status, 502);
    }

    #[tokio::test]
    async fn integrity_failure_is_502() {
        // Serve index.html content but under a DIFFERENT trusted root ⇒ RootMismatch ⇒ 502.
        let (_real_root, fc) = fixture(STORE_HEX, "index.html", b"APP");
        let node = StubNode::new(Ok("c".repeat(64))).with("index.html", fc);
        let r = serve_store(&node, &latest_target(), "/", None).await;
        assert_eq!(r.status, 502);
    }

    #[tokio::test]
    async fn traversal_path_is_400() {
        let node = StubNode::new(Ok("r".repeat(64)));
        let r = serve_store(&node, &latest_target(), "/a/../b", None).await;
        assert_eq!(r.status, 400);
    }

    // ---- range ----------------------------------------------------------------------------

    #[tokio::test]
    async fn range_request_returns_206_slice() {
        let (root, fc) = fixture(STORE_HEX, "data.bin", b"0123456789");
        let node = StubNode::new(Ok(root)).with("data.bin", fc);
        let r = serve_store(&node, &latest_target(), "/data.bin", Some("bytes=2-5")).await;
        assert_eq!(r.status, 206);
        assert_eq!(r.body, b"2345");
        assert_eq!(header(&r, "content-range").as_deref(), Some("bytes 2-5/10"));
    }

    #[tokio::test]
    async fn unsatisfiable_range_is_416() {
        let (root, fc) = fixture(STORE_HEX, "data.bin", b"0123456789");
        let node = StubNode::new(Ok(root)).with("data.bin", fc);
        let r = serve_store(&node, &latest_target(), "/data.bin", Some("bytes=50-60")).await;
        assert_eq!(r.status, 416);
        assert_eq!(header(&r, "content-range").as_deref(), Some("bytes */10"));
    }

    #[test]
    fn parse_range_forms() {
        assert_eq!(
            parse_range("bytes=0-3", 10),
            RangeSpec::Satisfiable { start: 0, end: 3 }
        );
        assert_eq!(
            parse_range("bytes=5-", 10),
            RangeSpec::Satisfiable { start: 5, end: 9 }
        );
        assert_eq!(
            parse_range("bytes=-4", 10),
            RangeSpec::Satisfiable { start: 6, end: 9 }
        );
        // End clamps to the last byte.
        assert_eq!(
            parse_range("bytes=8-100", 10),
            RangeSpec::Satisfiable { start: 8, end: 9 }
        );
        assert_eq!(parse_range("bytes=20-30", 10), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 10), RangeSpec::Unsatisfiable);
        // Malformed / multi-range ⇒ whole.
        assert_eq!(parse_range("bytes=abc", 10), RangeSpec::Whole);
        assert_eq!(parse_range("items=0-1", 10), RangeSpec::Whole);
        assert_eq!(parse_range("bytes=0-1,2-3", 10), RangeSpec::Whole);
    }

    #[test]
    fn host_under_tld_matcher() {
        assert!(host_is_under_tld("x.dig", "dig"));
        assert!(host_is_under_tld("a.b.dig.", "dig"));
        assert!(host_is_under_tld("DIG", "dig"));
        assert!(host_is_under_tld("x.dig:80", "dig"));
        assert!(!host_is_under_tld("example.com", "dig"));
        assert!(!host_is_under_tld("digx", "dig"));
    }
}
