//! The async dig-node transport — the live JSON-RPC client behind the pure [`crate::node`]
//! contract.
//!
//! [`NodeClient`] is the abstraction the gateway serves against; [`ReqwestNodeClient`] is the
//! real implementation that walks the §5.3 endpoint ladder (SPEC §6.3), POSTs JSON-RPC to the
//! resolved node, and pages `dig.getContent` windows into a [`FetchedContent`]. The gateway
//! holds a `&dyn NodeClient`, so tests drive it with an in-memory stub and no sockets, while
//! the integration test exercises `ReqwestNodeClient` against a real stub node over loopback.
//!
//! All the wire *shaping* (param builders, response parsing, window reassembly) lives in
//! [`crate::node`] and is unit-tested there; this module only adds the I/O (HTTP + the ladder
//! probe) on top.

use std::sync::Once;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::config::Config;
use crate::node::{
    assemble_windows, build_anchored_root_params, build_content_params, candidate_bases,
    parse_anchored_root, parse_rpc_result, FetchedContent, NodeError,
};

/// How long the ladder health-probe waits for a tier to answer before falling through.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Overall per-RPC request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound on `dig.getContent` windows for one resource — a safety valve against a
/// misbehaving node that never sets `complete`.
const MAX_CONTENT_WINDOWS: usize = 100_000;

/// The read surface the gateway depends on. Async, object-safe (via `async-trait`) so the
/// gateway can hold `Arc<dyn NodeClient>` and tests can substitute an in-memory stub.
#[async_trait]
pub trait NodeClient: Send + Sync {
    /// The resolved node base URL (for `/.dig/health` reporting).
    fn base_url(&self) -> &str;

    /// Whether the node answers a liveness probe right now (for `/.dig/health`).
    async fn healthy(&self) -> bool;

    /// `dig.getAnchoredRoot` — the store's latest chain-anchored root (64-hex).
    async fn get_anchored_root(&self, store_hex: &str) -> Result<String, NodeError>;

    /// `dig.getContent` — fetch + reassemble a resource's full ciphertext (+ first-window
    /// proof and chunk lengths). `root_hex` pins a concrete generation; `None` lets the node
    /// pin its tip.
    async fn get_content(
        &self,
        store_hex: &str,
        retrieval_key_hex: &str,
        root_hex: Option<&str>,
    ) -> Result<FetchedContent, NodeError>;
}

/// Install the process-wide **ring** rustls crypto provider exactly once. reqwest is built
/// with `rustls-tls-*-no-provider`, so a provider MUST be installed before the first HTTPS
/// client is constructed (only the `rpc.dig.net` tier is HTTPS; local tiers are plain HTTP).
/// Idempotent and safe to call from every entry point.
pub fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Ignore the error if a provider is somehow already installed (e.g. a test set it).
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A live dig-node JSON-RPC client bound to a resolved base URL.
pub struct ReqwestNodeClient {
    http: reqwest::Client,
    base: String,
}

impl ReqwestNodeClient {
    /// Resolve the node endpoint per the §5.3 ladder (SPEC §6.3) and return a client bound to
    /// the first tier that answers `GET <base>/health`. An explicit override is the sole
    /// candidate (no probing). The terminal `rpc.dig.net` tier is used unconditionally when no
    /// earlier tier answered — so this never fails to produce a client.
    pub async fn resolve(config: &Config) -> Result<Self, NodeError> {
        init_crypto();
        let http = build_http_client()?;
        let bases = candidate_bases(config);
        let last = bases.len().saturating_sub(1);
        for (i, base) in bases.iter().enumerate() {
            // The terminal fallback is used even if its probe fails — it is the safety net.
            if i == last || probe(&http, base).await {
                return Ok(Self {
                    http,
                    base: base.clone(),
                });
            }
        }
        // `candidate_bases` is never empty, but keep an explicit error rather than panic.
        Err(NodeError::Transport("no node endpoint candidates".into()))
    }

    /// Construct a client bound to an explicit base (used by the integration test to point at
    /// a stub node without ladder probing).
    pub fn with_base(base: impl Into<String>) -> Result<Self, NodeError> {
        init_crypto();
        Ok(Self {
            http: build_http_client()?,
            base: base.into().trim_end_matches('/').to_string(),
        })
    }

    /// POST a single JSON-RPC call and return its `result` (mapping a JSON-RPC `error` to
    /// [`NodeError::Rpc`], and any HTTP/transport failure to [`NodeError::Transport`]).
    async fn call(&self, method: &str, params: Value) -> Result<Value, NodeError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .http
            .post(format!("{}/", self.base))
            .json(&body)
            .send()
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(NodeError::Transport(format!("HTTP {}", resp.status())));
        }
        let value: Value = resp
            .json()
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;
        parse_rpc_result(&value)
    }
}

/// Build the shared reqwest client (timeouts; rustls already selected at the feature level).
fn build_http_client() -> Result<reqwest::Client, NodeError> {
    reqwest::Client::builder()
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| NodeError::Transport(e.to_string()))
}

/// Probe `GET <base>/health` with a short timeout — any HTTP response (even non-2xx) counts
/// as "the tier answered"; a connection/timeout error falls through to the next tier.
///
/// `pub(crate)` so [`crate::server`]'s `dig.local`-mapping check (SPEC §12.1 step 1) reuses the
/// SAME "any HTTP response = reachable" convention rather than duplicating it.
pub(crate) async fn probe(http: &reqwest::Client, base: &str) -> bool {
    http.get(format!("{base}/health"))
        .timeout(PROBE_TIMEOUT)
        .send()
        .await
        .is_ok()
}

#[async_trait]
impl NodeClient for ReqwestNodeClient {
    fn base_url(&self) -> &str {
        &self.base
    }

    async fn healthy(&self) -> bool {
        probe(&self.http, &self.base).await
    }

    async fn get_anchored_root(&self, store_hex: &str) -> Result<String, NodeError> {
        let result = self
            .call("dig.getAnchoredRoot", build_anchored_root_params(store_hex))
            .await?;
        parse_anchored_root(&result)
    }

    async fn get_content(
        &self,
        store_hex: &str,
        retrieval_key_hex: &str,
        root_hex: Option<&str>,
    ) -> Result<FetchedContent, NodeError> {
        let mut windows: Vec<Value> = Vec::new();
        let mut offset: u64 = 0;
        loop {
            if windows.len() >= MAX_CONTENT_WINDOWS {
                return Err(NodeError::Malformed(
                    "content never completed within the window cap".into(),
                ));
            }
            let params = build_content_params(store_hex, retrieval_key_hex, root_hex, offset);
            let result = self.call("dig.getContent", params).await?;

            let complete = result
                .get("complete")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let next_offset = result.get("next_offset").and_then(Value::as_u64);
            windows.push(result);

            if complete {
                break;
            }
            match next_offset {
                // A non-final window MUST advance the offset, or we would loop forever.
                Some(next) if next > offset => offset = next,
                _ => {
                    return Err(NodeError::Malformed(
                        "incomplete window without an advancing next_offset".into(),
                    ))
                }
            }
        }
        assemble_windows(&windows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_crypto_is_idempotent() {
        init_crypto();
        init_crypto();
    }

    #[tokio::test]
    async fn with_base_trims_trailing_slash() {
        let c = ReqwestNodeClient::with_base("http://127.0.0.1:9778/").unwrap();
        assert_eq!(c.base_url(), "http://127.0.0.1:9778");
    }

    #[tokio::test]
    async fn resolve_with_override_binds_without_probing() {
        // An explicit override is the sole candidate and is used verbatim (it is also the
        // terminal fallback of a one-element ladder), so `resolve` returns it without a live
        // node to probe.
        let cfg = Config {
            node_url: Some("http://127.0.0.1:9/".to_string()),
            ..Config::default()
        };
        let c = ReqwestNodeClient::resolve(&cfg).await.unwrap();
        assert_eq!(c.base_url(), "http://127.0.0.1:9");
    }

    #[tokio::test]
    async fn get_anchored_root_maps_unreachable_to_transport() {
        // Port 9 (discard) refuses/black-holes → a transport error, never a not-found.
        let c = ReqwestNodeClient::with_base("http://127.0.0.1:9").unwrap();
        let err = c.get_anchored_root(&"a".repeat(64)).await.unwrap_err();
        assert!(matches!(err, NodeError::Transport(_)));
        assert!(!err.is_not_found());
    }

    #[tokio::test]
    async fn healthy_is_false_for_dead_endpoint() {
        let c = ReqwestNodeClient::with_base("http://127.0.0.1:9").unwrap();
        assert!(!c.healthy().await);
    }
}
