//! The dig-node read contract — the request shapes, response parsing, windowed-content
//! reassembly, and the §5.3 endpoint ladder ordering.
//!
//! This module is PURE (no I/O): it builds the JSON-RPC params, parses responses, and
//! assembles a resource from its content windows. The async HTTP transport that actually
//! POSTs to a node (and the health-probe that walks the ladder) is built on top of these
//! in a later phase, so all the wire logic is unit-tested without a live server.
//!
//! Wire contract (SPEC §6, mirrors dig-node's `handle_rpc` / digstore-remote's `DigClient`):
//! - `dig.getAnchoredRoot {store_id} -> {store_id, root}`
//! - `dig.getContent {store_id, retrieval_key, offset[, root]} ->
//!    {ciphertext(b64), root, complete, next_offset?, inclusion_proof?(first), chunk_lens?(first)}`

use base64::Engine;
use serde_json::{json, Value};

use crate::config::Config;

/// The dig-node's default localhost control port (plain HTTP loopback). Re-exported from
/// `dig_constants::DIG_NODE_PORT` — the ecosystem-wide single source of truth for the §5.3
/// client->node localhost port — so dig-dns can never drift from dig-node/dig-installer/dig-sdk.
pub const DEFAULT_LOCAL_NODE_PORT: u16 = dig_constants::DIG_NODE_PORT;
/// The best-effort bare `dig.local` node base (the installed local node).
pub const DIG_LOCAL_BASE: &str = "http://dig.local";
/// The public gateway — the terminal ladder fallback.
pub const RPC_DIG_NET_BASE: &str = "https://rpc.dig.net";

/// Errors from the dig-node read contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeError {
    /// The node returned a JSON-RPC error object. `data_code` is the stable symbolic name
    /// (e.g. `RESOURCE_UNAVAILABLE`) when present — branch on it, not the numeric code.
    #[error("node JSON-RPC error {code}: {message}")]
    Rpc {
        /// The numeric JSON-RPC error code.
        code: i64,
        /// The human-readable message.
        message: String,
        /// The stable symbolic `data.code`, when present.
        data_code: Option<String>,
    },
    /// The node response did not match the expected shape.
    #[error("malformed node response: {0}")]
    Malformed(String),
    /// The node could not be reached (connection refused, timeout, DNS, TLS, non-2xx HTTP
    /// status). Distinct from a well-formed JSON-RPC error — this maps to an HTTP `502` at the
    /// gateway (the store may well exist; the node is just unreachable), never to a `404`.
    #[error("node transport error: {0}")]
    Transport(String),
}

impl NodeError {
    /// Whether this error means "the resource is not at this store/root" — a not-found the
    /// gateway resolves via the SPA catch-all. Covers `-32004 RESOURCE_UNAVAILABLE` and
    /// `-32005 ROOT_NOT_ANCHORED` (by symbolic code or numeric fallback).
    pub fn is_not_found(&self) -> bool {
        match self {
            NodeError::Rpc {
                code, data_code, ..
            } => {
                matches!(code, -32004 | -32005)
                    || matches!(
                        data_code.as_deref(),
                        Some("RESOURCE_UNAVAILABLE") | Some("ROOT_NOT_ANCHORED")
                    )
            }
            NodeError::Malformed(_) | NodeError::Transport(_) => false,
        }
    }
}

/// A resource reassembled from its content windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedContent {
    /// The full reassembled ciphertext (base64-decoded, all windows concatenated).
    pub ciphertext: Vec<u8>,
    /// The 64-hex served generation root.
    pub root_hex: String,
    /// The base64 whole-resource merkle inclusion proof (from the first window).
    pub inclusion_proof_b64: String,
    /// The per-chunk ciphertext byte lengths (from the first window; may be empty).
    pub chunk_lens: Vec<u64>,
}

/// The ordered node endpoint candidates (SPEC §6.3 ladder). An explicit override is the
/// SOLE candidate (it wins, no probing); otherwise the fixed order dig.local → localhost →
/// rpc.dig.net. The caller probes `GET <base>/health` in order and uses the first that
/// answers, treating the terminal `rpc.dig.net` as the unconditional fallback.
pub fn candidate_bases(cfg: &Config) -> Vec<String> {
    if let Some(url) = &cfg.node_url {
        return vec![url.trim_end_matches('/').to_string()];
    }
    vec![
        DIG_LOCAL_BASE.to_string(),
        format!("http://localhost:{DEFAULT_LOCAL_NODE_PORT}"),
        RPC_DIG_NET_BASE.to_string(),
    ]
}

/// Build the `dig.getAnchoredRoot` params.
pub fn build_anchored_root_params(store_hex: &str) -> Value {
    json!({ "store_id": store_hex })
}

/// Build the `dig.getContent` params. `root_hex` is omitted for a latest (rootless) read
/// and set for a pinned-root read.
pub fn build_content_params(
    store_hex: &str,
    retrieval_key_hex: &str,
    root_hex: Option<&str>,
    offset: u64,
) -> Value {
    let mut params = json!({
        "store_id": store_hex,
        "retrieval_key": retrieval_key_hex,
        "offset": offset,
    });
    if let Some(root) = root_hex {
        params["root"] = json!(root);
    }
    params
}

/// Extract the `result` from a full JSON-RPC response, mapping a JSON-RPC `error` object to
/// [`NodeError::Rpc`] (with the symbolic `data.code` when present).
pub fn parse_rpc_result(response: &Value) -> Result<Value, NodeError> {
    if let Some(err) = response.get("error") {
        return Err(NodeError::Rpc {
            code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            data_code: err
                .get("data")
                .and_then(|d| d.get("code"))
                .and_then(Value::as_str)
                .map(String::from),
        });
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| NodeError::Malformed("response has neither result nor error".into()))
}

/// Read the 64-hex `root` from a `dig.getAnchoredRoot` result.
pub fn parse_anchored_root(result: &Value) -> Result<String, NodeError> {
    let root = result
        .get("root")
        .and_then(Value::as_str)
        .ok_or_else(|| NodeError::Malformed("anchored-root result missing 'root'".into()))?;
    if root.len() != 64 || !root.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NodeError::Malformed(format!(
            "anchored root is not 64-hex: {root}"
        )));
    }
    Ok(root.to_string())
}

/// Reassemble a resource from the ordered sequence of `dig.getContent` window RESULTS
/// (offset-0 window first). Validates that the first window carries the `inclusion_proof`,
/// `chunk_lens`, and `root`; that every non-final window is `complete: false` and the final
/// window is `complete: true`; and concatenates the base64-decoded ciphertext.
pub fn assemble_windows(windows: &[Value]) -> Result<FetchedContent, NodeError> {
    let first = windows
        .first()
        .ok_or_else(|| NodeError::Malformed("no content windows".into()))?;

    let inclusion_proof_b64 = first
        .get("inclusion_proof")
        .and_then(Value::as_str)
        .ok_or_else(|| NodeError::Malformed("first window missing inclusion_proof".into()))?
        .to_string();
    let chunk_lens: Vec<u64> = match first.get("chunk_lens") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| NodeError::Malformed("chunk_lens entry is not a u64".into()))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(NodeError::Malformed("chunk_lens is not an array".into())),
        None => {
            return Err(NodeError::Malformed(
                "first window missing chunk_lens".into(),
            ))
        }
    };
    let root_hex = first
        .get("root")
        .and_then(Value::as_str)
        .ok_or_else(|| NodeError::Malformed("window missing root".into()))?
        .to_string();

    let mut ciphertext = Vec::new();
    let last_index = windows.len() - 1;
    for (i, w) in windows.iter().enumerate() {
        let ct_b64 = w
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| NodeError::Malformed("window missing ciphertext".into()))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .map_err(|_| NodeError::Malformed("ciphertext is not valid base64".into()))?;
        ciphertext.extend_from_slice(&bytes);

        let complete = w.get("complete").and_then(Value::as_bool).unwrap_or(false);
        if i == last_index && !complete {
            return Err(NodeError::Malformed("final window is not complete".into()));
        }
        if i != last_index && complete {
            return Err(NodeError::Malformed(
                "a non-final window is marked complete".into(),
            ));
        }
    }

    Ok(FetchedContent {
        ciphertext,
        root_hex,
        inclusion_proof_b64,
        chunk_lens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn local_node_port_is_wired_to_the_shared_dig_constants_crate() {
        // Guards against the port silently drifting from the ecosystem-wide single source of
        // truth (dig_ecosystem #502) — dig-node/dig-installer/dig-sdk all resolve the SAME
        // constant, so a change there must be a deliberate, coordinated ecosystem release.
        assert_eq!(DEFAULT_LOCAL_NODE_PORT, dig_constants::DIG_NODE_PORT);
        assert_eq!(DEFAULT_LOCAL_NODE_PORT, 9778);
    }

    #[test]
    fn candidate_bases_default_is_three_tier_ladder() {
        let bases = candidate_bases(&Config::default());
        assert_eq!(
            bases,
            vec![
                "http://dig.local".to_string(),
                "http://localhost:9778".to_string(),
                "https://rpc.dig.net".to_string(),
            ]
        );
    }

    #[test]
    fn candidate_bases_override_is_sole_candidate() {
        let cfg = Config {
            node_url: Some("http://127.0.0.1:9999/".to_string()),
            ..Config::default()
        };
        assert_eq!(
            candidate_bases(&cfg),
            vec!["http://127.0.0.1:9999".to_string()]
        );
    }

    #[test]
    fn anchored_root_params_shape() {
        assert_eq!(build_anchored_root_params("aa"), json!({"store_id": "aa"}));
    }

    #[test]
    fn content_params_omit_root_for_latest_and_include_for_pinned() {
        assert_eq!(
            build_content_params("st", "rk", None, 0),
            json!({"store_id": "st", "retrieval_key": "rk", "offset": 0})
        );
        assert_eq!(
            build_content_params("st", "rk", Some("rt"), 42),
            json!({"store_id": "st", "retrieval_key": "rk", "offset": 42, "root": "rt"})
        );
    }

    #[test]
    fn parse_rpc_result_returns_result_object() {
        let resp = json!({"jsonrpc": "2.0", "id": 1, "result": {"root": "abc"}});
        assert_eq!(parse_rpc_result(&resp).unwrap(), json!({"root": "abc"}));
    }

    #[test]
    fn parse_rpc_result_maps_error_with_symbolic_code() {
        let resp = json!({"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32004, "message": "not here", "data": {"code": "RESOURCE_UNAVAILABLE"}
        }});
        let err = parse_rpc_result(&resp).unwrap_err();
        assert_eq!(
            err,
            NodeError::Rpc {
                code: -32004,
                message: "not here".to_string(),
                data_code: Some("RESOURCE_UNAVAILABLE".to_string())
            }
        );
        assert!(err.is_not_found());
    }

    #[test]
    fn parse_rpc_result_missing_both_is_malformed() {
        assert!(matches!(
            parse_rpc_result(&json!({"jsonrpc": "2.0", "id": 1})),
            Err(NodeError::Malformed(_))
        ));
    }

    #[test]
    fn parse_anchored_root_reads_64_hex() {
        let root = "a".repeat(64);
        let result = json!({"store_id": "b", "root": root});
        assert_eq!(parse_anchored_root(&result).unwrap(), root);
    }

    #[test]
    fn parse_anchored_root_rejects_missing_or_bad_hex() {
        assert!(matches!(
            parse_anchored_root(&json!({"store_id": "b"})),
            Err(NodeError::Malformed(_))
        ));
        assert!(matches!(
            parse_anchored_root(&json!({"root": "xyz"})),
            Err(NodeError::Malformed(_))
        ));
    }

    #[test]
    fn assemble_single_complete_window() {
        let w = json!({
            "ciphertext": b64(b"CIPHERTEXT"),
            "root": "r".repeat(64),
            "complete": true,
            "inclusion_proof": "UFJPT0Y=",
            "chunk_lens": [10]
        });
        let fc = assemble_windows(&[w]).unwrap();
        assert_eq!(fc.ciphertext, b"CIPHERTEXT");
        assert_eq!(fc.inclusion_proof_b64, "UFJPT0Y=");
        assert_eq!(fc.chunk_lens, vec![10]);
        assert_eq!(fc.root_hex, "r".repeat(64));
    }

    #[test]
    fn assemble_two_windows_concatenates() {
        let w0 = json!({
            "ciphertext": b64(b"AAAA"),
            "root": "r".repeat(64),
            "complete": false,
            "next_offset": 4,
            "inclusion_proof": "cf8=",
            "chunk_lens": [8]
        });
        let w1 = json!({
            "ciphertext": b64(b"BBBB"),
            "root": "r".repeat(64),
            "complete": true
        });
        let fc = assemble_windows(&[w0, w1]).unwrap();
        assert_eq!(fc.ciphertext, b"AAAABBBB");
        assert_eq!(fc.inclusion_proof_b64, "cf8=");
        assert_eq!(fc.chunk_lens, vec![8]);
    }

    #[test]
    fn assemble_rejects_empty() {
        assert!(matches!(
            assemble_windows(&[]),
            Err(NodeError::Malformed(_))
        ));
    }

    #[test]
    fn assemble_rejects_first_window_without_proof() {
        let w = json!({"ciphertext": b64(b"x"), "root": "r".repeat(64), "complete": true, "chunk_lens": [1]});
        assert!(matches!(
            assemble_windows(&[w]),
            Err(NodeError::Malformed(_))
        ));
    }

    #[test]
    fn assemble_rejects_last_window_not_complete() {
        let w = json!({
            "ciphertext": b64(b"x"), "root": "r".repeat(64), "complete": false,
            "next_offset": 1, "inclusion_proof": "AA==", "chunk_lens": [1]
        });
        assert!(matches!(
            assemble_windows(&[w]),
            Err(NodeError::Malformed(_))
        ));
    }

    #[test]
    fn assemble_rejects_bad_base64_ciphertext() {
        let w = json!({
            "ciphertext": "!!!not base64!!!", "root": "r".repeat(64), "complete": true,
            "inclusion_proof": "AA==", "chunk_lens": [1]
        });
        assert!(matches!(
            assemble_windows(&[w]),
            Err(NodeError::Malformed(_))
        ));
    }
}
