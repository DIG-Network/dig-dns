//! End-to-end integration test: a real stub dig-node (hyper) + the real `dig-dns` HTTP
//! gateway, driven over loopback with `reqwest`.
//!
//! It proves the Phase 2b acceptance criteria without an installer or OS DNS:
//! - origin-form (`Host: <label>.dig`) AND absolute-form proxy (`-x`) both resolve;
//! - a non-`.dig` proxy target is refused with `403` (never an open proxy);
//! - the SPA catch-all serves `/index.html` for an extensionless miss, `404` for a missing
//!   extensioned asset;
//! - `HEAD` + byte-`Range` behave; the `/.dig/` control endpoints answer;
//! - **the pinned-vs-latest proof**: `<store>.dig` serves the LATEST root while
//!   `<root1>.<store>.dig` serves that exact older generation — the two bodies differ.
//!
//! The stub node serves canned `dig.getAnchoredRoot` / `dig.getContent` built with the SAME
//! read-crypto primitives the gateway verifies against, so every proof + decrypt is real.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use digstore_core::codec::Encode;
use digstore_core::crypto::{derive_decryption_key, encrypt_chunk};
use digstore_core::{resource_leaf, Bytes32, MerkleTree, Urn, CHAIN};

use dig_dns::config::Config;
use dig_dns::content::retrieval_key_hex;
use dig_dns::gateway::Ctx;
use dig_dns::label::store_hex_to_label;
use dig_dns::server::{fetch_resource, serve_on};
use dig_dns::transport::ReqwestNodeClient;

/// 32 bytes of 0x07 → the fixture store id.
fn store_hex() -> String {
    "07".repeat(32)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Encrypt a resource exactly as a producer would (root-independent URN key, public store).
fn encrypt_resource(
    store_id: Bytes32,
    resource_key: &str,
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u64>) {
    let urn = Urn {
        chain: CHAIN.to_string(),
        store_id,
        root_hash: None,
        resource_key: Some(resource_key.to_string()),
    };
    let key = derive_decryption_key(&urn.canonical(), None);
    let ct = encrypt_chunk(&key, plaintext);
    let lens = vec![ct.len() as u64];
    (ct, lens)
}

/// A single `dig.getContent` window: ciphertext + proof + chunk lengths.
#[derive(Clone)]
struct Window {
    ciphertext: Vec<u8>,
    proof_b64: String,
    chunk_lens: Vec<u64>,
}

/// The fixture: two generations of one store.
struct Fixture {
    /// (retrieval_key_hex, root_hex) → served window.
    windows: HashMap<(String, String), Window>,
    /// The latest anchored root (generation 2).
    latest_root: String,
    /// The pinned older root (generation 1).
    pinned_root: String,
}

/// Build a store with a LATEST generation (root R2: index.html "V2" + app.js + data.bin) and
/// an older PINNED generation (root R1: index.html "V1").
fn build_fixture() -> Fixture {
    let store = store_hex();
    let store_id = Bytes32::from_hex(&store).unwrap();

    // Generation 2 (latest): a 3-leaf tree.
    let (idx2, idx2_lens) = encrypt_resource(store_id, "index.html", b"<h1>V2 latest</h1>");
    let (app, app_lens) = encrypt_resource(store_id, "assets/app.js", b"console.log('v2')");
    let (data, data_lens) = encrypt_resource(store_id, "data.bin", b"0123456789");
    let tree2 = MerkleTree::from_leaves(vec![
        resource_leaf(&idx2),
        resource_leaf(&app),
        resource_leaf(&data),
    ]);
    let r2 = tree2.root().to_hex();

    // Generation 1 (pinned/older): index.html "V1" only.
    let (idx1, idx1_lens) = encrypt_resource(store_id, "index.html", b"<h1>V1 pinned</h1>");
    let tree1 = MerkleTree::from_leaves(vec![resource_leaf(&idx1)]);
    let r1 = tree1.root().to_hex();

    let rk_index = retrieval_key_hex(&store, "index.html").unwrap();
    let rk_app = retrieval_key_hex(&store, "assets/app.js").unwrap();
    let rk_data = retrieval_key_hex(&store, "data.bin").unwrap();

    let mut windows = HashMap::new();
    windows.insert(
        (rk_index.clone(), r2.clone()),
        Window {
            ciphertext: idx2,
            proof_b64: b64(&tree2.prove(0).unwrap().to_bytes()),
            chunk_lens: idx2_lens,
        },
    );
    windows.insert(
        (rk_app, r2.clone()),
        Window {
            ciphertext: app,
            proof_b64: b64(&tree2.prove(1).unwrap().to_bytes()),
            chunk_lens: app_lens,
        },
    );
    windows.insert(
        (rk_data, r2.clone()),
        Window {
            ciphertext: data,
            proof_b64: b64(&tree2.prove(2).unwrap().to_bytes()),
            chunk_lens: data_lens,
        },
    );
    windows.insert(
        (rk_index, r1.clone()),
        Window {
            ciphertext: idx1,
            proof_b64: b64(&tree1.prove(0).unwrap().to_bytes()),
            chunk_lens: idx1_lens,
        },
    );

    Fixture {
        windows,
        latest_root: r2,
        pinned_root: r1,
    }
}

/// The stub node's JSON-RPC + `/health` handler.
async fn stub_service(
    fixture: Arc<Fixture>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // Health probe for the ladder.
    if req.method() == hyper::Method::GET && req.uri().path() == "/health" {
        return Ok(json_response(200, json!({ "status": "ok" })));
    }

    let body = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let v: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    let method = v["method"].as_str().unwrap_or("");
    let params = &v["params"];

    let result = match method {
        "dig.getAnchoredRoot" => json!({
            "store_id": params["store_id"],
            "root": fixture.latest_root,
        }),
        "dig.getContent" => {
            let rk = params["retrieval_key"].as_str().unwrap_or("").to_string();
            let root = params["root"].as_str().unwrap_or("").to_string();
            match fixture.windows.get(&(rk, root.clone())) {
                Some(w) => json!({
                    "ciphertext": b64(&w.ciphertext),
                    "root": root,
                    "complete": true,
                    "inclusion_proof": w.proof_b64,
                    "chunk_lens": w.chunk_lens,
                }),
                None => {
                    return Ok(json_response(
                        200,
                        json!({
                            "jsonrpc": "2.0", "id": 1,
                            "error": { "code": -32004, "message": "resource unavailable",
                                       "data": { "code": "RESOURCE_UNAVAILABLE" } }
                        }),
                    ));
                }
            }
        }
        _ => {
            return Ok(json_response(
                200,
                json!({ "jsonrpc": "2.0", "id": 1,
                        "error": { "code": -32601, "message": "method not found" } }),
            ));
        }
    };
    Ok(json_response(
        200,
        json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
    ))
}

fn json_response(status: u16, body: Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap()
}

/// Spawn the stub node on an ephemeral loopback port; return its address.
async fn spawn_stub(fixture: Arc<Fixture>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let fixture = fixture.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| stub_service(fixture.clone(), req));
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

/// Bring up the stub node + the gateway; return (gateway base URL, gateway port, shutdown).
async fn spawn_gateway(fixture: Arc<Fixture>) -> (String, u16, tokio::sync::oneshot::Sender<()>) {
    let stub_addr = spawn_stub(fixture).await;
    let stub_url = format!("http://{stub_addr}");
    let client = Arc::new(ReqwestNodeClient::with_base(&stub_url).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = listener.local_addr().unwrap();
    let ctx = Ctx {
        config: Config::default(),
        bound_port: gw_addr.port(),
        dns_active: false,
        started: Instant::now(),
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_on(listener, client, ctx, async {
        let _ = rx.await;
    }));
    (format!("http://{gw_addr}"), gw_addr.port(), tx)
}

#[tokio::test]
async fn gateway_end_to_end_both_forms_and_pinned_vs_latest() {
    let fixture = Arc::new(build_fixture());
    let (base, gw_port, shutdown) = spawn_gateway(fixture.clone()).await;

    let store_label = store_hex_to_label(&store_hex()).unwrap();
    let host = format!("{store_label}.dig");
    let http = reqwest::Client::builder().build().unwrap();

    // --- Origin-form (Path A): Host header points at the gateway ---------------------------
    let resp = http
        .get(format!("{base}/"))
        .header("host", &host)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "origin-form GET / should serve latest index"
    );
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-cache",
        "latest-root responses are not immutable"
    );
    let latest_body = resp.text().await.unwrap();
    assert!(latest_body.contains("V2 latest"), "body: {latest_body}");

    // --- Pinned-vs-latest proof: <root1>.<store>.dig serves the OLD generation --------------
    let root_label = store_hex_to_label(&fixture.pinned_root).unwrap();
    let pinned_host = format!("{root_label}.{store_label}.dig");
    let resp = http
        .get(format!("{base}/"))
        .header("host", &pinned_host)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=31536000, immutable",
        "pinned-root responses are immutable"
    );
    let pinned_body = resp.text().await.unwrap();
    assert!(pinned_body.contains("V1 pinned"), "body: {pinned_body}");
    assert_ne!(
        latest_body, pinned_body,
        "THE proof: a pinned-root fetch differs from latest after the store advanced"
    );

    // --- SPA catch-all: extensionless miss → index.html; extensioned miss → 404 ------------
    let resp = http
        .get(format!("{base}/some/deep/route"))
        .header("host", &host)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("V2 latest"));

    let resp = http
        .get(format!("{base}/nope.js"))
        .header("host", &host)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // A real asset resolves with the right content type.
    let resp = http
        .get(format!("{base}/assets/app.js"))
        .header("host", &host)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/javascript; charset=utf-8"
    );

    // --- HEAD: headers + Content-Length, no body -------------------------------------------
    let resp = http
        .head(format!("{base}/"))
        .header("host", &host)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("content-length").is_some());
    assert!(resp.bytes().await.unwrap().is_empty(), "HEAD has no body");

    // --- Range: 206 slice ------------------------------------------------------------------
    let resp = http
        .get(format!("{base}/data.bin"))
        .header("host", &host)
        .header("range", "bytes=2-5")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes 2-5/10");
    assert_eq!(resp.text().await.unwrap(), "2345");

    // --- /.dig/ control endpoints ----------------------------------------------------------
    let resp = http
        .get(format!("{base}/.dig/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let health: Value = resp.json().await.unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["bound_port"], gw_port);
    assert_eq!(
        health["node"]["reachable"], true,
        "stub /health is reachable"
    );

    let resp = http
        .get(format!("{base}/.dig/resolve-probe"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = http
        .get(format!("{base}/.dig/proxy.pac"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let pac = resp.text().await.unwrap();
    assert!(pac.contains(&format!("PROXY 127.0.0.5:{gw_port}")));

    // --- Absolute-form proxy (Path B): reqwest with the gateway as an HTTP proxy ------------
    let proxied = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&base).unwrap())
        .build()
        .unwrap();
    let resp = proxied
        .get(format!("http://{host}/assets/app.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "proxy-form (-x) resolves .dig");
    assert!(resp.text().await.unwrap().contains("v2"));

    // A non-.dig proxy target is refused — never an open proxy.
    let resp = proxied.get("http://example.com/").send().await.unwrap();
    assert_eq!(resp.status(), 403, "non-.dig proxy target is 403");

    let _ = shutdown.send(());
}

#[tokio::test]
async fn fetch_resource_resolves_latest_via_reqwest_client() {
    // Exercises the `dig-dns fetch` path: resolve the node (override ladder) + run the
    // pipeline against the live stub — covers ReqwestNodeClient::resolve + fetch_resource.
    let fixture = Arc::new(build_fixture());
    let stub_addr = spawn_stub(fixture).await;
    let cfg = Config {
        node_url: Some(format!("http://{stub_addr}")),
        ..Config::default()
    };
    let store_label = store_hex_to_label(&store_hex()).unwrap();
    let resp = fetch_resource(cfg, &format!("{store_label}.dig"), "/")
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8_lossy(&resp.body).contains("V2 latest"));
}
