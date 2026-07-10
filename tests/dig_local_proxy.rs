//! End-to-end integration test: `dig-dns` ensures `http://dig.local` reaches a stub dig-node
//! via a real transparent reverse proxy over loopback (SPEC §12).
//!
//! Proves the issue #235 acceptance criteria without an installer or the real `127.0.0.2`
//! alias (uses ephemeral loopback ports/addresses instead):
//!
//! - **Established** (mapping absent): binding a fresh `dig.local` address and pointing the
//!   target at a stub node makes a `GET` **and** a `POST` reach that stub, headers relayed
//!   minus hop-by-hop, bodies byte-identical both ways.
//! - **Idempotent** (mapping already present): running `ensure_dig_local_mapping` a SECOND time
//!   against the SAME address returns `AlreadyMapped` and never attempts another bind — the
//!   concrete "no duplicate entries, re-running is safe" proof.
//! - **Node absent, gracefully**: pointing the target at an address nothing listens on serves
//!   `502`, never hanging or crashing the proxy — and the mapping is still `Established`, so it
//!   self-heals the moment a real node appears at that target.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpListener;

use dig_dns::config::Config;
use dig_dns::dig_local::EnsureOutcome;
use dig_dns::server::ensure_dig_local_mapping;

/// Spawn a stub "dig-node": `GET /health` → `200` JSON; anything else (the JSON-RPC `POST /`
/// surface) echoes the request body back verbatim with a marker header, so both the header and
/// body relaying of the proxy are directly provable.
async fn spawn_stub_node() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let resp =
                        if req.method() == hyper::Method::GET && req.uri().path() == "/health" {
                            Response::builder()
                                .status(200)
                                .header("x-stub", "node")
                                .body(Full::new(Bytes::from(
                                    serde_json::to_vec(&json!({ "status": "ok" })).unwrap(),
                                )))
                                .unwrap()
                        } else {
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default();
                            Response::builder()
                                .status(200)
                                .header("x-stub", "node")
                                .body(Full::new(body))
                                .unwrap()
                        };
                    Ok::<_, Infallible>(resp)
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

/// Reserve then free an ephemeral loopback port (free for the very next bind in practice).
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Poll `GET {base}/health` until it answers or the attempt budget is exhausted.
async fn wait_for_health(http: &reqwest::Client, base: &str) -> Option<reqwest::Response> {
    for _ in 0..50 {
        if let Ok(r) = http.get(format!("{base}/health")).send().await {
            return Some(r);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn established_proxy_forwards_get_and_post_and_is_idempotent() {
    dig_dns::transport::init_crypto();
    let stub_addr = spawn_stub_node().await;
    let dig_local_port = free_port().await;
    let cfg = Config {
        dig_local_ip: Ipv4Addr::new(127, 0, 0, 1),
        dig_local_port,
        node_url: Some(format!("http://{stub_addr}")),
        ..Config::default()
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let cfg_clone = cfg.clone();
    let established = tokio::spawn(async move {
        ensure_dig_local_mapping(&cfg_clone, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let dig_local_base = format!("http://127.0.0.1:{dig_local_port}");
    let http = reqwest::Client::builder().build().unwrap();

    // --- GET is forwarded, headers relayed, body intact ------------------------------------
    let resp = wait_for_health(&http, &dig_local_base)
        .await
        .expect("dig.local proxy should come up and reach the stub node");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-stub").unwrap(),
        "node",
        "stub's header must be relayed through the proxy"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    // --- POST (the node's JSON-RPC surface) is forwarded byte-for-byte too ------------------
    let rpc_body = r#"{"jsonrpc":"2.0","id":1,"method":"dig.getAnchoredRoot"}"#;
    let resp = http
        .post(format!("{dig_local_base}/"))
        .body(rpc_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert_eq!(text, rpc_body, "POST body relayed byte-for-byte: {text}");

    // --- Idempotent: a second ensure against the SAME address is a no-op -------------------
    let outcome2 = ensure_dig_local_mapping(&cfg, async {}).await;
    assert_eq!(
        outcome2,
        EnsureOutcome::AlreadyMapped,
        "re-running dig-dns must not attempt a duplicate bind"
    );

    let _ = shutdown_tx.send(());
    let outcome1 = established.await.unwrap();
    assert_eq!(
        outcome1,
        EnsureOutcome::Established {
            bound_port: dig_local_port
        }
    );
}

#[tokio::test]
async fn node_absent_is_a_graceful_502_never_a_crash() {
    dig_dns::transport::init_crypto();
    let dig_local_port = free_port().await;
    // Point the target at a port nothing listens on — models the node not (yet) running.
    let dead_port = free_port().await;
    let cfg = Config {
        dig_local_ip: Ipv4Addr::new(127, 0, 0, 1),
        dig_local_port,
        node_url: Some(format!("http://127.0.0.1:{dead_port}")),
        ..Config::default()
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let cfg_clone = cfg.clone();
    let established = tokio::spawn(async move {
        ensure_dig_local_mapping(&cfg_clone, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let dig_local_base = format!("http://127.0.0.1:{dig_local_port}");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = wait_for_health(&http, &dig_local_base)
        .await
        .expect("the proxy listener itself must come up even though the node is absent");
    assert_eq!(
        resp.status(),
        502,
        "node-absent must 502, never hang or crash the proxy"
    );

    let _ = shutdown_tx.send(());
    let outcome = established.await.unwrap();
    assert_eq!(
        outcome,
        EnsureOutcome::Established {
            bound_port: dig_local_port
        },
        "the mapping is still established — it self-heals the moment a real node appears"
    );
}
