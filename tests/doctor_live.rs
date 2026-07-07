//! Integration test for `doctor`'s LIVE probes against a running gateway + DNS responder.
//!
//! Brings both listeners up on ephemeral loopback ports (pointed at a tiny stub node that
//! answers `/health`), then runs `doctor::run` and asserts it observes the real system: the DNS
//! responder answers directly, the gateway answers on its port (Path B live), the node is
//! reachable, and a `.dig` URL can load. This exercises the probe layer that the pure-evaluator
//! unit tests cannot.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use dig_dns::config::Config;
use dig_dns::doctor;
use dig_dns::gateway::Ctx;
use dig_dns::server::{bind_dns, serve_dns, serve_on};
use dig_dns::transport::ReqwestNodeClient;

/// A stub node that answers `GET /health` with `200` (so the gateway's health reports the node
/// reachable) and anything else with `200 {}`.
async fn stub_node(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let _ = req;
    Ok(Response::builder()
        .status(200)
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap())
}

async fn spawn_stub_node() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(stub_node))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn doctor_sees_a_live_service() {
    // Stub node (for the node-reachable probe) + gateway + DNS responder, all on 127.0.0.1.
    let node_url = spawn_stub_node().await;
    let client = Arc::new(ReqwestNodeClient::with_base(&node_url).unwrap());

    let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_port = gw_listener.local_addr().unwrap().port();

    let (udp, tcp) = bind_dns(Ipv4Addr::LOCALHOST, 0).await.unwrap();
    let dns_port = udp.local_addr().unwrap().port();

    let ctx = Ctx {
        config: Config {
            loopback_ip: Ipv4Addr::LOCALHOST,
            http_port: gw_port,
            ..Config::default()
        },
        bound_port: gw_port,
        dns_active: true,
        started: Instant::now(),
    };

    let (gw_tx, gw_rx) = tokio::sync::oneshot::channel::<()>();
    let (dns_tx, dns_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_on(gw_listener, client, ctx, async {
        let _ = gw_rx.await;
    }));
    tokio::spawn(serve_dns(
        udp,
        tcp,
        Ipv4Addr::LOCALHOST,
        "dig".to_string(),
        2,
        async {
            let _ = dns_rx.await;
        },
    ));

    // A config describing exactly where we bound everything.
    let cfg = Config {
        loopback_ip: Ipv4Addr::LOCALHOST,
        dns_port,
        http_port: gw_port,
        http_fallback_port: gw_port,
        ..Config::default()
    };

    let report = doctor::run(&cfg).await;

    // Path B live (gateway answered), DNS responder answered directly, node reachable, ok.
    let status = |id: &str| {
        report
            .checks
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.status)
            .unwrap_or(doctor::CheckStatus::Info)
    };
    assert_eq!(
        status("loopback_ip"),
        doctor::CheckStatus::Pass,
        "127.0.0.1 is up"
    );
    assert_eq!(
        status("dns_direct"),
        doctor::CheckStatus::Pass,
        "responder answered A 127.0.0.1: {report:#?}"
    );
    assert_eq!(
        status("gateway_port"),
        doctor::CheckStatus::Pass,
        "gateway answered resolve-probe"
    );
    assert_eq!(
        status("node_reachable"),
        doctor::CheckStatus::Pass,
        "stub node /health reachable"
    );
    assert!(report.path_b, "Path B is live");
    assert!(report.ok, "a .dig URL can load");

    let _ = gw_tx.send(());
    let _ = dns_tx.send(());
}
