//! The hyper HTTP listener glue: bind the gateway (with the deterministic `:8053` fallback),
//! accept connections, and adapt hyper's request/response types to the pure [`crate::gateway`]
//! handler.
//!
//! Everything policy-related lives in [`crate::gateway`] (unit-tested without a socket); this
//! module is intentionally thin — bind, accept, convert — and is exercised end-to-end by the
//! integration test (`tests/gateway_stub_node.rs`) driving a real listener over loopback.

use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{HOST, RANGE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use hyper::Uri;

use crate::config::Config;
use crate::dns::{self, Transport};
use crate::gateway::{handle, Ctx, GatewayResponse};
use crate::transport::{NodeClient, ReqwestNodeClient};

/// A boxed error from the server bring-up (node resolution or socket bind).
pub type ServerError = Box<dyn std::error::Error + Send + Sync>;

/// Bind the primary gateway address, falling back deterministically to the fallback address
/// when the primary cannot be bound (e.g. `:80` held by `http.sys`). Returns the listener, the
/// actually-bound port, and whether the fallback was used (surfaced loudly + in health).
pub async fn bind_listener(
    primary: SocketAddr,
    fallback: SocketAddr,
) -> std::io::Result<(TcpListener, u16, bool)> {
    match TcpListener::bind(primary).await {
        Ok(l) => {
            let port = l.local_addr().map(|a| a.port()).unwrap_or(primary.port());
            Ok((l, port, false))
        }
        Err(primary_err) => match TcpListener::bind(fallback).await {
            Ok(l) => {
                let port = l.local_addr().map(|a| a.port()).unwrap_or(fallback.port());
                Ok((l, port, true))
            }
            Err(fallback_err) => Err(std::io::Error::new(
                fallback_err.kind(),
                format!(
                    "could not bind primary {primary} ({primary_err}) nor fallback \
                     {fallback} ({fallback_err})"
                ),
            )),
        },
    }
}

/// Convert a [`GatewayResponse`] into a hyper response. A malformed header/status degrades to
/// a `500` rather than panicking the connection task.
pub fn to_hyper(gw: GatewayResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(gw.status);
    for (k, v) in &gw.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder
        .body(Full::new(Bytes::from(gw.body)))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(500)
                .body(Full::new(Bytes::from_static(b"internal error")))
                .expect("static 500 response is valid")
        })
}

/// Adapt one hyper request to the gateway handler. The request body is never read (only
/// `GET`/`HEAD` are served); `HEAD` body suppression is handled by hyper from the request
/// method.
async fn respond<N: NodeClient + ?Sized>(
    client: &N,
    ctx: &Ctx,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let range = req
        .headers()
        .get(RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let gw = handle(
        client,
        ctx,
        &method,
        &uri,
        host.as_deref(),
        range.as_deref(),
    )
    .await;
    to_hyper(gw)
}

/// Serve HTTP/1.1 on an already-bound listener until `shutdown` resolves. Each connection is
/// served on its own task; a connection error is logged and does not stop the accept loop.
pub async fn serve_on<N>(
    listener: TcpListener,
    client: Arc<N>,
    ctx: Ctx,
    shutdown: impl Future<Output = ()>,
) where
    N: NodeClient + 'static,
{
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received; stopping accept loop");
                break;
            }
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                let client = client.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let client = client.clone();
                        let ctx = ctx.clone();
                        async move { Ok::<_, Infallible>(respond(&*client, &ctx, req).await) }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::debug!(error = %e, "connection closed with error");
                    }
                });
            }
        }
    }
}

/// Bind the DNS responder on `<ip>:<port>` for BOTH UDP and TCP (SPEC §3). Loopback-only —
/// the caller passes the validated loopback IP.
pub async fn bind_dns(ip: Ipv4Addr, port: u16) -> std::io::Result<(UdpSocket, TcpListener)> {
    let addr = SocketAddr::from((ip, port));
    let udp = UdpSocket::bind(addr).await?;
    let tcp = TcpListener::bind(addr).await?;
    Ok((udp, tcp))
}

/// Serve the DNS responder on an already-bound UDP socket + TCP listener until `shutdown`
/// resolves. UDP answers are built + sent inline (they are tiny + constant-time); each TCP
/// connection is handled on its own task. A per-message error is logged and never stops the
/// loop.
pub async fn serve_dns(
    udp: UdpSocket,
    tcp: TcpListener,
    ip: Ipv4Addr,
    tld: String,
    ttl: u32,
    shutdown: impl Future<Output = ()>,
) {
    let udp = Arc::new(udp);
    let mut buf = vec![0u8; 4096]; // EDNS payloads up to 4 KiB
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("DNS responder shutting down");
                break;
            }
            recv = udp.recv_from(&mut buf) => {
                let (n, peer) = match recv {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!(error = %e, "DNS UDP recv failed"); continue; }
                };
                if let Some(resp) = dns::respond(&buf[..n], ip, &tld, ttl, Transport::Udp) {
                    if let Err(e) = udp.send_to(&resp, peer).await {
                        tracing::debug!(error = %e, "DNS UDP send failed");
                    }
                }
            }
            accepted = tcp.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!(error = %e, "DNS TCP accept failed"); continue; }
                };
                let tld = tld.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_dns_tcp(stream, ip, tld, ttl).await {
                        tracing::debug!(error = %e, "DNS TCP query failed");
                    }
                });
            }
        }
    }
}

/// Handle one length-prefixed DNS-over-TCP query (RFC 1035 §4.2.2): read the 2-byte length,
/// the message, build the (untruncated) response, and write it back length-prefixed.
async fn handle_dns_tcp(
    mut stream: tokio::net::TcpStream,
    ip: Ipv4Addr,
    tld: String,
    ttl: u32,
) -> std::io::Result<()> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    if let Some(resp) = dns::respond(&msg, ip, &tld, ttl, Transport::Tcp) {
        let rlen = (resp.len() as u16).to_be_bytes();
        stream.write_all(&rlen).await?;
        stream.write_all(&resp).await?;
        stream.flush().await?;
    }
    Ok(())
}

/// Resolve the node (§5.3 ladder), bind the HTTP gateway (with the `:8053` fallback) AND the
/// DNS responder (`:53`), log loudly, and serve both until Ctrl-C. This is the `dig-dns serve`
/// entry point. The two resolution paths are independent: a DNS `:53` bind failure (e.g.
/// unprivileged, or `:53` held) is NON-fatal — the gateway + PAC (Path B) still serve `.dig`.
pub async fn run_service(config: Config) -> Result<(), ServerError> {
    crate::transport::init_crypto();
    let client = Arc::new(ReqwestNodeClient::resolve(&config).await?);
    let primary = SocketAddr::from((config.loopback_ip, config.http_port));
    let fallback = SocketAddr::from((config.loopback_ip, config.http_fallback_port));
    let (listener, bound_port, used_fallback) = bind_listener(primary, fallback).await?;

    // Path A (DNS) is best-effort; Path B (gateway + PAC) is the floor.
    let dns = bind_dns(config.loopback_ip, config.dns_port).await;
    let dns_active = dns.is_ok();
    if let Err(e) = &dns {
        tracing::warn!(
            error = %e,
            "DNS responder could not bind :{} — Path A (OS split-DNS) is unavailable; the \
             gateway + PAC (Path B) still serve .dig",
            config.dns_port
        );
    }

    let ctx = Ctx {
        config: config.clone(),
        bound_port,
        dns_active,
        started: Instant::now(),
    };
    tracing::info!(
        loopback_ip = %config.loopback_ip,
        bound_port,
        used_fallback,
        dns_active,
        node = client.base_url(),
        "dig-dns service listening"
    );
    if used_fallback {
        tracing::warn!(
            bound_port,
            "primary :{} was unavailable — bound the fallback :{}. Browsers relying on OS DNS \
             (Path A) will hit :{} directly; if that is not the browser default port, use the \
             PAC file (/.dig/proxy.pac), which advertises the bound port.",
            config.http_port,
            bound_port,
            bound_port
        );
    }

    if let Ok((udp, tcp)) = dns {
        let ip = config.loopback_ip;
        let tld = config.tld.clone();
        let ttl = config.dns_ttl_secs;
        tokio::spawn(async move {
            serve_dns(udp, tcp, ip, tld, ttl, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
        });
    }

    serve_on(listener, client, ctx, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await;
    Ok(())
}

/// Split a `fetch` target into `(host, path)`. Accepts a full `http(s)://host/path` URL, a
/// bare `host` (using the supplied `path`), or a `host/path` string.
pub fn split_target(target: &str, path: &str) -> (String, String) {
    // A full URL (has BOTH a scheme and an authority). A bare `abc.dig` also parses to an
    // authority (authority-form), so the scheme is what distinguishes a real URL.
    if let Ok(uri) = target.parse::<Uri>() {
        if uri.scheme().is_some() {
            if let Some(auth) = uri.authority() {
                let p = if uri.path().is_empty() {
                    "/"
                } else {
                    uri.path()
                };
                return (auth.host().to_string(), p.to_string());
            }
        }
    }
    match target.split_once('/') {
        Some((host, rest)) => (
            host.to_string(),
            format!("/{}", rest.trim_start_matches('/')),
        ),
        None => (target.to_string(), path.to_string()),
    }
}

/// One-shot: resolve the node (§5.3 ladder), then run a single request through the gateway
/// pipeline and return the response. Used by `dig-dns fetch` + the acceptance scripts (a
/// curl-free proof the pipeline resolves a real `.dig` resource).
pub async fn fetch_resource(
    config: Config,
    target: &str,
    path: &str,
) -> Result<GatewayResponse, ServerError> {
    crate::transport::init_crypto();
    let client = ReqwestNodeClient::resolve(&config).await?;
    let (host, res_path) = split_target(target, path);
    let uri: Uri = res_path
        .parse()
        .map_err(|e| format!("invalid path {res_path:?}: {e}"))?;
    let ctx = Ctx {
        config,
        bound_port: 0,
        dns_active: false,
        started: Instant::now(),
    };
    Ok(handle(&client, &ctx, "GET", &uri, Some(&host), None).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_target_full_url() {
        assert_eq!(
            split_target("http://abc.dig/assets/app.js", "/"),
            ("abc.dig".to_string(), "/assets/app.js".to_string())
        );
        assert_eq!(
            split_target("http://abc.dig", "/ignored"),
            ("abc.dig".to_string(), "/".to_string())
        );
    }

    #[test]
    fn split_target_bare_host_uses_path_arg() {
        assert_eq!(
            split_target("abc.dig", "/index.html"),
            ("abc.dig".to_string(), "/index.html".to_string())
        );
    }

    #[test]
    fn split_target_host_slash_path() {
        assert_eq!(
            split_target("abc.dig/app.js", "/"),
            ("abc.dig".to_string(), "/app.js".to_string())
        );
    }

    #[tokio::test]
    async fn bind_listener_uses_primary_when_free() {
        let (_l, port, used_fallback) = bind_listener(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        assert!(!used_fallback);
        assert_ne!(port, 0);
    }

    #[tokio::test]
    async fn bind_listener_falls_back_when_primary_held() {
        // Occupy a port, then ask bind_listener to use it as "primary" → it must fall back.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary = occupied.local_addr().unwrap();
        let (_l, port, used_fallback) = bind_listener(primary, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(used_fallback);
        assert_ne!(port, primary.port());
    }

    #[test]
    fn to_hyper_maps_status_and_headers() {
        let gw = GatewayResponse {
            status: 206,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"hi".to_vec(),
        };
        let resp = to_hyper(gw);
        assert_eq!(resp.status(), 206);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
    }
}
