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
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
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
use crate::dig_local::{self, EnsureOutcome};
use crate::dns::{self, Transport};
use crate::gateway::{handle, Ctx, GatewayResponse};
use crate::transport::{NodeClient, ReqwestNodeClient};

/// How long between `dig.local`-mapping retries after a bind failure (SPEC §12.1 step 3): the
/// loopback alias or a transient port holder may not be ready yet at `dig-dns` startup.
const DIG_LOCAL_RETRY_INTERVAL: Duration = Duration::from_secs(30);

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

/// The `dig-dns serve` entry point (and the unix service entrypoint): resolve + bind + serve
/// both paths until **Ctrl-C**. A thin wrapper over [`serve_with_shutdown`] with a Ctrl-C
/// shutdown trigger.
pub async fn run_service(config: Config) -> Result<(), ServerError> {
    serve_with_shutdown(config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Resolve the node (§5.3 ladder), bind the HTTP gateway (with the `:8053` fallback) AND the
/// DNS responder (`:53`), log loudly, and serve both until `shutdown` resolves. The two
/// resolution paths are independent: a DNS `:53` bind failure (e.g. unprivileged, or `:53`
/// held) is NON-fatal — the gateway + PAC (Path B) still serve `.dig`.
///
/// `shutdown` is fanned out to EVERY subtask (the gateway accept loop, the DNS responder, and
/// the `dig.local` ensure loop) through one shared [`tokio::sync::watch`] flag, so a single
/// signal stops all of them gracefully. [`run_service`] passes Ctrl-C; the Windows-service
/// entrypoint ([`crate::win_service`], Windows only) passes the SCM `Stop` control — so a
/// service stop tears down the whole service, not just the foreground process.
pub async fn serve_with_shutdown(
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServerError> {
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

    // Record the machine-wide runtime info (pid + the ACTUALLY-bound port, which may be the
    // `:8053` fallback) so the CLI can locate + identify THIS service process regardless of the
    // invoking user (#501). The guard is held for the whole serve lifetime and removes the file
    // on shutdown, so the CLI never inherits a stale pid/port. Best-effort — a non-admin
    // foreground `serve` may be unable to write the system dir (logged, non-fatal).
    let _runtime_guard = crate::state::RuntimeGuard::record(
        crate::state::state_dir(),
        &crate::state::RuntimeInfo {
            pid: std::process::id(),
            loopback_ip: config.loopback_ip.to_string(),
            http_port: bound_port,
            dns_active,
        },
    );

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

    // One shared shutdown, fanned out to every subtask: flip the watch when `shutdown`
    // resolves; each subtask waits for the flag. `watch` (not `Notify`) so a subtask that
    // subscribes after the trigger still observes it — no lost-wakeup race on a fast stop.
    let (shutdown_tx, _keep) = tokio::sync::watch::channel(false);
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown.await;
            let _ = tx.send(true);
        });
    }

    if let Ok((udp, tcp)) = dns {
        let ip = config.loopback_ip;
        let tld = config.tld.clone();
        let ttl = config.dns_ttl_secs;
        let wait = wait_for_shutdown(shutdown_tx.subscribe());
        tokio::spawn(async move {
            serve_dns(udp, tcp, ip, tld, ttl, wait).await;
        });
    }

    // Ensure http://dig.local reaches the local dig-node too (SPEC §12) — independent of, and
    // non-fatal relative to, the .dig gateway/DNS paths above.
    spawn_dig_local_ensure(config.clone(), shutdown_tx.subscribe());

    serve_on(
        listener,
        client,
        ctx,
        wait_for_shutdown(shutdown_tx.subscribe()),
    )
    .await;
    Ok(())
}

/// A future that resolves once the shared shutdown [`tokio::sync::watch`] flag flips to `true`
/// (or the sender is dropped). `wait_for` also returns immediately when the flag is ALREADY
/// `true`, so a subtask spawned just after the trigger still shuts down.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|flagged| *flagged).await;
}

/// Probe-then-bind-if-absent (SPEC §12.1 steps 1–2): the idempotency check + bind, isolated
/// from serving so it is directly unit-testable with real ephemeral loopback sockets (no
/// privilege, no dependency on the real `127.0.0.2` alias). Returns the listener only on
/// `Established` — the caller decides whether/how to serve it.
async fn probe_and_bind_dig_local(
    http: &reqwest::Client,
    ip: Ipv4Addr,
    port: u16,
) -> (EnsureOutcome, Option<TcpListener>) {
    if crate::transport::probe(http, &format!("http://{ip}:{port}")).await {
        return (EnsureOutcome::AlreadyMapped, None);
    }
    match TcpListener::bind(SocketAddr::from((ip, port))).await {
        Ok(listener) => {
            let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
            (EnsureOutcome::Established { bound_port }, Some(listener))
        }
        Err(e) => (
            EnsureOutcome::Unavailable {
                reason: e.to_string(),
            },
            None,
        ),
    }
}

/// Ensure `http://dig.local` reaches the local dig-node (SPEC §12): one attempt — probe, and if
/// absent, bind + serve a transparent reverse proxy to the discovered local-node target UNTIL
/// `shutdown` resolves. Returns immediately for `AlreadyMapped`/`Unavailable`; for `Established`
/// this call does not return until `shutdown` resolves (mirrors `serve_on`'s bind-then-serve
/// shape). Public so both [`run_service`] and the integration test drive the exact same path
/// over real loopback sockets.
pub async fn ensure_dig_local_mapping(
    config: &Config,
    shutdown: impl Future<Output = ()>,
) -> EnsureOutcome {
    // Every entry point that builds a `reqwest::Client` installs the rustls crypto provider
    // first (idempotent `Once`) — the SAME defensive call `ReqwestNodeClient::{resolve,
    // with_base}` make, so this function is correct even when called before `run_service`'s own
    // (also-present) `init_crypto()` call, e.g. directly from a test.
    crate::transport::init_crypto();
    let http = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "dig.local: failed to build HTTP client");
            return EnsureOutcome::Unavailable {
                reason: e.to_string(),
            };
        }
    };
    let (outcome, listener) =
        probe_and_bind_dig_local(&http, config.dig_local_ip, config.dig_local_port).await;
    match &outcome {
        EnsureOutcome::AlreadyMapped => {
            tracing::info!(
                ip = %config.dig_local_ip,
                port = config.dig_local_port,
                "http://dig.local already reaches a dig-node; leaving it"
            );
        }
        EnsureOutcome::Established { bound_port } => {
            let target = dig_local::local_node_target(config);
            tracing::info!(
                ip = %config.dig_local_ip,
                bound_port,
                target = %target,
                "ensured http://dig.local reaches the local dig-node"
            );
            if let Some(listener) = listener {
                serve_dig_local_proxy(listener, http, target, shutdown).await;
            }
        }
        EnsureOutcome::Unavailable { reason } => {
            tracing::warn!(
                reason = %reason,
                ip = %config.dig_local_ip,
                port = config.dig_local_port,
                "could not ensure http://dig.local (non-fatal; the .dig gateway still serves)"
            );
        }
    }
    outcome
}

/// Spawn [`ensure_dig_local_mapping`] fire-and-forget from [`serve_with_shutdown`], retrying on
/// [`DIG_LOCAL_RETRY_INTERVAL`] only when it reports `Unavailable` (a transient bind failure —
/// the loopback alias not up yet, or a stale holder that exits shortly) — self-healing without
/// restarting `dig-dns`. `AlreadyMapped` and `Established` need no retry: the former is already
/// satisfied, the latter has already served until `shutdown` by the time it returns. Shares the
/// service-wide shutdown watch (`shutdown_rx`), so a service stop ends both the ensure loop and
/// any established reverse-proxy it is serving.
fn spawn_dig_local_ensure(config: Config, shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            let outcome =
                ensure_dig_local_mapping(&config, wait_for_shutdown(shutdown_rx.clone())).await;
            match outcome {
                EnsureOutcome::Unavailable { .. } => {
                    tokio::select! {
                        _ = wait_for_shutdown(shutdown_rx.clone()) => return,
                        _ = tokio::time::sleep(DIG_LOCAL_RETRY_INTERVAL) => {}
                    }
                }
                EnsureOutcome::AlreadyMapped | EnsureOutcome::Established { .. } => return,
            }
        }
    });
}

/// Serve the `dig.local` transparent reverse proxy on an already-bound listener until
/// `shutdown` resolves (SPEC §12.1 step 2). Every request is forwarded byte-for-byte (method,
/// path+query, headers minus hop-by-hop, body) to `target_base` and the response relayed back
/// unmodified — `dig.local` is the node's OWN control host (JSON-RPC `POST /`, `GET /health`,
/// …), not `.dig` store content, so this is a plain passthrough, never the gateway's
/// verify-then-decrypt path.
async fn serve_dig_local_proxy(
    listener: TcpListener,
    http: reqwest::Client,
    target_base: String,
    shutdown: impl Future<Output = ()>,
) {
    let target = Arc::new(target_base);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("dig.local proxy shutting down");
                break;
            }
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => { tracing::warn!(error = %e, "dig.local accept failed"); continue; }
                };
                let io = TokioIo::new(stream);
                let http = http.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let http = http.clone();
                        let target = target.clone();
                        async move { Ok::<_, Infallible>(proxy_respond(&http, &target, req).await) }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::debug!(error = %e, "dig.local connection closed with error");
                    }
                });
            }
        }
    }
}

/// Forward one hyper request to `target_base`, verbatim (method, path+query, headers minus
/// hop-by-hop, body), and convert the response back — a plain relay, never touching bytes.
async fn proxy_respond(
    http: &reqwest::Client,
    target_base: &str,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return proxy_text(400, "invalid method"),
    };
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let headers = req.headers().clone();
    let body = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();

    let url = format!("{target_base}{path_and_query}");
    let mut builder = http.request(method, &url);
    for (name, value) in headers.iter() {
        if is_hop_by_hop_header(name.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }
    if !body.is_empty() {
        builder = builder.body(body.to_vec());
    }

    match builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let mut out = Response::builder().status(status);
            for (name, value) in resp.headers().iter() {
                if is_hop_by_hop_header(name.as_str()) {
                    continue;
                }
                out = out.header(name.as_str(), value.as_bytes());
            }
            let bytes = resp.bytes().await.unwrap_or_default();
            out.body(Full::new(bytes))
                .unwrap_or_else(|_| proxy_text(500, "internal error"))
        }
        Err(_) => proxy_text(502, "dig-node unreachable"),
    }
}

/// Hop-by-hop / connection-management headers a proxy must never blindly relay (RFC 9110
/// §7.6.1) — `content-length`/`transfer-encoding` are recomputed by the HTTP layers on each
/// side, and `host` must name the TARGET, not the original request's authority.
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

/// A short `text/plain` response for a proxy-local error (never something the node itself sent).
fn proxy_text(status: u16, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(500)
                .body(Full::new(Bytes::from_static(b"internal error")))
                .expect("static 500 response is valid")
        })
}

/// Probe a running gateway for its actually-bound port: try `/.dig/resolve-probe` on the
/// primary then the fallback, returning the first that answers `204`. Used by `dig-dns pac` to
/// emit a PAC file advertising the real bound port (which may be the `:8053` fallback). Returns
/// `None` when no gateway is running.
pub async fn probe_gateway_port(ip: Ipv4Addr, primary: u16, fallback: u16) -> Option<u16> {
    crate::transport::init_crypto();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    for port in [primary, fallback] {
        let url = format!("http://{ip}:{port}/.dig/resolve-probe");
        if let Ok(resp) = http.get(&url).send().await {
            if resp.status().as_u16() == 204 {
                return Some(port);
            }
        }
    }
    None
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

    #[tokio::test]
    async fn bind_listener_errors_fast_when_both_primary_and_fallback_are_held() {
        // The 1053 fix requires bind failure to be a FAST, diagnosable error — never a hang.
        // Occupy BOTH the primary and the fallback, then assert `bind_listener` returns an error
        // naming both addresses (so a service can report STOPPED + a clear cause) rather than
        // blocking. The whole assertion is wrapped in a short timeout to prove non-blocking.
        let held_primary = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let held_fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary = held_primary.local_addr().unwrap();
        let fallback = held_fallback.local_addr().unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), bind_listener(primary, fallback))
            .await
            .expect("bind_listener must return promptly, never hang");

        let err = result.expect_err("both addresses held ⇒ a hard bind error");
        let msg = err.to_string();
        assert!(
            msg.contains(&primary.to_string()),
            "error names the primary: {msg}"
        );
        assert!(
            msg.contains(&fallback.to_string()),
            "error names the fallback: {msg}"
        );
    }

    #[tokio::test]
    async fn probe_and_bind_dig_local_binds_when_absent() {
        crate::transport::init_crypto();
        // Reserve then free an ephemeral port so it is free for the ensure() call.
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);

        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let (outcome, listener) =
            probe_and_bind_dig_local(&http, Ipv4Addr::new(127, 0, 0, 1), port).await;
        assert_eq!(outcome, EnsureOutcome::Established { bound_port: port });
        assert!(
            listener.is_some(),
            "Established must hand back the listener"
        );
    }

    #[tokio::test]
    async fn probe_and_bind_dig_local_already_mapped_is_a_noop() {
        crate::transport::init_crypto();
        // Spin a tiny stub that answers ANY request (models dig-node's own /health bind, or a
        // dig-dns proxy still running from an earlier start).
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
                    let svc = service_fn(|_req: Request<Incoming>| async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let (outcome, listener) =
            probe_and_bind_dig_local(&http, Ipv4Addr::new(127, 0, 0, 1), addr.port()).await;
        assert_eq!(outcome, EnsureOutcome::AlreadyMapped);
        assert!(
            listener.is_none(),
            "already-mapped must never bind a second listener"
        );
    }

    #[tokio::test]
    async fn probe_and_bind_dig_local_is_idempotent_across_repeated_calls() {
        crate::transport::init_crypto();
        // First call: absent -> Established (binds + holds the listener).
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);

        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let (first, listener) =
            probe_and_bind_dig_local(&http, Ipv4Addr::new(127, 0, 0, 1), port).await;
        assert_eq!(first, EnsureOutcome::Established { bound_port: port });
        let listener = listener.expect("first call binds");

        // Serve it minimally (answers anything) so the second call's probe finds it live.
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(|_req: Request<Incoming>| async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        // Second call against the SAME address: must be a no-op, never attempt another bind.
        let http2 = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let (second, listener2) =
            probe_and_bind_dig_local(&http2, Ipv4Addr::new(127, 0, 0, 1), port).await;
        assert_eq!(
            second,
            EnsureOutcome::AlreadyMapped,
            "re-running is safe: no duplicate bind"
        );
        assert!(listener2.is_none());
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
