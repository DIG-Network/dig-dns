//! Integration test for the machine-wide runtime-info recording (#501) driven through the REAL
//! top-level serve entry point, [`serve_with_shutdown`].
//!
//! It brings the whole service up on ephemeral loopback ports with a `DIG_DNS_STATE_DIR`
//! override pointing at a private temp dir, then asserts the service records `runtime.json`
//! (its pid + the ACTUALLY-bound port) while serving and REMOVES it on graceful shutdown — the
//! contract the CLI relies on to locate + identify the running service regardless of the
//! invoking user.
//!
//! This lives in its OWN test binary with a SINGLE test so the `DIG_DNS_STATE_DIR` env override
//! is process-isolated (each cargo/nextest test binary is a separate process), never racing
//! another test that reads the state dir.

use std::net::Ipv4Addr;
use std::time::Duration;

use dig_dns::config::Config;
use dig_dns::server::serve_with_shutdown;
use dig_dns::state::{self, ENV_STATE_DIR};
use tokio::net::TcpListener;

/// Reserve an ephemeral loopback port, then free it so the service can bind it. A tiny TOCTOU
/// window, acceptable in a test (nothing else races for a just-freed high port on 127.0.0.1).
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[tokio::test]
async fn serve_records_runtime_info_and_clears_it_on_shutdown() {
    // A private machine-wide state dir for this test process only.
    let state_dir = std::env::temp_dir().join(format!("dig-dns-rt-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::env::set_var(ENV_STATE_DIR, &state_dir);

    let http_port = free_port().await;
    let fallback_port = free_port().await;
    let dns_port = free_port().await;
    let dig_local_port = free_port().await;

    let config = Config {
        loopback_ip: Ipv4Addr::LOCALHOST,
        http_port,
        http_fallback_port: fallback_port,
        dns_port,
        // An explicit override is the sole node candidate and is used verbatim (no probing, no
        // network), so bring-up is fast and hermetic.
        node_url: Some("http://127.0.0.1:1".to_string()),
        dig_local_ip: Ipv4Addr::LOCALHOST,
        dig_local_port,
        ..Config::default()
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let serve = tokio::spawn(serve_with_shutdown(config, async move {
        let _ = shutdown_rx.await;
    }));

    // Wait for the service to bind + record its runtime info (bounded, so a failure is a prompt
    // test failure rather than a hang).
    let mut recorded = None;
    for _ in 0..100 {
        if let Some(info) = state::read_runtime_from(&state_dir) {
            recorded = Some(info);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let info = recorded.expect("the service must record runtime.json while serving");
    assert_eq!(info.pid, std::process::id(), "records THIS process's pid");
    assert_eq!(
        info.http_port, http_port,
        "records the actually-bound gateway port"
    );
    assert_eq!(info.loopback_ip, "127.0.0.1");

    // Graceful shutdown → the RuntimeGuard drops → the runtime file is removed.
    let _ = shutdown_tx.send(());
    serve
        .await
        .expect("serve task joins")
        .expect("serve returns Ok on graceful shutdown");
    assert!(
        state::read_runtime_from(&state_dir).is_none(),
        "graceful shutdown must clear runtime.json (no stale pid/port left behind)"
    );

    std::env::remove_var(ENV_STATE_DIR);
    let _ = std::fs::remove_dir_all(&state_dir);
}
