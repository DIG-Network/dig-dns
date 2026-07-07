//! The `doctor` diagnostic (SPEC §9): check each link of each resolution path INDEPENDENTLY,
//! report pass/fail + a fix hint, and exit non-zero when a `.dig` URL cannot load.
//!
//! Design: the DECISION logic is pure - each `evaluate_*` turns an observation into a [`Check`],
//! and [`Report`] aggregates them + decides which path(s) are live - so it is fully unit-tested
//! without touching the system. The async [`run`] performs the live probes (bind the loopback
//! IP, query the DNS responder, resolve via the OS, probe the gateway, read browser policy, find
//! the `:80` holder) and feeds them to the evaluators.
//!
//! Overall outcome: a `.dig` URL loads iff the loopback IP is up AND at least one of Path A (OS
//! split-DNS) or Path B (gateway + PAC) is live; `doctor` exits non-zero otherwise. Individual
//! link results explain WHY, and which path(s) are live.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use crate::config::Config;

/// A single diagnostic check's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// The link works.
    Pass,
    /// The link is broken (contributes to a failing diagnosis when it blocks both paths).
    Fail,
    /// A non-blocking concern.
    Warn,
    /// Informational (never affects the outcome).
    Info,
}

impl CheckStatus {
    fn symbol(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Warn => "WARN",
            CheckStatus::Info => "INFO",
        }
    }
}

/// One diagnostic check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Stable machine id (e.g. `loopback_ip`).
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Outcome.
    pub status: CheckStatus,
    /// A one-line detail.
    pub detail: String,
    /// A suggested fix (present on failures/warnings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    fn new(
        id: &'static str,
        name: &'static str,
        status: CheckStatus,
        detail: impl Into<String>,
    ) -> Self {
        Check {
            id,
            name,
            status,
            detail: detail.into(),
            fix: None,
        }
    }
    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// The full diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// All checks, in run order.
    pub checks: Vec<Check>,
    /// Path A (OS split-DNS) is live end-to-end.
    pub path_a: bool,
    /// Path B (gateway + PAC) is live.
    pub path_b: bool,
    /// A `.dig` URL can load (loopback up AND at least one path live).
    pub ok: bool,
}

impl Report {
    /// Build a report from checks, deriving the path liveness + overall outcome by check id.
    pub fn build(checks: Vec<Check>) -> Self {
        let passed = |id: &str| {
            checks
                .iter()
                .any(|c| c.id == id && c.status == CheckStatus::Pass)
        };
        let loopback_up = passed("loopback_ip");
        let path_a = passed("os_routing");
        let path_b = passed("gateway_port");
        Report {
            ok: overall_ok(loopback_up, path_a, path_b),
            path_a,
            path_b,
            checks,
        }
    }

    /// Machine-readable JSON (`--json`), with stable field names.
    pub fn to_json(&self) -> String {
        json!({
            "ok": self.ok,
            "path_a": self.path_a,
            "path_b": self.path_b,
            "checks": self.checks,
        })
        .to_string()
    }

    /// Human-readable multi-line text.
    pub fn to_text(&self) -> String {
        let mut out = String::from("dig-dns doctor\n");
        for c in &self.checks {
            out.push_str(&format!(
                "  [{}] {}: {}\n",
                c.status.symbol(),
                c.name,
                c.detail
            ));
            if let Some(fix) = &c.fix {
                out.push_str(&format!("         fix: {fix}\n"));
            }
        }
        let paths = match (self.path_a, self.path_b) {
            (true, true) => "Path A (OS DNS) and Path B (PAC proxy) are both live",
            (true, false) => "Path A (OS DNS) is live",
            (false, true) => "Path B (PAC proxy) is live",
            (false, false) => "NEITHER path is live",
        };
        out.push_str(&format!(
            "\n{}\n{}\n",
            paths,
            if self.ok {
                "RESULT: a .dig URL can load."
            } else {
                "RESULT: a .dig URL will NOT load - fix the failing links above."
            }
        ));
        out
    }
}

/// A `.dig` URL loads iff the dedicated loopback IP is up AND at least one resolution path is
/// live.
pub fn overall_ok(loopback_up: bool, path_a: bool, path_b: bool) -> bool {
    loopback_up && (path_a || path_b)
}

// --- Pure evaluators (observation → Check) -------------------------------------------------

/// Evaluate whether the dedicated loopback IP is up (bindable) locally.
pub fn evaluate_loopback(ip: Ipv4Addr, bindable: bool) -> Check {
    if bindable {
        Check::new(
            "loopback_ip",
            "Loopback IP is up",
            CheckStatus::Pass,
            format!("{ip} is assigned to a local interface"),
        )
    } else {
        Check::new(
            "loopback_ip",
            "Loopback IP is up",
            CheckStatus::Fail,
            format!("{ip} is not a local address"),
        )
        .with_fix(format!(
            "the installer must add {ip} to the loopback interface \
             (macOS: `ifconfig lo0 alias {ip}`; Linux/Windows 127/8 is usually already up)"
        ))
    }
}

/// Evaluate the direct DNS-responder probe: query `<loopback>:53` and expect it to return the
/// served IP.
pub fn evaluate_dns_direct(expected: Ipv4Addr, answered: Option<Ipv4Addr>) -> Check {
    match answered {
        Some(ip) if ip == expected => Check::new(
            "dns_direct",
            "DNS responder answers directly",
            CheckStatus::Pass,
            format!("responder returned A {ip}"),
        ),
        Some(ip) => Check::new(
            "dns_direct",
            "DNS responder answers directly",
            CheckStatus::Fail,
            format!("responder returned A {ip}, expected {expected}"),
        )
        .with_fix("the DNS responder is answering with the wrong address - check DIG_DNS_IP"),
        None => Check::new(
            "dns_direct",
            "DNS responder answers directly",
            CheckStatus::Fail,
            "no A answer from the responder".to_string(),
        )
        .with_fix("is the service running? start `dig-dns serve` (needs privilege to bind :53)"),
    }
}

/// Evaluate Path A end-to-end: does the OS resolver route a `.dig` name to the served IP?
pub fn evaluate_os_routing(expected: Ipv4Addr, resolved: &[IpAddr]) -> Check {
    if resolved.contains(&IpAddr::V4(expected)) {
        Check::new(
            "os_routing",
            "OS resolves .dig to the loopback IP (Path A)",
            CheckStatus::Pass,
            format!("the OS resolver returned {expected}"),
        )
    } else {
        Check::new(
            "os_routing",
            "OS resolves .dig to the loopback IP (Path A)",
            CheckStatus::Warn,
            "the OS does not route .dig to the responder (Path A not configured)".to_string(),
        )
        .with_fix(
            "the installer configures OS split-DNS for .dig (macOS `/etc/resolver/dig`, \
             Windows NRPT, Linux systemd-resolved) - or rely on Path B (the PAC proxy)",
        )
    }
}

/// Evaluate Path B: which gateway port answered the liveness probe (if any).
pub fn evaluate_gateway(primary: u16, fallback: u16, answered_port: Option<u16>) -> Check {
    match answered_port {
        Some(p) if p == primary => Check::new(
            "gateway_port",
            "HTTP gateway answers (Path B)",
            CheckStatus::Pass,
            format!("gateway answered /.dig/resolve-probe on :{p}"),
        ),
        Some(p) => Check::new(
            "gateway_port",
            "HTTP gateway answers (Path B)",
            CheckStatus::Pass,
            format!("gateway answered on the fallback :{p} (:{primary} was unavailable)"),
        )
        .with_fix(format!(
            "browsers using OS DNS reach :{primary}; since the gateway is on :{p}, use the PAC \
             (/.dig/proxy.pac) which advertises :{p}"
        )),
        None => Check::new(
            "gateway_port",
            "HTTP gateway answers (Path B)",
            CheckStatus::Fail,
            format!("no gateway on :{primary} or :{fallback}"),
        )
        .with_fix("start the service: `dig-dns serve`"),
    }
}

/// Evaluate the content link: can the gateway reach a dig-node?
pub fn evaluate_node(reachable: Option<bool>) -> Check {
    match reachable {
        Some(true) => Check::new(
            "node_reachable",
            "Gateway can reach a dig-node",
            CheckStatus::Pass,
            "the resolved dig-node answered".to_string(),
        ),
        Some(false) => Check::new(
            "node_reachable",
            "Gateway can reach a dig-node",
            CheckStatus::Warn,
            "the gateway is up but no dig-node is reachable - content will 502".to_string(),
        )
        .with_fix(
            "start your dig-node (localhost:9778) or point at one with `--node` / DIG_NODE_URL",
        ),
        None => Check::new(
            "node_reachable",
            "Gateway can reach a dig-node",
            CheckStatus::Info,
            "not determined (the gateway did not answer /.dig/health)".to_string(),
        ),
    }
}

// --- Live probes (async) -------------------------------------------------------------------

/// Run all checks against the live system and build the report.
pub async fn run(config: &Config) -> Report {
    let ip = config.loopback_ip;
    let mut checks = Vec::new();

    // 1) loopback IP up (bindable).
    let bindable = tokio::net::UdpSocket::bind(SocketAddr::from((ip, 0)))
        .await
        .is_ok();
    checks.push(evaluate_loopback(ip, bindable));

    // 2) DNS responder answers directly.
    let dns_answer = probe_dns(ip, config.dns_port, &config.tld).await;
    checks.push(evaluate_dns_direct(ip, dns_answer));

    // 3) OS routing (Path A end-to-end).
    let resolved = probe_os_routing(&config.tld).await;
    checks.push(evaluate_os_routing(ip, &resolved));

    // 4) gateway port (Path B).
    let http = build_probe_client();
    let answered_port = probe_gateway(&http, ip, config.http_port, config.http_fallback_port).await;
    checks.push(evaluate_gateway(
        config.http_port,
        config.http_fallback_port,
        answered_port,
    ));

    // 5) node reachable (content link) - only meaningful if the gateway answered.
    let reachable = match answered_port {
        Some(port) => probe_node(&http, ip, port).await,
        None => None,
    };
    checks.push(evaluate_node(reachable));

    // 6) browser DoH / built-in-resolver policy (informational - explains Path A bypass).
    checks.push(check_browser_doh());

    // 7) who holds :80 (informational - explains an :8053 fallback).
    checks.push(check_port_holder(config.http_port, answered_port));

    Report::build(checks)
}

/// A short-timeout HTTP client for the gateway probes.
fn build_probe_client() -> reqwest::Client {
    crate::transport::init_crypto();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default()
}

/// Query the DNS responder directly for a sample `.dig` name; return the first A address.
async fn probe_dns(ip: Ipv4Addr, port: u16, tld: &str) -> Option<Ipv4Addr> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    socket.connect(SocketAddr::from((ip, port))).await.ok()?;
    let query = crate::dns::build_a_query(&format!("doctor-probe.{tld}"));
    socket.send(&query).await.ok()?;
    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    crate::dns::parse_first_a_ipv4(&buf[..n])
}

/// Resolve a sample `.dig` name via the OS resolver (blocking getaddrinfo, run off-thread with
/// a timeout). An empty result means the OS does not route `.dig` to the responder.
async fn probe_os_routing(tld: &str) -> Vec<IpAddr> {
    let host = format!("doctor-probe.{tld}:0");
    let lookup = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        host.to_socket_addrs()
            .map(|it| it.map(|s| s.ip()).collect::<Vec<_>>())
            .unwrap_or_default()
    });
    tokio::time::timeout(Duration::from_secs(3), lookup)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
}

/// Probe `/.dig/resolve-probe` on the primary then the fallback port; return the port that
/// returned `204`.
async fn probe_gateway(
    http: &reqwest::Client,
    ip: Ipv4Addr,
    primary: u16,
    fallback: u16,
) -> Option<u16> {
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

/// Read `node.reachable` from `/.dig/health` on the bound gateway port.
async fn probe_node(http: &reqwest::Client, ip: Ipv4Addr, port: u16) -> Option<bool> {
    let url = format!("http://{ip}:{port}/.dig/health");
    let resp = http.get(&url).send().await.ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("node")?.get("reachable")?.as_bool()
}

/// Best-effort read of the browser DoH / built-in-resolver policy (informational). Branches on
/// the OS at runtime (no `#[cfg]`), so it compiles identically on every target; a missing tool
/// simply yields "not determined".
fn check_browser_doh() -> Check {
    let found = read_browser_doh_policy();
    if found.is_empty() {
        Check::new(
            "browser_doh",
            "Browser DNS-over-HTTPS / built-in-resolver policy",
            CheckStatus::Info,
            "no managed DoH policy found; browsers may auto-enable DoH, which bypasses OS \
             split-DNS (Path A) - Path B (the PAC proxy) is the reliable fallback"
                .to_string(),
        )
    } else {
        Check::new(
            "browser_doh",
            "Browser DNS-over-HTTPS / built-in-resolver policy",
            CheckStatus::Info,
            found.join("; "),
        )
    }
}

/// Read any managed DoH-mode policy values for Chrome/Edge/Chromium (best-effort, per OS).
fn read_browser_doh_policy() -> Vec<String> {
    let mut found = Vec::new();
    match std::env::consts::OS {
        "windows" => {
            for (browser, key) in [
                ("Chrome", r"HKLM\SOFTWARE\Policies\Google\Chrome"),
                ("Edge", r"HKLM\SOFTWARE\Policies\Microsoft\Edge"),
            ] {
                if let Some(v) = reg_query(key, "DnsOverHttpsMode") {
                    found.push(format!("{browser} DnsOverHttpsMode={v}"));
                }
            }
        }
        "macos" => {
            for (browser, domain) in [
                ("Chrome", "/Library/Managed Preferences/com.google.Chrome"),
                ("Edge", "/Library/Managed Preferences/com.microsoft.Edge"),
            ] {
                if let Some(v) = defaults_read(domain, "DnsOverHttpsMode") {
                    found.push(format!("{browser} DnsOverHttpsMode={v}"));
                }
            }
        }
        _ => {
            for dir in [
                "/etc/opt/chrome/policies/managed",
                "/etc/chromium/policies/managed",
                "/etc/opt/edge/policies/managed",
            ] {
                if let Some(v) = scan_json_dir_for(dir, "DnsOverHttpsMode") {
                    found.push(format!("{dir}: DnsOverHttpsMode={v}"));
                }
            }
        }
    }
    found
}

/// `reg query <key> /v <value>` → the value's data, best-effort.
fn reg_query(key: &str, value: &str) -> Option<String> {
    let out = std::process::Command::new("reg")
        .args(["query", key, "/v", value])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.contains(value))
        .and_then(|l| l.split_whitespace().last())
        .map(str::to_string)
}

/// `defaults read <domain> <key>` → the value, best-effort.
fn defaults_read(domain: &str, key: &str) -> Option<String> {
    let out = std::process::Command::new("defaults")
        .args(["read", domain, key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Scan a managed-policy JSON directory for a key mention, best-effort.
fn scan_json_dir_for(dir: &str, key: &str) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(val) = v.get(key) {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Report who holds the primary HTTP port (informational). If the gateway answered on the
/// primary, `dig-dns` holds it; if it answered on the fallback, something else does - attempt a
/// best-effort name via the OS tooling.
fn check_port_holder(primary: u16, answered_port: Option<u16>) -> Check {
    match answered_port {
        Some(p) if p == primary => Check::new(
            "port80_holder",
            "Primary HTTP port holder",
            CheckStatus::Info,
            format!("dig-dns holds :{primary}"),
        ),
        _ => {
            let holder = port_holder(primary).unwrap_or_else(|| "unknown".to_string());
            Check::new(
                "port80_holder",
                "Primary HTTP port holder",
                CheckStatus::Info,
                format!(":{primary} appears held by another process ({holder}); dig-dns uses the fallback"),
            )
            .with_fix(format!(
                "free :{primary} or keep the fallback - the PAC advertises the actual bound port"
            ))
        }
    }
}

/// Best-effort name of the process holding `port`, per OS (never fails the run).
fn port_holder(port: u16) -> Option<String> {
    let (cmd, args): (&str, Vec<String>) = match std::env::consts::OS {
        "windows" => ("netstat", vec!["-ano".into()]),
        "macos" => (
            "lsof",
            vec!["-i".into(), format!(":{port}"), "-sTCP:LISTEN".into()],
        ),
        _ => ("ss", vec!["-ltnp".into()]),
    };
    let out = std::process::Command::new(cmd).args(&args).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let needle = format!(":{port}");
    // Match `:port` only when NOT followed by another digit, so `:80` does not match `:8000`.
    text.lines()
        .find(|l| {
            l.match_indices(&needle).any(|(i, _)| {
                l.as_bytes()
                    .get(i + needle.len())
                    .is_none_or(|b| !b.is_ascii_digit())
            })
        })
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);

    #[test]
    fn overall_ok_needs_loopback_and_one_path() {
        assert!(overall_ok(true, true, false));
        assert!(overall_ok(true, false, true));
        assert!(overall_ok(true, true, true));
        assert!(!overall_ok(true, false, false)); // no path
        assert!(!overall_ok(false, true, true)); // loopback down
    }

    #[test]
    fn loopback_evaluator() {
        assert_eq!(evaluate_loopback(IP, true).status, CheckStatus::Pass);
        let f = evaluate_loopback(IP, false);
        assert_eq!(f.status, CheckStatus::Fail);
        assert!(f.fix.is_some());
    }

    #[test]
    fn dns_direct_evaluator() {
        assert_eq!(evaluate_dns_direct(IP, Some(IP)).status, CheckStatus::Pass);
        assert_eq!(
            evaluate_dns_direct(IP, Some(Ipv4Addr::new(127, 0, 0, 9))).status,
            CheckStatus::Fail
        );
        assert_eq!(evaluate_dns_direct(IP, None).status, CheckStatus::Fail);
    }

    #[test]
    fn os_routing_evaluator() {
        let pass = evaluate_os_routing(IP, &[IpAddr::V4(IP)]);
        assert_eq!(pass.status, CheckStatus::Pass);
        // Not configured is a WARN (Path B may still carry traffic), not a hard fail.
        let warn = evaluate_os_routing(IP, &[]);
        assert_eq!(warn.status, CheckStatus::Warn);
        assert!(warn.fix.is_some());
    }

    #[test]
    fn gateway_evaluator_primary_and_fallback() {
        assert_eq!(
            evaluate_gateway(80, 8053, Some(80)).status,
            CheckStatus::Pass
        );
        let fb = evaluate_gateway(80, 8053, Some(8053));
        assert_eq!(fb.status, CheckStatus::Pass);
        assert!(fb.detail.contains("fallback"));
        assert!(fb.fix.is_some());
        assert_eq!(evaluate_gateway(80, 8053, None).status, CheckStatus::Fail);
    }

    #[test]
    fn node_evaluator() {
        assert_eq!(evaluate_node(Some(true)).status, CheckStatus::Pass);
        assert_eq!(evaluate_node(Some(false)).status, CheckStatus::Warn);
        assert_eq!(evaluate_node(None).status, CheckStatus::Info);
    }

    /// A representative dev-machine report: loopback up, DNS + gateway answering, OS routing not
    /// configured (Path B only), node reachable.
    fn dev_checks() -> Vec<Check> {
        vec![
            evaluate_loopback(IP, true),
            evaluate_dns_direct(IP, Some(IP)),
            evaluate_os_routing(IP, &[]), // Path A not configured
            evaluate_gateway(80, 8053, Some(80)),
            evaluate_node(Some(true)),
        ]
    }

    #[test]
    fn report_derives_paths_and_ok() {
        let r = Report::build(dev_checks());
        assert!(!r.path_a, "OS routing not configured");
        assert!(r.path_b, "gateway answered");
        assert!(r.ok, "loopback up + Path B live → a .dig URL loads");
    }

    #[test]
    fn report_fails_when_no_path_live() {
        let checks = vec![
            evaluate_loopback(IP, true),
            evaluate_dns_direct(IP, None),
            evaluate_os_routing(IP, &[]),
            evaluate_gateway(80, 8053, None), // gateway down
            evaluate_node(None),
        ];
        let r = Report::build(checks);
        assert!(!r.path_a && !r.path_b);
        assert!(!r.ok);
        assert!(r.to_text().contains("NEITHER path is live"));
    }

    #[test]
    fn report_fails_when_loopback_down() {
        let checks = vec![
            evaluate_loopback(IP, false),
            evaluate_gateway(80, 8053, Some(80)),
        ];
        let r = Report::build(checks);
        assert!(!r.ok, "loopback down blocks everything");
    }

    #[test]
    fn json_report_has_stable_shape() {
        let r = Report::build(dev_checks());
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["path_a"], false);
        assert_eq!(v["path_b"], true);
        assert!(v["checks"].is_array());
        // status serializes lowercase.
        assert_eq!(v["checks"][0]["status"], "pass");
        assert_eq!(v["checks"][0]["id"], "loopback_ip");
    }

    #[test]
    fn text_report_lists_checks_and_result() {
        let text = Report::build(dev_checks()).to_text();
        assert!(text.contains("[PASS]"));
        assert!(text.contains("Path B (PAC proxy) is live"));
        assert!(text.contains("a .dig URL can load"));
    }

    #[test]
    fn browser_doh_check_is_informational_and_never_panics() {
        // Runs the real (best-effort) probe on this OS; it must be Info regardless of result.
        assert_eq!(check_browser_doh().status, CheckStatus::Info);
    }

    #[test]
    fn port_holder_check_is_informational() {
        assert_eq!(check_port_holder(80, Some(80)).status, CheckStatus::Info);
        assert_eq!(check_port_holder(80, Some(8053)).status, CheckStatus::Info);
        assert_eq!(check_port_holder(80, None).status, CheckStatus::Info);
    }
}
