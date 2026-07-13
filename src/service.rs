//! OS-service registration for `dig-dns`, across Windows (SCM), Linux (systemd) and macOS
//! (launchd) via the `service-manager` crate.
//!
//! `dig-dns` installs as an auto-starting OS service that runs `dig-dns serve` — the local
//! `*.dig` resolver (DNS responder + HTTP gateway). This module owns the service IDENTITY and
//! the **clean-reinstall** contract:
//!
//! * **Service id** — [`SERVICE_LABEL`] `net.dignetwork.dig-dns`, the reverse-DNS name used
//!   verbatim as the Windows SCM service name (`sc create`/`query`/`start`/`stop`/`delete`),
//!   the launchd plist label, and the systemd unit name.
//! * **Display name** — [`SERVICE_DISPLAY_NAME`] "DIG NETWORK: DNS", the human-friendly name
//!   shown in the Windows Services console (set with `sc config … displayname=` after create,
//!   because `service-manager` 0.7's `sc create` hardcodes the display name to the service id).
//! * **Clean-reinstall** — [`reinstall`]: if the service ALREADY EXISTS, **stop → delete
//!   (deregister) → wait for removal → (re)create → start** — a clean recreate, never a
//!   reconfigure-in-place. This is what avoids Windows `CreateService 1073 "the specified
//!   service already exists"` on a re-run of the installer.
//!
//! Install level by platform mirrors the sibling `dig-node` service:
//!   * Linux (systemd) / macOS (launchd) — **user-level** by default (no root/sudo).
//!   * Windows (SCM) — **system-level only** (SCM has no per-user services); `install` /
//!     `uninstall` require an **elevated (Administrator)** console, detected up front with a
//!     clear message rather than a cryptic access-denied deep inside `sc.exe`.
//!
//! The OS calls are behind the [`ServiceBackend`] trait so the clean-reinstall ORDER is
//! unit-tested against a recording mock — CI never shells out to `sc`/`launchctl`/`systemctl`.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use serde_json::{json, Value};
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use crate::config::{self, Config};

/// The reverse-DNS service id. Used verbatim as the Windows SCM service name, the launchd
/// plist label, and the systemd unit name. `ServiceLabel::to_qualified_name` rejoins its 3
/// dot-separated segments unchanged, so on Windows this addresses the service literally.
pub const SERVICE_LABEL: &str = "net.dignetwork.dig-dns";

/// The human-friendly display name shown in the Windows Services console. On launchd/systemd
/// the service id IS the visible name, so this is a Windows-facing label.
pub const SERVICE_DISPLAY_NAME: &str = "DIG NETWORK: DNS";

/// How many times [`reinstall`] polls for a deleted service to disappear before giving up. A
/// Windows service marked for deletion (`sc delete`) can linger until its open handles close;
/// `40 × 500ms = 20s` is generous for a loopback resolver with no long-lived clients.
const REMOVAL_POLL_ATTEMPTS: u32 = 40;

/// The interval between removal polls (see [`REMOVAL_POLL_ATTEMPTS`]).
const REMOVAL_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Whether user-level (no-elevation) install is supported on this OS. Windows SCM is
/// system-only; systemd/launchd support a user domain.
#[cfg(windows)]
const PREFERS_USER_LEVEL: bool = false;
#[cfg(not(windows))]
const PREFERS_USER_LEVEL: bool = true;

/// What to register: the service identity + the program the SCM/launchd/systemd runs, plus the
/// environment that reproduces the resolved [`Config`] so the installed service serves
/// identically to a manual `dig-dns serve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// The reverse-DNS service id ([`SERVICE_LABEL`]).
    pub label: String,
    /// The Windows display name ([`SERVICE_DISPLAY_NAME`]).
    pub display_name: String,
    /// Absolute path to the program the service runs (this `dig-dns` binary).
    pub program: PathBuf,
    /// Arguments passed to `program` (`run-service` on Windows, else `serve`).
    pub args: Vec<OsString>,
    /// Environment variables baked into the service so it resolves the SAME config the
    /// installing invocation did (the service does not inherit the installer's shell env).
    pub environment: Vec<(String, String)>,
    /// Whether the service auto-starts on boot/login.
    pub autostart: bool,
}

/// The OS-service backend: the five primitive operations the clean-reinstall composes. Behind a
/// trait so [`reinstall`]'s ORDER (stop → delete → wait → create → start) is unit-tested with a
/// recording mock and CI never registers a real service. The real implementation is
/// [`SystemServiceBackend`].
pub trait ServiceBackend {
    /// Is the service currently registered with the OS service manager?
    fn is_installed(&self) -> io::Result<bool>;
    /// Stop the running service (best-effort at the call site: a not-running service is not an
    /// error the caller must fail on).
    fn stop(&self) -> io::Result<()>;
    /// Deregister (delete) the service from the OS service manager.
    fn delete(&self) -> io::Result<()>;
    /// Register (create) the service from `plan`, including the display name on Windows.
    fn create(&self, plan: &InstallPlan) -> io::Result<()>;
    /// Start the registered service.
    fn start(&self) -> io::Result<()>;
}

/// What [`reinstall`] did, for machine-readable + human output. `existed` records whether a
/// prior registration was found (⇒ the stop/delete/wait clean-recreate ran); a fresh install
/// leaves `existed`/`stopped`/`deleted` false.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReinstallReport {
    /// A prior registration existed, so the clean-recreate path ran.
    pub existed: bool,
    /// The existing service was stopped before deletion.
    pub stopped: bool,
    /// The existing service was deleted (deregistered).
    pub deleted: bool,
    /// The service was (re)created.
    pub created: bool,
    /// The service was started.
    pub started: bool,
}

/// **Clean-reinstall.** If the service ALREADY EXISTS: stop it (best-effort), delete
/// (deregister) it, wait for the removal to take effect, THEN (re)create it with the display
/// name and start it — a clean recreate, NEVER a reconfigure-in-place. When no prior
/// registration exists it simply creates + starts.
///
/// This ordering is the fix for Windows `CreateService 1073 "the specified service already
/// exists"`: by deleting before creating, `create` never targets an existing service.
pub fn reinstall<B: ServiceBackend>(
    backend: &B,
    plan: &InstallPlan,
) -> io::Result<ReinstallReport> {
    let mut report = ReinstallReport::default();

    if backend.is_installed()? {
        report.existed = true;
        // Stop is best-effort: a registered-but-already-stopped service errors on stop, and
        // that must not block the delete + recreate that follows.
        if backend.stop().is_ok() {
            report.stopped = true;
        }
        backend.delete()?;
        report.deleted = true;
        wait_for_removal(backend)?;
    }

    backend.create(plan)?;
    report.created = true;
    backend.start()?;
    report.started = true;
    Ok(report)
}

/// Poll [`ServiceBackend::is_installed`] until the service is gone, bounded by
/// [`REMOVAL_POLL_ATTEMPTS`]. Checks BEFORE sleeping, so a backend that removes synchronously
/// (the test mock, and systemd/launchd) returns immediately with no delay; only a lingering
/// Windows deletion actually waits. Errors with `TimedOut` if the service is still present
/// after the window, so a caller never blindly recreates onto a still-existing service (1073).
fn wait_for_removal<B: ServiceBackend>(backend: &B) -> io::Result<()> {
    for _ in 0..REMOVAL_POLL_ATTEMPTS {
        if !backend.is_installed()? {
            return Ok(());
        }
        std::thread::sleep(REMOVAL_POLL_INTERVAL);
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "dig-dns: service \"{SERVICE_LABEL}\" was deleted but is still present after \
             waiting for removal; cannot cleanly recreate it (a handle may be held open — \
             close the Services console and retry)"
        ),
    ))
}

/// Build the [`InstallPlan`] for `program` from a resolved [`Config`]. PURE (given the program
/// path), so the identity + args + baked environment are unit-tested without touching the OS.
/// The installed service runs `run-service` on Windows (the SCM protocol entrypoint) and
/// `serve` elsewhere (systemd/launchd exec the foreground process directly).
pub fn build_plan(config: &Config, program: PathBuf) -> InstallPlan {
    let entry_arg = if cfg!(windows) {
        "run-service"
    } else {
        "serve"
    };

    // Bake the resolved config into the service environment so it serves identically to the
    // invocation that installed it (a service does not inherit the installer's shell env).
    let mut environment = vec![
        (config::ENV_IP.to_string(), config.loopback_ip.to_string()),
        (
            config::ENV_DNS_PORT.to_string(),
            config.dns_port.to_string(),
        ),
        (
            config::ENV_HTTP_PORT.to_string(),
            config.http_port.to_string(),
        ),
        (
            config::ENV_HTTP_FALLBACK_PORT.to_string(),
            config.http_fallback_port.to_string(),
        ),
        (config::ENV_TLD.to_string(), config.tld.clone()),
        (
            config::ENV_DNS_TTL.to_string(),
            config.dns_ttl_secs.to_string(),
        ),
    ];
    // Only record an explicit node override; absent it, the service resolves the §6.3 ladder
    // (dig.local → localhost:9778 → rpc.dig.net) itself rather than freezing a value.
    if let Some(url) = config.node_url.as_deref() {
        if !url.trim().is_empty() {
            environment.push((config::ENV_NODE_URL.to_string(), url.trim().to_string()));
        }
    }

    InstallPlan {
        label: SERVICE_LABEL.to_string(),
        display_name: SERVICE_DISPLAY_NAME.to_string(),
        program,
        args: vec![OsString::from(entry_arg)],
        environment,
        autostart: true,
    }
}

/// Build the `sc.exe config <name> displayname= "<display>"` argument list that overrides the
/// Windows service display name after `service-manager`'s `sc create` (which sets it to the
/// service id). PURE (no process spawn) so the argument construction is unit-testable without
/// invoking `sc.exe`.
#[cfg_attr(not(windows), allow(dead_code))]
fn display_name_config_args(service_name: &str, display_name: &str) -> Vec<String> {
    vec![
        "config".to_string(),
        service_name.to_string(),
        "displayname=".to_string(),
        display_name.to_string(),
    ]
}

// ---------------------------------------------------------------------------------------------
// The real, OS-backed backend + the CLI-facing install/uninstall/start/stop/status commands.
// ---------------------------------------------------------------------------------------------

/// The result of a service command: a human summary + a `--json` object, matching the crate's
/// agent-friendly output idiom (CLAUDE.md §6.2).
#[derive(Debug, Clone)]
pub struct ServiceOutcome {
    /// Human-readable summary (stdout in text mode).
    pub summary: String,
    /// Machine-readable object (stdout in `--json` mode).
    pub json: Value,
}

/// Build the parsed service label (infallible for our constant, but the crate returns a
/// Result, so surface a clear error if the constant is ever mis-edited).
fn label() -> io::Result<ServiceLabel> {
    ServiceLabel::from_str(SERVICE_LABEL)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// On Windows, is this process elevated (Administrator)? Used to fail `install`/`uninstall`
/// early with a helpful message instead of a cryptic SCM access-denied. Always `true` off
/// Windows (those paths are user-level).
#[cfg(windows)]
fn is_elevated() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

/// The real [`ServiceBackend`]: the native OS service manager (user-level on Linux/macOS,
/// system-level on Windows) plus the OS existence probe and the Windows display-name override.
pub struct SystemServiceBackend {
    label: ServiceLabel,
    manager: Box<dyn ServiceManager>,
    /// Whether the manager is operating at user level (Linux/macOS) — surfaced for messaging.
    user_level: bool,
}

impl SystemServiceBackend {
    /// Acquire the native service manager, set to user-level where the platform supports it.
    pub fn new() -> io::Result<Self> {
        let mut manager = <dyn ServiceManager>::native()?;
        let mut user_level = false;
        if PREFERS_USER_LEVEL && manager.set_level(ServiceLevel::User).is_ok() {
            user_level = true;
        }
        Ok(Self {
            label: label()?,
            manager,
            user_level,
        })
    }

    /// Whether this backend installs at user level (no elevation) vs system level.
    pub fn user_level(&self) -> bool {
        self.user_level
    }
}

impl ServiceBackend for SystemServiceBackend {
    fn is_installed(&self) -> io::Result<bool> {
        Ok(query_installed(&self.label.to_qualified_name()))
    }

    fn stop(&self) -> io::Result<()> {
        self.manager.stop(ServiceStopCtx {
            label: self.label.clone(),
        })
    }

    fn delete(&self) -> io::Result<()> {
        self.manager.uninstall(ServiceUninstallCtx {
            label: self.label.clone(),
        })
    }

    fn create(&self, plan: &InstallPlan) -> io::Result<()> {
        self.manager.install(ServiceInstallCtx {
            label: self.label.clone(),
            program: plan.program.clone(),
            args: plan.args.clone(),
            contents: None,
            username: None,
            working_directory: None,
            environment: Some(plan.environment.clone()),
            autostart: plan.autostart,
        })?;
        // service-manager's `sc create` sets the display name to the service id; override it
        // with the human-friendly name. Best-effort: a failure here leaves the service
        // installed + working, just showing the id in the Services console.
        #[cfg(windows)]
        set_windows_display_name(&self.label.to_qualified_name(), &plan.display_name);
        Ok(())
    }

    fn start(&self) -> io::Result<()> {
        self.manager.start(ServiceStartCtx {
            label: self.label.clone(),
        })
    }
}

/// Probe whether a service named `service_name` is registered, per OS. Best-effort: a probe
/// that cannot run (tool missing) reports `false` so the clean-reinstall proceeds to create.
#[cfg(windows)]
fn query_installed(service_name: &str) -> bool {
    // `sc query <name>` exits 0 when the service exists, 1060 (does-not-exist) otherwise.
    std::process::Command::new("sc.exe")
        .args(["query", service_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// macOS launchd existence probe: `launchctl print <domain>/<label>` exits 0 when the service
/// is bootstrapped.
#[cfg(target_os = "macos")]
fn query_installed(service_name: &str) -> bool {
    let domain = launchd_domain_target(service_name);
    std::process::Command::new("launchctl")
        .args(["print", &domain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Linux systemd existence probe: `systemctl [--user] cat <label>.service` exits 0 when the
/// unit file exists (non-zero "No files found" otherwise).
#[cfg(all(unix, not(target_os = "macos")))]
fn query_installed(service_name: &str) -> bool {
    let unit = format!("{service_name}.service");
    let mut cmd = std::process::Command::new("systemctl");
    if PREFERS_USER_LEVEL {
        cmd.arg("--user");
    }
    cmd.args(["cat", &unit])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The launchd domain target (`gui/<uid>/<label>` for a user agent, `system/<label>` for a
/// daemon) `launchctl print` addresses. PURE given the uid, so the format is testable.
#[cfg(target_os = "macos")]
fn launchd_domain_target(service_name: &str) -> String {
    if PREFERS_USER_LEVEL {
        format!("gui/{}/{}", unsafe { libc_getuid() }, service_name)
    } else {
        format!("system/{service_name}")
    }
}

#[cfg(target_os = "macos")]
fn libc_getuid() -> u32 {
    // Avoid a `libc` dependency for one call: read the effective uid via `id -u`.
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Override the Windows service display name (`sc config <name> displayname= "<display>"`).
/// Best-effort; a failure is swallowed (the service is already usable under its id).
#[cfg(windows)]
fn set_windows_display_name(service_name: &str, display_name: &str) {
    let args = display_name_config_args(service_name, display_name);
    let _ = std::process::Command::new("sc.exe")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Install `dig-dns` as an auto-starting OS service via the clean-reinstall contract (stop →
/// delete → recreate on an existing service; create otherwise). The service runs `dig-dns
/// serve` (or `run-service` on Windows) with the resolved `config` baked into its environment.
pub fn install(config: &Config) -> io::Result<ServiceOutcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dig-dns: installing a Windows service requires an elevated (Administrator) \
             console. Re-run this in a terminal opened with \"Run as administrator\".",
        ));
    }

    let backend = SystemServiceBackend::new()?;
    let program = std::env::current_exe()?;
    let plan = build_plan(config, program.clone());
    let report = reinstall(&backend, &plan)?;

    let scope = if backend.user_level() {
        "user"
    } else {
        "system"
    };
    let action = if report.existed {
        "reinstalled (stopped + deleted the existing service, then recreated it)"
    } else {
        "installed"
    };
    let addr = format!("{}:{}", config.loopback_ip, config.http_port);
    let summary = format!(
        "dig-dns: {action} as a {scope}-level service\n  \
         id:      {SERVICE_LABEL}\n  \
         display: {SERVICE_DISPLAY_NAME}\n  \
         program: {}\n  \
         serves:  http://{addr} (+ DNS :{})\n  \
         The service was started; check it with: dig-dns status",
        program.display(),
        config.dns_port,
    );
    Ok(ServiceOutcome {
        summary,
        json: json!({
            "installed": true,
            "reinstalled": report.existed,
            "started": report.started,
            "label": SERVICE_LABEL,
            "display_name": SERVICE_DISPLAY_NAME,
            "scope": scope,
            "program": program.display().to_string(),
            "addr": addr,
        }),
    })
}

/// Uninstall the `dig-dns` service. Stops it first (best-effort) so the removal is clean.
pub fn uninstall() -> io::Result<ServiceOutcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dig-dns: uninstalling a Windows service requires an elevated (Administrator) \
             console.",
        ));
    }
    let backend = SystemServiceBackend::new()?;
    let _ = backend.stop();
    backend.delete()?;
    Ok(ServiceOutcome {
        summary: format!("dig-dns: uninstalled service \"{SERVICE_LABEL}\""),
        json: json!({ "installed": false, "label": SERVICE_LABEL }),
    })
}

/// Start the installed service.
pub fn start() -> io::Result<ServiceOutcome> {
    let backend = SystemServiceBackend::new()?;
    backend.start()?;
    Ok(ServiceOutcome {
        summary: format!("dig-dns: start requested for \"{SERVICE_LABEL}\""),
        json: json!({ "started": true, "label": SERVICE_LABEL }),
    })
}

/// Stop the running service.
pub fn stop() -> io::Result<ServiceOutcome> {
    let backend = SystemServiceBackend::new()?;
    backend.stop()?;
    Ok(ServiceOutcome {
        summary: format!("dig-dns: stop requested for \"{SERVICE_LABEL}\""),
        json: json!({ "stopped": true, "label": SERVICE_LABEL }),
    })
}

/// Report whether the resolver is actually serving, by probing the gateway over loopback (the
/// meaningful "is it up?" check — `service-manager` exposes no status query), and best-effort
/// whether it is registered. The `serving` boolean is the answer the caller maps to an exit
/// code; `registered` is informational.
pub fn status(config: &Config) -> io::Result<ServiceOutcome> {
    let serving = probe_serving(config);
    let registered = SystemServiceBackend::new()
        .and_then(|b| b.is_installed())
        .unwrap_or(false);
    let primary = format!("{}:{}", config.loopback_ip, config.http_port);
    let summary = if serving {
        format!("dig-dns: SERVING on http://{primary} (registered: {registered})")
    } else {
        format!(
            "dig-dns: NOT responding on http://{primary} (registered: {registered}) — the \
             service may be stopped or not installed"
        )
    };
    Ok(ServiceOutcome {
        summary,
        json: json!({
            "serving": serving,
            "registered": registered,
            "label": SERVICE_LABEL,
            "addr": primary,
        }),
    })
}

/// Blocking gateway probe over loopback: try the primary HTTP port then the `:8053` fallback,
/// GET the `/.dig/resolve-probe` liveness endpoint, and report whether either answers 2xx.
/// Kept blocking (no async runtime) so `status` stays a lightweight one-shot.
fn probe_serving(config: &Config) -> bool {
    let ip = config.loopback_ip.to_string();
    probe_resolve(&ip, config.http_port) || probe_resolve(&ip, config.http_fallback_port)
}

/// Minimal blocking HTTP/1.0 `GET /.dig/resolve-probe` over loopback; returns whether the
/// status line is 2xx (the gateway answers this liveness endpoint with `204`).
fn probe_resolve(ip: &str, port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("{ip}:{port}");
    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let req =
        format!("GET /.dig/resolve-probe HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut chunk = [0u8; 256];
    let n = stream.read(&mut chunk).unwrap_or(0);
    is_2xx_status_line(&String::from_utf8_lossy(&chunk[..n]))
}

/// Is the first line of an HTTP response a 2xx status line? PURE — parses only the status line
/// (`HTTP/x.y CODE …`), so a stray `2` elsewhere (e.g. a `Date: … 2026` header) is never
/// mistaken for success.
fn is_2xx_status_line(response_head: &str) -> bool {
    let first = response_head.lines().next().unwrap_or("");
    if !first.starts_with("HTTP/") {
        return false;
    }
    first
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .map(|code| (200..300).contains(&code))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // -- identity + pure builders ----------------------------------------------------------

    #[test]
    fn service_identity_constants_are_the_canonical_values() {
        assert_eq!(SERVICE_LABEL, "net.dignetwork.dig-dns");
        assert_eq!(SERVICE_DISPLAY_NAME, "DIG NETWORK: DNS");
    }

    #[test]
    fn service_label_parses_as_three_reverse_dns_segments() {
        let l = label().expect("constant label must parse");
        // `to_qualified_name` must reproduce the literal id we register/query under.
        assert_eq!(l.to_qualified_name(), SERVICE_LABEL);
    }

    #[test]
    fn display_name_config_args_build_the_sc_config_command() {
        let args = display_name_config_args(SERVICE_LABEL, SERVICE_DISPLAY_NAME);
        assert_eq!(
            args,
            vec![
                "config".to_string(),
                "net.dignetwork.dig-dns".to_string(),
                "displayname=".to_string(),
                "DIG NETWORK: DNS".to_string(),
            ]
        );
    }

    #[test]
    fn build_plan_carries_identity_display_and_baked_config() {
        let config = Config {
            http_port: 8080,
            tld: "dig".to_string(),
            ..Config::default()
        };
        let plan = build_plan(&config, PathBuf::from("/opt/dig-dns"));

        assert_eq!(plan.label, SERVICE_LABEL);
        assert_eq!(plan.display_name, SERVICE_DISPLAY_NAME);
        assert_eq!(plan.program, PathBuf::from("/opt/dig-dns"));
        assert!(plan.autostart);
        // The resolved config is baked into the service environment.
        let env: std::collections::HashMap<_, _> = plan.environment.iter().cloned().collect();
        assert_eq!(
            env.get(config::ENV_HTTP_PORT).map(String::as_str),
            Some("8080")
        );
        assert_eq!(env.get(config::ENV_TLD).map(String::as_str), Some("dig"));
        assert_eq!(
            env.get(config::ENV_IP).map(String::as_str),
            Some(config.loopback_ip.to_string().as_str())
        );
    }

    #[test]
    fn build_plan_omits_node_url_when_no_explicit_override() {
        let config = Config::default(); // node_url = None ⇒ the service resolves the ladder
        let plan = build_plan(&config, PathBuf::from("dig-dns"));
        assert!(!plan
            .environment
            .iter()
            .any(|(k, _)| k == config::ENV_NODE_URL));
    }

    #[test]
    fn build_plan_records_an_explicit_node_url() {
        let config = Config {
            node_url: Some("http://127.0.0.1:9778".to_string()),
            ..Config::default()
        };
        let plan = build_plan(&config, PathBuf::from("dig-dns"));
        let env: std::collections::HashMap<_, _> = plan.environment.iter().cloned().collect();
        assert_eq!(
            env.get(config::ENV_NODE_URL).map(String::as_str),
            Some("http://127.0.0.1:9778")
        );
    }

    #[test]
    fn is_2xx_status_line_parses_the_code_not_stray_digits() {
        assert!(is_2xx_status_line("HTTP/1.1 204 No Content\r\n"));
        assert!(is_2xx_status_line("HTTP/1.0 200 OK"));
        assert!(!is_2xx_status_line(
            "HTTP/1.0 404 Not Found\r\nDate: Sun, 12 Jul 2026 00:00:00 GMT\r\n"
        ));
        assert!(!is_2xx_status_line("HTTP/1.1 500 Internal Server Error"));
        assert!(!is_2xx_status_line("garbage"));
        assert!(!is_2xx_status_line(""));
    }

    // -- the real OS-backed path (no state mutation): probe + status only -----------------

    #[test]
    fn status_reports_not_serving_when_the_gateway_is_absent() {
        // High loopback ports nothing is bound to ⇒ a deterministic not-serving status. This
        // exercises the real probe + backend construction + registration query end-to-end
        // WITHOUT creating/mutating any OS service (safe in CI, mirrors dig-node's status test).
        let cfg = Config {
            http_port: 59_123,
            http_fallback_port: 59_124,
            ..Config::default()
        };
        let outcome = status(&cfg).expect("status never hard-errors");
        assert_eq!(outcome.json["serving"], json!(false));
        assert!(outcome.json["registered"].is_boolean());
        assert_eq!(outcome.json["label"], json!(SERVICE_LABEL));
        assert!(outcome.summary.contains("NOT responding"));
    }

    #[test]
    fn system_backend_builds_and_probes_an_unregistered_service_cleanly() {
        // Building the native backend + probing for a service that is not registered must never
        // panic and must report a boolean (false in a clean env). No service is created.
        if let Ok(backend) = SystemServiceBackend::new() {
            let _installed = backend.is_installed().expect("probe never hard-errors");
            let _user_level = backend.user_level();
        }
    }

    #[test]
    fn probe_resolve_is_false_on_a_refused_connection() {
        // Nothing listens on this high loopback port → connect refused → not serving.
        assert!(!probe_resolve("127.0.0.1", 59_125));
    }

    // -- clean-reinstall orchestration (the core contract), via a recording mock ----------

    /// A recording [`ServiceBackend`] mock. `installed` starts at the given value; `delete`
    /// flips it to `false` (a synchronous removal, like systemd/launchd). `create` SIMULATES
    /// the Windows `CreateService 1073` bug: it FAILS if the service still appears installed —
    /// so a test that recreates onto a live service fails exactly as Windows would, and the
    /// clean-reinstall (which deletes first) is proven to defeat it.
    struct MockBackend {
        installed: RefCell<bool>,
        calls: RefCell<Vec<String>>,
        created_plan: RefCell<Option<InstallPlan>>,
        fail_stop: bool,
    }

    impl MockBackend {
        fn new(installed: bool) -> Self {
            Self {
                installed: RefCell::new(installed),
                calls: RefCell::new(Vec::new()),
                created_plan: RefCell::new(None),
                fail_stop: false,
            }
        }
        fn with_failing_stop(installed: bool) -> Self {
            let m = Self::new(installed);
            Self {
                fail_stop: true,
                ..m
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl ServiceBackend for MockBackend {
        fn is_installed(&self) -> io::Result<bool> {
            self.calls.borrow_mut().push("is_installed".into());
            Ok(*self.installed.borrow())
        }
        fn stop(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("stop".into());
            if self.fail_stop {
                Err(io::Error::other("not running"))
            } else {
                Ok(())
            }
        }
        fn delete(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("delete".into());
            *self.installed.borrow_mut() = false; // synchronous removal
            Ok(())
        }
        fn create(&self, plan: &InstallPlan) -> io::Result<()> {
            self.calls.borrow_mut().push("create".into());
            if *self.installed.borrow() {
                // Reproduce Windows error 1073: cannot create an already-existing service.
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "CreateService 1073: the specified service already exists",
                ));
            }
            *self.created_plan.borrow_mut() = Some(plan.clone());
            *self.installed.borrow_mut() = true;
            Ok(())
        }
        fn start(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("start".into());
            Ok(())
        }
    }

    fn plan() -> InstallPlan {
        build_plan(&Config::default(), PathBuf::from("dig-dns"))
    }

    #[test]
    fn fresh_install_creates_and_starts_without_stop_or_delete() {
        let backend = MockBackend::new(false);
        let report = reinstall(&backend, &plan()).expect("fresh install succeeds");

        assert!(!report.existed);
        assert!(report.created && report.started);
        assert!(!report.stopped && !report.deleted);
        // No stop/delete on a fresh install; it probes, then creates + starts.
        assert_eq!(backend.calls(), vec!["is_installed", "create", "start"]);
        // The created service carries the canonical id + display name.
        let created = backend.created_plan.borrow().clone().unwrap();
        assert_eq!(created.label, "net.dignetwork.dig-dns");
        assert_eq!(created.display_name, "DIG NETWORK: DNS");
    }

    #[test]
    fn existing_service_is_stopped_deleted_then_recreated_no_1073() {
        // The service already exists — a naive `create` would hit Windows error 1073. The
        // clean-reinstall must stop + delete FIRST, then recreate, and succeed.
        let backend = MockBackend::new(true);
        let report = reinstall(&backend, &plan()).expect("clean-reinstall must NOT hit 1073");

        assert!(report.existed && report.stopped && report.deleted);
        assert!(report.created && report.started);
        // Order: probe, stop, delete, (removal re-probe), create, start — delete precedes
        // create, which is the whole point (no 1073).
        let calls = backend.calls();
        let create_idx = calls.iter().position(|c| c == "create").unwrap();
        let delete_idx = calls.iter().position(|c| c == "delete").unwrap();
        let stop_idx = calls.iter().position(|c| c == "stop").unwrap();
        assert!(stop_idx < delete_idx, "stop before delete: {calls:?}");
        assert!(delete_idx < create_idx, "delete before create: {calls:?}");
        assert_eq!(calls.last().map(String::as_str), Some("start"));
    }

    #[test]
    fn reinstall_recreates_even_when_stop_fails() {
        // A registered-but-stopped service errors on `stop`; that is best-effort and must NOT
        // block the delete + recreate.
        let backend = MockBackend::with_failing_stop(true);
        let report = reinstall(&backend, &plan()).expect("stop failure is non-fatal");

        assert!(report.existed);
        assert!(!report.stopped, "stop failed, so it is not marked stopped");
        assert!(report.deleted && report.created && report.started);
        let calls = backend.calls();
        assert!(calls.contains(&"delete".to_string()));
        assert!(calls.contains(&"create".to_string()));
    }

    #[test]
    fn naive_create_without_delete_would_hit_1073() {
        // Guard the guard: prove the mock actually reproduces 1073 when a live service is
        // recreated WITHOUT the clean-reinstall delete — otherwise the regression test above
        // would pass vacuously.
        let backend = MockBackend::new(true);
        let err = backend.create(&plan()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("1073"));
    }
}
