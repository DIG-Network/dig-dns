//! OS-service registration for `dig-dns`, across Windows (SCM), Linux (systemd) and macOS
//! (launchd) via the `service-manager` crate.
//!
//! `dig-dns` installs as an auto-starting OS service that runs `dig-dns serve` — the local
//! `*.dig` resolver (DNS responder + HTTP gateway). This module owns the service IDENTITY and
//! the **clean-reinstall** contract:
//!
//! * **Service id** — [`SERVICE_LABEL`] `net.dignetwork.dig-dns`, the reverse-DNS name used
//!   verbatim as the Windows SCM service name (`sc create`/`query`/`start`/`stop`/`delete`), the
//!   launchd plist label, AND — as of dig_ecosystem #523 — the Linux systemd unit file name
//!   ([`LINUX_UNIT_FILE_NAME`] = `net.dignetwork.dig-dns.service`), identical to the name the
//!   native `.deb` installs. The CLI Linux path no longer goes through the `service-manager`
//!   crate (whose `to_script_name` dropped the `net` qualifier to `dignetwork-dig-dns`,
//!   diverging from the `.deb`); it manages the canonical-named SYSTEM unit directly (running as
//!   root with a bounded `CAP_NET_BIND_SERVICE`, #528, so it binds `:53`/`:80` and execs the
//!   binary from any install dir). See `SPEC.md` §13.1.
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
// `FromStr` is only needed to parse the label for the `service-manager`-backed backends (not Linux).
#[cfg(not(all(unix, not(target_os = "macos"))))]
use std::str::FromStr;
use std::time::Duration;

use serde_json::{json, Value};
// The `service-manager` surface drives the Windows-SCM / macOS-launchd backends; Linux manages its
// systemd unit directly ([`SystemServiceBackend`] under the linux cfg, #523) and needs none of it.
#[cfg(not(all(unix, not(target_os = "macos"))))]
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use crate::config::{self, Config};
use crate::system_tool::resolve_system_tool;

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
/// system-only. Linux is system-level too (dig_ecosystem #523/#528): dig-dns binds the privileged
/// loopback ports `:53`/`:80`, which a user-domain systemd unit cannot, so the CLI registers a
/// SYSTEM unit under the canonical `net.dignetwork.dig-dns` name — identical to the native `.deb`.
/// Only macOS keeps a user-domain launchd agent.
#[cfg(target_os = "macos")]
const PREFERS_USER_LEVEL: bool = true;
#[cfg(not(target_os = "macos"))]
const PREFERS_USER_LEVEL: bool = false;

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
/// Result, so surface a clear error if the constant is ever mis-edited). Used by the
/// `service-manager`-backed Windows/macOS backends; Linux registers the raw canonical name (#523).
#[cfg(not(all(unix, not(target_os = "macos"))))]
fn label() -> io::Result<ServiceLabel> {
    ServiceLabel::from_str(SERVICE_LABEL)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// Does this platform require elevation to (un)install the service, and if so, do we HAVE it?
/// `install`/`uninstall` call this to fail early with a helpful message instead of a cryptic
/// deep-in-the-OS access-denied.
///
/// - **Windows** — needs an elevated (Administrator) token (SCM is system-scope).
/// - **Linux** — needs root (dig_ecosystem #523/#528): the unit is written to `/etc/systemd/system`
///   and runs at systemd system scope binding the privileged `:53`/`:80` ports.
/// - **macOS** — the launchd install is a user-domain agent, so no elevation is required.
#[cfg(windows)]
fn has_required_elevation() -> bool {
    // Absolute-pathed (#657): this runs under elevation, so a bare `net` could be hijacked by a
    // search-order-planted binary in an attacker-controlled working directory.
    std::process::Command::new(resolve_system_tool("net"))
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
#[cfg(all(unix, not(target_os = "macos")))]
fn has_required_elevation() -> bool {
    // Root check via `id -u` (absolute-pathed, #657); root's effective uid is 0.
    std::process::Command::new(resolve_system_tool("id"))
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}
#[cfg(target_os = "macos")]
fn has_required_elevation() -> bool {
    true
}

/// Whether this platform's install requires elevation at all (so the caller can tailor the
/// refusal message). Only macOS's user-domain launchd agent does not.
#[cfg(not(target_os = "macos"))]
const INSTALL_REQUIRES_ELEVATION: bool = true;
#[cfg(target_os = "macos")]
const INSTALL_REQUIRES_ELEVATION: bool = false;

/// The platform-specific elevation-refusal message for `install`/`uninstall`.
fn elevation_refusal(action: &str) -> io::Error {
    let how = if cfg!(windows) {
        "an elevated (Administrator) console. Re-run this in a terminal opened with \
         \"Run as administrator\"."
    } else {
        "root. Re-run with sudo."
    };
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("dig-dns: {action} the service requires {how}"),
    )
}

/// The real [`ServiceBackend`] on Windows (SCM) and macOS (launchd): the native `service-manager`
/// crate, system-level on Windows, user-domain on macOS. Linux does NOT use this — see
/// [`LinuxSystemdBackend`], which manages the canonical-named system unit directly (#523).
#[cfg(not(all(unix, not(target_os = "macos"))))]
pub struct SystemServiceBackend {
    label: ServiceLabel,
    manager: Box<dyn ServiceManager>,
    /// Whether the manager is operating at user level (macOS) — surfaced for messaging.
    user_level: bool,
}

#[cfg(not(all(unix, not(target_os = "macos"))))]
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

#[cfg(not(all(unix, not(target_os = "macos"))))]
impl ServiceBackend for SystemServiceBackend {
    fn is_installed(&self) -> io::Result<bool> {
        Ok(query_installed(&self.label))
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

/// Probe whether `label` is registered, per OS. Best-effort: a probe that cannot run (tool
/// missing) reports `false` so the clean-reinstall proceeds to create. Each OS resolves `label`
/// to the name-form its OWN `service_manager` backend actually registers under — see the
/// per-`query_installed` doc comments for why these differ.
#[cfg(windows)]
fn query_installed(label: &ServiceLabel) -> bool {
    // `service_manager::ScServiceManager` (Windows) names the service with the fully-qualified
    // id verbatim (`ctx.label.to_qualified_name()`), matching SERVICE_LABEL. `sc query <name>`
    // exits 0 when it exists, 1060 (does-not-exist) otherwise.
    let service_name = label.to_qualified_name();
    std::process::Command::new(resolve_system_tool("sc.exe"))
        .args(["query", &service_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// macOS launchd existence probe: `launchctl print <domain>/<label>` exits 0 when the service
/// is bootstrapped.
#[cfg(target_os = "macos")]
fn query_installed(label: &ServiceLabel) -> bool {
    // `service_manager::LaunchdServiceManager` names the plist with the fully-qualified id
    // verbatim (`ctx.label.to_qualified_name()`), matching SERVICE_LABEL.
    let service_name = label.to_qualified_name();
    let domain = launchd_domain_target(&service_name);
    std::process::Command::new(resolve_system_tool("launchctl"))
        .args(["print", &domain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------------------------
// Linux systemd backend (#523) — the canonical-named system unit, managed directly.
// ---------------------------------------------------------------------------------------------

/// The canonical systemd unit FILE name on Linux: `net.dignetwork.dig-dns.service` — the
/// [`SERVICE_LABEL`] id plus `.service`, IDENTICAL to the name the native `.deb` installs
/// ([`crate::packaging::SYSTEMD_UNIT_PATH`]) and to the launchd/Windows id. This is the
/// dig_ecosystem #523 unification: the CLI install path and the `.deb` register the SAME unit
/// name, so `systemctl … net.dignetwork.dig-dns` addresses one service however it was installed.
///
/// The prior CLI path went through the `service-manager` crate, whose `SystemdServiceManager`
/// derives the file name from `ServiceLabel::to_script_name()` — `dignetwork-dig-dns`, DROPPING
/// the `net` qualifier — diverging from the `.deb`. The Linux backend below bypasses that crate
/// and writes the canonical name directly. See `SPEC.md` §13.1.
#[cfg(all(unix, not(target_os = "macos")))]
pub const LINUX_UNIT_FILE_NAME: &str = "net.dignetwork.dig-dns.service";

/// The admin unit directory the CLI writes the unit to. `/etc/systemd/system` (the machine
/// administrator's unit dir) rather than the `.deb`'s `/lib/systemd/system` (the package-vendor
/// dir) — the correct home for a manually-run `dig-dns install`, and one that takes precedence if
/// both ever coexist. Same NAME as the `.deb` regardless (#523).
#[cfg(all(unix, not(target_os = "macos")))]
const LINUX_UNIT_DIR: &str = "/etc/systemd/system";

/// The absolute path of the canonical Linux unit file. PURE.
#[cfg(all(unix, not(target_os = "macos")))]
fn linux_unit_file_path() -> PathBuf {
    PathBuf::from(LINUX_UNIT_DIR).join(LINUX_UNIT_FILE_NAME)
}

/// Build the systemd unit contents for a CLI install from the resolved [`InstallPlan`]. PURE (no
/// I/O), so the exact unit body is unit-tested.
///
/// **#528 — runs as root with a bounded capability set, so `ExecStart` succeeds from ANY bin dir.**
/// The service runs as root (no `User=`/`DynamicUser=`), exactly like the `.deb` unit
/// ([`crate::packaging::systemd_unit`]): a dedicated unprivileged account cannot traverse into a
/// user's `0750` home to `execve` a binary under `~/.dig/bin` (systemd `203/EXEC`), whereas root
/// can exec from any install location. The privilege is then narrowed to exactly what binding
/// `:53`/`:80` needs — `AmbientCapabilities`/`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
/// `NoNewPrivileges`, `ProtectSystem`/`ProtectHome`/`PrivateTmp` — a loopback-only service holding
/// no secret material. The resolved config is baked in as `Environment=` lines so the unit serves
/// identically to the invoking `dig-dns serve`.
#[cfg(all(unix, not(target_os = "macos")))]
fn linux_unit_contents(plan: &InstallPlan) -> String {
    use crate::packaging::NET_BIND_CAPABILITY;

    let program = plan.program.display();
    let args: Vec<String> = plan
        .args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let exec_args = args.join(" ");
    let env_lines: String = plan
        .environment
        .iter()
        .map(|(k, v)| format!("Environment={k}={v}\n"))
        .collect();
    let wanted_by = if plan.autostart {
        "\n[Install]\nWantedBy=multi-user.target\n"
    } else {
        ""
    };

    format!(
        "[Unit]\n\
         Description={SERVICE_DISPLAY_NAME} — local *.dig resolver (DNS responder + HTTP gateway)\n\
         Documentation=https://docs.dig.net\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={program} {exec_args}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         # Runs as root so ExecStart can reach the binary in ANY install dir (#528); privilege is\n\
         # then bounded to exactly the loopback :53/:80 bind (#177).\n\
         AmbientCapabilities={NET_BIND_CAPABILITY}\n\
         CapabilityBoundingSet={NET_BIND_CAPABILITY}\n\
         StateDirectory=dig-dns\n\
         NoNewPrivileges=true\n\
         ProtectSystem=full\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         {env_lines}\
         {wanted_by}"
    )
}

/// The real Linux [`ServiceBackend`]: manages the canonical-named system unit directly via a unit
/// file in [`LINUX_UNIT_DIR`] + `systemctl` (#523). Requires root (systemd system scope + the
/// privileged loopback ports); the `install`/`uninstall` entrypoints check elevation up front.
#[cfg(all(unix, not(target_os = "macos")))]
pub struct SystemServiceBackend {
    unit_path: PathBuf,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl SystemServiceBackend {
    /// Construct the Linux systemd backend (infallible — no manager handle to acquire).
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            unit_path: linux_unit_file_path(),
        })
    }

    /// Linux always installs at SYSTEM level ([`PREFERS_USER_LEVEL`] is `false`); never user level.
    pub fn user_level(&self) -> bool {
        PREFERS_USER_LEVEL
    }

    /// Run `systemctl <args…>`, mapping a non-zero exit to an `io::Error`. `systemctl` is resolved
    /// to its trusted absolute path (#657) since this runs as root.
    fn systemctl(args: &[&str]) -> io::Result<()> {
        let status = std::process::Command::new(resolve_system_tool("systemctl"))
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "systemctl {} exited non-zero",
                args.join(" ")
            )))
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
impl ServiceBackend for SystemServiceBackend {
    fn is_installed(&self) -> io::Result<bool> {
        Ok(self.unit_path.is_file())
    }

    fn stop(&self) -> io::Result<()> {
        Self::systemctl(&["stop", LINUX_UNIT_FILE_NAME])
    }

    fn delete(&self) -> io::Result<()> {
        // Disable (drops the [Install] symlinks) best-effort, then remove the unit file and
        // reload so systemd forgets it — the mirror of `create`.
        let _ = Self::systemctl(&["disable", LINUX_UNIT_FILE_NAME]);
        if self.unit_path.exists() {
            std::fs::remove_file(&self.unit_path)?;
        }
        let _ = Self::systemctl(&["daemon-reload"]);
        Ok(())
    }

    fn create(&self, plan: &InstallPlan) -> io::Result<()> {
        std::fs::write(&self.unit_path, linux_unit_contents(plan))?;
        Self::systemctl(&["daemon-reload"])?;
        if plan.autostart {
            Self::systemctl(&["enable", LINUX_UNIT_FILE_NAME])?;
        }
        Ok(())
    }

    fn start(&self) -> io::Result<()> {
        Self::systemctl(&["start", LINUX_UNIT_FILE_NAME])
    }
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
    // Avoid a `libc` dependency for one call: read the effective uid via `id -u` (absolute-pathed
    // for the same anti-hijack reason as the elevated spawns, #657).
    std::process::Command::new(resolve_system_tool("id"))
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
    let _ = std::process::Command::new(resolve_system_tool("sc.exe"))
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Install `dig-dns` as an auto-starting OS service via the clean-reinstall contract (stop →
/// delete → recreate on an existing service; create otherwise). The service runs `dig-dns
/// serve` (or `run-service` on Windows) with the resolved `config` baked into its environment.
pub fn install(config: &Config) -> io::Result<ServiceOutcome> {
    if INSTALL_REQUIRES_ELEVATION && !has_required_elevation() {
        return Err(elevation_refusal("installing"));
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
    if INSTALL_REQUIRES_ELEVATION && !has_required_elevation() {
        return Err(elevation_refusal("uninstalling"));
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
///
/// **#501 — the CLI targets the RUNNING service regardless of who invokes it.** The gateway
/// probe already hits the shared loopback port (user-independent), and this additionally reads
/// the machine-wide runtime file the service records on startup ([`crate::state`]:
/// `%PROGRAMDATA%\DigDns` / `/var/lib/dig-dns` / `/Library/Application Support/DigDns`,
/// `DIG_DNS_STATE_DIR` override) to surface the exact service `pid` and the ACTUALLY-bound port
/// (which may be the `:8053` fallback) — the same values whichever user runs `dig-dns status`,
/// since the state dir is identity-independent, never a per-user profile dir.
pub fn status(config: &Config) -> io::Result<ServiceOutcome> {
    let serving = probe_serving(config);
    let registered = SystemServiceBackend::new()
        .and_then(|b| b.is_installed())
        .unwrap_or(false);
    let runtime = crate::state::read_runtime();
    let primary = format!("{}:{}", config.loopback_ip, config.http_port);

    // The runtime file records the port the service actually bound; prefer it in the reported
    // address (it may be the fallback), falling back to the configured primary when absent.
    let bound = runtime
        .as_ref()
        .map(|r| format!("{}:{}", r.loopback_ip, r.http_port))
        .unwrap_or_else(|| primary.clone());
    let pid_note = runtime
        .as_ref()
        .map(|r| format!(", pid {}", r.pid))
        .unwrap_or_default();
    let summary = if serving {
        format!("dig-dns: SERVING on http://{bound} (registered: {registered}{pid_note})")
    } else {
        format!(
            "dig-dns: NOT responding on http://{bound} (registered: {registered}{pid_note}) — \
             the service may be stopped or not installed"
        )
    };
    let mut obj = json!({
        "serving": serving,
        "registered": registered,
        "label": SERVICE_LABEL,
        "addr": bound,
        "state_dir": crate::state::state_dir().display().to_string(),
    });
    // Surface the recorded runtime facts (pid, bound port, DNS-path active) when present, so a
    // scripted client can identify the exact process regardless of the invoking user (#501).
    if let Some(r) = runtime {
        obj["pid"] = json!(r.pid);
        obj["bound_port"] = json!(r.http_port);
        obj["dns_active"] = json!(r.dns_active);
    }
    Ok(ServiceOutcome { summary, json: obj })
}

/// Query the running service's machine-readable health (`GET /.dig/health`) over loopback and
/// print it — the CLI verb that mirrors the gateway's `/.dig/health` control endpoint, so the same
/// service state is obtainable from the command line, not only over HTTP (CLAUDE.md §6.2 machine-
/// consumable parity; dig_ecosystem #569). Tries the primary HTTP port then the `:8053` fallback.
///
/// When the service is reachable the endpoint's JSON body is surfaced verbatim as the `--json`
/// object (and summarised for humans). When nothing answers, `serving` is `false` and the caller
/// maps that to a non-zero exit — the same contract as `status`.
pub fn health(config: &Config) -> io::Result<ServiceOutcome> {
    let ip = config.loopback_ip.to_string();
    let fetched = fetch_control_body(&ip, config.http_port, "/.dig/health")
        .or_else(|| fetch_control_body(&ip, config.http_fallback_port, "/.dig/health"));

    match fetched.and_then(|body| serde_json::from_str::<Value>(&body).ok()) {
        Some(health) => {
            let bound = health
                .get("bound_port")
                .and_then(Value::as_u64)
                .map(|p| format!("{ip}:{p}"))
                .unwrap_or_else(|| format!("{ip}:{}", config.http_port));
            let node_reachable = health
                .get("node")
                .and_then(|n| n.get("reachable"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let summary =
                format!("dig-dns: SERVING on http://{bound} (node reachable: {node_reachable})");
            Ok(ServiceOutcome {
                summary,
                json: json!({ "serving": true, "health": health }),
            })
        }
        None => Ok(ServiceOutcome {
            summary: format!(
                "dig-dns: NOT responding on http://{ip}:{} — the service may be stopped or not \
                 installed (see: dig-dns status)",
                config.http_port
            ),
            json: json!({ "serving": false, "label": SERVICE_LABEL }),
        }),
    }
}

/// Blocking gateway probe over loopback: try the primary HTTP port then the `:8053` fallback,
/// GET the `/.dig/resolve-probe` liveness endpoint, and report whether either answers 2xx.
/// Kept blocking (no async runtime) so `status` stays a lightweight one-shot.
fn probe_serving(config: &Config) -> bool {
    let ip = config.loopback_ip.to_string();
    probe_resolve(&ip, config.http_port) || probe_resolve(&ip, config.http_fallback_port)
}

/// Blocking HTTP/1.0 `GET <path>` over loopback returning the response BODY when the status is 2xx,
/// else `None`. Shares the [`PROBE_TIMEOUT`] connect/read bounds with [`probe_resolve`] so a CLI
/// verb built on it (e.g. [`health`]) can never hang on an unrouted loopback IP (dig_ecosystem
/// #502). Reads the whole response then splits off the body at the header terminator.
fn fetch_control_body(ip: &str, port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("{ip}:{port}");
    let socket_addr = addr.parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, PROBE_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROBE_TIMEOUT));
    let req = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = split_http_message(&text)?;
    is_2xx_status_line(head).then(|| body.to_string())
}

/// Split a raw HTTP response into its (status line + headers) head and its body, at the first
/// blank line (`\r\n\r\n`, tolerating a bare `\n\n`). Returns `None` when no terminator is present.
/// PURE — the parsing is unit-tested without a socket.
fn split_http_message(response: &str) -> Option<(&str, &str)> {
    if let Some(idx) = response.find("\r\n\r\n") {
        Some((&response[..idx], &response[idx + 4..]))
    } else {
        response
            .find("\n\n")
            .map(|idx| (&response[..idx], &response[idx + 2..]))
    }
}

/// How long [`probe_resolve`] waits on EACH phase (connect, then read) before giving up. Applied
/// to the CONNECT itself (not just the post-connect read/write) — see [`probe_resolve`]'s doc
/// comment for why that matters.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimal blocking HTTP/1.0 `GET /.dig/resolve-probe` over loopback; returns whether the
/// status line is 2xx (the gateway answers this liveness endpoint with `204`).
///
/// Uses [`TcpStream::connect_timeout`], NOT plain `connect`, bounding the CONNECT phase itself
/// (dig_ecosystem #502): connecting to a loopback IP the OS has no interface/route entry for —
/// e.g. `127.0.0.5` on macOS, which (unlike Linux/Windows) does NOT accept the whole `127.0.0.0/8`
/// range on `lo0` by default, only whatever is explicitly aliased (SPEC §5, `doctor`'s
/// `loopback_ip` check) — can hang rather than fail-fast with "connection refused". A real
/// service-smoke CI run against a bare macOS runner (no alias yet applied) demonstrated this
/// exact hang: `dig-dns status` blocked for 10+ minutes instead of promptly reporting "not
/// serving". A diagnostic command MUST never hang on the very condition it exists to detect.
fn probe_resolve(ip: &str, port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("{ip}:{port}");
    let Ok(socket_addr) = addr.parse() else {
        return false;
    };
    let mut stream = match TcpStream::connect_timeout(&socket_addr, PROBE_TIMEOUT) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROBE_TIMEOUT));
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
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    fn service_label_parses_as_three_reverse_dns_segments() {
        let l = label().expect("constant label must parse");
        // `to_qualified_name` must reproduce the literal id we register/query under (the
        // Windows-SCM / macOS-launchd identity; Linux registers the raw canonical name, #523).
        assert_eq!(l.to_qualified_name(), SERVICE_LABEL);
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn linux_unit_file_uses_the_canonical_dotted_name_matching_the_deb() {
        // dig_ecosystem #523: the CLI Linux install path MUST register the unit under the SAME
        // canonical name the native .deb installs — `net.dignetwork.dig-dns.service`, the
        // SERVICE_LABEL id + `.service` — NOT the `service-manager` crate's `dignetwork-dig-dns`
        // (to_script_name, which drops the `net` qualifier). One name however it was installed.
        assert_eq!(LINUX_UNIT_FILE_NAME, "net.dignetwork.dig-dns.service");
        assert_eq!(LINUX_UNIT_FILE_NAME, format!("{SERVICE_LABEL}.service"));
        // The .deb's unit file name (its own path constant) agrees, byte-for-byte.
        assert!(crate::packaging::SYSTEMD_UNIT_PATH.ends_with(LINUX_UNIT_FILE_NAME));
        // Written to the admin unit dir under the canonical name.
        assert_eq!(
            linux_unit_file_path(),
            PathBuf::from("/etc/systemd/system/net.dignetwork.dig-dns.service")
        );
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn linux_unit_contents_run_as_root_with_bounded_capability_and_baked_env() {
        // dig_ecosystem #528: the unit runs as root (no User=/DynamicUser=, so ExecStart can reach
        // a binary under a 0750 home like ~/.dig/bin), bounded to CAP_NET_BIND_SERVICE, with the
        // resolved config baked as Environment= lines and the ExecStart pointing at the installed
        // program.
        let config = Config {
            http_port: 8080,
            tld: "dig".to_string(),
            ..Config::default()
        };
        let plan = build_plan(&config, PathBuf::from("/home/alice/.dig/bin/dig-dns"));
        let unit = linux_unit_contents(&plan);

        assert!(unit.contains("ExecStart=/home/alice/.dig/bin/dig-dns serve"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("NoNewPrivileges=true"));
        // Runs as root: it must NOT drop to a dedicated account that can't traverse the home dir.
        assert!(!unit.contains("User="));
        assert!(!unit.contains("DynamicUser="));
        // Baked config + autostart install section.
        assert!(unit.contains(&format!("Environment={}=8080", config::ENV_HTTP_PORT)));
        assert!(unit.contains("Environment=DIG_DNS_TLD=dig"));
        assert!(unit.contains("[Install]\nWantedBy=multi-user.target"));
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
    fn split_http_message_separates_head_from_body_crlf_and_bare_lf() {
        let (head, body) = split_http_message(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}",
        )
        .expect("has a header terminator");
        assert!(head.starts_with("HTTP/1.0 200 OK"));
        assert_eq!(body, "{\"a\":1}");

        let (head2, body2) =
            split_http_message("HTTP/1.0 204 No Content\n\nbody").expect("bare LF terminator");
        assert!(head2.contains("204"));
        assert_eq!(body2, "body");

        assert!(split_http_message("no terminator here").is_none());
    }

    #[test]
    fn health_reports_not_serving_when_the_gateway_is_absent() {
        // dig_ecosystem #569: the `health` CLI verb mirrors `/.dig/health`. With nothing bound on
        // these high loopback ports it must report a clean not-serving result (never hang, never
        // hard-error) and mark serving=false so the CLI exits non-zero.
        let cfg = Config {
            http_port: 59_133,
            http_fallback_port: 59_134,
            ..Config::default()
        };
        let outcome = health(&cfg).expect("health never hard-errors");
        assert_eq!(outcome.json["serving"], json!(false));
        assert_eq!(outcome.json["label"], json!(SERVICE_LABEL));
        assert!(outcome.summary.contains("NOT responding"));
    }

    #[test]
    fn health_never_blocks_past_the_probe_timeout() {
        // Same unrouted-loopback hang guard as probe_resolve (#502) — the health fetch is bounded.
        let cfg = Config {
            http_port: 59_135,
            http_fallback_port: 59_136,
            ..Config::default()
        };
        let start = std::time::Instant::now();
        let _ = health(&cfg).unwrap();
        assert!(start.elapsed() < (PROBE_TIMEOUT * 2) + Duration::from_secs(1));
    }

    #[test]
    fn probe_resolve_is_false_on_a_refused_connection() {
        // Nothing listens on this high loopback port → connect refused → not serving.
        assert!(!probe_resolve("127.0.0.1", 59_125));
    }

    #[test]
    fn probe_resolve_never_blocks_past_the_probe_timeout() {
        // Regression for dig_ecosystem #502: a real macOS service-smoke CI run hung for 10+
        // minutes because plain `TcpStream::connect` (unlike `connect_timeout`) has no bound on
        // the CONNECT phase itself -- connecting to a loopback IP the OS has no route/interface
        // entry for can hang rather than fail-fast. This can't reproduce that exact
        // unassigned-loopback hang hermetically, but it pins that `probe_resolve` never takes
        // meaningfully longer than [`PROBE_TIMEOUT`], guarding against a future regression back
        // to an unbounded connect.
        let start = std::time::Instant::now();
        assert!(!probe_resolve("127.0.0.1", 59_126));
        assert!(start.elapsed() < PROBE_TIMEOUT + Duration::from_secs(1));
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
