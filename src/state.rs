//! Machine-wide, identity-independent service state directory (dig_ecosystem #501).
//!
//! The `dig-dns` OS service runs as a system account (Windows LocalSystem, Linux/macOS root);
//! its CLI counterpart (`status`, `stop`, …) may be invoked by ANY user. So any state the CLI
//! must share with the running service lives in a MACHINE-WIDE, user-independent directory —
//! NEVER a per-user profile dir — so the control/observation path does not vary by who runs the
//! CLI. This mirrors the sibling dig-node machine-wide state model.
//!
//! | OS | Default state dir |
//! |----|-------------------|
//! | Windows | `%PROGRAMDATA%\DigDns` (typically `C:\ProgramData\DigDns`) |
//! | macOS | `/Library/Application Support/DigDns` |
//! | Linux | `/var/lib/dig-dns` |
//!
//! The `DIG_DNS_STATE_DIR` environment variable overrides the default (both the service and the
//! CLI honour it, so they agree). The installer creates the dir + applies its ACL (SYSTEM +
//! Administrators full control, install-user read; Unix `0640`/`0600`); `dig-dns` only RESOLVES
//! the path here. `dig-dns` holds NO control-token/secret (its gateway is loopback-only and
//! unauthenticated), so the state dir carries no secret material — only the non-sensitive
//! [`RuntimeInfo`] (pid + bound port) the CLI reads to locate the running service.
//!
//! ## Runtime discovery
//! `dig-dns`'s CLI reaches the service over a FIXED loopback port (`127.0.0.5:80`, fallback
//! `:8053` — SPEC Appendix A), so it can always find the service by probing those ports. The
//! service additionally records its ACTUALLY-bound port + pid in [`RUNTIME_FILE`] on startup so
//! the CLI can identify the exact running process and its real port (which may be the fallback)
//! without guessing — again, regardless of the invoking user.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Environment variable overriding the machine-wide state dir (shared by the service + CLI).
pub const ENV_STATE_DIR: &str = "DIG_DNS_STATE_DIR";

/// The runtime-info file name inside the state dir.
pub const RUNTIME_FILE: &str = "runtime.json";

/// Non-secret runtime facts the running service records so its CLI can locate + identify it
/// regardless of the invoking user (#501). Serialised as JSON in [`RUNTIME_FILE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    /// The service process id.
    pub pid: u32,
    /// The loopback IP the gateway is bound to (e.g. `127.0.0.5`).
    pub loopback_ip: String,
    /// The ACTUALLY-bound HTTP gateway port (the primary `:80`, or the `:8053` fallback).
    pub http_port: u16,
    /// Whether the DNS responder (`:53`) is also active (best-effort, non-fatal — SPEC §3).
    pub dns_active: bool,
}

/// Resolve the state dir from an injected env getter: the [`ENV_STATE_DIR`] override wins (blank
/// is ignored), else the per-OS machine-wide default. PURE — testable without touching the
/// process environment.
pub fn resolve_state_dir<F: Fn(&str) -> Option<String>>(get: F) -> PathBuf {
    if let Some(dir) = get(ENV_STATE_DIR)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return PathBuf::from(dir);
    }
    default_state_dir(&get)
}

/// The machine-wide state dir, reading the process environment. See [`resolve_state_dir`].
pub fn state_dir() -> PathBuf {
    resolve_state_dir(|k| std::env::var(k).ok())
}

/// Windows default: `%PROGRAMDATA%\DigDns`. `ProgramData` is a system-wide, user-independent
/// path (`C:\ProgramData` by default) — never a per-user profile dir.
#[cfg(windows)]
fn default_state_dir<F: Fn(&str) -> Option<String>>(get: &F) -> PathBuf {
    let base = get("ProgramData")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("DigDns")
}

/// macOS default: the system Application-Support dir (a daemon, not a user agent).
#[cfg(target_os = "macos")]
fn default_state_dir<F: Fn(&str) -> Option<String>>(_get: &F) -> PathBuf {
    PathBuf::from("/Library/Application Support/DigDns")
}

/// Linux default: the FHS machine-wide variable-state dir.
#[cfg(all(unix, not(target_os = "macos")))]
fn default_state_dir<F: Fn(&str) -> Option<String>>(_get: &F) -> PathBuf {
    PathBuf::from("/var/lib/dig-dns")
}

/// The path to [`RUNTIME_FILE`] inside the resolved state dir.
pub fn runtime_path() -> PathBuf {
    state_dir().join(RUNTIME_FILE)
}

/// Write `info` as JSON into `dir` (creating `dir` if needed). Kept dir-parameterised so it is
/// unit-tested against a temp dir without mutating the process environment.
pub fn write_runtime_to(dir: &Path, info: &RuntimeInfo) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_vec_pretty(info)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(dir.join(RUNTIME_FILE), json)
}

/// Read + parse [`RuntimeInfo`] from `dir`; `None` if absent or unparseable. Dir-parameterised
/// for hermetic testing.
pub fn read_runtime_from(dir: &Path) -> Option<RuntimeInfo> {
    let bytes = std::fs::read(dir.join(RUNTIME_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Best-effort write of the runtime info to the machine-wide state dir. Returns the error so the
/// caller can log it; the caller MUST treat a failure as non-fatal (a non-admin foreground
/// `dig-dns serve` may be unable to write the system dir — the service still serves).
pub fn write_runtime(info: &RuntimeInfo) -> io::Result<()> {
    write_runtime_to(&state_dir(), info)
}

/// Best-effort read of the runtime info from the machine-wide state dir.
pub fn read_runtime() -> Option<RuntimeInfo> {
    read_runtime_from(&state_dir())
}

/// Best-effort removal of the runtime file (on graceful shutdown). Never fails the caller.
pub fn remove_runtime() {
    let _ = std::fs::remove_file(runtime_path());
}

/// RAII lifetime marker for the runtime-info file: [`RuntimeGuard::record`] best-effort WRITES
/// [`RUNTIME_FILE`] into the machine-wide state dir, and `Drop` REMOVES it. The serve loop holds
/// one for its whole lifetime, so the file is present exactly while the service is serving and
/// is cleared on a graceful stop — the CLI never inherits a stale pid/port from a prior run.
///
/// The write is best-effort (a non-admin foreground `dig-dns serve` may be unable to write the
/// system dir); a failure is logged, not fatal — the service still serves, and the CLI falls
/// back to probing the loopback port. Dir-parameterised so it is unit-testable against a temp
/// dir without touching the process environment.
pub struct RuntimeGuard {
    dir: PathBuf,
}

impl RuntimeGuard {
    /// Record `info` into `dir` (best-effort) and return a guard that removes it on drop.
    pub fn record(dir: PathBuf, info: &RuntimeInfo) -> Self {
        if let Err(e) = write_runtime_to(&dir, info) {
            tracing::warn!(
                error = %e,
                dir = %dir.display(),
                "could not record runtime info to the machine-wide state dir (non-fatal; the \
                 CLI will fall back to probing the loopback port)"
            );
        }
        Self { dir }
    }
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.dir.join(RUNTIME_FILE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn getter(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn explicit_override_wins() {
        let dir = resolve_state_dir(getter(&[(ENV_STATE_DIR, "/custom/dig-dns-state")]));
        assert_eq!(dir, PathBuf::from("/custom/dig-dns-state"));
    }

    #[test]
    fn blank_override_falls_through_to_the_default() {
        // A blank/whitespace override must NOT be treated as a real path.
        let dir = resolve_state_dir(getter(&[(ENV_STATE_DIR, "   ")]));
        assert_eq!(dir, resolve_state_dir(getter(&[])));
    }

    #[test]
    #[cfg(windows)]
    fn windows_default_is_programdata_digdns() {
        let dir = resolve_state_dir(getter(&[("ProgramData", r"D:\PD")]));
        assert_eq!(dir, PathBuf::from(r"D:\PD\DigDns"));
        // With ProgramData unset it falls back to the canonical C:\ProgramData.
        let fallback = resolve_state_dir(getter(&[]));
        assert_eq!(fallback, PathBuf::from(r"C:\ProgramData\DigDns"));
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn linux_default_is_var_lib() {
        assert_eq!(
            resolve_state_dir(getter(&[])),
            PathBuf::from("/var/lib/dig-dns")
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_default_is_application_support() {
        assert_eq!(
            resolve_state_dir(getter(&[])),
            PathBuf::from("/Library/Application Support/DigDns")
        );
    }

    #[test]
    fn runtime_info_round_trips_through_the_state_dir() {
        // A unique temp dir stands in for the machine-wide dir — hermetic, no env mutation.
        let dir = std::env::temp_dir().join(format!("dig-dns-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let info = RuntimeInfo {
            pid: 4242,
            loopback_ip: "127.0.0.5".to_string(),
            http_port: 8053,
            dns_active: false,
        };
        write_runtime_to(&dir, &info).expect("write runtime");
        let read = read_runtime_from(&dir).expect("read runtime back");
        assert_eq!(read, info);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_runtime_is_none_when_absent() {
        let dir = std::env::temp_dir().join(format!("dig-dns-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read_runtime_from(&dir), None);
    }

    #[test]
    fn runtime_guard_records_on_create_and_clears_on_drop() {
        // The serve loop holds a `RuntimeGuard` for its whole lifetime: the runtime file MUST
        // exist while serving (so the CLI can find the service) and be gone once the guard drops
        // (a graceful stop), never leaving a stale pid/port behind for the next CLI to trust.
        let dir = std::env::temp_dir().join(format!("dig-dns-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let info = RuntimeInfo {
            pid: std::process::id(),
            loopback_ip: "127.0.0.5".to_string(),
            http_port: 80,
            dns_active: true,
        };
        {
            let _guard = RuntimeGuard::record(dir.clone(), &info);
            assert_eq!(
                read_runtime_from(&dir).as_ref(),
                Some(&info),
                "runtime file must be present while the guard is alive"
            );
        }
        assert_eq!(
            read_runtime_from(&dir),
            None,
            "dropping the guard must remove the runtime file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
