//! Native OS install-package contract (dig_ecosystem #503).
//!
//! `dig-dns` ships THREE native OS install packages that install it **as a service** — a
//! Windows `.msi`, a macOS `.pkg`, and an Ubuntu `.deb`. The `dig-installer` just downloads +
//! runs them (it no longer hand-rolls service registration). Each package registers the SAME
//! canonical service identity ([`crate::service::SERVICE_LABEL`] /
//! [`crate::service::SERVICE_DISPLAY_NAME`]) running the SAME entrypoint, and creates the SAME
//! machine-wide state dir ([`crate::state`]) as a manual `dig-dns install` — the packaged and
//! manual paths are interchangeable (SPEC §14).
//!
//! This module is the **single source of truth** for the two text-templated service manifests —
//! the systemd unit ([`systemd_unit`]) and the launchd plist ([`launchd_plist`]) — built from the
//! canonical constants so a change to the service id or a path can never silently desync the
//! shipped file from the code. The committed manifest files (`packaging/linux/…service`,
//! `packaging/macos/…plist`) are snapshots of these generators, and a test asserts they match
//! byte-for-byte (modulo line endings). The Windows `.msi` is a WiX source (`wix/main.wxs`) whose
//! service contract is asserted by token, since generating WiX XML from Rust would be overkill.
//!
//! Nothing here runs in the service hot path; it is pure string construction + the packaging
//! contract, exercised entirely by unit tests.

use crate::service::{SERVICE_DISPLAY_NAME, SERVICE_LABEL};

/// Absolute path the Ubuntu `.deb` installs the binary to (on `PATH`).
pub const LINUX_BIN_PATH: &str = "/usr/bin/dig-dns";
/// Absolute path the macOS `.pkg` installs the binary to (on `PATH`).
pub const MACOS_BIN_PATH: &str = "/usr/local/bin/dig-dns";

/// Linux machine-wide state dir (matches [`crate::state`] default + SPEC §13.5).
pub const LINUX_STATE_DIR: &str = "/var/lib/dig-dns";
/// macOS machine-wide state dir (matches [`crate::state`] default + SPEC §13.5).
pub const MACOS_STATE_DIR: &str = "/Library/Application Support/DigDns";
/// Windows machine-wide state dir folder name under `%PROGRAMDATA%` (the MSI creates
/// `CommonAppDataFolder\DigDns`, i.e. `C:\ProgramData\DigDns`).
pub const WINDOWS_STATE_DIR_NAME: &str = "DigDns";

/// The macOS LaunchDaemon plist install path.
pub const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/net.dignetwork.dig-dns.plist";
/// The Linux systemd unit install path.
pub const SYSTEMD_UNIT_PATH: &str = "/lib/systemd/system/net.dignetwork.dig-dns.service";

/// The Linux capability `dig-dns` needs to bind its privileged loopback ports (`:53` DNS, `:80`
/// gateway) — the ONLY privilege it requires. Declared in the systemd unit so the service can be
/// granted exactly this and nothing more.
pub const NET_BIND_CAPABILITY: &str = "CAP_NET_BIND_SERVICE";

/// The systemd unit (`net.dignetwork.dig-dns.service`) the Ubuntu `.deb` installs.
///
/// Runs `dig-dns serve` (the foreground run mode — systemd owns the lifecycle, SPEC §13). Grants
/// only [`NET_BIND_CAPABILITY`] so it can bind `:53`/`:80` on the loopback IP; `StateDirectory`
/// makes systemd create [`LINUX_STATE_DIR`] for `runtime.json`. Restart-on-failure keeps the
/// resolver up. The `[Install]` `WantedBy` + the `.deb` maintainer scripts (`daemon-reload` +
/// `enable --now` on install, `stop`+`disable` on removal) make it auto-start.
pub fn systemd_unit() -> String {
    format!(
        "[Unit]\n\
         Description={SERVICE_DISPLAY_NAME} — local *.dig resolver (DNS responder + HTTP gateway)\n\
         Documentation=https://docs.dig.net\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={LINUX_BIN_PATH} serve\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         # dig-dns binds :53 (DNS) + :80 (HTTP gateway) on a loopback IP; CAP_NET_BIND_SERVICE is\n\
         # the ONLY privilege it needs (SPEC §5 loopback-only; it holds no secret).\n\
         AmbientCapabilities={NET_BIND_CAPABILITY}\n\
         CapabilityBoundingSet={NET_BIND_CAPABILITY}\n\
         # Machine-wide, identity-independent runtime state (SPEC §13.5): systemd creates\n\
         # {LINUX_STATE_DIR} and the service records runtime.json there.\n\
         StateDirectory=dig-dns\n\
         Environment=DIG_DNS_STATE_DIR={LINUX_STATE_DIR}\n\
         # Hardening — loopback-only service, no secret material.\n\
         NoNewPrivileges=true\n\
         ProtectSystem=full\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// The macOS LaunchDaemon plist (`net.dignetwork.dig-dns.plist`) the `.pkg` installs.
///
/// A system daemon (not a per-user agent — SPEC §13.5), `RunAtLoad` + `KeepAlive` so it starts on
/// boot and is restarted if it exits. Runs `dig-dns serve` from [`MACOS_BIN_PATH`]; points the
/// service at [`MACOS_STATE_DIR`] for `runtime.json`. `launchd` runs it as root, which can bind
/// the privileged `:53`/`:80` loopback ports directly.
pub fn launchd_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{SERVICE_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{MACOS_BIN_PATH}</string>\n\
         \t\t<string>serve</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<true/>\n\
         \t<key>EnvironmentVariables</key>\n\
         \t<dict>\n\
         \t\t<key>DIG_DNS_STATE_DIR</key>\n\
         \t\t<string>{MACOS_STATE_DIR}</string>\n\
         \t</dict>\n\
         \t<key>StandardOutPath</key>\n\
         \t<string>/Library/Logs/DigDns/dig-dns.log</string>\n\
         \t<key>StandardErrorPath</key>\n\
         \t<string>/Library/Logs/DigDns/dig-dns.log</string>\n\
         \t<key>ProcessType</key>\n\
         \t<string>Adaptive</string>\n\
         </dict>\n\
         </plist>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The repo root (the crate manifest dir) — where the committed packaging files live.
    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Read a committed packaging file, normalising CRLF→LF so an autocrlf checkout on Windows
    /// does not spuriously fail the byte-for-byte match (the files ship LF via `.gitattributes`).
    fn read_normalized(rel: &str) -> String {
        let path = repo_root().join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        raw.replace("\r\n", "\n")
    }

    // -- systemd unit ---------------------------------------------------------------------------

    #[test]
    fn systemd_unit_encodes_the_service_contract() {
        let unit = systemd_unit();
        // Runs the canonical foreground run mode from the installed binary path.
        assert!(unit.contains("ExecStart=/usr/bin/dig-dns serve"), "{unit}");
        // The ONLY privilege: bind the low loopback ports.
        assert!(
            unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"),
            "{unit}"
        );
        assert!(
            unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"),
            "{unit}"
        );
        // Machine-wide state dir (SPEC §13.5).
        assert!(unit.contains("StateDirectory=dig-dns"), "{unit}");
        assert!(
            unit.contains(&format!("Environment=DIG_DNS_STATE_DIR={LINUX_STATE_DIR}")),
            "{unit}"
        );
        // Auto-start target + resilience.
        assert!(unit.contains("WantedBy=multi-user.target"), "{unit}");
        assert!(unit.contains("Restart=on-failure"), "{unit}");
        // The display name is the human description.
        assert!(unit.contains(SERVICE_DISPLAY_NAME), "{unit}");
    }

    #[test]
    fn shipped_systemd_unit_matches_the_generator() {
        // The committed file the `.deb` ships MUST be exactly what the code generates, so the
        // service id / paths / capability can never drift from the constants.
        let shipped = read_normalized("packaging/linux/net.dignetwork.dig-dns.service");
        assert_eq!(shipped, systemd_unit());
    }

    // -- launchd plist --------------------------------------------------------------------------

    #[test]
    fn launchd_plist_encodes_the_service_contract() {
        let plist = launchd_plist();
        assert!(
            plist.contains(&format!("<string>{SERVICE_LABEL}</string>")),
            "{plist}"
        );
        assert!(
            plist.contains(&format!("<string>{MACOS_BIN_PATH}</string>")),
            "{plist}"
        );
        assert!(plist.contains("<string>serve</string>"), "{plist}");
        // A boot daemon that stays up.
        assert!(plist.contains("<key>RunAtLoad</key>"), "{plist}");
        assert!(plist.contains("<key>KeepAlive</key>"), "{plist}");
        // Machine-wide state dir (SPEC §13.5).
        assert!(plist.contains(MACOS_STATE_DIR), "{plist}");
        assert!(plist.contains("DIG_DNS_STATE_DIR"), "{plist}");
    }

    #[test]
    fn shipped_launchd_plist_matches_the_generator() {
        let shipped = read_normalized("packaging/macos/net.dignetwork.dig-dns.plist");
        assert_eq!(shipped, launchd_plist());
    }

    // -- macOS install scripts ------------------------------------------------------------------

    #[test]
    fn macos_scripts_bootout_then_bootstrap_the_daemon() {
        // preinstall must tear down any existing daemon so an upgrade re-bootstraps the new plist
        // cleanly (mirrors the clean-reinstall contract, SPEC §13.2).
        let pre = read_normalized("packaging/macos/scripts/preinstall");
        assert!(
            pre.contains(&format!("bootout system/{SERVICE_LABEL}")),
            "{pre}"
        );
        // postinstall creates the state dir + bootstraps/enables the daemon.
        let post = read_normalized("packaging/macos/scripts/postinstall");
        assert!(
            post.contains(LAUNCHD_PLIST_PATH),
            "plist path referenced: {post}"
        );
        assert!(post.contains("bootstrap system"), "bootstrap: {post}");
        assert!(
            post.contains(&format!("enable system/{SERVICE_LABEL}")),
            "{post}"
        );
        assert!(post.contains(MACOS_STATE_DIR), "{post}");
    }

    // -- Windows MSI (WiX source) ---------------------------------------------------------------

    #[test]
    fn wix_source_encodes_the_service_contract() {
        let wxs = read_normalized("wix/main.wxs");
        // The canonical service identity.
        assert!(
            wxs.contains(&format!("Name=\"{SERVICE_LABEL}\"")),
            "service name"
        );
        assert!(
            wxs.contains(&format!("DisplayName=\"{SERVICE_DISPLAY_NAME}\"")),
            "display name"
        );
        // The service runs the SCM `run-service` entrypoint (NOT a host shim), auto-start.
        assert!(wxs.contains("Arguments=\"run-service\""), "run-service arg");
        assert!(wxs.contains("Start=\"auto\""), "auto start");
        assert!(
            wxs.contains("Account=\"LocalSystem\""),
            "LocalSystem account"
        );
        // Start on install; stop + remove on uninstall.
        assert!(wxs.contains("Start=\"install\""), "start on install");
        assert!(wxs.contains("Remove=\"uninstall\""), "remove on uninstall");
        // The machine-wide state dir under %PROGRAMDATA% (SPEC §13.5).
        assert!(wxs.contains("CommonAppDataFolder"), "ProgramData dir");
        assert!(
            wxs.contains(&format!("Name=\"{WINDOWS_STATE_DIR_NAME}\"")),
            "DigDns state dir"
        );
        // A fixed UpgradeCode gives clean upgrade + uninstall.
        assert!(wxs.contains("UpgradeCode="), "upgrade code");
        assert!(wxs.contains("<MajorUpgrade"), "major upgrade");
        // Adds the install dir to PATH.
        assert!(wxs.contains("Name=\"PATH\""), "PATH env");
    }

    // -- the .deb control metadata (apt-correct, #425) ------------------------------------------

    #[test]
    fn cargo_deb_metadata_is_apt_correct() {
        // The `.deb` is published as a GitHub release asset and ingested by apt.dig.net, so the
        // control metadata (package name, section, systemd unit wiring) MUST be present + stable.
        let cargo = read_normalized("Cargo.toml");
        assert!(cargo.contains("[package.metadata.deb]"), "deb metadata");
        assert!(
            cargo.contains("[package.metadata.deb.systemd-units]"),
            "systemd-units"
        );
        assert!(
            cargo.contains(&format!("unit-name = \"{SERVICE_LABEL}\"")),
            "unit-name pins the canonical service id"
        );
        assert!(
            cargo.contains("unit-scripts = \"packaging/linux\""),
            "unit-scripts dir"
        );
    }
}
