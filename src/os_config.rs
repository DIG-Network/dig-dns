//! `configure-os` / `unconfigure-os`: OS-level split-DNS wiring so `*.<tld>` names resolve to
//! the local `dig-dns` responder SYSTEM-WIDE (SPEC §15).
//!
//! This is an **explicit administrator action**, deliberately separate from the `serve` /
//! `run-service` runtime — which NEVER touches the OS resolver (SPEC §5, invariant intact). A
//! bare `apt install dig-dns` / `.msi` / `.pkg` gives a running service, but without this wiring
//! the OS does not route `<label>.<tld>` to `127.0.0.5`; the native package post-installs call
//! `configure-os` so the package alone works (dig_ecosystem #530), and the `dig-installer` will
//! later call the SAME subcommand instead of its own duplicated `src/dns/*` logic.
//!
//! ## What it does, per OS (the RESOLVER wiring — always)
//! - **Linux** — writes a `systemd-resolved` drop-in (`/etc/systemd/resolved.conf.d/dig.conf`)
//!   routing `~<tld>` at the responder, reloading + flushing; falls back to a NetworkManager-
//!   dnsmasq drop-in when systemd-resolved does not own `/etc/resolv.conf`. The owning resolver
//!   is DETECTED, never assumed ([`detect_resolv_owner`]); a plain `resolv.conf` is left untouched
//!   (Path B / the PAC carries it).
//! - **macOS** — creates the boot-persistent `lo0` alias for the responder's loopback IP (a
//!   FUNCTIONAL PREREQUISITE: macOS does not answer `127.0.0.0/8` beyond `127.0.0.1` without an
//!   explicit alias — mirroring `service.rs`'s probe note), writes `/etc/resolver/<tld>`, and
//!   flushes the DNS cache.
//! - **Windows** — adds an NRPT rule (`Add-DnsClientNrptRule -Namespace .<tld>`) routing the
//!   namespace at the responder.
//!
//! ## The browser managed-DoH policy is OPT-IN (`--browser-policy`)
//! Setting a Chrome/Edge *managed policy* (DoH off + built-in resolver off) is invasive — a
//! package must never silently place a user's browser under managed policy. So it is gated behind
//! `--browser-policy`, which the native packages do NOT pass; only an explicit admin (or, later,
//! the `dig-installer`) opts in. Browsers with Secure DNS still bypass the OS resolver otherwise —
//! that is the documented DoH caveat, covered by Path B (the PAC).
//!
//! ## Idempotency, marker-scoping, legacy migration
//! Every artifact this tool writes carries [`MARKER`] (or is a uniquely-named file it solely
//! owns). `unconfigure-os` removes ONLY those — plus artifacts left by the OLD dig-installer
//! ([`LEGACY_INSTALLER_MARKER`]), so machines wired by the previous installer clean up cleanly. A
//! `.<tld>` rule a user or org added is NEVER touched. Re-running either subcommand is a no-op-
//! equivalent.
//!
//! ## Elevation
//! All of the above needs OS privilege (root / Administrator). When not elevated, the subcommands
//! REFUSE with a clear message and a stable `needs_elevation: true` JSON field (§6.2) rather than
//! failing cryptically deep inside a system tool.
//!
//! Design: the DECISIONS (file contents, command argv, resolver-owner detection, marker
//! ownership) are pure functions unit-tested on every platform; the thin apply layer performs the
//! real file writes + `systemctl`/`resolvectl`/`ifconfig`/`launchctl`/`powershell`/`reg` I/O and
//! is exercised by the 3-OS smoke CI (SPEC §15 / CLAUDE.md §2.4a). No `#[cfg]` gating: the module
//! compiles identically on every target and branches on [`std::env::consts::OS`] at runtime
//! (mirroring `doctor.rs`), keeping the whole surface testable.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Serialize;
use serde_json::json;

use crate::config::Config;
use crate::system_tool::resolve_system_tool;

/// The marker stamped into every artifact `configure-os` writes, so `unconfigure-os` recognises —
/// and only removes — what THIS tool added.
pub const MARKER: &str = "managed by dig-dns configure-os";

/// The marker the OLD `dig-installer` stamped into the artifacts it wrote (dig-installer
/// `src/dns/plan.rs`). `unconfigure-os` also recognises this so a machine wired by the previous
/// installer migrates/cleans cleanly (dig_ecosystem #530 / #272).
pub const LEGACY_INSTALLER_MARKER: &str = "managed by dig-installer (dig-dns, task #177)";

// -- per-OS artifact paths ---------------------------------------------------------------------

/// Linux `systemd-resolved` per-domain drop-in path.
const LINUX_RESOLVED_DROPIN: &str = "/etc/systemd/resolved.conf.d/dig.conf";
/// Linux NetworkManager-dnsmasq split-DNS drop-in path.
const LINUX_NM_DNSMASQ_CONF: &str = "/etc/NetworkManager/dnsmasq.d/dig.conf";
/// Linux Chrome managed-policy file (uniquely named — this tool solely owns it).
const LINUX_CHROME_POLICY: &str = "/etc/opt/chrome/policies/managed/dig-dns.json";
/// Linux Chromium managed-policy file (uniquely named — this tool solely owns it).
const LINUX_CHROMIUM_POLICY: &str = "/etc/chromium/policies/managed/dig-dns.json";

/// macOS boot-persistent `lo0`-alias LaunchDaemon plist path.
const MACOS_LO0_PLIST: &str = "/Library/LaunchDaemons/net.dignetwork.dig-dns-lo0.plist";
/// macOS boot-persistent `lo0`-alias LaunchDaemon label.
const MACOS_LO0_LABEL: &str = "net.dignetwork.dig-dns-lo0";
/// Where macOS MDM-provisioned Chrome managed preferences live — scanned (never written) to
/// detect an existing org policy this tool must not clobber.
const MACOS_MANAGED_PREFS_DIR: &str = "/Library/Managed Preferences";
/// The best-effort Chrome managed-preference plist this tool writes with `--browser-policy` when
/// no existing (non-ours) managed policy is present.
const MACOS_CHROME_PLIST: &str = "/Library/Managed Preferences/com.google.Chrome.plist";

/// Windows Chrome policy key (relative to `HKLM`).
const WIN_CHROME_POLICY_KEY: &str = r"SOFTWARE\Policies\Google\Chrome";
/// Windows Edge policy key (relative to `HKLM`).
const WIN_EDGE_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Edge";
/// `DnsOverHttpsMode` policy value name (REG_SZ, set to `off`).
const WIN_POLICY_DOH_NAME: &str = "DnsOverHttpsMode";
/// `BuiltInDnsClientEnabled` policy value name (REG_DWORD, set to `0`).
const WIN_POLICY_BUILTIN_NAME: &str = "BuiltInDnsClientEnabled";
/// Marker value written alongside the policy so removal only ever touches a key THIS tool owns.
const WIN_POLICY_MARKER: &str = "DigDnsManaged";
/// The marker value the OLD dig-installer wrote — recognised on removal for legacy cleanup.
const WIN_LEGACY_POLICY_MARKER: &str = "DigInstallerManaged";

/// The macOS `/etc/resolver/<tld>` path — macOS reads a per-TLD file NAMED for the domain.
fn macos_resolver_path(tld: &str) -> String {
    format!("/etc/resolver/{tld}")
}

// ==============================================================================================
// Pure content + command builders (unit-tested on every platform).
// ==============================================================================================

/// The `systemd-resolved` drop-in routing `~<tld>` lookups at the responder.
pub fn systemd_resolved_dropin(ip: Ipv4Addr, tld: &str) -> String {
    format!("# {MARKER}\n[Resolve]\nDNS={ip}\nDomains=~{tld}\n")
}

/// The NetworkManager-dnsmasq split-DNS drop-in routing `<tld>` at the responder.
pub fn networkmanager_dnsmasq_conf(ip: Ipv4Addr, tld: &str) -> String {
    format!("# {MARKER}\nserver=/{tld}/{ip}\n")
}

/// The `/etc/resolver/<tld>` body (macOS): a marker comment + the `nameserver` line. macOS's
/// resolver files accept `#` comments, so the marker is preserved for marker-scoped removal.
pub fn resolver_file_content(ip: Ipv4Addr) -> String {
    format!("# {MARKER}\nnameserver {ip}\n")
}

/// The PowerShell cmdlet that flushes the Windows DNS client resolver cache. Run AFTER the NRPT
/// rule is added so the rule takes effect for names that were negatively cached before install —
/// this is what makes `.dig` resolution live without a reboot (dig_ecosystem #627).
pub const CLEAR_DNS_CLIENT_CACHE: &str = "Clear-DnsClientCache";

/// A PowerShell one-liner that adds the `.<tld>` NRPT rule IDEMPOTENTLY (a no-op if a rule for the
/// namespace already exists — never fighting a pre-existing rule) and tags it with [`MARKER`] via
/// `-Comment` so [`nrpt_remove_ps_command`] finds + removes only ours.
pub fn nrpt_add_ps_command(ip: Ipv4Addr, tld: &str) -> String {
    let ns = format!(".{tld}");
    format!(
        "if (-not (Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '{ns}' }})) {{ \
         Add-DnsClientNrptRule -Namespace '{ns}' -NameServers '{ip}' -Comment '{MARKER}' | Out-Null }}"
    )
}

/// A PowerShell one-liner that removes ONLY NRPT rules tagged with [`MARKER`] or the legacy
/// installer marker — never a `.<tld>` rule a user or another tool added.
pub fn nrpt_remove_ps_command() -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{MARKER}' -or \
         $_.Comment -eq '{LEGACY_INSTALLER_MARKER}' }} | Remove-DnsClientNrptRule -Force"
    )
}

/// The boot-persistent `lo0`-alias LaunchDaemon plist. macOS does not persist `ifconfig` aliases
/// across reboot, so this one-shot daemon re-applies `ifconfig lo0 alias <ip> up` at every boot
/// (`RunAtLoad`, not `KeepAlive` — the command exits immediately).
pub fn launchd_lo0_alias_plist(ip: Ipv4Addr) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <!-- {MARKER} -->\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{MACOS_LO0_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>/sbin/ifconfig</string>\n\
         \t\t<string>lo0</string>\n\
         \t\t<string>alias</string>\n\
         \t\t<string>{ip}</string>\n\
         \t\t<string>up</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<false/>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// The Chrome/Chromium managed-policy JSON (Linux): DoH off + built-in resolver off, so those
/// browsers honour the OS resolver rather than their own DNS-over-HTTPS.
pub fn chrome_policy_json() -> String {
    json!({ "DnsOverHttpsMode": "off", "BuiltInDnsClientEnabled": false }).to_string()
}

/// The Chrome managed-preference plist (macOS): DoH off + built-in resolver off, tagged with
/// [`MARKER`] so removal only touches what this tool wrote.
pub fn chrome_managed_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <!-- {MARKER} -->\n\
         <dict>\n\
         \t<key>DnsOverHttpsMode</key>\n\
         \t<string>off</string>\n\
         \t<key>BuiltInDnsClientEnabled</key>\n\
         \t<false/>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// `reg query HKLM\<key>` argv (excluding `reg`): exit 0 iff the key exists.
fn reg_query_key_args(key: &str) -> Vec<String> {
    vec!["query".to_string(), format!(r"HKLM\{key}")]
}

/// `reg query HKLM\<key> /v <value>` argv: exit 0 iff the value exists under the key.
fn reg_query_value_args(key: &str, value: &str) -> Vec<String> {
    vec![
        "query".to_string(),
        format!(r"HKLM\{key}"),
        "/v".to_string(),
        value.to_string(),
    ]
}

/// The three `reg add` argv (excluding `reg`) that write the DoH-off + built-in-resolver-off
/// policy + this tool's marker under `HKLM\<key>`.
fn reg_add_policy_args(key: &str) -> Vec<Vec<String>> {
    let full = format!(r"HKLM\{key}");
    vec![
        vec![
            "add".into(),
            full.clone(),
            "/v".into(),
            WIN_POLICY_DOH_NAME.into(),
            "/t".into(),
            "REG_SZ".into(),
            "/d".into(),
            "off".into(),
            "/f".into(),
        ],
        vec![
            "add".into(),
            full.clone(),
            "/v".into(),
            WIN_POLICY_BUILTIN_NAME.into(),
            "/t".into(),
            "REG_DWORD".into(),
            "/d".into(),
            "0".into(),
            "/f".into(),
        ],
        vec![
            "add".into(),
            full,
            "/v".into(),
            WIN_POLICY_MARKER.into(),
            "/t".into(),
            "REG_DWORD".into(),
            "/d".into(),
            "1".into(),
            "/f".into(),
        ],
    ]
}

/// `reg delete HKLM\<key> /v <value> /f` argv (excluding `reg`).
fn reg_delete_value_args(key: &str, value: &str) -> Vec<String> {
    vec![
        "delete".to_string(),
        format!(r"HKLM\{key}"),
        "/v".to_string(),
        value.to_string(),
        "/f".to_string(),
    ]
}

// -- marker ownership --------------------------------------------------------------------------

/// Which resolver owns `/etc/resolv.conf` on Linux, so split-DNS is wired the way that resolver
/// actually reads it — never assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvOwner {
    /// `systemd-resolved` (the `/etc/resolv.conf` symlink points into `systemd`).
    SystemdResolved,
    /// NetworkManager with the dnsmasq plugin (its drop-in directory exists).
    NetworkManagerDnsmasq,
    /// Neither is detectable — a plain `resolv.conf` is left untouched (rely on Path B).
    Unknown,
}

impl ResolvOwner {
    /// A stable machine label for the `--json` `resolver` field.
    fn label(self) -> &'static str {
        match self {
            ResolvOwner::SystemdResolved => "systemd-resolved",
            ResolvOwner::NetworkManagerDnsmasq => "networkmanager-dnsmasq",
            ResolvOwner::Unknown => "unknown",
        }
    }
}

/// Decide the resolv.conf owner from the `/etc/resolv.conf` symlink target (if any) and whether
/// the NetworkManager-dnsmasq drop-in directory exists. PURE — the caller supplies the two
/// observations, so the decision is unit-tested without a real `/etc`.
pub fn detect_resolv_owner(
    resolv_conf_link_target: Option<&str>,
    nm_dnsmasq_dir_exists: bool,
) -> ResolvOwner {
    if let Some(target) = resolv_conf_link_target {
        if target.contains("systemd") {
            return ResolvOwner::SystemdResolved;
        }
    }
    if nm_dnsmasq_dir_exists {
        return ResolvOwner::NetworkManagerDnsmasq;
    }
    ResolvOwner::Unknown
}

/// Is `content` an artifact this tool (or the legacy installer) owns and may remove? True when it
/// carries either marker, OR when it is the legacy `dig-installer`'s UNMARKED `/etc/resolver/<tld>`
/// body — a bare `nameserver <our-ip>` line (the old installer wrote that file without a marker).
/// PURE, so the whole ownership policy is unit-tested.
pub fn content_is_ours(content: &str, our_ip: Ipv4Addr) -> bool {
    content.contains(MARKER)
        || content.contains(LEGACY_INSTALLER_MARKER)
        || content.trim() == format!("nameserver {our_ip}")
}

// ==============================================================================================
// The report the subcommands return (its JSON is the machine contract, §6.2).
// ==============================================================================================

/// The structured outcome of `configure-os` / `unconfigure-os`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsConfigReport {
    /// `"configure-os"` or `"unconfigure-os"`.
    pub action: &'static str,
    /// The OS this ran on ([`std::env::consts::OS`]).
    pub os: String,
    /// Did the action complete its work (or find nothing to do)? Maps to the process exit code.
    pub ok: bool,
    /// `true` iff the action was REFUSED for lack of elevation — a stable, agent-checkable signal.
    pub needs_elevation: bool,
    /// Artifacts written/updated (configure) — stable paths/ids.
    pub applied: Vec<String>,
    /// Artifacts removed (unconfigure) — stable paths/ids.
    pub removed: Vec<String>,
    /// The detected Linux resolver owner, when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    /// Human-facing notes (one line each): what happened + any caveats.
    pub notes: Vec<String>,
    /// `true` iff, after applying + flushing, an end-to-end resolve VERIFY confirmed the OS now
    /// routes `*.<tld>` to the responder LIVE (no reboot needed). The expected outcome on all three
    /// OSes. `false` when no resolver wiring was applied (e.g. the Linux PAC-only path) or the
    /// verify has not passed yet.
    pub activated: bool,
    /// `true` ONLY as a defensive fallback: resolver wiring WAS applied but the post-activate verify
    /// still failed, so a restart is prompted to pick up the split-DNS. Expected to stay `false`.
    pub reboot_required: bool,
    /// Why a reboot is being prompted, when [`Self::reboot_required`]. `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reboot_reason: Option<String>,
}

impl OsConfigReport {
    fn started(action: &'static str) -> Self {
        OsConfigReport {
            action,
            os: std::env::consts::OS.to_string(),
            ok: false,
            needs_elevation: false,
            applied: Vec::new(),
            removed: Vec::new(),
            resolver: None,
            notes: Vec::new(),
            activated: false,
            reboot_required: false,
            reboot_reason: None,
        }
    }

    fn not_elevated(action: &'static str, message: &str) -> Self {
        let mut r = Self::started(action);
        r.needs_elevation = true;
        r.notes.push(message.to_string());
        r
    }

    fn unsupported(action: &'static str, os: &str) -> Self {
        let mut r = Self::started(action);
        r.notes
            .push(format!("{action} is not supported on this platform ({os})"));
        r
    }

    fn note(&mut self, msg: impl Into<String>) {
        self.notes.push(msg.into());
    }

    /// The `--json` object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// The human-readable summary.
    pub fn summary(&self) -> String {
        if self.needs_elevation {
            return format!("dig-dns {}: {}", self.action, self.notes.join("; "));
        }
        let mut out = format!(
            "dig-dns {} on {}: {}\n",
            self.action,
            self.os,
            if self.ok { "OK" } else { "FAILED" }
        );
        if let Some(r) = &self.resolver {
            out.push_str(&format!("  resolver: {r}\n"));
        }
        for a in &self.applied {
            out.push_str(&format!("  applied:  {a}\n"));
        }
        for rm in &self.removed {
            out.push_str(&format!("  removed:  {rm}\n"));
        }
        for n in &self.notes {
            out.push_str(&format!("  note:     {n}\n"));
        }
        if self.activated {
            out.push_str("  activated: .dig resolution is LIVE now (no reboot required)\n");
        }
        if self.reboot_required {
            let reason = self.reboot_reason.as_deref().unwrap_or("");
            out.push_str(&format!("  reboot:   RESTART REQUIRED — {reason}\n"));
        }
        out
    }
}

// ==============================================================================================
// The plan: per-OS resolver wiring modelled as an ordered list of pure STEPS. Keeping the
// orchestration (which artifacts, in what order, per OS/resolver) as data returned by a pure
// function means it is unit-tested by ASSERTING the plan — the only untestable OS glue left is the
// tiny [`execute`] loop + the live environment probes.
// ==============================================================================================

/// Which list of an [`OsConfigReport`] a successful step records into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    /// Push the label onto `applied` (a configure artifact).
    Applied,
    /// Push the label onto `removed` (an unconfigure artifact).
    Removed,
}

impl Bucket {
    fn record(self, report: &mut OsConfigReport, label: String) {
        match self {
            Bucket::Applied => report.applied.push(label),
            Bucket::Removed => report.removed.push(label),
        }
    }
}

/// One primitive step of an OS-config plan. PURE DATA — [`execute`] performs the I/O.
#[derive(Debug, Clone)]
enum Step {
    /// Idempotently write `content` to `path`; record the path in `applied` on success.
    Write { path: String, content: String },
    /// Remove `path` iff it is ours/legacy ([`content_is_ours`]); record it in `removed`.
    RemoveOurs { path: String },
    /// A best-effort external command — a reload / cache-flush / `ifconfig` / `launchctl` side
    /// effect that records nothing (its failure is non-fatal and expected on some hosts).
    Exec { program: String, args: Vec<String> },
    /// A PowerShell one-liner (the NRPT add/remove); record `label` in `bucket` on success.
    Ps {
        command: String,
        label: String,
        bucket: Bucket,
    },
    /// A best-effort PowerShell one-liner (a cache flush / reload) that records nothing — the
    /// Windows analogue of [`Step::Exec`]. Its failure is non-fatal (mirrors `resolvectl
    /// flush-caches` / `dscacheutil -flushcache` on the other OSes).
    PsExec { command: String },
    /// A note only (a caveat / an informational line).
    Note(String),
}

/// Build a best-effort [`Step::Exec`] with owned arguments.
fn exec(program: &str, args: &[&str]) -> Step {
    Step::Exec {
        program: program.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
    }
}

/// The ordered resolver-wiring steps `configure-os` applies for `os` + (on Linux) `owner`. PURE.
fn configure_resolver_steps(os: &str, owner: ResolvOwner, ip: Ipv4Addr, tld: &str) -> Vec<Step> {
    match os {
        "linux" => match owner {
            ResolvOwner::SystemdResolved => vec![
                Step::Write {
                    path: LINUX_RESOLVED_DROPIN.to_string(),
                    content: systemd_resolved_dropin(ip, tld),
                },
                exec("systemctl", &["reload-or-restart", "systemd-resolved"]),
                exec("resolvectl", &["flush-caches"]),
            ],
            ResolvOwner::NetworkManagerDnsmasq => vec![
                Step::Write {
                    path: LINUX_NM_DNSMASQ_CONF.to_string(),
                    content: networkmanager_dnsmasq_conf(ip, tld),
                },
                exec("systemctl", &["reload", "NetworkManager"]),
            ],
            ResolvOwner::Unknown => vec![Step::Note(
                "no systemd-resolved/NetworkManager-dnsmasq resolver detected; /etc/resolv.conf \
                 left untouched — browsers reach *.dig via the PAC (Path B)"
                    .to_string(),
            )],
        },
        // macOS: the lo0 alias is a FUNCTIONAL PREREQUISITE (macOS answers only 127.0.0.1 on lo0)
        // — apply it now AND persist it across reboots via a one-shot LaunchDaemon — then the
        // per-TLD resolver file, then flush the cache.
        "macos" => vec![
            exec("ifconfig", &["lo0", "alias", &ip.to_string(), "up"]),
            Step::Write {
                path: MACOS_LO0_PLIST.to_string(),
                content: launchd_lo0_alias_plist(ip),
            },
            exec(
                "launchctl",
                &["bootout", &format!("system/{MACOS_LO0_LABEL}")],
            ),
            exec("launchctl", &["bootstrap", "system", MACOS_LO0_PLIST]),
            exec(
                "launchctl",
                &["enable", &format!("system/{MACOS_LO0_LABEL}")],
            ),
            Step::Write {
                path: macos_resolver_path(tld),
                content: resolver_file_content(ip),
            },
            exec("dscacheutil", &["-flushcache"]),
            exec("killall", &["-HUP", "mDNSResponder"]),
        ],
        // Windows: add the NRPT rule (live for subsequent queries immediately) THEN flush the DNS
        // client cache. The reboot symptom was purely stale negatively-cached entries — an NRPT
        // local rule needs no service restart, only the cache cleared (dig_ecosystem #627). We do
        // NOT restart the `Dnscache` service (it has dependents and the flush is sufficient).
        "windows" => vec![
            Step::Ps {
                command: nrpt_add_ps_command(ip, tld),
                label: format!(".{tld} NRPT rule"),
                bucket: Bucket::Applied,
            },
            Step::PsExec {
                command: CLEAR_DNS_CLIENT_CACHE.to_string(),
            },
        ],
        _ => Vec::new(),
    }
}

/// The ordered resolver-wiring steps `unconfigure-os` reverses for `os`. PURE. Removals are
/// marker-scoped in [`execute`]; the reload/flush side effects run unconditionally (a no-op reload
/// is harmless), which keeps the plan a simple, testable list.
fn unconfigure_resolver_steps(os: &str, ip: Ipv4Addr, tld: &str) -> Vec<Step> {
    match os {
        "linux" => vec![
            Step::RemoveOurs {
                path: LINUX_RESOLVED_DROPIN.to_string(),
            },
            exec("systemctl", &["reload-or-restart", "systemd-resolved"]),
            exec("resolvectl", &["flush-caches"]),
            Step::RemoveOurs {
                path: LINUX_NM_DNSMASQ_CONF.to_string(),
            },
            exec("systemctl", &["reload", "NetworkManager"]),
        ],
        "macos" => vec![
            exec(
                "launchctl",
                &["bootout", &format!("system/{MACOS_LO0_LABEL}")],
            ),
            Step::RemoveOurs {
                path: MACOS_LO0_PLIST.to_string(),
            },
            exec("ifconfig", &["lo0", "-alias", &ip.to_string()]),
            Step::RemoveOurs {
                path: macos_resolver_path(tld),
            },
            exec("dscacheutil", &["-flushcache"]),
            exec("killall", &["-HUP", "mDNSResponder"]),
        ],
        "windows" => vec![
            Step::Ps {
                command: nrpt_remove_ps_command(),
                label: format!(".{tld} NRPT rule"),
                bucket: Bucket::Removed,
            },
            Step::PsExec {
                command: CLEAR_DNS_CLIENT_CACHE.to_string(),
            },
        ],
        _ => Vec::new(),
    }
}

/// Execute a plan, performing the I/O and assembling the report. The recording arms (Write /
/// RemoveOurs / Ps / Note) are unit-tested; only the external-command spawns are OS glue.
fn execute(
    action: &'static str,
    our_ip: Ipv4Addr,
    resolver: Option<String>,
    steps: Vec<Step>,
) -> OsConfigReport {
    let mut r = OsConfigReport::started(action);
    r.resolver = resolver;
    for step in steps {
        match step {
            Step::Write { path, content } => match write_if_changed(Path::new(&path), &content) {
                Ok(_) => r.applied.push(path),
                Err(e) => r.note(format!("{path} not written: {e}")),
            },
            Step::RemoveOurs { path } => match remove_if_ours(Path::new(&path), our_ip) {
                Ok(true) => r.removed.push(path),
                Ok(false) => {}
                Err(e) => r.note(format!("{path} not removed: {e}")),
            },
            Step::Exec { program, args } => {
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                let _ = run(&program, &refs);
            }
            Step::Ps {
                command,
                label,
                bucket,
            } => match run_ps(&command) {
                Ok(()) => bucket.record(&mut r, label),
                Err(e) => r.note(format!("{label}: {e}")),
            },
            Step::PsExec { command } => {
                let _ = run_ps(&command);
            }
            Step::Note(msg) => r.note(msg),
        }
    }
    r
}

// ==============================================================================================
// Public entry points + the OS dispatch.
// ==============================================================================================

/// Is `os` one this tool can configure OS resolution on?
fn is_supported(os: &str) -> bool {
    matches!(os, "linux" | "macos" | "windows")
}

/// Configure OS-level `*.<tld>` resolution (SPEC §15). Refuses without elevation. When
/// `browser_policy` is set it ALSO applies the Chrome/Edge managed DoH-off policy (opt-in — the
/// packages never pass it).
pub fn configure(config: &Config, browser_policy: bool) -> OsConfigReport {
    if !is_elevated() {
        return OsConfigReport::not_elevated("configure-os", &elevation_message());
    }
    let os = std::env::consts::OS;
    if !is_supported(os) {
        return OsConfigReport::unsupported("configure-os", os);
    }
    let ip = config.loopback_ip;
    // Detect the owning resolver live on Linux; it drives which drop-in gets written (and the
    // `resolver` field). Other OSes don't have this notion.
    let owner = if os == "linux" {
        detect_resolv_owner_live()
    } else {
        ResolvOwner::Unknown
    };
    let resolver = (os == "linux").then(|| owner.label().to_string());
    let steps = configure_resolver_steps(os, owner, ip, &config.tld);
    let mut r = execute("configure-os", ip, resolver, steps);
    // Whether we actually wired the OS resolver (an NRPT rule / resolver file / drop-in was
    // applied). On the Linux PAC-only path nothing is applied, so there is nothing to verify and no
    // reboot to prompt — browsers reach `*.dig` via Path B (the PAC). Capture BEFORE the browser
    // policy (which also records into `applied`).
    let wired = !r.applied.is_empty();
    if browser_policy {
        apply_browser_policy(os, ip, &mut r);
    }
    // Post-configure VERIFY: after applying + flushing, resolve a probe name through the OS
    // resolver and confirm it now routes to our loopback IP — reusing the doctor OS-routing oracle.
    let activated = wired && verify_os_routing(config);
    apply_activation_result(&mut r, os, wired, activated);
    r.ok = true;
    r
}

/// Record the activation outcome onto the report. PURE (unit-tested): `activated` is set as told;
/// `reboot_required` is set (with a per-OS reason) ONLY when resolver wiring was applied but the
/// verify did NOT confirm live resolution — the defensive fallback that prompts a restart.
fn apply_activation_result(r: &mut OsConfigReport, os: &str, wired: bool, activated: bool) {
    r.activated = activated;
    if wired && !activated {
        r.reboot_required = true;
        r.reboot_reason = Some(reboot_reason(os));
    }
}

/// The per-OS restart-prompt reason, used only when the post-activate verify fails. PURE.
fn reboot_reason(os: &str) -> String {
    let how = match os {
        "windows" => "the NRPT split-DNS rule",
        "macos" => "the /etc/resolver split-DNS config",
        "linux" => "the systemd-resolved/NetworkManager split-DNS config",
        _ => "the split-DNS config",
    };
    format!(
        "restart to activate .dig name resolution — the OS resolver has not yet picked up {how}"
    )
}

/// Resolve a probe `.<tld>` name through the OS resolver and evaluate it against the doctor
/// OS-routing oracle. `true` iff the OS now routes `*.<tld>` to our loopback IP LIVE. OS glue
/// (a real `getaddrinfo`), mirroring [`execute`]; the oracle it defers to is pure + unit-tested.
fn verify_os_routing(config: &Config) -> bool {
    use std::net::ToSocketAddrs;
    let host = format!("configure-probe.{}:0", config.tld);
    let resolved: Vec<std::net::IpAddr> = host
        .to_socket_addrs()
        .map(|it| it.map(|s| s.ip()).collect())
        .unwrap_or_default();
    crate::doctor::evaluate_os_routing(config.loopback_ip, &resolved).status
        == crate::doctor::CheckStatus::Pass
}

/// Reverse [`configure`]: remove the `*.<tld>` resolver wiring this tool OR the legacy installer
/// added (marker-scoped), plus any managed browser policy it wrote. Refuses without elevation.
pub fn unconfigure(config: &Config) -> OsConfigReport {
    if !is_elevated() {
        return OsConfigReport::not_elevated("unconfigure-os", &elevation_message());
    }
    let os = std::env::consts::OS;
    if !is_supported(os) {
        return OsConfigReport::unsupported("unconfigure-os", os);
    }
    let ip = config.loopback_ip;
    let steps = unconfigure_resolver_steps(os, ip, &config.tld);
    let mut r = execute("unconfigure-os", ip, None, steps);
    // Always attempt to remove any managed browser policy — it is marker-scoped (never touches an
    // org policy), so this cleanly migrates a machine the legacy installer put a policy on.
    remove_browser_policy(os, ip, &mut r);
    r.ok = true;
    note_if_nothing_removed(&mut r);
    r
}

/// Push a "nothing to remove" note when an unconfigure removed no artifacts. PURE.
fn note_if_nothing_removed(r: &mut OsConfigReport) {
    if r.removed.is_empty() {
        r.note("nothing to remove (no dig-dns OS resolver config found)".to_string());
    }
}

/// Whether this machine currently carries `configure-os` (or legacy) `*.<tld>` resolver wiring, for
/// the `doctor` OS-config check. `Some(true/false)` on Linux/macOS via a file check; `None` on
/// Windows (its NRPT state needs a PowerShell round-trip — `doctor`'s `os_routing` end-to-end
/// probe already covers Windows).
pub fn is_configured(config: &Config) -> Option<bool> {
    match std::env::consts::OS {
        "linux" => Some(
            file_is_ours(Path::new(LINUX_RESOLVED_DROPIN), config.loopback_ip)
                || file_is_ours(Path::new(LINUX_NM_DNSMASQ_CONF), config.loopback_ip),
        ),
        "macos" => Some(Path::new(&macos_resolver_path(&config.tld)).exists()),
        _ => None,
    }
}

// -- elevation ---------------------------------------------------------------------------------

/// Is this process privileged enough to edit the OS resolver? Windows: an elevated (Administrator)
/// token (probed via `net session`, which only an elevated token can run). Unix: root (`id -u`
/// = 0) — writing `/etc/resolver`, `/etc/systemd/resolved.conf.d`, or a LaunchDaemon all require
/// it (unlike the user-level SERVICE install in `service.rs`).
fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        Command::new(resolve_system_tool("net"))
            .arg("session")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        Command::new(resolve_system_tool("id"))
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }
}

/// The elevation-refusal message, per platform.
fn elevation_message() -> String {
    if cfg!(windows) {
        "configuring OS-level *.dig resolution requires an elevated (Administrator) console; \
         re-run in a terminal opened with \"Run as administrator\""
            .to_string()
    } else {
        "configuring OS-level *.dig resolution requires root; re-run with sudo".to_string()
    }
}

// -- small I/O helpers -------------------------------------------------------------------------

/// Write `content` to `path` only if it differs from what's already there (idempotent), creating
/// parent dirs as needed. `Ok(true)` iff a write happened.
///
/// The write itself is symlink-safe + atomic ([`atomic_write`], dig_ecosystem #650): every path
/// this runs against is a compiled-in root-owned `/etc/**` policy/resolver file, written as root,
/// so a temp-file-then-`rename` (which replaces a target symlink instead of following it) plus
/// `O_NOFOLLOW` on the temp create is the correct hardened pattern for a privileged writer — a
/// reader never observes a half-written file, and a pre-seeded symlink can never redirect the write.
fn write_if_changed(path: &Path, content: &str) -> Result<bool, String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == content {
            return Ok(false);
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    atomic_write(path, content)?;
    Ok(true)
}

/// Symlink-safe, atomic write of `content` to `path` (dig_ecosystem #650).
///
/// On Unix: write to a sibling temp file opened `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW` (so a planted
/// temp symlink cannot redirect the bytes and a stale temp is never silently reused), `fsync` it,
/// then `rename` it over `path`. `rename(2)` replaces a symlink AT the destination rather than
/// following it, so even if an attacker pre-seeded `path` as a symlink the final file lands where
/// intended, atomically. On non-Unix this is a plain `fs::write` (no elevated `/etc` writer exists
/// there — the Windows path wires the resolver via NRPT/registry, not file writes).
fn atomic_write(path: &Path, content: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let parent = path
            .parent()
            .ok_or_else(|| format!("{}: no parent directory", path.display()))?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{}: no file name", path.display()))?;
        let tmp = parent.join(format!(".{file_name}.dig-dns.{}.tmp", std::process::id()));

        // O_EXCL: fail rather than reuse/follow a pre-existing temp. O_NOFOLLOW: never open through
        // a symlink at the temp path. 0o644 mirrors a normal /etc policy file's mode.
        let open = || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o644)
                .open(&tmp)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
            Ok(())
        };
        open().map_err(|e| format!("write {}: {e}", tmp.display()))?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("install {}: {e}", path.display()));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
    }
}

/// Does `path` hold content this tool (or the legacy installer) owns? A missing/unreadable file
/// is `false`.
fn file_is_ours(path: &Path, our_ip: Ipv4Addr) -> bool {
    std::fs::read_to_string(path)
        .map(|c| content_is_ours(&c, our_ip))
        .unwrap_or(false)
}

/// Remove `path` only if [`file_is_ours`]. `Ok(true)` iff a file was removed.
fn remove_if_ours(path: &Path, our_ip: Ipv4Addr) -> Result<bool, String> {
    if file_is_ours(path, our_ip) {
        std::fs::remove_file(path).map_err(|e| format!("remove {}: {e}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Run `cmd args…` by its ABSOLUTE path, discarding output. `Ok(())` iff it exits 0.
///
/// The bare tool name is resolved to a trusted absolute path ([`resolve_system_tool`]) BEFORE
/// spawning — this whole module runs elevated, so a bare-name lookup would let a `PATH`-planted
/// binary hijack the privileged process (dig_ecosystem #565/#657).
fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(resolve_system_tool(cmd))
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn {cmd}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd} exited non-zero"))
    }
}

/// Run a PowerShell command line by PowerShell's ABSOLUTE path, discarding stdout. `Ok(())` iff
/// PowerShell exits 0. Absolute-pathed for the same anti-hijack reason as [`run`].
fn run_ps(command: &str) -> Result<(), String> {
    let status = Command::new(resolve_system_tool("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .status()
        .map_err(|e| format!("spawn powershell: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("powershell exited non-zero".to_string())
    }
}

/// Run `reg <args…>`, discarding output. `Ok(())` iff it exits 0.
fn reg(args: &[String]) -> Result<(), String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run("reg", &refs)
}

/// Does `reg <query-args>` exit 0 (the key/value exists)?
fn reg_present(args: &[String]) -> bool {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run("reg", &refs).is_ok()
}

// ==============================================================================================
// Live environment probe.
// ==============================================================================================

/// Read the live `/etc/resolv.conf` symlink target + NM-dnsmasq dir to decide the resolver owner.
fn detect_resolv_owner_live() -> ResolvOwner {
    let link_target = std::fs::read_link("/etc/resolv.conf")
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let nm_dir = Path::new("/etc/NetworkManager/dnsmasq.d").is_dir();
    detect_resolv_owner(link_target.as_deref(), nm_dir)
}

// ==============================================================================================
// Browser managed-DoH policy (opt-in, `--browser-policy`). Kept OFF the resolver-wiring plan (and
// never applied by the packages) because a Windows/macOS org-policy check needs runtime "is a
// non-ours policy already here?" logic the pure plan cannot express.
// ==============================================================================================

/// Apply the Chrome/Edge managed DoH-off policy for `os`, best-effort, never clobbering an existing
/// org/MDM policy. Successes are recorded in the report's `applied`.
fn apply_browser_policy(os: &str, our_ip: Ipv4Addr, r: &mut OsConfigReport) {
    match os {
        "linux" => {
            for path in [LINUX_CHROME_POLICY, LINUX_CHROMIUM_POLICY] {
                match write_if_changed(Path::new(path), &chrome_policy_json()) {
                    Ok(_) => r.applied.push(path.to_string()),
                    Err(e) => r.note(format!("{path} not written: {e}")),
                }
            }
            r.note("Chrome/Chromium managed DoH-off policy applied".to_string());
        }
        "macos" => apply_macos_browser_policy(our_ip, r),
        "windows" => {
            for (browser, key) in [
                ("Chrome", WIN_CHROME_POLICY_KEY),
                ("Edge", WIN_EDGE_POLICY_KEY),
            ] {
                match apply_windows_browser_policy(key) {
                    Ok(true) => r.applied.push(format!("{browser} HKLM DoH policy")),
                    Ok(false) => r.note(format!(
                        "{browser} policy left untouched (an existing org policy manages it)"
                    )),
                    Err(e) => r.note(format!("{browser} policy not applied: {e}")),
                }
            }
        }
        _ => {}
    }
}

/// Remove any managed DoH policy this tool — or the legacy installer — wrote for `os` (marker-
/// scoped; never an org policy). Successes are recorded in `removed`.
fn remove_browser_policy(os: &str, our_ip: Ipv4Addr, r: &mut OsConfigReport) {
    match os {
        "linux" => {
            // Uniquely-named files this tool solely owns — safe to remove on sight (migrates a
            // legacy-installer machine too).
            for path in [LINUX_CHROME_POLICY, LINUX_CHROMIUM_POLICY] {
                if Path::new(path).exists() && std::fs::remove_file(path).is_ok() {
                    r.removed.push(path.to_string());
                }
            }
        }
        "macos" => {
            if let Ok(true) = remove_if_ours(Path::new(MACOS_CHROME_PLIST), our_ip) {
                r.removed.push(MACOS_CHROME_PLIST.to_string());
            }
        }
        "windows" => {
            for (browser, key) in [
                ("Chrome", WIN_CHROME_POLICY_KEY),
                ("Edge", WIN_EDGE_POLICY_KEY),
            ] {
                if let Ok(true) = remove_windows_browser_policy(key) {
                    r.removed.push(format!("{browser} HKLM DoH policy"));
                }
            }
        }
        _ => {}
    }
}

/// Is there an existing (non-ours) Chrome managed policy under `/Library/Managed Preferences`?
/// Scans plist filenames + per-user subdirs for `com.google.Chrome`, so this tool never clobbers
/// an MDM-provisioned policy.
fn existing_chrome_managed_policy(our_ip: Ipv4Addr) -> bool {
    let Ok(entries) = std::fs::read_dir(MACOS_MANAGED_PREFS_DIR) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().contains("com.google.Chrome")
            && !file_is_ours(&entry.path(), our_ip)
        {
            return true;
        }
        if entry.path().is_dir() {
            let nested = entry.path().join("com.google.Chrome.plist");
            if nested.exists() && !file_is_ours(&nested, our_ip) {
                return true;
            }
        }
    }
    false
}

fn apply_macos_browser_policy(our_ip: Ipv4Addr, r: &mut OsConfigReport) {
    if existing_chrome_managed_policy(our_ip) {
        r.note("Chrome policy left untouched (an existing managed policy was found)".to_string());
        return;
    }
    match write_if_changed(Path::new(MACOS_CHROME_PLIST), &chrome_managed_plist()) {
        Ok(_) => r.applied.push(MACOS_CHROME_PLIST.to_string()),
        Err(e) => r.note(format!("Chrome managed policy not written: {e}")),
    }
    r.note(
        "Chrome enterprise policy on macOS is normally MDM-provisioned; if the DoH-off policy does \
         not take effect, set it via MDM (see the runbook)"
            .to_string(),
    );
}

// ==============================================================================================
// Windows registry browser-policy helpers (used by `apply`/`remove_browser_policy`).
// ==============================================================================================

/// Apply the DoH-off policy under `HKLM\<key>`, UNLESS the key already exists WITHOUT this tool's
/// (or the legacy installer's) marker — that is an org policy, left alone. `Ok(true)` iff applied.
fn apply_windows_browser_policy(key: &str) -> Result<bool, String> {
    let key_exists = reg_present(&reg_query_key_args(key));
    let ours = reg_present(&reg_query_value_args(key, WIN_POLICY_MARKER))
        || reg_present(&reg_query_value_args(key, WIN_LEGACY_POLICY_MARKER));
    if key_exists && !ours {
        return Ok(false);
    }
    for cmd in reg_add_policy_args(key) {
        reg(&cmd)?;
    }
    Ok(true)
}

/// Remove ONLY the values this tool / the legacy installer wrote under `HKLM\<key>` (never the
/// key itself — an org may share it). `Ok(true)` iff our marker was present + values removed.
fn remove_windows_browser_policy(key: &str) -> Result<bool, String> {
    let ours = reg_present(&reg_query_value_args(key, WIN_POLICY_MARKER))
        || reg_present(&reg_query_value_args(key, WIN_LEGACY_POLICY_MARKER));
    if !ours {
        return Ok(false);
    }
    for value in [
        WIN_POLICY_DOH_NAME,
        WIN_POLICY_BUILTIN_NAME,
        WIN_POLICY_MARKER,
        WIN_LEGACY_POLICY_MARKER,
    ] {
        let _ = reg(&reg_delete_value_args(key, value));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);

    fn tmp_subdir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("dig-dns-os-config-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // -- resolver content builders -------------------------------------------------------------

    #[test]
    fn systemd_resolved_dropin_routes_the_tld_domain() {
        let d = systemd_resolved_dropin(IP, "dig");
        assert!(d.contains("[Resolve]"), "{d}");
        assert!(d.contains("DNS=127.0.0.5"), "{d}");
        assert!(d.contains("Domains=~dig"), "{d}");
        assert!(d.contains(MARKER), "must be marker-tagged: {d}");
    }

    #[test]
    fn systemd_resolved_dropin_honours_a_custom_tld() {
        let d = systemd_resolved_dropin(IP, "web3");
        assert!(d.contains("Domains=~web3"), "{d}");
    }

    #[test]
    fn networkmanager_dnsmasq_conf_routes_the_tld_domain() {
        let c = networkmanager_dnsmasq_conf(IP, "dig");
        assert!(c.contains("server=/dig/127.0.0.5"), "{c}");
        assert!(c.contains(MARKER), "{c}");
    }

    #[test]
    fn resolver_file_content_is_a_marked_nameserver_line() {
        let c = resolver_file_content(IP);
        assert!(c.contains("nameserver 127.0.0.5"), "{c}");
        assert!(c.contains(MARKER), "{c}");
    }

    #[test]
    fn nrpt_add_command_is_idempotent_and_tagged() {
        let cmd = nrpt_add_ps_command(IP, "dig");
        assert!(cmd.contains("Add-DnsClientNrptRule"), "{cmd}");
        assert!(cmd.contains("-Namespace '.dig'"), "{cmd}");
        assert!(cmd.contains("-NameServers '127.0.0.5'"), "{cmd}");
        assert!(cmd.contains(MARKER), "{cmd}");
        assert!(
            cmd.contains("if (-not (Get-DnsClientNrptRule"),
            "must guard re-adding: {cmd}"
        );
    }

    #[test]
    fn nrpt_add_command_honours_a_custom_tld() {
        let cmd = nrpt_add_ps_command(IP, "web3");
        assert!(cmd.contains("-Namespace '.web3'"), "{cmd}");
    }

    #[test]
    fn nrpt_remove_command_targets_our_marker_and_the_legacy_marker() {
        let cmd = nrpt_remove_ps_command();
        assert!(cmd.contains(&format!("$_.Comment -eq '{MARKER}'")), "{cmd}");
        assert!(
            cmd.contains(&format!("$_.Comment -eq '{LEGACY_INSTALLER_MARKER}'")),
            "must also clean the legacy installer's rules: {cmd}"
        );
        assert!(cmd.contains("Remove-DnsClientNrptRule -Force"), "{cmd}");
    }

    #[test]
    fn launchd_lo0_alias_plist_is_a_one_shot_boot_task() {
        let p = launchd_lo0_alias_plist(IP);
        assert!(
            p.contains(&format!("<string>{MACOS_LO0_LABEL}</string>")),
            "{p}"
        );
        assert!(p.contains("<string>/sbin/ifconfig</string>"), "{p}");
        assert!(p.contains("<string>127.0.0.5</string>"), "{p}");
        assert!(p.contains("<key>RunAtLoad</key>\n\t<true/>"), "{p}");
        assert!(p.contains("<key>KeepAlive</key>\n\t<false/>"), "{p}");
        assert!(p.contains(MARKER), "{p}");
    }

    #[test]
    fn chrome_policy_json_disables_doh_and_builtin_resolver() {
        let v: serde_json::Value = serde_json::from_str(&chrome_policy_json()).unwrap();
        assert_eq!(v["DnsOverHttpsMode"], "off");
        assert_eq!(v["BuiltInDnsClientEnabled"], false);
    }

    #[test]
    fn chrome_managed_plist_disables_doh_and_is_tagged() {
        let p = chrome_managed_plist();
        assert!(p.contains("DnsOverHttpsMode"), "{p}");
        assert!(p.contains("<string>off</string>"), "{p}");
        assert!(p.contains("BuiltInDnsClientEnabled"), "{p}");
        assert!(p.contains(MARKER), "{p}");
    }

    // -- Windows registry argv builders --------------------------------------------------------

    #[test]
    fn reg_query_args_address_the_hklm_key_and_value() {
        assert_eq!(
            reg_query_key_args(WIN_CHROME_POLICY_KEY),
            vec![
                "query".to_string(),
                r"HKLM\SOFTWARE\Policies\Google\Chrome".to_string()
            ]
        );
        assert_eq!(
            reg_query_value_args(WIN_EDGE_POLICY_KEY, WIN_POLICY_MARKER),
            vec![
                "query".to_string(),
                r"HKLM\SOFTWARE\Policies\Microsoft\Edge".to_string(),
                "/v".to_string(),
                "DigDnsManaged".to_string(),
            ]
        );
    }

    #[test]
    fn reg_add_policy_args_write_doh_off_builtin_off_and_marker() {
        let cmds = reg_add_policy_args(WIN_CHROME_POLICY_KEY);
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].contains(&"DnsOverHttpsMode".to_string()));
        assert!(cmds[0].contains(&"off".to_string()));
        assert!(cmds[1].contains(&"BuiltInDnsClientEnabled".to_string()));
        assert!(cmds[1].contains(&"REG_DWORD".to_string()));
        assert!(cmds[2].contains(&"DigDnsManaged".to_string()));
        // Every command targets the Chrome policy key and forces the write.
        for c in &cmds {
            assert_eq!(c[0], "add");
            assert_eq!(c[1], r"HKLM\SOFTWARE\Policies\Google\Chrome");
            assert!(c.contains(&"/f".to_string()));
        }
    }

    #[test]
    fn reg_delete_value_args_force_delete_the_named_value() {
        assert_eq!(
            reg_delete_value_args(WIN_CHROME_POLICY_KEY, WIN_POLICY_DOH_NAME),
            vec![
                "delete".to_string(),
                r"HKLM\SOFTWARE\Policies\Google\Chrome".to_string(),
                "/v".to_string(),
                "DnsOverHttpsMode".to_string(),
                "/f".to_string(),
            ]
        );
    }

    // -- resolver-owner detection --------------------------------------------------------------

    #[test]
    fn detects_systemd_resolved_from_the_symlink_target() {
        assert_eq!(
            detect_resolv_owner(Some("/run/systemd/resolve/stub-resolv.conf"), false),
            ResolvOwner::SystemdResolved
        );
        assert_eq!(
            detect_resolv_owner(Some("../run/systemd/resolve/resolv.conf"), true),
            ResolvOwner::SystemdResolved,
            "systemd-resolved wins even when the NM dnsmasq dir also exists"
        );
    }

    #[test]
    fn detects_networkmanager_dnsmasq_when_no_systemd_symlink() {
        assert_eq!(
            detect_resolv_owner(None, true),
            ResolvOwner::NetworkManagerDnsmasq
        );
        assert_eq!(
            detect_resolv_owner(Some("/etc/some-other-target"), true),
            ResolvOwner::NetworkManagerDnsmasq
        );
    }

    #[test]
    fn detects_unknown_for_a_plain_resolv_conf() {
        assert_eq!(detect_resolv_owner(None, false), ResolvOwner::Unknown);
    }

    #[test]
    fn resolv_owner_labels_are_stable() {
        assert_eq!(ResolvOwner::SystemdResolved.label(), "systemd-resolved");
        assert_eq!(
            ResolvOwner::NetworkManagerDnsmasq.label(),
            "networkmanager-dnsmasq"
        );
        assert_eq!(ResolvOwner::Unknown.label(), "unknown");
    }

    // -- marker ownership ----------------------------------------------------------------------

    #[test]
    fn content_is_ours_recognises_our_marker() {
        assert!(content_is_ours(&systemd_resolved_dropin(IP, "dig"), IP));
    }

    #[test]
    fn content_is_ours_recognises_the_legacy_installer_marker() {
        let legacy =
            format!("# {LEGACY_INSTALLER_MARKER}\n[Resolve]\nDNS=127.0.0.5\nDomains=~dig\n");
        assert!(content_is_ours(&legacy, IP));
    }

    #[test]
    fn content_is_ours_recognises_the_legacy_unmarked_resolver_line() {
        // The old installer wrote /etc/resolver/dig as a bare nameserver line (no marker).
        assert!(content_is_ours("nameserver 127.0.0.5\n", IP));
        assert!(content_is_ours("  nameserver 127.0.0.5  ", IP));
    }

    #[test]
    fn content_is_ours_rejects_a_foreign_file() {
        assert!(!content_is_ours("nameserver 1.1.1.1\n", IP));
        assert!(!content_is_ours(
            "# someone else's config\nDNS=9.9.9.9\n",
            IP
        ));
        // A bare nameserver line for a DIFFERENT ip is not ours.
        assert!(!content_is_ours("nameserver 127.0.0.9\n", IP));
    }

    // -- file helpers --------------------------------------------------------------------------

    #[test]
    fn write_if_changed_is_idempotent() {
        let dir = tmp_subdir("write-changed");
        let p = dir.join("dig.conf");
        assert!(write_if_changed(&p, "a\n").unwrap());
        assert!(!write_if_changed(&p, "a\n").unwrap());
        assert!(write_if_changed(&p, "b\n").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_replaces_a_symlink_target_instead_of_following_it() {
        // dig_ecosystem #650: if the target path is (or is pre-seeded as) a symlink, the hardened
        // writer must NOT write through it to the link's target — the `rename` must replace the
        // symlink itself, leaving the pointed-at file untouched.
        use std::os::unix::fs::symlink;
        let dir = tmp_subdir("atomic-symlink");
        let victim = dir.join("victim.conf");
        std::fs::write(&victim, "ORIGINAL-VICTIM\n").unwrap();
        let target = dir.join("dig.conf");
        symlink(&victim, &target).unwrap(); // target -> victim (the classic redirect attack)

        assert!(write_if_changed(&target, "DIG-CONTENT\n").unwrap());

        // The victim the symlink pointed at is untouched…
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ORIGINAL-VICTIM\n"
        );
        // …and the target is now a REAL file with our content, no longer a symlink.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "DIG-CONTENT\n");
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_leaves_no_temp_files_behind() {
        // The temp file must be renamed away (or cleaned on failure) — a successful write leaves
        // exactly the one target file in the directory.
        let dir = tmp_subdir("atomic-clean");
        let p = dir.join("dig.conf");
        assert!(write_if_changed(&p, "x\n").unwrap());
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "only the target should remain: {entries:?}"
        );
        assert_eq!(entries[0], std::ffi::OsStr::new("dig.conf"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_if_ours_only_deletes_marked_or_legacy_files() {
        let dir = tmp_subdir("remove-ours");
        let ours = dir.join("ours.conf");
        std::fs::write(&ours, systemd_resolved_dropin(IP, "dig")).unwrap();
        let legacy = dir.join("legacy.conf");
        std::fs::write(
            &legacy,
            format!("# {LEGACY_INSTALLER_MARKER}\nDNS=127.0.0.5\n"),
        )
        .unwrap();
        let foreign = dir.join("foreign.conf");
        std::fs::write(&foreign, "DNS=1.1.1.1\n").unwrap();

        assert!(remove_if_ours(&ours, IP).unwrap());
        assert!(!ours.exists());
        assert!(remove_if_ours(&legacy, IP).unwrap());
        assert!(!legacy.exists());
        assert!(!remove_if_ours(&foreign, IP).unwrap());
        assert!(foreign.exists());
        // Missing file → no-op, not an error.
        assert!(!remove_if_ours(&dir.join("absent.conf"), IP).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- report shape --------------------------------------------------------------------------

    #[test]
    fn not_elevated_report_is_a_stable_machine_signal() {
        let r = OsConfigReport::not_elevated("configure-os", "need root");
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["needs_elevation"], true);
        assert_eq!(v["ok"], false);
        assert_eq!(v["action"], "configure-os");
        assert!(r.summary().contains("need root"));
    }

    #[test]
    fn unsupported_report_names_the_platform() {
        let r = OsConfigReport::unsupported("configure-os", "freebsd");
        assert!(!r.ok);
        assert!(r.notes[0].contains("freebsd"));
    }

    #[test]
    fn report_json_has_stable_fields() {
        let mut r = OsConfigReport::started("configure-os");
        r.resolver = Some("systemd-resolved".to_string());
        r.applied.push(LINUX_RESOLVED_DROPIN.to_string());
        r.ok = true;
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["action"], "configure-os");
        assert_eq!(v["ok"], true);
        assert_eq!(v["resolver"], "systemd-resolved");
        assert!(v["applied"]
            .as_array()
            .unwrap()
            .contains(&json!(LINUX_RESOLVED_DROPIN)));
        // needs_elevation is always present (stable agent contract).
        assert_eq!(v["needs_elevation"], false);
    }

    #[test]
    fn note_if_nothing_removed_only_notes_on_an_empty_removal() {
        let mut empty = OsConfigReport::started("unconfigure-os");
        note_if_nothing_removed(&mut empty);
        assert!(empty.notes.iter().any(|n| n.contains("nothing to remove")));

        let mut did_remove = OsConfigReport::started("unconfigure-os");
        did_remove.removed.push("x".to_string());
        note_if_nothing_removed(&mut did_remove);
        assert!(!did_remove
            .notes
            .iter()
            .any(|n| n.contains("nothing to remove")));
    }

    // -- the per-OS resolver-wiring PLANS (pure; the orchestration under test) -----------------

    #[test]
    fn linux_systemd_resolved_plan_writes_the_dropin_then_reloads_and_flushes() {
        let steps = configure_resolver_steps("linux", ResolvOwner::SystemdResolved, IP, "dig");
        assert!(matches!(
            &steps[0],
            Step::Write { path, content }
                if path == LINUX_RESOLVED_DROPIN && content.contains("Domains=~dig")
        ));
        assert!(steps
            .iter()
            .any(|s| matches!(s, Step::Exec { program, args }
                if program == "systemctl" && args == &["reload-or-restart", "systemd-resolved"])));
        assert!(steps
            .iter()
            .any(|s| matches!(s, Step::Exec { program, .. } if program == "resolvectl")));
    }

    #[test]
    fn linux_networkmanager_plan_writes_the_dnsmasq_dropin() {
        let steps =
            configure_resolver_steps("linux", ResolvOwner::NetworkManagerDnsmasq, IP, "dig");
        assert!(matches!(
            &steps[0],
            Step::Write { path, content }
                if path == LINUX_NM_DNSMASQ_CONF && content.contains("server=/dig/127.0.0.5")
        ));
        assert!(steps
            .iter()
            .any(|s| matches!(s, Step::Exec { program, .. } if program == "systemctl")));
    }

    #[test]
    fn linux_unknown_resolver_plan_is_a_single_note() {
        let steps = configure_resolver_steps("linux", ResolvOwner::Unknown, IP, "dig");
        assert_eq!(steps.len(), 1);
        assert!(matches!(&steps[0], Step::Note(msg) if msg.contains("PAC")));
    }

    #[test]
    fn macos_plan_aliases_lo0_writes_the_boot_daemon_and_resolver_file_then_flushes() {
        let steps = configure_resolver_steps("macos", ResolvOwner::Unknown, IP, "dig");
        // The lo0 alias comes FIRST (functional prerequisite).
        assert!(matches!(&steps[0], Step::Exec { program, args }
            if program == "ifconfig" && args == &["lo0", "alias", "127.0.0.5", "up"]));
        // Both the boot-persistent plist and the per-TLD resolver file are written.
        assert!(steps
            .iter()
            .any(|s| matches!(s, Step::Write { path, .. } if path == MACOS_LO0_PLIST)));
        assert!(steps
            .iter()
            .any(|s| matches!(s, Step::Write { path, .. } if path == "/etc/resolver/dig")));
        // launchctl bootstrap + a DNS-cache flush are present.
        assert!(steps
            .iter()
            .any(|s| matches!(s, Step::Exec { program, args }
            if program == "launchctl" && args.first().map(String::as_str) == Some("bootstrap"))));
        assert!(steps
            .iter()
            .any(|s| matches!(s, Step::Exec { program, .. } if program == "dscacheutil")));
    }

    #[test]
    fn windows_plan_is_the_nrpt_add_then_a_cache_flush() {
        let steps = configure_resolver_steps("windows", ResolvOwner::Unknown, IP, "dig");
        // The NRPT add (recorded as applied) FOLLOWED BY the DNS-cache flush that makes it live
        // without a reboot (dig_ecosystem #627).
        assert_eq!(steps.len(), 2);
        assert!(matches!(&steps[0], Step::Ps { command, label, bucket }
            if command.contains("Add-DnsClientNrptRule")
                && label == ".dig NRPT rule"
                && *bucket == Bucket::Applied));
        assert!(matches!(&steps[1], Step::PsExec { command }
            if command == CLEAR_DNS_CLIENT_CACHE));
    }

    #[test]
    fn windows_unconfigure_flushes_the_cache_after_removing_the_rule() {
        let win = unconfigure_resolver_steps("windows", IP, "dig");
        assert!(win
            .iter()
            .any(|s| matches!(s, Step::PsExec { command } if command == CLEAR_DNS_CLIENT_CACHE)));
    }

    #[test]
    fn reboot_is_required_only_when_wired_but_verify_failed() {
        // Applied resolver wiring + verify PASSED -> live, no reboot.
        let mut live = OsConfigReport::started("configure-os");
        apply_activation_result(&mut live, "windows", true, true);
        assert!(live.activated);
        assert!(!live.reboot_required);
        assert!(live.reboot_reason.is_none());

        // Applied wiring + verify FAILED -> defensive reboot prompt with a per-OS reason.
        let mut stale = OsConfigReport::started("configure-os");
        apply_activation_result(&mut stale, "windows", true, false);
        assert!(!stale.activated);
        assert!(stale.reboot_required);
        assert!(stale.reboot_reason.unwrap().contains("NRPT"));

        // Nothing wired (Linux PAC-only path) -> not activated, but NO reboot prompt.
        let mut pac = OsConfigReport::started("configure-os");
        apply_activation_result(&mut pac, "linux", false, false);
        assert!(!pac.activated);
        assert!(!pac.reboot_required);
        assert!(pac.reboot_reason.is_none());
    }

    #[test]
    fn reboot_reason_names_the_per_os_mechanism() {
        assert!(reboot_reason("windows").contains("NRPT"));
        assert!(reboot_reason("macos").contains("/etc/resolver"));
        assert!(reboot_reason("linux").contains("systemd-resolved"));
        assert!(reboot_reason("freebsd").contains("split-DNS"));
    }

    #[test]
    fn summary_surfaces_the_activation_and_reboot_lines() {
        let mut live = OsConfigReport::started("configure-os");
        live.ok = true;
        live.activated = true;
        assert!(live.summary().contains("LIVE now"));

        let mut stale = OsConfigReport::started("configure-os");
        stale.ok = true;
        stale.reboot_required = true;
        stale.reboot_reason = Some("restart to activate .dig".to_string());
        assert!(stale.summary().contains("RESTART REQUIRED"));
    }

    #[test]
    fn report_json_carries_the_stable_activation_fields() {
        let mut r = OsConfigReport::started("configure-os");
        r.activated = true;
        let json = r.to_json();
        assert!(json.contains("\"activated\":true"));
        assert!(json.contains("\"reboot_required\":false"));
        // reboot_reason is omitted when None (skip_serializing_if).
        assert!(!json.contains("reboot_reason"));
    }

    // The trusted system-tool resolver itself is tested in `crate::system_tool` (dig_ecosystem
    // #657); os_config only consumes it via `resolve_system_tool`.

    #[test]
    fn unconfigure_plans_remove_and_record_into_the_removed_bucket() {
        let linux = unconfigure_resolver_steps("linux", IP, "dig");
        assert!(linux
            .iter()
            .any(|s| matches!(s, Step::RemoveOurs { path } if path == LINUX_RESOLVED_DROPIN)));
        let win = unconfigure_resolver_steps("windows", IP, "dig");
        assert!(matches!(&win[0], Step::Ps { command, bucket, .. }
            if command.contains("Remove-DnsClientNrptRule") && *bucket == Bucket::Removed));
        let mac = unconfigure_resolver_steps("macos", IP, "dig");
        assert!(mac
            .iter()
            .any(|s| matches!(s, Step::RemoveOurs { path } if path == "/etc/resolver/dig")));
    }

    #[test]
    fn unsupported_os_plans_are_empty() {
        assert!(configure_resolver_steps("freebsd", ResolvOwner::Unknown, IP, "dig").is_empty());
        assert!(unconfigure_resolver_steps("freebsd", IP, "dig").is_empty());
        assert!(!is_supported("freebsd"));
        assert!(is_supported("linux") && is_supported("macos") && is_supported("windows"));
    }

    // -- the executor (I/O + report assembly) --------------------------------------------------

    #[test]
    fn execute_writes_removes_notes_and_ignores_a_failed_exec() {
        let dir = tmp_subdir("execute");
        let write_path = dir.join("written.conf");
        let remove_path = dir.join("ours.conf");
        std::fs::write(&remove_path, systemd_resolved_dropin(IP, "dig")).unwrap();
        let keep_path = dir.join("foreign.conf");
        std::fs::write(&keep_path, "nameserver 1.1.1.1\n").unwrap();

        let steps = vec![
            Step::Write {
                path: write_path.to_string_lossy().into_owned(),
                content: "hello\n".to_string(),
            },
            Step::RemoveOurs {
                path: remove_path.to_string_lossy().into_owned(),
            },
            Step::RemoveOurs {
                path: keep_path.to_string_lossy().into_owned(),
            },
            // A command that cannot spawn — its failure is swallowed (best-effort side effect).
            exec("dig-dns-definitely-not-a-real-command-xyz", &["x"]),
            Step::Note("a caveat".to_string()),
        ];
        let r = execute(
            "configure-os",
            IP,
            Some("systemd-resolved".to_string()),
            steps,
        );

        assert!(r.applied.iter().any(|a| a.ends_with("written.conf")));
        assert_eq!(r.resolver.as_deref(), Some("systemd-resolved"));
        assert_eq!(std::fs::read_to_string(&write_path).unwrap(), "hello\n");
        assert!(r.removed.iter().any(|a| a.ends_with("ours.conf")));
        assert!(!remove_path.exists());
        assert!(
            !r.removed.iter().any(|a| a.ends_with("foreign.conf")),
            "a foreign file is never removed or recorded"
        );
        assert!(keep_path.exists());
        assert!(r.notes.iter().any(|n| n == "a caveat"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn macos_resolver_path_is_named_for_the_tld() {
        assert_eq!(macos_resolver_path("dig"), "/etc/resolver/dig");
        assert_eq!(macos_resolver_path("web3"), "/etc/resolver/web3");
    }

    #[test]
    fn markers_are_the_canonical_strings() {
        assert_eq!(MARKER, "managed by dig-dns configure-os");
        assert_eq!(
            LEGACY_INSTALLER_MARKER,
            "managed by dig-installer (dig-dns, task #177)"
        );
    }
}
