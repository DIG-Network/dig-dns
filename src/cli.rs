//! The `dig-dns` command surface.
//!
//! Every command has a pretty (human) output and a `--json` (machine) output, per the
//! agent-friendly baseline (CLAUDE.md §6.2). The pure command logic lives in [`execute`]
//! (returning the stdout text or an error string) so it is unit-tested without touching
//! the process environment or exit codes; [`run`] is the thin `main` glue that parses
//! argv, prints, and maps to an exit code.
//!
//! `label` (the base32 codec) + `config` (introspect the resolved configuration) are pure and
//! run through [`execute`]. `serve` (run the HTTP gateway) and `fetch` (one-shot resolve a
//! `.dig` resource) are async and dispatched directly in [`run`] on a tokio runtime. `doctor`
//! and `pac` are added in their phases.

use std::io::Write;

use clap::{Parser, Subcommand};
use serde_json::json;

use crate::{config, label};

/// `dig-dns` — local `*.dig` name resolution.
#[derive(Debug, Parser)]
#[command(
    name = "dig-dns",
    version,
    about = "Local *.dig name resolution: a DNS responder + HTTP gateway resolving <storeId>.dig via a dig-node."
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encode/decode the base32 `.dig` DNS label for a store id.
    Label {
        /// The label operation.
        #[command(subcommand)]
        action: LabelAction,
    },
    /// Print the resolved configuration (defaults layered with environment overrides).
    Config {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Run the resolver service on the loopback IP: the HTTP gateway (`:80`, fallback `:8053`)
    /// AND the DNS responder (`:53`, best-effort). Serves `.dig` content from a dig-node; runs
    /// until Ctrl-C.
    Serve {
        /// Explicit dig-node endpoint (highest precedence; else the §5.3 ladder
        /// dig.local → localhost:9778 → rpc.dig.net).
        #[arg(long, value_name = "URL")]
        node: Option<String>,
    },
    /// Internal: the Windows-service entrypoint (speaks the SCM service protocol). Installed by
    /// `install` on Windows; not meant to be run by hand. On non-Windows it behaves like `serve`.
    #[command(hide = true)]
    RunService,
    /// Register `dig-dns` as an auto-starting OS service (id `net.dignetwork.dig-dns`, display
    /// "DIG NETWORK: DNS"). If the service already exists it is cleanly recreated
    /// (stop → delete → recreate), never reconfigured in place — so a re-run never hits
    /// `CreateService 1073`. Windows requires an elevated (Administrator) console.
    Install {
        /// Explicit dig-node endpoint baked into the service (else it resolves the §5.3 ladder).
        #[arg(long, value_name = "URL")]
        node: Option<String>,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Remove the `dig-dns` OS service (stops it first). Windows requires elevation.
    Uninstall {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Start the installed `dig-dns` service.
    Start {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Stop the running `dig-dns` service.
    Stop {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Report whether the resolver is serving (probes the gateway) + whether it is registered.
    /// Exits non-zero when nothing is serving.
    Status {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Query the running service's machine-readable health (the same object the gateway serves at
    /// `GET /.dig/health`: version, bound port, listeners, node reachability). Exits non-zero when
    /// nothing is serving. The CLI counterpart of the HTTP control endpoint (§6.2 parity).
    Health {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Resolve a single `.dig` resource through the gateway pipeline and print it. Accepts a
    /// bare host (`<label>.dig`), a `host/path`, or a full `http://<label>.dig/path` URL.
    Fetch {
        /// The `.dig` host or full URL to resolve.
        target: String,
        /// The resource path (used only when `target` is a bare host). Defaults to `/`.
        #[arg(default_value = "/")]
        path: String,
        /// Explicit dig-node endpoint (highest precedence; else the §5.3 ladder).
        #[arg(long, value_name = "URL")]
        node: Option<String>,
        /// Emit JSON metadata (status, content-type, length, node) instead of the raw body.
        #[arg(long)]
        json: bool,
    },
    /// Diagnose each link of both resolution paths (DNS + gateway) with fix hints. Exits
    /// non-zero when a `.dig` URL cannot load.
    Doctor {
        /// Emit the report as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Configure this machine's DNS resolver so `*.<tld>` names resolve to the local dig-dns
    /// responder SYSTEM-WIDE (an explicit admin action, distinct from the serve runtime which
    /// never touches the resolver). Per OS: systemd-resolved/NetworkManager-dnsmasq split-DNS
    /// (Linux), `/etc/resolver/<tld>` + a boot-persistent `lo0` alias (macOS), an NRPT rule
    /// (Windows). Idempotent + marker-scoped; needs elevation (root / Administrator).
    ConfigureOs {
        /// ALSO set a Chrome/Edge managed policy turning DNS-over-HTTPS off, so those browsers
        /// honour the OS resolver. Off by default — the native packages never pass it; only an
        /// explicit admin opts a machine's browsers into a managed policy (Path B / the PAC
        /// otherwise covers Secure-DNS browsers).
        #[arg(long)]
        browser_policy: bool,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Reverse `configure-os`: remove the `*.<tld>` resolver wiring this tool — OR the legacy
    /// dig-installer — added (marker-scoped; never touches an unmarked rule or an org policy),
    /// plus any managed browser policy it wrote. Needs elevation.
    UnconfigureOs {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Generate the PAC file (Path B) routing `*.<tld>` through the gateway. Uses the actual
    /// bound port: `--port` if given, else the running gateway's port, else the configured port.
    Pac {
        /// Force a specific gateway port instead of probing the running gateway.
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,
        /// Emit JSON metadata (loopback_ip, port, tld, pac) instead of the raw PAC text.
        #[arg(long)]
        json: bool,
    },
}

/// `dig-dns label …` operations.
#[derive(Debug, Subcommand)]
pub enum LabelAction {
    /// Encode a 64-hex store id to its `<label>.<tld>` browsable host.
    Encode {
        /// The 64-lowercase-hex store id.
        store_hex: String,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Decode a `.dig` label (or a full `<label>.dig` host) to the 64-hex store id.
    Decode {
        /// The base32 label, or a `<label>.dig` host.
        label: String,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
}

/// Execute a parsed command against an injected environment getter, returning the stdout
/// text on success or a human error message on failure. PURE (no I/O, no process exit).
pub fn execute<F>(cli: &Cli, get: F) -> Result<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    match &cli.command {
        Command::Label { action } => match action {
            LabelAction::Encode { store_hex, json } => {
                let cfg = config::from_env(&get).map_err(|e| e.to_string())?;
                let lbl = label::store_hex_to_label(store_hex).map_err(|e| e.to_string())?;
                let host = format!("{lbl}.{}", cfg.tld);
                if *json {
                    Ok(
                        json!({ "store_id_hex": store_hex, "label": lbl, "host": host })
                            .to_string(),
                    )
                } else {
                    Ok(host)
                }
            }
            LabelAction::Decode { label: host, json } => {
                // Accept either a bare label or a full `<label>.<tld>` host: the store
                // label is the first DNS label.
                let lbl = host.split('.').next().unwrap_or(host);
                let hex = label::label_to_store_hex(lbl).map_err(|e| e.to_string())?;
                if *json {
                    Ok(json!({ "host": host, "label": lbl, "store_id_hex": hex }).to_string())
                } else {
                    Ok(hex)
                }
            }
        },
        Command::Config { json } => {
            let cfg = config::from_env(&get).map_err(|e| e.to_string())?;
            if *json {
                serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())
            } else {
                let node = cfg
                    .node_url
                    .as_deref()
                    .unwrap_or("(ladder: dig.local -> localhost:9778 -> rpc.dig.net)");
                Ok(format!(
                    "loopback_ip = {}\n\
                     dns_port = {}\n\
                     http_port = {}\n\
                     http_fallback_port = {}\n\
                     tld = {}\n\
                     dns_ttl_secs = {}\n\
                     node_url = {}",
                    cfg.loopback_ip,
                    cfg.dns_port,
                    cfg.http_port,
                    cfg.http_fallback_port,
                    cfg.tld,
                    cfg.dns_ttl_secs,
                    node,
                ))
            }
        }
        // `serve`/`fetch`/`doctor`/`pac` (async) and the service commands (touch the OS service
        // manager) run directly in `run()`; `execute` is the pure path.
        Command::Serve { .. }
        | Command::Fetch { .. }
        | Command::Doctor { .. }
        | Command::Pac { .. }
        | Command::RunService
        | Command::Install { .. }
        | Command::Uninstall { .. }
        | Command::Start { .. }
        | Command::Stop { .. }
        | Command::Status { .. }
        | Command::Health { .. }
        | Command::ConfigureOs { .. }
        | Command::UnconfigureOs { .. } => {
            Err("this command runs via the binary entrypoint, not execute()".to_string())
        }
    }
}

/// Load the config from the environment, layering an explicit `--node` flag over it (the
/// flag has the highest §5.3 precedence). A blank flag is ignored (⇒ use the ladder).
/// The flag value is validated the same as environment values (SPEC §13.1).
fn load_config(node_flag: Option<&str>) -> Result<config::Config, String> {
    let mut cfg = config::from_env(|k| std::env::var(k).ok()).map_err(|e| e.to_string())?;
    if let Some(url) = node_flag {
        if !url.trim().is_empty() {
            cfg.node_url = Some(url.trim().to_string());
        }
    }
    // Re-validate after applying the flag to ensure it meets the same guard (SPEC §13.1).
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// A multi-threaded tokio runtime for the async subcommands.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

/// Initialise loud, env-filterable structured logging for the service (`RUST_LOG` respected,
/// default `info`). Best-effort: a second init (e.g. in tests) is ignored.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

/// Parse argv, run the command, print the result, and return the process exit code.
///
/// Argv is parsed with the ACTUAL invoked binary name ([`crate::invoked_bin_name`]) as BOTH the
/// displayed program name and the usage `bin_name`, so the `digd` alias (dig_ecosystem #548) is
/// first-class: `digd --help` reads `digd` and `dig-dns --help` reads `dig-dns`, from ONE shared
/// codepath. `get_matches()` still intercepts `--help`/`--version` and exits on a parse error,
/// using that name.
pub fn run() -> std::process::ExitCode {
    use clap::{CommandFactory, FromArgMatches};
    use std::process::ExitCode;

    // `Command::name` requires a `'static` string, but the invoked name is computed at runtime,
    // so we leak the tiny stem to obtain a `'static` reference. This is a single, process-lifetime
    // allocation on a short-lived CLI's entrypoint — never in a loop — so it is not a meaningful
    // leak. (`bin_name` takes the owned `String` directly.)
    let bin = crate::invoked_bin_name();
    let bin_static: &'static str = Box::leak(bin.clone().into_boxed_str());
    let matches = Cli::command().name(bin_static).bin_name(bin).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    match &cli.command {
        Command::Serve { node } => {
            init_tracing();
            let cfg = match load_config(node.as_deref()) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            let rt = match runtime() {
                Ok(rt) => rt,
                Err(e) => return fail(&e.to_string()),
            };
            match rt.block_on(crate::server::run_service(cfg)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::Fetch {
            target,
            path,
            node,
            json,
        } => {
            let cfg = match load_config(node.as_deref()) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            let rt = match runtime() {
                Ok(rt) => rt,
                Err(e) => return fail(&e.to_string()),
            };
            match rt.block_on(crate::server::fetch_resource(cfg, target, path)) {
                Ok(resp) => print_fetch(&resp, *json),
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::Doctor { json } => {
            let cfg = match load_config(None) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            let rt = match runtime() {
                Ok(rt) => rt,
                Err(e) => return fail(&e.to_string()),
            };
            let report = rt.block_on(crate::doctor::run(&cfg));
            if *json {
                println!("{}", report.to_json());
            } else {
                print!("{}", report.to_text());
            }
            if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::Pac { port, json } => {
            let cfg = match load_config(None) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            // The bound port: an explicit --port, else the running gateway's port, else the
            // configured primary (noted as a best-effort default when nothing is running).
            let bound_port = match port {
                Some(p) => *p,
                None => {
                    let rt = match runtime() {
                        Ok(rt) => rt,
                        Err(e) => return fail(&e.to_string()),
                    };
                    rt.block_on(crate::server::probe_gateway_port(
                        cfg.loopback_ip,
                        cfg.http_port,
                        cfg.http_fallback_port,
                    ))
                    .unwrap_or(cfg.http_port)
                }
            };
            let pac = crate::pac::generate(cfg.loopback_ip, bound_port, &cfg.tld);
            if *json {
                let meta = json!({
                    "loopback_ip": cfg.loopback_ip.to_string(),
                    "port": bound_port,
                    "tld": cfg.tld,
                    "pac": pac,
                });
                println!("{meta}");
            } else {
                print!("{pac}");
            }
            ExitCode::SUCCESS
        }
        // The Windows-service entrypoint: hand control to the SCM dispatcher. Off Windows there
        // is no SCM, so behave like `serve` (systemd/launchd exec the foreground process).
        Command::RunService => {
            init_tracing();
            #[cfg(windows)]
            {
                match crate::win_service::run() {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e.to_string()),
                }
            }
            #[cfg(not(windows))]
            {
                let cfg = match load_config(None) {
                    Ok(c) => c,
                    Err(e) => return fail(&e),
                };
                let rt = match runtime() {
                    Ok(rt) => rt,
                    Err(e) => return fail(&e.to_string()),
                };
                match rt.block_on(crate::server::run_service(cfg)) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e.to_string()),
                }
            }
        }
        Command::Install { node, json } => {
            let cfg = match load_config(node.as_deref()) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            match crate::service::install(&cfg) {
                Ok(out) => print_service_outcome(&out, *json),
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::Uninstall { json } => match crate::service::uninstall() {
            Ok(out) => print_service_outcome(&out, *json),
            Err(e) => fail(&e.to_string()),
        },
        Command::Start { json } => match crate::service::start() {
            Ok(out) => print_service_outcome(&out, *json),
            Err(e) => fail(&e.to_string()),
        },
        Command::Stop { json } => match crate::service::stop() {
            Ok(out) => print_service_outcome(&out, *json),
            Err(e) => fail(&e.to_string()),
        },
        Command::Status { json } => {
            let cfg = match load_config(None) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            match crate::service::status(&cfg) {
                Ok(out) => {
                    let serving = out.json["serving"].as_bool().unwrap_or(false);
                    print_service_outcome(&out, *json);
                    if serving {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::Health { json } => {
            let cfg = match load_config(None) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            match crate::service::health(&cfg) {
                Ok(out) => {
                    let serving = out.json["serving"].as_bool().unwrap_or(false);
                    print_service_outcome(&out, *json);
                    if serving {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::ConfigureOs {
            browser_policy,
            json,
        } => {
            let cfg = match load_config(None) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            let report = crate::os_config::configure(&cfg, *browser_policy);
            print_os_config_report(&report, *json)
        }
        Command::UnconfigureOs { json } => {
            let cfg = match load_config(None) {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            let report = crate::os_config::unconfigure(&cfg);
            print_os_config_report(&report, *json)
        }
        _ => match execute(&cli, |k| std::env::var(k).ok()) {
            Ok(out) => {
                println!("{out}");
                ExitCode::SUCCESS
            }
            Err(msg) => fail(&msg),
        },
    }
}

/// Print an [`crate::os_config::OsConfigReport`] (`--json` object or human summary) and map its
/// outcome to an exit code: success when it did its work, failure otherwise (incl. a
/// not-elevated refusal) so a script/package can branch on the exit status.
fn print_os_config_report(
    report: &crate::os_config::OsConfigReport,
    json: bool,
) -> std::process::ExitCode {
    if json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.summary());
    }
    if report.ok {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

/// Print a [`crate::service::ServiceOutcome`]: the JSON object in `--json` mode, else the human
/// summary. Returns `SUCCESS` (the caller overrides the exit code where the outcome implies one,
/// e.g. `status`).
fn print_service_outcome(
    out: &crate::service::ServiceOutcome,
    json: bool,
) -> std::process::ExitCode {
    if json {
        println!("{}", out.json);
    } else {
        println!("{}", out.summary);
    }
    std::process::ExitCode::SUCCESS
}

/// Print an error to stderr and return the failure exit code.
fn fail(msg: &str) -> std::process::ExitCode {
    eprintln!("error: {msg}");
    std::process::ExitCode::FAILURE
}

/// Print a fetched resource: `--json` metadata to stdout, or the raw body to stdout (a
/// non-2xx status is reported on stderr + a non-zero exit).
fn print_fetch(resp: &crate::gateway::GatewayResponse, json: bool) -> std::process::ExitCode {
    let content_type = resp
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if json {
        let meta = json!({
            "status": resp.status,
            "content_type": content_type,
            "length": resp.body.len(),
        });
        println!("{meta}");
    } else {
        let _ = std::io::stdout().write_all(&resp.body);
        let _ = std::io::stdout().flush();
        if resp.status >= 400 {
            eprintln!("\nerror: status {}", resp.status);
        }
    }
    if resp.status < 400 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_LABEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("dig-dns").chain(args.iter().copied()))
            .expect("args parse")
    }

    #[test]
    fn label_encode_text_appends_default_tld() {
        let out = execute(&cli(&["label", "encode", ZERO_HEX]), no_env).unwrap();
        assert_eq!(out, format!("{ZERO_LABEL}.dig"));
    }

    #[test]
    fn label_encode_honors_tld_override() {
        let out = execute(&cli(&["label", "encode", ZERO_HEX]), |k| {
            (k == config::ENV_TLD).then(|| "web3".to_string())
        })
        .unwrap();
        assert_eq!(out, format!("{ZERO_LABEL}.web3"));
    }

    #[test]
    fn label_encode_json_has_all_fields() {
        let out = execute(&cli(&["label", "encode", ZERO_HEX, "--json"]), no_env).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["store_id_hex"], ZERO_HEX);
        assert_eq!(v["label"], ZERO_LABEL);
        assert_eq!(v["host"], format!("{ZERO_LABEL}.dig"));
    }

    #[test]
    fn label_decode_accepts_bare_label_and_full_host() {
        let bare = execute(&cli(&["label", "decode", ZERO_LABEL]), no_env).unwrap();
        assert_eq!(bare, ZERO_HEX);
        let host = execute(
            &cli(&["label", "decode", &format!("{ZERO_LABEL}.dig")]),
            no_env,
        )
        .unwrap();
        assert_eq!(host, ZERO_HEX);
    }

    #[test]
    fn label_decode_json_has_all_fields() {
        let out = execute(&cli(&["label", "decode", ZERO_LABEL, "--json"]), no_env).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["label"], ZERO_LABEL);
        assert_eq!(v["store_id_hex"], ZERO_HEX);
    }

    #[test]
    fn label_encode_bad_hex_is_error() {
        let err = execute(&cli(&["label", "encode", "nope"]), no_env).unwrap_err();
        assert!(err.contains("hex"), "unexpected error: {err}");
    }

    #[test]
    fn label_decode_bad_label_is_error() {
        let err = execute(&cli(&["label", "decode", "too-short"]), no_env).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn config_json_reflects_env_overrides() {
        let out = execute(&cli(&["config", "--json"]), |k| {
            (k == config::ENV_HTTP_PORT).then(|| "8080".to_string())
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["http_port"], 8080);
        assert_eq!(v["loopback_ip"], "127.0.0.5");
    }

    #[test]
    fn config_text_lists_key_values() {
        let out = execute(&cli(&["config"]), no_env).unwrap();
        assert!(out.contains("loopback_ip"));
        assert!(out.contains("127.0.0.5"));
        assert!(out.contains("dig"));
    }

    #[test]
    fn execute_rejects_binary_entrypoint_commands() {
        // `serve`/`fetch` (async) and the service commands are dispatched by run(), not
        // execute(); execute reports that rather than silently mishandling them.
        for args in [
            vec!["serve"],
            vec!["fetch", "abc.dig"],
            vec!["install"],
            vec!["uninstall"],
            vec!["status"],
            vec!["configure-os"],
            vec!["unconfigure-os"],
        ] {
            let err = execute(&cli(&args), no_env).unwrap_err();
            assert!(
                err.contains("runs via the binary entrypoint"),
                "unexpected for {args:?}: {err}"
            );
        }
    }

    #[test]
    fn configure_os_parses_the_browser_policy_and_json_flags() {
        // Default: resolver-only (no browser policy).
        let plain = cli(&["configure-os"]);
        assert!(matches!(
            plain.command,
            Command::ConfigureOs {
                browser_policy: false,
                json: false
            }
        ));
        // Both flags set.
        let full = cli(&["configure-os", "--browser-policy", "--json"]);
        assert!(matches!(
            full.command,
            Command::ConfigureOs {
                browser_policy: true,
                json: true
            }
        ));
        // unconfigure-os takes only --json.
        assert!(matches!(
            cli(&["unconfigure-os", "--json"]).command,
            Command::UnconfigureOs { json: true }
        ));
    }

    #[test]
    fn config_surfaces_invalid_env_as_error() {
        let err = execute(&cli(&["config"]), |k| {
            (k == config::ENV_IP).then(|| "0.0.0.0".to_string())
        })
        .unwrap_err();
        assert!(err.contains("loopback"), "unexpected error: {err}");
    }

    #[test]
    fn load_config_rejects_flag_with_control_characters() {
        // Regression test for dig_ecosystem #565: the --node flag must validate the same way
        // the env path does (SPEC §13.1). An embedded newline / control character is rejected
        // (would otherwise inject a systemd directive into the root unit).
        // Without the fix, this flag value bypasses is_safe_node_url and reaches the config.
        let err = load_config(Some("http://x\nExecStartPre=/bin/rm -rf /")).unwrap_err();
        assert!(
            err.contains("control character"),
            "expected control-char rejection; got {err}"
        );
    }

    #[test]
    fn load_config_accepts_flag_without_control_characters() {
        // The flag path should accept a valid node URL after validation.
        let cfg = load_config(Some("http://localhost:9778")).unwrap();
        assert_eq!(cfg.node_url.as_deref(), Some("http://localhost:9778"));
    }

    #[test]
    fn load_config_rejects_flag_with_other_control_chars() {
        // Also test other control characters: tab, carriage return, DEL.
        for hostile in [
            "http://x\tx",        // tab
            "http://x\rDNS=evil", // carriage return
            "http://x\x7fx",      // DEL
        ] {
            let err = load_config(Some(hostile)).unwrap_err();
            assert!(
                err.contains("control character"),
                "expected control-char rejection for {hostile:?}; got {err}"
            );
        }
    }
}
