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
        // `serve`/`fetch`/`doctor` are async and run directly in `run()`; `execute` is the pure
        // path.
        Command::Serve { .. } | Command::Fetch { .. } | Command::Doctor { .. } => {
            Err("serve/fetch/doctor run via the binary entrypoint, not execute()".to_string())
        }
    }
}

/// Load the config from the environment, layering an explicit `--node` flag over it (the
/// flag has the highest §5.3 precedence). A blank flag is ignored (⇒ use the ladder).
fn load_config(node_flag: Option<&str>) -> Result<config::Config, String> {
    let mut cfg = config::from_env(|k| std::env::var(k).ok()).map_err(|e| e.to_string())?;
    if let Some(url) = node_flag {
        if !url.trim().is_empty() {
            cfg.node_url = Some(url.trim().to_string());
        }
    }
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
pub fn run() -> std::process::ExitCode {
    use std::process::ExitCode;
    let cli = Cli::parse();
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
        _ => match execute(&cli, |k| std::env::var(k).ok()) {
            Ok(out) => {
                println!("{out}");
                ExitCode::SUCCESS
            }
            Err(msg) => fail(&msg),
        },
    }
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
    fn execute_rejects_async_commands() {
        // `serve`/`fetch` are dispatched by run(), not execute(); execute reports that.
        let err = execute(&cli(&["serve"]), no_env).unwrap_err();
        assert!(err.contains("serve/fetch"), "unexpected: {err}");
        let err = execute(&cli(&["fetch", "abc.dig"]), no_env).unwrap_err();
        assert!(err.contains("serve/fetch"), "unexpected: {err}");
    }

    #[test]
    fn config_surfaces_invalid_env_as_error() {
        let err = execute(&cli(&["config"]), |k| {
            (k == config::ENV_IP).then(|| "0.0.0.0".to_string())
        })
        .unwrap_err();
        assert!(err.contains("loopback"), "unexpected error: {err}");
    }
}
