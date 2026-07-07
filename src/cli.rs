//! The `dig-dns` command surface.
//!
//! Every command has a pretty (human) output and a `--json` (machine) output, per the
//! agent-friendly baseline (CLAUDE.md §6.2). The pure command logic lives in [`execute`]
//! (returning the stdout text or an error string) so it is unit-tested without touching
//! the process environment or exit codes; [`run`] is the thin `main` glue that parses
//! argv, prints, and maps to an exit code.
//!
//! Phase 1 ships `label` (the base32 codec as a CLI tool) and `config` (introspect the
//! resolved configuration). `serve`, `doctor`, and `pac` are added in their phases.

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
    }
}

/// Parse argv, run the command, print the result, and return the process exit code.
pub fn run() -> std::process::ExitCode {
    let cli = Cli::parse();
    match execute(&cli, |k| std::env::var(k).ok()) {
        Ok(out) => {
            println!("{out}");
            std::process::ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("error: {msg}");
            std::process::ExitCode::FAILURE
        }
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
    fn config_surfaces_invalid_env_as_error() {
        let err = execute(&cli(&["config"]), |k| {
            (k == config::ENV_IP).then(|| "0.0.0.0".to_string())
        })
        .unwrap_err();
        assert!(err.contains("loopback"), "unexpected error: {err}");
    }
}
