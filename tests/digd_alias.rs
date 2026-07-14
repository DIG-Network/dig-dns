//! `digd` is a FIRST-CLASS alias binary for `dig-dns` (dig_ecosystem #548): the two bins
//! share ONE codepath (`dig_dns::cli::run()`), expose the SAME command surface (including
//! every service verb — install/uninstall/start/stop/status/serve/run-service), and each
//! reflects its OWN invoked name (arg0) in `--help`/`--version` — so `digd <args>` behaves
//! identically to `dig-dns <args>`.
//!
//! These run against the REAL built binaries via `assert_cmd::cargo_bin`, so they also prove
//! the second `[[bin]]` target actually builds. This mirrors digstore's `cli_digs_alias.rs`
//! (#434); dig-dns has no `--help-json`/`completion`, so the full-`--help` byte-identity check
//! stands in for digstore's `--help-json` command-surface comparison.

use assert_cmd::Command;
use predicates::prelude::*;

/// The 64-hex all-zero store id and its 52-char base32 `.dig` label — a pure, deterministic
/// input for the dispatch-identity check (no network, no store, no chain).
const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ZERO_LABEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Both binaries build/run, and each `--version` reports the SAME semver — with its OWN
/// program name (clap prints "<bin> <semver>"): `digd 0.x.y` vs `dig-dns 0.x.y`.
#[test]
fn digd_and_dig_dns_report_the_same_version() {
    let dns = Command::cargo_bin("dig-dns")
        .unwrap()
        .arg("--version")
        .output()
        .unwrap();
    let dgd = Command::cargo_bin("digd")
        .unwrap()
        .arg("--version")
        .output()
        .unwrap();
    assert!(dns.status.success() && dgd.status.success());
    let dns = String::from_utf8_lossy(&dns.stdout);
    let dgd = String::from_utf8_lossy(&dgd.stdout);
    // The trailing semver token must match; the leading program name differs.
    let dns_ver = dns.split_whitespace().last().unwrap();
    let dgd_ver = dgd.split_whitespace().last().unwrap();
    assert_eq!(dns_ver, dgd_ver, "same version: `{dns}` vs `{dgd}`");
    assert!(
        dns.starts_with("dig-dns "),
        "dig-dns leads with its name: {dns}"
    );
    assert!(
        dgd.starts_with("digd "),
        "digd leads with its own name: {dgd}"
    );
}

/// `digd --help` renders its OWN name in the usage line, not a hardcoded "dig-dns".
#[test]
fn digd_help_usage_shows_digd() {
    Command::cargo_bin("digd")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: digd"));
}

/// The primary `dig-dns` binary still shows its OWN name — a regression guard proving the
/// arg0-name refactor did not accidentally rename the canonical binary to the alias.
#[test]
fn dig_dns_help_usage_shows_dig_dns() {
    Command::cargo_bin("dig-dns")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: dig-dns"));
}

/// The two bins expose the IDENTICAL command surface: `--help` is byte-for-byte equal once the
/// program name in the usage line is normalized. Because the program name appears ONLY in the
/// usage line (no help text contains the literal token "digd"), this proves every command —
/// including the service verbs `install`/`uninstall`/`start`/`stop`/`status`/`serve` — is the
/// SAME under `digd` as under `dig-dns`.
#[test]
fn digd_and_dig_dns_share_the_same_help_surface() {
    let dns = Command::cargo_bin("dig-dns")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    let dgd = Command::cargo_bin("digd")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    assert!(dns.status.success() && dgd.status.success());
    let dns_help = String::from_utf8_lossy(&dns.stdout).into_owned();
    let dgd_help = String::from_utf8_lossy(&dgd.stdout).into_owned();

    // Sanity: each help carries the service verbs (the alias exposes the identical CLI).
    for verb in ["install", "uninstall", "start", "stop", "status", "serve"] {
        assert!(dgd_help.contains(verb), "digd --help missing `{verb}`");
    }
    // Normalize ONLY the usage program name, then require exact equality of the whole surface.
    let dgd_normalized = dgd_help.replacen("Usage: digd", "Usage: dig-dns", 1);
    assert_eq!(
        dgd_normalized, dns_help,
        "identical command surface modulo the program name"
    );
}

/// `digd` runs the SAME dispatch path: `digd label encode <hex>` produces byte-identical output
/// to `dig-dns label encode <hex>`, proving commands dispatch end-to-end under the alias.
#[test]
fn digd_dispatches_commands_like_dig_dns() {
    let dns = Command::cargo_bin("dig-dns")
        .unwrap()
        .args(["label", "encode", ZERO_HEX])
        .output()
        .unwrap();
    let dgd = Command::cargo_bin("digd")
        .unwrap()
        .args(["label", "encode", ZERO_HEX])
        .output()
        .unwrap();
    assert!(dns.status.success() && dgd.status.success());
    let dns_out = String::from_utf8_lossy(&dns.stdout);
    let dgd_out = String::from_utf8_lossy(&dgd.stdout);
    assert_eq!(dns_out.trim(), format!("{ZERO_LABEL}.dig"));
    assert_eq!(
        dgd_out, dns_out,
        "digd dispatches label encode like dig-dns"
    );
}
