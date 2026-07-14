//! `digd` — a FIRST-CLASS alias binary for the `dig-dns` service CLI (dig_ecosystem #548).
//!
//! `digd <args>` behaves IDENTICALLY to `dig-dns <args>`: the same subcommands (including the
//! service verbs `install`/`uninstall`/`start`/`stop`/`status`/`serve`/`run-service`), flags,
//! `--json`, and help. It is a real installed binary (not a shell alias) that shares the SINGLE
//! entrypoint [`dig_dns::cli::run`] with `dig-dns` — there is no duplicated logic. clap derives
//! the displayed program name from arg0, so `digd --help`/`--version` read `digd`.
//!
//! This mirrors how `digs` is the first-class alias for `digstore` (digstore #434).

fn main() -> std::process::ExitCode {
    dig_dns::cli::run()
}
