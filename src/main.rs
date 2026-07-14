//! The `dig-dns` service binary — a thin shell over the `dig_dns` library. All command
//! logic lives in [`dig_dns::cli`]; this entry point only parses argv and maps the result
//! to a process exit code. The `digd` alias binary (`src/bin/digd.rs`, dig_ecosystem #548)
//! shares this exact codepath, so the two binaries are identical modulo the invoked program
//! name (which clap derives from arg0).

fn main() -> std::process::ExitCode {
    dig_dns::cli::run()
}
