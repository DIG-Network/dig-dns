//! The `dig-dns` service binary — a thin shell over the `dig_dns` library. All command
//! logic lives in [`dig_dns::cli`]; this entry point only parses argv and maps the result
//! to a process exit code.

fn main() -> std::process::ExitCode {
    dig_dns::cli::run()
}
