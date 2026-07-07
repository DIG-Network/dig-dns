//! Proxy Auto-Config (PAC) generation for Path B (SPEC §1, §4.7).
//!
//! A PAC file tells a browser to route every `*.<tld>` request through the `dig-dns` gateway
//! as an HTTP **proxy** (absolute-form) and to send everything else `DIRECT`. This is the
//! second, DNS-independent resolution path: a browser that bypasses the OS resolver (forced
//! DNS-over-HTTPS, its own built-in resolver) still loads `.dig` URLs by proxying them.
//!
//! The generated file MUST embed the ACTUAL bound gateway port (the primary `:80`, or the
//! `:8053` fallback when `:80` was held), so a browser configured from `/.dig/proxy.pac`
//! reaches the gateway wherever it actually landed (SPEC §4).
//!
//! This module is pure (a string builder) so it is unit-tested directly and reused by both
//! the `/.dig/proxy.pac` control endpoint and the `dig-dns pac` CLI subcommand.

use std::net::Ipv4Addr;

/// Generate the PAC (`FindProxyForURL`) script routing `*.<tld>` to
/// `PROXY <loopback_ip>:<port>` and everything else `DIRECT`.
///
/// The host match is a case-insensitive `.<tld>` suffix test PLUS the bare apex (`<tld>`
/// itself), covering both `<store>.dig` and any deeper `<root>.<store>.dig` capsule host
/// (SPEC §2.1). The `tld` is lowercased and its regex/`dnsDomainIs` metacharacters are not a
/// concern because a TLD is DNS-label characters only (`[a-z0-9-]`).
pub fn generate(loopback_ip: Ipv4Addr, port: u16, tld: &str) -> String {
    let tld = tld.trim().trim_start_matches('.').to_ascii_lowercase();
    // `.dig` suffix (covers `x.dig` and `a.b.dig`) OR the bare apex `dig`.
    format!(
        "// dig-dns PAC - routes *.{tld} to the local gateway, everything else DIRECT.\n\
         // Generated with the actually-bound gateway port ({port}).\n\
         function FindProxyForURL(url, host) {{\n\
         \x20 host = host.toLowerCase();\n\
         \x20 if (dnsDomainIs(host, \".{tld}\") || host === \"{tld}\") {{\n\
         \x20   return \"PROXY {ip}:{port}\";\n\
         \x20 }}\n\
         \x20 return \"DIRECT\";\n\
         }}\n",
        tld = tld,
        port = port,
        ip = loopback_ip,
    )
}

/// The MIME type browsers expect for a PAC file.
pub const PAC_CONTENT_TYPE: &str = "application/x-ns-proxy-autoconfig";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_the_actual_bound_port() {
        let pac = generate(Ipv4Addr::new(127, 0, 0, 5), 8053, "dig");
        assert!(pac.contains("PROXY 127.0.0.5:8053"), "pac: {pac}");
        // The primary port must NOT leak in when the fallback bound.
        assert!(!pac.contains(":80\""));
    }

    #[test]
    fn matches_tld_suffix_and_apex_and_defaults_direct() {
        let pac = generate(Ipv4Addr::new(127, 0, 0, 5), 80, "dig");
        assert!(pac.contains("dnsDomainIs(host, \".dig\")"));
        assert!(pac.contains("host === \"dig\""));
        assert!(pac.contains("return \"DIRECT\""));
        assert!(pac.contains("function FindProxyForURL(url, host)"));
    }

    #[test]
    fn honors_custom_tld_lowercased_and_dot_stripped() {
        let pac = generate(Ipv4Addr::new(127, 0, 0, 5), 80, ".WEB3");
        assert!(pac.contains("dnsDomainIs(host, \".web3\")"));
        assert!(pac.contains("host === \"web3\""));
        // No stale `.dig` routing leaks in (the `dig-dns` banner mentioning "dig" is fine).
        assert!(!pac.contains("dnsDomainIs(host, \".dig\")"));
    }

    #[test]
    fn honors_custom_loopback_ip() {
        let pac = generate(Ipv4Addr::new(127, 0, 0, 9), 80, "dig");
        assert!(pac.contains("PROXY 127.0.0.9:80"));
    }
}
