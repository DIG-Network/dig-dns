//! Service configuration: the loopback bind IP, the DNS + HTTP ports, the TLD, the DNS
//! answer TTL, and the optional dig-node endpoint override.
//!
//! Every value has a documented default and is overridable by environment variable (and,
//! for the node endpoint, by a CLI flag with the §5.3 precedence). Values are validated on
//! load: the bind IP MUST be a loopback address (`127.0.0.0/8`) — `dig-dns` NEVER binds a
//! routable interface or `0.0.0.0` (SPEC §5, the loopback-only security invariant) — and
//! ports MUST be non-zero.
//!
//! The functions take an injected env getter (`Fn(&str) -> Option<String>`) rather than
//! reading the process environment directly, so precedence + validation are unit-testable
//! without mutating global state.

use std::net::Ipv4Addr;

/// Default dedicated loopback IP for the resolver. Distinct from the dig-node's own
/// loopback listeners (`127.0.0.1` / `127.0.0.2`) so the two services never contend for a
/// port, and so `*.dig` traffic is isolated to its own address (SPEC §3, §5).
pub const DEFAULT_LOOPBACK_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);
/// Default DNS responder port.
pub const DEFAULT_DNS_PORT: u16 = 53;
/// Default HTTP gateway port.
pub const DEFAULT_HTTP_PORT: u16 = 80;
/// Deterministic HTTP fallback port when `:80` cannot be bound (e.g. held by `http.sys`
/// / another server). The gateway advertises the actually-bound port via the PAC file.
pub const DEFAULT_HTTP_FALLBACK_PORT: u16 = 8053;
/// Default browsable TLD.
pub const DEFAULT_TLD: &str = "dig";
/// Default TTL (seconds) on DNS answers — short so a re-point/uninstall takes effect fast
/// (SPEC §3: 1–5s).
pub const DEFAULT_DNS_TTL_SECS: u32 = 2;

/// Environment variable naming the dig-node endpoint (ecosystem-standard, §5.3). When set
/// it overrides the node-resolution ladder.
pub const ENV_NODE_URL: &str = "DIG_NODE_URL";
/// Environment variable for the loopback bind IP.
pub const ENV_IP: &str = "DIG_DNS_IP";
/// Environment variable for the DNS port.
pub const ENV_DNS_PORT: &str = "DIG_DNS_DNS_PORT";
/// Environment variable for the primary HTTP port.
pub const ENV_HTTP_PORT: &str = "DIG_DNS_HTTP_PORT";
/// Environment variable for the HTTP fallback port.
pub const ENV_HTTP_FALLBACK_PORT: &str = "DIG_DNS_HTTP_FALLBACK_PORT";
/// Environment variable for the TLD.
pub const ENV_TLD: &str = "DIG_DNS_TLD";
/// Environment variable for the DNS answer TTL (seconds).
pub const ENV_DNS_TTL: &str = "DIG_DNS_TTL";

/// A fully-resolved, validated `dig-dns` configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Config {
    /// The loopback IPv4 address the DNS responder and HTTP gateway bind (127.0.0.0/8).
    pub loopback_ip: Ipv4Addr,
    /// The DNS responder port (UDP + TCP).
    pub dns_port: u16,
    /// The primary HTTP gateway port.
    pub http_port: u16,
    /// The fallback HTTP gateway port used when the primary cannot be bound.
    pub http_fallback_port: u16,
    /// The browsable TLD (without a leading dot), e.g. `dig`.
    pub tld: String,
    /// The TTL (seconds) placed on DNS answers.
    pub dns_ttl_secs: u32,
    /// An explicit dig-node endpoint that overrides the §5.3 resolution ladder. `None`
    /// means "use the ladder" (dig.local → localhost → rpc.dig.net).
    pub node_url: Option<String>,
}

/// Errors from building/validating a [`Config`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A value that should be an IPv4 address did not parse.
    #[error("{key}: '{value}' is not a valid IPv4 address")]
    InvalidIp { key: &'static str, value: String },
    /// A value that should be a non-zero port did not parse or was zero.
    #[error("{key}: '{value}' is not a valid port (1-65535)")]
    InvalidPort { key: &'static str, value: String },
    /// A value that should be an unsigned integer did not parse.
    #[error("{key}: '{value}' is not a valid integer")]
    InvalidInt { key: &'static str, value: String },
    /// The bind IP was not a loopback address — refused (SPEC §5 loopback-only invariant).
    #[error("bind IP {0} is not a loopback address (must be in 127.0.0.0/8)")]
    NotLoopback(Ipv4Addr),
    /// The TLD normalised to an empty string.
    #[error("TLD must not be empty")]
    EmptyTld,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            loopback_ip: DEFAULT_LOOPBACK_IP,
            dns_port: DEFAULT_DNS_PORT,
            http_port: DEFAULT_HTTP_PORT,
            http_fallback_port: DEFAULT_HTTP_FALLBACK_PORT,
            tld: DEFAULT_TLD.to_string(),
            dns_ttl_secs: DEFAULT_DNS_TTL_SECS,
            node_url: None,
        }
    }
}

impl Config {
    /// Validate the invariants: loopback-only bind IP, non-zero ports, non-empty TLD.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.loopback_ip.is_loopback() {
            return Err(ConfigError::NotLoopback(self.loopback_ip));
        }
        for (key, port) in [
            (ENV_DNS_PORT, self.dns_port),
            (ENV_HTTP_PORT, self.http_port),
            (ENV_HTTP_FALLBACK_PORT, self.http_fallback_port),
        ] {
            if port == 0 {
                return Err(ConfigError::InvalidPort {
                    key,
                    value: "0".to_string(),
                });
            }
        }
        if self.tld.is_empty() {
            return Err(ConfigError::EmptyTld);
        }
        Ok(())
    }
}

/// Normalise a TLD: trim whitespace, strip a single leading `.`, lowercase.
pub fn normalize_tld(raw: &str) -> String {
    raw.trim()
        .strip_prefix('.')
        .unwrap_or_else(|| raw.trim())
        .to_ascii_lowercase()
}

/// Resolve the dig-node endpoint override by precedence: CLI flag > env > file config.
/// Returns `None` (⇒ use the §5.3 ladder) when no source supplies a non-empty value.
pub fn resolve_node_override(
    flag: Option<&str>,
    env: Option<&str>,
    file: Option<&str>,
) -> Option<String> {
    [flag, env, file]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|v| !v.is_empty())
        .map(str::to_string)
}

/// Parse a non-zero port from a config value, tagging the source `key` on failure.
fn parse_port(key: &'static str, value: &str) -> Result<u16, ConfigError> {
    match value.trim().parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(ConfigError::InvalidPort {
            key,
            value: value.to_string(),
        }),
    }
}

/// Build a validated [`Config`] from an injected environment getter, layering any set
/// variables over the defaults. Fails if a set value is malformed or violates an invariant.
pub fn from_env<F>(get: F) -> Result<Config, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut cfg = Config::default();

    if let Some(v) = get(ENV_IP) {
        cfg.loopback_ip = v.trim().parse().map_err(|_| ConfigError::InvalidIp {
            key: ENV_IP,
            value: v.clone(),
        })?;
    }
    if let Some(v) = get(ENV_DNS_PORT) {
        cfg.dns_port = parse_port(ENV_DNS_PORT, &v)?;
    }
    if let Some(v) = get(ENV_HTTP_PORT) {
        cfg.http_port = parse_port(ENV_HTTP_PORT, &v)?;
    }
    if let Some(v) = get(ENV_HTTP_FALLBACK_PORT) {
        cfg.http_fallback_port = parse_port(ENV_HTTP_FALLBACK_PORT, &v)?;
    }
    if let Some(v) = get(ENV_TLD) {
        cfg.tld = normalize_tld(&v);
    }
    if let Some(v) = get(ENV_DNS_TTL) {
        cfg.dns_ttl_secs = v.trim().parse().map_err(|_| ConfigError::InvalidInt {
            key: ENV_DNS_TTL,
            value: v.clone(),
        })?;
    }
    // A blank node URL means "use the ladder", not an explicit empty endpoint.
    cfg.node_url = resolve_node_override(None, get(ENV_NODE_URL).as_deref(), None);

    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// An env getter backed by a map — no process-global state touched.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn defaults_match_spec() {
        let c = Config::default();
        assert_eq!(c.loopback_ip, Ipv4Addr::new(127, 0, 0, 5));
        assert_eq!(c.dns_port, 53);
        assert_eq!(c.http_port, 80);
        assert_eq!(c.http_fallback_port, 8053);
        assert_eq!(c.tld, "dig");
        assert_eq!(c.dns_ttl_secs, 2);
        assert_eq!(c.node_url, None);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn from_env_with_nothing_set_is_default() {
        let c = from_env(env_of(&[])).unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn from_env_overrides_each_field() {
        let c = from_env(env_of(&[
            (ENV_IP, "127.0.0.9"),
            (ENV_DNS_PORT, "5353"),
            (ENV_HTTP_PORT, "8080"),
            (ENV_HTTP_FALLBACK_PORT, "8153"),
            (ENV_TLD, "DIG"),
            (ENV_DNS_TTL, "5"),
            (ENV_NODE_URL, "http://127.0.0.1:9778"),
        ]))
        .unwrap();
        assert_eq!(c.loopback_ip, Ipv4Addr::new(127, 0, 0, 9));
        assert_eq!(c.dns_port, 5353);
        assert_eq!(c.http_port, 8080);
        assert_eq!(c.http_fallback_port, 8153);
        assert_eq!(c.tld, "dig"); // lowercased
        assert_eq!(c.dns_ttl_secs, 5);
        assert_eq!(c.node_url.as_deref(), Some("http://127.0.0.1:9778"));
    }

    #[test]
    fn from_env_rejects_non_loopback_bind_ip() {
        let err = from_env(env_of(&[(ENV_IP, "10.0.0.1")])).unwrap_err();
        assert_eq!(err, ConfigError::NotLoopback(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn from_env_rejects_zero_and_garbage_ports() {
        assert!(matches!(
            from_env(env_of(&[(ENV_DNS_PORT, "0")])).unwrap_err(),
            ConfigError::InvalidPort { .. }
        ));
        assert!(matches!(
            from_env(env_of(&[(ENV_HTTP_PORT, "notaport")])).unwrap_err(),
            ConfigError::InvalidPort { .. }
        ));
    }

    #[test]
    fn from_env_rejects_bad_ip_and_ttl() {
        assert!(matches!(
            from_env(env_of(&[(ENV_IP, "not.an.ip")])).unwrap_err(),
            ConfigError::InvalidIp { .. }
        ));
        assert!(matches!(
            from_env(env_of(&[(ENV_DNS_TTL, "-1")])).unwrap_err(),
            ConfigError::InvalidInt { .. }
        ));
    }

    #[test]
    fn empty_node_url_env_means_use_ladder() {
        let c = from_env(env_of(&[(ENV_NODE_URL, "   ")])).unwrap();
        assert_eq!(c.node_url, None);
    }

    #[test]
    fn normalize_tld_strips_dot_and_lowercases() {
        assert_eq!(normalize_tld(".DIG"), "dig");
        assert_eq!(normalize_tld("  Dig  "), "dig");
        assert_eq!(normalize_tld("dig"), "dig");
    }

    #[test]
    fn node_override_precedence_is_flag_then_env_then_file() {
        assert_eq!(
            resolve_node_override(Some("http://flag"), Some("http://env"), Some("http://file")),
            Some("http://flag".to_string())
        );
        assert_eq!(
            resolve_node_override(None, Some("http://env"), Some("http://file")),
            Some("http://env".to_string())
        );
        assert_eq!(
            resolve_node_override(None, None, Some("http://file")),
            Some("http://file".to_string())
        );
        assert_eq!(resolve_node_override(None, None, None), None);
        // A blank value at any tier is skipped, not treated as a value.
        assert_eq!(
            resolve_node_override(Some("  "), Some("http://env"), None),
            Some("http://env".to_string())
        );
    }

    #[test]
    fn validate_rejects_empty_tld() {
        let c = Config {
            tld: String::new(),
            ..Config::default()
        };
        assert_eq!(c.validate(), Err(ConfigError::EmptyTld));
    }
}
