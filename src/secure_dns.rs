//! Encrypted upstream resolution for dig-dns's OWN outbound name lookup (dig_ecosystem #574).
//!
//! This is deliberately narrow: the `.dig` DNS **responder** (`crate::dns`) is untouched — it
//! stays loopback-only, authoritative-only, `REFUSED` for every non-`.dig` name (SPEC §5). The
//! ONE public name `dig-dns` itself ever asks the network to resolve is [`UPSTREAM_HOST`] (the
//! §5.3 client→node ladder's terminal tier, `crate::node::RPC_DIG_NET_BASE`); this module routes
//! THAT lookup — and only that lookup — through an encrypted chain, so a local resolver can
//! neither observe nor tamper with it. Every other name a `dig-dns` `reqwest` client ever
//! resolves (`dig.local`, `localhost`, a loopback probe IP) passes straight through to the OS
//! resolver, unchanged and at no added latency ([`is_scoped_host`]).
//!
//! ## Chain (SPEC §6.4, dig_ecosystem #572 design comment §3)
//!
//! In strict try-order, each provider dialed IPv6-first (CLAUDE.md §5.2):
//!
//! 1. **Mullvad DoH** — `[2a07:e340::2]` then `194.242.2.2`, TLS name `dns.mullvad.net`.
//! 2. **Mullvad DoT** — the same IPs, port 853.
//! 3. **Quad9 unfiltered DoT** — `[2620:fe::10]` then `9.9.9.10`, TLS name `dns10.quad9.net`.
//! 4. **The OS stub resolver** — a terminal availability net, used only for [`UPSTREAM_HOST`],
//!    surfaced by `doctor --json` as `degraded` (see `crate::doctor::evaluate_secure_upstream`).
//!
//! Bootstrap is static IPs + hostname-verified TLS against the webpki root store
//! (`hickory-resolver`'s default `ClientConfig`, features `tls-ring`/`https-ring`/
//! `webpki-roots`) — deliberately NOT a leaf-certificate pin: a provider's leaf rotates
//! routinely, and pinning it would brick resolution on the next rotation.
//!
//! `hickory-resolver` is the resolution ENGINE for every tier (DoH/DoT are never hand-rolled
//! here); this module supplies only the tier ORDER, the fallback control flow
//! ([`resolve_with_fallback`]), and the scope check, exposed to `reqwest` via [`SecureResolver`]
//! (`impl reqwest::dns::Resolve`).

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// The one public hostname dig-dns ever resolves — the §5.3 ladder's terminal tier
/// (`crate::node::RPC_DIG_NET_BASE`). Every other name bypasses this module's chain entirely
/// (see [`is_scoped_host`]).
pub const UPSTREAM_HOST: &str = "rpc.dig.net";

/// How long a single tier's lookup may take before [`resolve_with_fallback`] moves to the next
/// one. Short, because a blocked/filtered tier should fail fast rather than stall the ladder —
/// matches the crate's existing probe-timeout convention (`doctor::build_probe_client`).
const TIER_TIMEOUT: Duration = Duration::from_secs(3);

/// One encrypted-DNS hop in the fallback chain, identified for logging and for the `doctor
/// --json secure_upstream` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Mullvad's DNS-over-HTTPS resolver.
    MullvadDoh,
    /// Mullvad's DNS-over-TLS resolver (same network, opportunistic-encryption-free transport).
    MullvadDot,
    /// Quad9's unfiltered DNS-over-TLS resolver (provider diversity: a Mullvad outage never
    /// takes down the whole chain).
    Quad9Dot,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Tier::MullvadDoh => "Mullvad DoH",
            Tier::MullvadDot => "Mullvad DoT",
            Tier::Quad9Dot => "Quad9 DoT",
        })
    }
}

/// The encrypted transport a [`ProviderTier`] speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncryptedProtocol {
    /// DNS-over-HTTPS (`POST https://<tls_name>/dns-query`).
    Doh,
    /// DNS-over-TLS (port 853).
    Dot,
}

/// One provider's static bootstrap data: a fixed IPv6 + IPv4 address pair (dialed IPv6-first,
/// CLAUDE.md §5.2) and the TLS name verified against the webpki root store. Static IPs +
/// hostname verification dodge the DNS bootstrap chicken-and-egg without pinning a leaf
/// certificate (dig_ecosystem #572 design comment §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderTier {
    id: Tier,
    ipv6: Ipv6Addr,
    ipv4: Ipv4Addr,
    tls_name: &'static str,
    protocol: EncryptedProtocol,
}

/// Mullvad's unfiltered DoH resolver — tier 1.
const MULLVAD_DOH: ProviderTier = ProviderTier {
    id: Tier::MullvadDoh,
    ipv6: Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 2),
    ipv4: Ipv4Addr::new(194, 242, 2, 2),
    tls_name: "dns.mullvad.net",
    protocol: EncryptedProtocol::Doh,
};

/// Mullvad's unfiltered DoT resolver (same network as [`MULLVAD_DOH`]) — tier 2.
const MULLVAD_DOT: ProviderTier = ProviderTier {
    id: Tier::MullvadDot,
    protocol: EncryptedProtocol::Dot,
    ..MULLVAD_DOH
};

/// Quad9's unfiltered DoT resolver — tier 3 (provider diversity from Mullvad).
const QUAD9_DOT: ProviderTier = ProviderTier {
    id: Tier::Quad9Dot,
    ipv6: Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0010),
    ipv4: Ipv4Addr::new(9, 9, 9, 10),
    tls_name: "dns10.quad9.net",
    protocol: EncryptedProtocol::Dot,
};

/// The fixed, user-decided fallback chain, in try order (dig_ecosystem #572 design comment §3).
/// The OS stub resolver — tier 4 — is not a member of this array: it is a categorically
/// different, unencrypted availability net, handled separately by [`resolve_scoped`].
const PROVIDER_CHAIN: [ProviderTier; 3] = [MULLVAD_DOH, MULLVAD_DOT, QUAD9_DOT];

/// Whether `host` is [`UPSTREAM_HOST`] — an EXACT match (never a suffix, so
/// `evil-rpc.dig.net`/`rpc.dig.net.evil.example` never qualify), tolerant of a trailing FQDN dot
/// and of case. Every other name — `dig.local`, `localhost`, a loopback probe IP — is left to
/// the OS resolver with no added latency, which is what makes it safe to wire [`SecureResolver`]
/// into every `reqwest` client dig-dns builds, not just the one that can reach `rpc.dig.net`.
pub fn is_scoped_host(host: &str) -> bool {
    host.trim_end_matches('.')
        .eq_ignore_ascii_case(UPSTREAM_HOST)
}

/// Try each `candidates` entry in order, awaiting `attempt` for each and returning the first
/// non-empty success — short-circuiting before ever trying the next one. This is the WHOLE
/// fallback contract (dig_ecosystem #572 design comment §3): pure control flow, generic over
/// how an attempt is actually performed, so it is exercised directly in tests with injected
/// canned outcomes (no network) and reused, unmodified, by the live resolution path.
async fn resolve_with_fallback<'a, C, F, Fut>(
    candidates: &'a [C],
    mut attempt: F,
) -> Option<(&'a C, Vec<IpAddr>)>
where
    F: FnMut(&'a C) -> Fut,
    Fut: Future<Output = Option<Vec<IpAddr>>>,
{
    for candidate in candidates {
        if let Some(addrs) = attempt(candidate).await {
            if !addrs.is_empty() {
                return Some((candidate, addrs));
            }
        }
    }
    None
}

/// Build the `NameServerConfig` pair (IPv6 first, then IPv4) for one provider tier.
fn provider_name_servers(tier: &ProviderTier) -> ResolverConfig {
    let server_name: Arc<str> = Arc::from(tier.tls_name);
    let mut config = ResolverConfig::default();
    for ip in [IpAddr::V6(tier.ipv6), IpAddr::V4(tier.ipv4)] {
        config.add_name_server(match tier.protocol {
            // `None` path defaults to `/dns-query` — Mullvad's own DoH endpoint.
            EncryptedProtocol::Doh => NameServerConfig::https(ip, server_name.clone(), None),
            EncryptedProtocol::Dot => NameServerConfig::tls(ip, server_name.clone()),
        });
    }
    config
}

/// Build one tier's `hickory-resolver` client: its two name servers, tried strictly in order
/// (`UserProvidedOrder` + `num_concurrent_reqs = 1`, so IPv4 is only ever dialed after the IPv6
/// attempt fails — never raced), a single attempt per tier (the CHAIN is the retry ladder; this
/// resolver should not multiply that with its own retries), and a short per-tier timeout.
/// Pure configuration — building a resolver performs no I/O.
fn build_tier_resolver(
    tier: &ProviderTier,
) -> Result<TokioResolver, hickory_resolver::net::NetError> {
    let mut opts = ResolverOpts::default();
    opts.timeout = TIER_TIMEOUT;
    opts.attempts = 1;
    opts.num_concurrent_reqs = 1;
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    opts.ip_strategy = LookupIpStrategy::Ipv6thenIpv4;

    Resolver::builder_with_config(provider_name_servers(tier), TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
}

/// Resolve `host` via the OS stub resolver — the same mechanism `reqwest`'s own default resolver
/// uses (a blocking `getaddrinfo` off `tokio::net::lookup_host`). This is tier 4: the terminal
/// availability net, and dig-dns's ENTIRE pre-#574 behavior for every lookup.
async fn os_resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
        .await?
        .map(|s| s.ip())
        .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("the OS resolver returned no addresses for {host}"),
        ));
    }
    Ok(addrs)
}

/// The encrypted-upstream resolver dig-dns wires into every `reqwest` client it builds
/// (dig_ecosystem #574). Cheap to clone (an `Arc`-backed `hickory-resolver` client per tier),
/// which [`Resolve::resolve`] requires — the returned future must be `'static` and so cannot
/// borrow `&self`.
#[derive(Clone)]
pub struct SecureResolver {
    /// One built resolver per [`PROVIDER_CHAIN`] entry, same order.
    tiers: Vec<(Tier, TokioResolver)>,
}

impl SecureResolver {
    /// Build the resolver, constructing one `hickory-resolver` client per encrypted tier. No
    /// I/O is performed here — the network isn't touched until the first lookup.
    pub fn new() -> Result<Self, hickory_resolver::net::NetError> {
        let tiers = PROVIDER_CHAIN
            .iter()
            .map(|tier| {
                Ok::<_, hickory_resolver::net::NetError>((tier.id, build_tier_resolver(tier)?))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { tiers })
    }
}

/// Resolve `host` — expected to be [`UPSTREAM_HOST`] — via the encrypted chain, falling back to
/// the OS resolver as the terminal availability net. The returned `Tier` is `None` exactly when
/// the OS-resolver net had to be used: the lookup was not end-to-end encrypted (surfaced by
/// `doctor --json` as `secure_upstream: degraded`) — though the connection this enables is still
/// TLS-authenticated by webpki regardless of how its address was learned, so no integrity is
/// lost, only the confidentiality of the lookup itself (dig_ecosystem #572 design comment §3).
pub async fn resolve_scoped(
    resolver: &SecureResolver,
    host: &str,
) -> io::Result<(Option<Tier>, Vec<IpAddr>)> {
    let encrypted = resolve_with_fallback(&resolver.tiers, |(_, tier_resolver)| async move {
        match tier_resolver.lookup_ip(host).await {
            Ok(lookup) => {
                let addrs: Vec<IpAddr> = lookup.iter().collect();
                (!addrs.is_empty()).then_some(addrs)
            }
            Err(_) => None,
        }
    })
    .await;

    match encrypted {
        Some(((tier, _), addrs)) => Ok((Some(*tier), addrs)),
        None => Ok((None, os_resolve(host).await?)),
    }
}

impl Resolve for SecureResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Every name except UPSTREAM_HOST bypasses the chain entirely — no added latency
            // for dig.local/localhost/loopback-literal dials (see the module doc + is_scoped_host).
            let addrs = if is_scoped_host(&host) {
                resolve_scoped(&this, &host)
                    .await
                    .map(|(_tier, addrs)| addrs)
            } else {
                os_resolve(&host).await
            }
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            let sockets: Addrs = Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(sockets)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // --- pure data: chain order, IPv6-first, TLS names, provider identity -----------------

    #[test]
    fn provider_chain_is_in_the_decided_try_order() {
        assert_eq!(
            PROVIDER_CHAIN.map(|t| t.id),
            [Tier::MullvadDoh, Tier::MullvadDot, Tier::Quad9Dot]
        );
    }

    #[test]
    fn mullvad_tiers_share_bootstrap_ips_and_differ_only_by_protocol() {
        assert_eq!(MULLVAD_DOH.ipv6, MULLVAD_DOT.ipv6);
        assert_eq!(MULLVAD_DOH.ipv4, MULLVAD_DOT.ipv4);
        assert_eq!(MULLVAD_DOH.tls_name, MULLVAD_DOT.tls_name);
        assert_eq!(MULLVAD_DOH.protocol, EncryptedProtocol::Doh);
        assert_eq!(MULLVAD_DOT.protocol, EncryptedProtocol::Dot);
    }

    #[test]
    fn provider_static_bootstrap_addresses_match_the_decided_chain() {
        assert_eq!(
            MULLVAD_DOH.ipv6,
            Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 2)
        );
        assert_eq!(MULLVAD_DOH.ipv4, Ipv4Addr::new(194, 242, 2, 2));
        assert_eq!(MULLVAD_DOH.tls_name, "dns.mullvad.net");
        assert_eq!(
            QUAD9_DOT.ipv6,
            Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0010)
        );
        assert_eq!(QUAD9_DOT.ipv4, Ipv4Addr::new(9, 9, 9, 10));
        assert_eq!(QUAD9_DOT.tls_name, "dns10.quad9.net");
    }

    #[test]
    fn upstream_host_matches_the_rpc_gateway_base() {
        // Guards UPSTREAM_HOST against drifting from the §5.3 ladder's own constant.
        assert!(crate::node::RPC_DIG_NET_BASE.ends_with(UPSTREAM_HOST));
    }

    // --- pure logic: which names are in scope for the encrypted chain ---------------------

    #[test]
    fn only_rpc_dig_net_is_scoped_to_the_encrypted_chain() {
        assert!(is_scoped_host("rpc.dig.net"));
        assert!(is_scoped_host("rpc.dig.net.")); // FQDN trailing dot
        assert!(is_scoped_host("RPC.DIG.NET")); // case-insensitive
        assert!(!is_scoped_host("dig.local"));
        assert!(!is_scoped_host("localhost"));
        assert!(!is_scoped_host("evil-rpc.dig.net"));
        assert!(!is_scoped_host("rpc.dig.net.evil.example"));
    }

    // --- pure control flow: the fallback contract, no network needed ----------------------

    #[tokio::test]
    async fn falls_through_failing_tiers_in_order() {
        let attempted = RefCell::new(Vec::new());
        let chain = [Tier::MullvadDoh, Tier::MullvadDot, Tier::Quad9Dot];
        let found = resolve_with_fallback(&chain, |tier| {
            let tier = *tier;
            attempted.borrow_mut().push(tier);
            async move {
                match tier {
                    Tier::Quad9Dot => Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10))]),
                    _ => None,
                }
            }
        })
        .await;

        assert_eq!(
            found.map(|(t, a)| (*t, a)),
            Some((Tier::Quad9Dot, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10))]))
        );
        assert_eq!(
            *attempted.borrow(),
            vec![Tier::MullvadDoh, Tier::MullvadDot, Tier::Quad9Dot]
        );
    }

    #[tokio::test]
    async fn stops_at_first_success_never_tries_the_remaining_tiers() {
        let attempted = RefCell::new(Vec::new());
        let chain = [Tier::MullvadDoh, Tier::MullvadDot, Tier::Quad9Dot];
        let found = resolve_with_fallback(&chain, |tier| {
            let tier = *tier;
            attempted.borrow_mut().push(tier);
            async move {
                (tier == Tier::MullvadDot).then(|| vec![IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2))])
            }
        })
        .await;

        assert_eq!(found.unwrap().0, &Tier::MullvadDot);
        assert_eq!(
            *attempted.borrow(),
            vec![Tier::MullvadDoh, Tier::MullvadDot],
            "Quad9Dot must never be attempted once MullvadDot already answered"
        );
    }

    #[tokio::test]
    async fn empty_address_list_is_not_treated_as_success() {
        let chain = [Tier::MullvadDoh, Tier::MullvadDot];
        let found = resolve_with_fallback(&chain, |tier| {
            let tier = *tier;
            async move {
                match tier {
                    Tier::MullvadDoh => Some(vec![]), // answered, but with nothing usable
                    Tier::MullvadDot => Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
                    _ => None,
                }
            }
        })
        .await;

        assert_eq!(found.unwrap().0, &Tier::MullvadDot);
    }

    #[tokio::test]
    async fn all_tiers_failing_yields_none_for_the_caller_to_treat_as_degraded() {
        let chain = [Tier::MullvadDoh, Tier::MullvadDot, Tier::Quad9Dot];
        let found = resolve_with_fallback(&chain, |_| async { None }).await;
        assert!(found.is_none());
    }

    // --- provider config shape: IPv6-first, webpki hostname (not a leaf pin) --------------

    #[test]
    fn mullvad_doh_name_servers_are_ipv6_first_https_with_the_tls_hostname() {
        let config = provider_name_servers(&MULLVAD_DOH);
        let servers = config.name_servers();
        assert_eq!(servers.len(), 2, "IPv6 then IPv4 (CLAUDE.md §5.2)");
        assert_eq!(servers[0].ip, IpAddr::V6(MULLVAD_DOH.ipv6));
        assert_eq!(servers[1].ip, IpAddr::V4(MULLVAD_DOH.ipv4));
        for server in servers {
            match &server.connections[0].protocol {
                hickory_resolver::config::ProtocolConfig::Https { server_name, .. } => {
                    // A hostname string verified against webpki roots — never a leaf-cert pin
                    // (dig_ecosystem #572 design comment §3).
                    assert_eq!(&**server_name, "dns.mullvad.net");
                }
                other => panic!("expected an HTTPS (DoH) connection, got {other:?}"),
            }
        }
    }

    #[test]
    fn quad9_name_servers_use_dns_over_tls() {
        let config = provider_name_servers(&QUAD9_DOT);
        match &config.name_servers()[0].connections[0].protocol {
            hickory_resolver::config::ProtocolConfig::Tls { server_name } => {
                assert_eq!(&**server_name, "dns10.quad9.net");
            }
            other => panic!("expected a TLS (DoT) connection, got {other:?}"),
        }
    }

    #[test]
    fn every_tier_builds_a_resolver_without_touching_the_network() {
        for tier in &PROVIDER_CHAIN {
            build_tier_resolver(tier).expect("tier resolver construction is pure config");
        }
    }

    #[test]
    fn secure_resolver_construction_succeeds_offline() {
        SecureResolver::new().expect("no network access is needed to build the chain's clients");
    }

    // --- a live-network sanity check (ignored by default in CI; run manually) -------------

    #[tokio::test]
    #[ignore = "hits real Mullvad/Quad9/OS resolvers over the live network"]
    async fn resolves_rpc_dig_net_over_the_live_encrypted_chain() {
        let resolver = SecureResolver::new().unwrap();
        let (tier, addrs) = resolve_scoped(&resolver, UPSTREAM_HOST).await.unwrap();
        assert!(!addrs.is_empty());
        eprintln!("resolved {UPSTREAM_HOST} via {tier:?}: {addrs:?}");
    }
}
