//! Ensuring `http://dig.local` reaches the local dig-node (SPEC §12) — the idempotent decision
//! logic + target discovery, kept PURE (no sockets) so it is unit-tested directly; the actual
//! bind + reverse-proxy serve loop is `server.rs` glue (the same pure/glue split as
//! `gateway.rs`/`dns.rs` use elsewhere in this crate).
//!
//! `dig.local` is a hosts-file-mapped hostname (the installer's concern, #91) distinct from the
//! `.dig` TLD this crate otherwise serves: it is dig-node's OWN control/root host (JSON-RPC
//! `POST /`, `GET /health`, …), not a store. DNS carries no port, so `http://dig.local` always
//! implies `:80` at whatever IP the hosts file maps it to (default `127.0.0.2`, matching
//! dig-node's own best-effort bind, SYSTEM.md). `dig-dns` ensures that mapping too: if something
//! already answers there (dig-node's own bind, or dig-dns's own reverse proxy from an earlier
//! start), it does nothing; otherwise it binds a transparent reverse proxy there itself.

use crate::config::Config;
use crate::node::DEFAULT_LOCAL_NODE_PORT;

/// The outcome of one `ensure` attempt (SPEC §12.1) — WHY `dig-dns` did or didn't act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// Something already answers at the `dig.local` address — idempotent no-op; `dig-dns`
    /// never double-binds (never fights dig-node's own best-effort bind, or its own prior
    /// listener from an earlier start).
    AlreadyMapped,
    /// `dig-dns` bound the reverse-proxy listener itself and is now serving `http://dig.local`.
    Established {
        /// The actually-bound port. Unlike the `.dig` gateway (§4), there is no deterministic
        /// fallback port here — `http://dig.local` has no PAC-style indirection to advertise an
        /// alternate port to a browser, so this always equals the configured port (SPEC §12.3).
        bound_port: u16,
    },
    /// The address could not be bound (held by something unrelated, or insufficient privilege).
    /// Logged, never fatal — the `.dig` gateway + DNS responder keep serving regardless, and
    /// the caller (`server::spawn_dig_local_ensure`) retries on an interval until this resolves.
    Unavailable {
        /// The bind error's message.
        reason: String,
    },
}

/// Pure idempotency decision (SPEC §12.1 step 1): given whether something already answers at
/// the `dig.local` address, should `dig-dns` attempt to bind its own reverse-proxy listener
/// there? `true` ⇒ absent, attempt the bind; `false` ⇒ already mapped, no-op.
pub fn should_establish(already_mapped: bool) -> bool {
    !already_mapped
}

/// Resolve the reverse-proxy TARGET (SPEC §12.2): an explicit node override wins entirely (the
/// same §5.3 override the content-serving ladder honors); otherwise the local node's canonical
/// always-on port. Unlike [`crate::node::candidate_bases`], this NEVER falls through to
/// `rpc.dig.net` — `dig.local` names the user's OWN node, so proxying it to the public gateway
/// would defeat the purpose of an ensured LOCAL mapping.
pub fn local_node_target(config: &Config) -> String {
    match &config.node_url {
        Some(url) => url.trim_end_matches('/').to_string(),
        None => format!("http://localhost:{DEFAULT_LOCAL_NODE_PORT}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_establish_is_the_negation_of_already_mapped() {
        assert!(should_establish(false), "absent -> attempt the bind");
        assert!(
            !should_establish(true),
            "already mapped -> no-op, never double-bind"
        );
    }

    #[test]
    fn local_node_target_defaults_to_localhost_canonical_port() {
        assert_eq!(
            local_node_target(&Config::default()),
            "http://localhost:9778"
        );
    }

    #[test]
    fn local_node_target_honors_explicit_override() {
        let cfg = Config {
            node_url: Some("http://127.0.0.1:9999/".to_string()),
            ..Config::default()
        };
        assert_eq!(local_node_target(&cfg), "http://127.0.0.1:9999");
    }

    #[test]
    fn local_node_target_never_falls_back_to_rpc_dig_net() {
        // Unlike node::candidate_bases (the content-serving ladder), the dig.local target has
        // no terminal rpc.dig.net fallback — it names the LOCAL node only.
        assert!(!local_node_target(&Config::default()).contains("rpc.dig.net"));
    }

    #[test]
    fn ensure_outcome_variants_carry_and_compare_their_data() {
        assert_eq!(
            EnsureOutcome::Established { bound_port: 80 },
            EnsureOutcome::Established { bound_port: 80 }
        );
        assert_ne!(
            EnsureOutcome::Established { bound_port: 80 },
            EnsureOutcome::Established { bound_port: 81 }
        );
        assert_eq!(EnsureOutcome::AlreadyMapped, EnsureOutcome::AlreadyMapped);
        assert_ne!(
            EnsureOutcome::Unavailable { reason: "a".into() },
            EnsureOutcome::Unavailable { reason: "b".into() }
        );
    }
}
