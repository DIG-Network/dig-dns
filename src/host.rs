//! Parsing a `.dig` request host into a resolution target.
//!
//! Two browser-valid host forms are supported (SPEC §2, §4.1; aligns with the #128 URN
//! grammar where a capsule is `storeId:rootHash`):
//!
//! - **`<storeId>.dig`** (one label before the TLD) → resolve the store's LATEST
//!   chain-anchored root.
//! - **`<rootId>.<storeId>.dig`** (two labels; leftmost = the pinned root) → serve that
//!   EXACT root (a capsule). A literal `storeId:rootHash` colon is only the logical/URN
//!   form — `:` is not a valid DNS label character and a browser parses `host:NNN` as a
//!   port — so the pinned root is carried as a left-most subdomain label instead.
//!
//! Each label is the lowercase base32 (RFC 4648, no padding, 52 chars) encoding of a
//! 32-byte id ([`crate::label`]). More than two labels, or any label that is not a valid
//! base32 store/root id, is rejected (the gateway answers 404).

use crate::label::{self, LabelError};

/// What a parsed `.dig` host resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTarget {
    /// `<storeId>.dig` — serve the store's latest chain-anchored root.
    Latest {
        /// 64-lowercase-hex store id.
        store_hex: String,
    },
    /// `<rootId>.<storeId>.dig` — serve this exact pinned root (a capsule).
    Pinned {
        /// 64-lowercase-hex store id.
        store_hex: String,
        /// 64-lowercase-hex pinned generation root.
        root_hex: String,
    },
}

/// Errors from parsing a request host.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// The host did not end with the configured `.<tld>`.
    #[error("host is not under .{0}")]
    NotDigTld(String),
    /// The host had no store label (bare TLD, or an empty label).
    #[error("host has no store label")]
    NoStoreLabel,
    /// The host had more than two labels before the TLD.
    #[error("host has {0} labels before the TLD; expected 1 (store) or 2 (root.store)")]
    TooManyLabels(usize),
    /// A label was not a valid base32 store/root id.
    #[error("invalid store/root label: {0}")]
    BadLabel(#[from] LabelError),
}

/// Parse a request host (from the `Host` header or the absolute-form proxy target authority)
/// into a [`HostTarget`]. A trailing FQDN dot and a `:port` suffix are tolerated. Matching
/// the TLD is case-insensitive; label decoding is case-insensitive (DNS 0x20).
pub fn parse_dig_host(host: &str, tld: &str) -> Result<HostTarget, HostError> {
    // Normalise: trim, drop a trailing FQDN dot, drop a `:port` suffix (labels are base32
    // and never contain ':', so splitting on the first ':' is safe).
    let h = host.trim();
    let h = h.strip_suffix('.').unwrap_or(h);
    let h = h.split(':').next().unwrap_or(h);

    let tld_lower = tld.to_ascii_lowercase();
    let lower = h.to_ascii_lowercase();

    // The bare TLD (e.g. `dig`) names no store.
    if lower == tld_lower {
        return Err(HostError::NoStoreLabel);
    }
    let dot_tld = format!(".{tld_lower}");
    if !lower.ends_with(&dot_tld) {
        return Err(HostError::NotDigTld(tld.to_string()));
    }
    // Strip the trailing `.<tld>` (ASCII, so byte length == char length).
    let remainder = &h[..h.len() - dot_tld.len()];
    if remainder.is_empty() {
        return Err(HostError::NoStoreLabel);
    }
    let labels: Vec<&str> = remainder.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return Err(HostError::NoStoreLabel);
    }
    match labels.as_slice() {
        [store] => Ok(HostTarget::Latest {
            store_hex: label::label_to_store_hex(store)?,
        }),
        // Leftmost label is the pinned root, next is the store.
        [root, store] => Ok(HostTarget::Pinned {
            store_hex: label::label_to_store_hex(store)?,
            root_hex: label::label_to_store_hex(root)?,
        }),
        _ => Err(HostError::TooManyLabels(labels.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 52-char labels for two distinct 32-byte ids.
    const STORE_LABEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // all-zero id
    const STORE_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn root_label_hex() -> (String, String) {
        // A non-zero root id.
        let mut id = [0u8; 32];
        id[31] = 1;
        (label::store_bytes_to_label(&id), hex::encode(id))
    }

    #[test]
    fn one_label_is_latest() {
        assert_eq!(
            parse_dig_host(&format!("{STORE_LABEL}.dig"), "dig").unwrap(),
            HostTarget::Latest {
                store_hex: STORE_HEX.to_string()
            }
        );
    }

    #[test]
    fn two_labels_is_pinned_root_then_store() {
        let (root_label, root_hex) = root_label_hex();
        assert_eq!(
            parse_dig_host(&format!("{root_label}.{STORE_LABEL}.dig"), "dig").unwrap(),
            HostTarget::Pinned {
                store_hex: STORE_HEX.to_string(),
                root_hex,
            }
        );
    }

    #[test]
    fn tolerates_trailing_dot_and_port() {
        assert!(matches!(
            parse_dig_host(&format!("{STORE_LABEL}.dig."), "dig").unwrap(),
            HostTarget::Latest { .. }
        ));
        assert!(matches!(
            parse_dig_host(&format!("{STORE_LABEL}.dig:80"), "dig").unwrap(),
            HostTarget::Latest { .. }
        ));
    }

    #[test]
    fn tld_and_labels_are_case_insensitive() {
        let upper = format!("{STORE_LABEL}.DIG").to_ascii_uppercase();
        assert_eq!(
            parse_dig_host(&upper, "dig").unwrap(),
            HostTarget::Latest {
                store_hex: STORE_HEX.to_string()
            }
        );
    }

    #[test]
    fn honors_custom_tld() {
        assert!(matches!(
            parse_dig_host(&format!("{STORE_LABEL}.web3"), "web3").unwrap(),
            HostTarget::Latest { .. }
        ));
        assert!(matches!(
            parse_dig_host(&format!("{STORE_LABEL}.dig"), "web3"),
            Err(HostError::NotDigTld(_))
        ));
    }

    #[test]
    fn rejects_non_dig_tld() {
        assert!(matches!(
            parse_dig_host("example.com", "dig"),
            Err(HostError::NotDigTld(_))
        ));
    }

    #[test]
    fn rejects_more_than_two_labels() {
        let (root_label, _) = root_label_hex();
        assert_eq!(
            parse_dig_host(
                &format!("{root_label}.{root_label}.{STORE_LABEL}.dig"),
                "dig"
            ),
            Err(HostError::TooManyLabels(3))
        );
    }

    #[test]
    fn rejects_bare_tld_and_empty_label() {
        assert_eq!(parse_dig_host("dig", "dig"), Err(HostError::NoStoreLabel));
        assert_eq!(parse_dig_host(".dig", "dig"), Err(HostError::NoStoreLabel));
    }

    #[test]
    fn rejects_bad_base32_label() {
        assert!(matches!(
            parse_dig_host("short.dig", "dig"),
            Err(HostError::BadLabel(_))
        ));
        // A bad root label in the two-label form is also rejected.
        assert!(matches!(
            parse_dig_host(&format!("short.{STORE_LABEL}.dig"), "dig"),
            Err(HostError::BadLabel(_))
        ));
    }
}
