//! The `.dig` DNS-label ↔ storeId codec.
//!
//! A DIG store id is 32 bytes, canonically written as 64 lowercase hex characters. A DNS
//! label is limited to 63 characters (RFC 1035 §2.3.4), so 64 hex chars will NOT fit as a
//! single label. `dig-dns` therefore encodes the 32-byte store id as **lowercase RFC 4648
//! base32 with no padding** — exactly 52 characters — which fits comfortably in one label:
//! the browsable host is `<52-char-base32>.dig`.
//!
//! Base32 (not base64) because DNS labels are case-insensitive and restricted to
//! letters/digits/hyphen (LDH): base32's `a–z2–7` alphabet is all LDH and survives the
//! case-insensitivity, whereas base64 uses case to distinguish symbols and includes
//! non-LDH characters. Decoding is case-insensitive so a resolver applying DNS 0x20
//! bit-mixing (randomised label case, a cache-poisoning defense) still round-trips.
//!
//! This codec is the ONLY representation change between the DNS name and the node lookup:
//! the decoded 32 bytes are rendered back to 64 lowercase hex for the dig-node RPC
//! (`store_id`), matching `digstore_core::Bytes32::to_hex`.

use data_encoding::BASE32_NOPAD;

/// Length in bytes of a DIG store id.
pub const STORE_ID_LEN: usize = 32;

/// Length in characters of the base32 (no-padding) label for a 32-byte store id.
/// `ceil(32 * 8 / 5) = 52`.
pub const LABEL_LEN: usize = 52;

/// Errors from decoding/encoding a `.dig` label.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    /// The label was not exactly [`LABEL_LEN`] characters.
    #[error("label must be {LABEL_LEN} base32 characters, got {0}")]
    WrongLabelLength(usize),
    /// The label contained a character outside the base32 alphabet (`a–z2–7`).
    #[error("label is not valid base32 (RFC 4648, alphabet a-z2-7)")]
    NotBase32,
    /// The base32 decoded to a byte string that was not [`STORE_ID_LEN`] bytes.
    #[error("label decoded to {0} bytes, expected {STORE_ID_LEN}")]
    WrongDecodedLength(usize),
    /// The hex store id was not exactly `2 * STORE_ID_LEN` hex characters.
    #[error("store id must be {} hex characters", STORE_ID_LEN * 2)]
    WrongHexLength(usize),
    /// The hex store id contained a non-hex character.
    #[error("store id is not valid hex")]
    NotHex,
}

/// Encode a 32-byte store id as its lowercase, no-padding base32 DNS label
/// (without the `.dig` suffix).
pub fn store_bytes_to_label(id: &[u8; STORE_ID_LEN]) -> String {
    BASE32_NOPAD.encode(id).to_ascii_lowercase()
}

/// Encode a 64-hex store id as its `.dig` DNS label (without the suffix).
///
/// Rejects any input that is not exactly 64 hex characters.
pub fn store_hex_to_label(store_hex: &str) -> Result<String, LabelError> {
    if store_hex.len() != STORE_ID_LEN * 2 {
        return Err(LabelError::WrongHexLength(store_hex.len()));
    }
    let bytes = hex::decode(store_hex).map_err(|_| LabelError::NotHex)?;
    let id: [u8; STORE_ID_LEN] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| LabelError::WrongHexLength(v.len() * 2))?;
    Ok(store_bytes_to_label(&id))
}

/// Decode a `.dig` DNS label to the 32-byte store id.
///
/// Case-insensitive (DNS 0x20 tolerant). Rejects a wrong length, a non-base32 character,
/// or a base32 string that does not decode to exactly 32 bytes.
pub fn label_to_store_bytes(label: &str) -> Result<[u8; STORE_ID_LEN], LabelError> {
    if label.len() != LABEL_LEN {
        return Err(LabelError::WrongLabelLength(label.len()));
    }
    // Base32 is case-insensitive; canonicalise to the uppercase RFC 4648 alphabet so a
    // resolver's 0x20 case randomisation still decodes.
    let upper = label.to_ascii_uppercase();
    let bytes = BASE32_NOPAD
        .decode(upper.as_bytes())
        .map_err(|_| LabelError::NotBase32)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| LabelError::WrongDecodedLength(v.len()))
}

/// Decode a `.dig` DNS label to the 64-lowercase-hex store id used in the dig-node RPC.
pub fn label_to_store_hex(label: &str) -> Result<String, LabelError> {
    Ok(hex::encode(label_to_store_bytes(label)?))
}

/// Whether `label` is a syntactically valid `.dig` store label (correct length, base32
/// alphabet, decodes to 32 bytes). A cheap gate before doing any work for a request.
pub fn is_valid_label(label: &str) -> bool {
    label_to_store_bytes(label).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    // base32 of 32 zero bytes = 52 'A's, lowercased.
    const ZERO_LABEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SAMPLE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn zero_store_id_encodes_to_52_lowercase_a() {
        assert_eq!(ZERO_LABEL.len(), LABEL_LEN);
        assert_eq!(store_bytes_to_label(&[0u8; STORE_ID_LEN]), ZERO_LABEL);
    }

    #[test]
    fn label_is_always_52_lowercase_chars() {
        let label = store_bytes_to_label(&[0xff; STORE_ID_LEN]);
        assert_eq!(label.len(), LABEL_LEN);
        assert!(label.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')));
    }

    #[test]
    fn hex_to_label_round_trips() {
        let label = store_hex_to_label(SAMPLE_HEX).unwrap();
        assert_eq!(label.len(), LABEL_LEN);
        assert_eq!(label_to_store_hex(&label).unwrap(), SAMPLE_HEX);
    }

    #[test]
    fn bytes_round_trip() {
        let mut id = [0u8; STORE_ID_LEN];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let label = store_bytes_to_label(&id);
        assert_eq!(label_to_store_bytes(&label).unwrap(), id);
    }

    #[test]
    fn decode_is_case_insensitive_for_dns_0x20() {
        let label = store_hex_to_label(SAMPLE_HEX).unwrap();
        let upper = label.to_ascii_uppercase();
        let mixed: String = label
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(label_to_store_hex(&upper).unwrap(), SAMPLE_HEX);
        assert_eq!(label_to_store_hex(&mixed).unwrap(), SAMPLE_HEX);
    }

    #[test]
    fn zero_label_decodes_to_zero_store_id() {
        assert_eq!(
            label_to_store_bytes(ZERO_LABEL).unwrap(),
            [0u8; STORE_ID_LEN]
        );
        assert_eq!(label_to_store_hex(ZERO_LABEL).unwrap(), ZERO_HEX);
    }

    #[test]
    fn rejects_wrong_label_length() {
        assert_eq!(
            label_to_store_bytes(&"a".repeat(51)),
            Err(LabelError::WrongLabelLength(51))
        );
        assert_eq!(
            label_to_store_bytes(&"a".repeat(53)),
            Err(LabelError::WrongLabelLength(53))
        );
        assert_eq!(
            label_to_store_bytes(""),
            Err(LabelError::WrongLabelLength(0))
        );
    }

    #[test]
    fn rejects_non_base32_characters() {
        // '0', '1', '8', '9' and '-' are NOT in the base32 alphabet (a-z2-7).
        let with_digit_zero = format!("{}0", "a".repeat(51));
        assert_eq!(
            label_to_store_bytes(&with_digit_zero),
            Err(LabelError::NotBase32)
        );
        let with_hyphen = format!("{}-", "a".repeat(51));
        assert_eq!(
            label_to_store_bytes(&with_hyphen),
            Err(LabelError::NotBase32)
        );
    }

    #[test]
    fn is_valid_label_agrees_with_decode() {
        assert!(is_valid_label(&store_hex_to_label(SAMPLE_HEX).unwrap()));
        assert!(!is_valid_label("not-a-valid-dig-label"));
        assert!(!is_valid_label(&"a".repeat(51)));
    }

    #[test]
    fn hex_encode_rejects_bad_hex() {
        assert_eq!(
            store_hex_to_label("abc"),
            Err(LabelError::WrongHexLength(3))
        );
        assert_eq!(store_hex_to_label(&"g".repeat(64)), Err(LabelError::NotHex));
    }
}
