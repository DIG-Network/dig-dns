//! The `.dig` content read path: HTTP path → resource_key, resource_key → retrieval_key,
//! and the verify-then-decrypt pipeline over node-served ciphertext.
//!
//! This is byte-identical to `digstore-core` / `dig-client-wasm`: it reuses the same
//! `Urn`, `resource_leaf`, `MerkleProof`, `derive_decryption_key`, and `decrypt_chunk`, so
//! a `.dig` resource decrypts here exactly as it does in the browser read crate. `dig-dns`
//! serves PUBLIC stores (the URN alone decrypts — no secret salt).
//!
//! Trust model (SPEC §5, §8): the served ciphertext MUST pass merkle-inclusion verification
//! against the trusted anchored root BEFORE it is decrypted; a failure serves no bytes. A
//! GCM tag failure is indistinguishable from a decoy (an unknown key returns ciphertext
//! that simply fails to decrypt) and is surfaced as "not found", never "corrupt".

use base64::Engine;
use digstore_core::codec::Decode;
use digstore_core::crypto::{decrypt_chunk, derive_decryption_key};
use digstore_core::{resource_leaf, Bytes32, MerkleProof, Urn, CHAIN, DEFAULT_RESOURCE_KEY};

/// Errors from the content read path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentError {
    /// The request path contained a traversal component (`.`/`..`), a backslash, or a
    /// control character.
    #[error("invalid or traversing request path")]
    InvalidPath,
    /// The store id was not valid hex.
    #[error("store id is not valid hex")]
    BadStoreId,
    /// The trusted root was not valid hex.
    #[error("trusted root is not valid hex")]
    BadRoot,
    /// The inclusion proof was not valid base64 / a decodable proof.
    #[error("inclusion proof is not valid base64 or encoding")]
    BadProof,
    /// The served ciphertext does not match the proof's leaf (tampered).
    #[error("content does not match its inclusion proof (tampered ciphertext)")]
    ProofLeafMismatch,
    /// The proof path does not fold to its declared root.
    #[error("inclusion proof does not resolve to its declared root")]
    ProofFoldMismatch,
    /// The proof's root is not the trusted anchored root (decoy / wrong store).
    #[error("inclusion proof root does not match the trusted anchored root")]
    RootMismatch,
    /// The chunk lengths do not sum to the ciphertext length.
    #[error("ciphertext length {got} does not match chunk_lens sum {expected}")]
    ChunkLenMismatch { got: usize, expected: usize },
    /// Decryption failed — a decoy (unknown key) or tampered ciphertext.
    #[error("decryption failed (decoy or wrong key)")]
    Decrypt,
}

/// Map an HTTP request path to a store resource_key: strip the leading `/`, map the empty
/// path to `index.html`, and reject traversal. The resource_key is only ever hashed into a
/// retrieval key (never used as a filesystem path), but traversal components are refused
/// anyway (SPEC §4.4, defense in depth).
pub fn resource_key_for_path(path: &str) -> Result<String, ContentError> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return Ok(DEFAULT_RESOURCE_KEY.to_string());
    }
    // Reject backslashes and control characters (incl. NUL) outright.
    if trimmed.contains('\\') || trimmed.bytes().any(|b| b < 0x20) {
        return Err(ContentError::InvalidPath);
    }
    // Reject dot/dot-dot traversal components.
    if trimmed.split('/').any(|c| c == "." || c == "..") {
        return Err(ContentError::InvalidPath);
    }
    Ok(trimmed.to_string())
}

/// `retrieval_key = SHA-256(canonical ROOT-INDEPENDENT urn)`, lowercase hex — the only
/// URN-derived value sent to the node. An empty resource_key uses `index.html`.
pub fn retrieval_key_hex(store_hex: &str, resource_key: &str) -> Result<String, ContentError> {
    let store_id = Bytes32::from_hex(store_hex).map_err(|_| ContentError::BadStoreId)?;
    Ok(canonical_urn(store_id, resource_key)
        .retrieval_key()
        .to_hex())
}

/// The `Content-Type` for a resource_key, inferred from its extension.
pub fn content_type_for(resource_key: &str) -> &'static str {
    let filename = resource_key.rsplit('/').next().unwrap_or(resource_key);
    let ext = match filename.rsplit_once('.') {
        Some((_, e)) => e.to_ascii_lowercase(),
        None => return "application/octet-stream",
    };
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "wasm" => "application/wasm",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}

/// Whether the request path's last segment has no file extension — the SPA catch-all
/// condition (an extensionless not-found path falls back to `index.html`; an extensioned
/// one is a 404).
pub fn is_extensionless(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or(path);
    !last.contains('.')
}

/// Verify the served ciphertext's merkle inclusion against `trusted_root_hex`, then decrypt
/// it, returning the plaintext. Fail-closed: any verification or decryption failure returns
/// an error and no bytes. `chunk_lens` are the per-chunk CIPHERTEXT byte lengths in order
/// (empty ⇒ a single chunk spanning the whole ciphertext) and MUST sum to `ciphertext.len()`.
pub fn verify_and_decrypt(
    store_hex: &str,
    resource_key: &str,
    ciphertext: &[u8],
    inclusion_proof_b64: &str,
    trusted_root_hex: &str,
    chunk_lens: &[u64],
) -> Result<Vec<u8>, ContentError> {
    let store_id = Bytes32::from_hex(store_hex).map_err(|_| ContentError::BadStoreId)?;
    let trusted_root = Bytes32::from_hex(trusted_root_hex).map_err(|_| ContentError::BadRoot)?;
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(inclusion_proof_b64.trim().as_bytes())
        .map_err(|_| ContentError::BadProof)?;
    let proof = MerkleProof::from_bytes(&proof_bytes).map_err(|_| ContentError::BadProof)?;

    // 1) Integrity gate (fail-closed): served bytes ARE the committed leaf, the path folds
    //    to its root, and that root is the trusted anchored root.
    if resource_leaf(ciphertext) != proof.leaf {
        return Err(ContentError::ProofLeafMismatch);
    }
    if !proof.verify() {
        return Err(ContentError::ProofFoldMismatch);
    }
    if proof.root != trusted_root {
        return Err(ContentError::RootMismatch);
    }

    // 2) Confidentiality: derive the URN key (public store ⇒ no salt), split the
    //    plain-concatenated chunk ciphertexts by chunk_lens, GCM-SIV-open each.
    let canonical = canonical_urn(store_id, resource_key).canonical();
    let aes_key = derive_decryption_key(&canonical, None);

    let plan: Vec<usize> = if chunk_lens.is_empty() {
        vec![ciphertext.len()]
    } else {
        chunk_lens.iter().map(|&l| l as usize).collect()
    };
    let mut total: usize = 0;
    for &len in &plan {
        total = total
            .checked_add(len)
            .ok_or(ContentError::ChunkLenMismatch {
                got: ciphertext.len(),
                expected: usize::MAX,
            })?;
    }
    if total != ciphertext.len() {
        return Err(ContentError::ChunkLenMismatch {
            got: ciphertext.len(),
            expected: total,
        });
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut p = 0usize;
    for len in plan {
        let ct = &ciphertext[p..p + len];
        p += len;
        let pt = decrypt_chunk(&aes_key, ct).map_err(|_| ContentError::Decrypt)?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(plaintext)
}

/// Build the canonical root-independent resource URN for a store + key.
fn canonical_urn(store_id: Bytes32, resource_key: &str) -> Urn {
    let key = if resource_key.is_empty() {
        DEFAULT_RESOURCE_KEY
    } else {
        resource_key
    };
    Urn {
        chain: CHAIN.to_string(),
        store_id,
        root_hash: None,
        resource_key: Some(key.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digstore_core::codec::Encode;
    use digstore_core::crypto::encrypt_chunk;
    use digstore_core::MerkleTree;

    const STORE_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// Build a single-resource fixture: derive the key from the URN, encrypt the plaintext
    /// (optionally as several chunks), build the single-leaf tree, and return
    /// (ciphertext, proof_b64, root_hex, chunk_lens) exactly as the node would serve them.
    fn fixture(resource_key: &str, chunks: &[&[u8]]) -> (Vec<u8>, String, String, Vec<u64>) {
        let store_id = Bytes32::from_hex(STORE_HEX).unwrap();
        let canonical = canonical_urn(store_id, resource_key).canonical();
        let key = derive_decryption_key(&canonical, None);

        let mut ciphertext = Vec::new();
        let mut lens = Vec::new();
        for c in chunks {
            let ct = encrypt_chunk(&key, c);
            lens.push(ct.len() as u64);
            ciphertext.extend_from_slice(&ct);
        }
        let leaf = resource_leaf(&ciphertext);
        let tree = MerkleTree::from_leaves(vec![leaf]);
        let proof = tree.prove(0).unwrap();
        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof.to_bytes());
        (ciphertext, proof_b64, tree.root().to_hex(), lens)
    }

    #[test]
    fn resource_key_maps_root_and_paths() {
        assert_eq!(resource_key_for_path("/").unwrap(), "index.html");
        assert_eq!(resource_key_for_path("").unwrap(), "index.html");
        assert_eq!(resource_key_for_path("/index.html").unwrap(), "index.html");
        assert_eq!(
            resource_key_for_path("/assets/app.js").unwrap(),
            "assets/app.js"
        );
    }

    #[test]
    fn resource_key_rejects_traversal() {
        assert_eq!(
            resource_key_for_path("/a/../b"),
            Err(ContentError::InvalidPath)
        );
        assert_eq!(
            resource_key_for_path("/a/./b"),
            Err(ContentError::InvalidPath)
        );
        assert_eq!(
            resource_key_for_path("/a\\b"),
            Err(ContentError::InvalidPath)
        );
        assert_eq!(
            resource_key_for_path("/a\0b"),
            Err(ContentError::InvalidPath)
        );
    }

    #[test]
    fn retrieval_key_is_64_hex_and_rootless_stable() {
        let k = retrieval_key_hex(STORE_HEX, "index.html").unwrap();
        assert_eq!(k.len(), 64);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
        // Empty resource_key resolves to index.html → same key.
        assert_eq!(retrieval_key_hex(STORE_HEX, "").unwrap(), k);
        // A different resource_key yields a different key.
        assert_ne!(retrieval_key_hex(STORE_HEX, "other.js").unwrap(), k);
    }

    #[test]
    fn retrieval_key_matches_direct_urn_derivation() {
        let store_id = Bytes32::from_hex(STORE_HEX).unwrap();
        let expected = canonical_urn(store_id, "assets/app.js")
            .retrieval_key()
            .to_hex();
        assert_eq!(
            retrieval_key_hex(STORE_HEX, "assets/app.js").unwrap(),
            expected
        );
    }

    #[test]
    fn retrieval_key_rejects_bad_store_id() {
        assert_eq!(
            retrieval_key_hex("nothex", "index.html"),
            Err(ContentError::BadStoreId)
        );
    }

    #[test]
    fn verify_and_decrypt_round_trips_single_chunk() {
        let plaintext = b"<!doctype html><title>dig</title>";
        let (ct, proof, root, lens) = fixture("index.html", &[plaintext]);
        let out = verify_and_decrypt(STORE_HEX, "index.html", &ct, &proof, &root, &lens).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn verify_and_decrypt_round_trips_multi_chunk() {
        let (ct, proof, root, lens) = fixture("index.html", &[b"hello ", b"world"]);
        let out = verify_and_decrypt(STORE_HEX, "index.html", &ct, &proof, &root, &lens).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn verify_rejects_wrong_trusted_root() {
        let (ct, proof, _root, lens) = fixture("index.html", &[b"x"]);
        let wrong_root = "2222222222222222222222222222222222222222222222222222222222222222";
        assert_eq!(
            verify_and_decrypt(STORE_HEX, "index.html", &ct, &proof, wrong_root, &lens),
            Err(ContentError::RootMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_ciphertext() {
        let (mut ct, proof, root, lens) = fixture("index.html", &[b"hello"]);
        ct[0] ^= 0xff; // flip a byte → leaf no longer matches the proof
        assert_eq!(
            verify_and_decrypt(STORE_HEX, "index.html", &ct, &proof, &root, &lens),
            Err(ContentError::ProofLeafMismatch)
        );
    }

    #[test]
    fn verify_rejects_chunk_len_mismatch() {
        let (ct, proof, root, _lens) = fixture("index.html", &[b"hello"]);
        let bad_lens = vec![(ct.len() + 5) as u64];
        assert_eq!(
            verify_and_decrypt(STORE_HEX, "index.html", &ct, &proof, &root, &bad_lens),
            Err(ContentError::ChunkLenMismatch {
                got: ct.len(),
                expected: ct.len() + 5
            })
        );
    }

    #[test]
    fn decoy_passes_proof_but_fails_decrypt() {
        // Random bytes that ARE the committed leaf (so the proof verifies) but are not a
        // valid GCM ciphertext under the URN key → a decoy: decrypt fails "not found".
        let decoy = vec![0x42u8; 40];
        let leaf = resource_leaf(&decoy);
        let tree = MerkleTree::from_leaves(vec![leaf]);
        let proof_b64 =
            base64::engine::general_purpose::STANDARD.encode(tree.prove(0).unwrap().to_bytes());
        let root = tree.root().to_hex();
        assert_eq!(
            verify_and_decrypt(STORE_HEX, "index.html", &decoy, &proof_b64, &root, &[]),
            Err(ContentError::Decrypt)
        );
    }

    #[test]
    fn verify_rejects_bad_proof_base64() {
        let (ct, _proof, root, lens) = fixture("index.html", &[b"x"]);
        assert_eq!(
            verify_and_decrypt(
                STORE_HEX,
                "index.html",
                &ct,
                "!!!not base64!!!",
                &root,
                &lens
            ),
            Err(ContentError::BadProof)
        );
    }

    #[test]
    fn content_type_by_extension() {
        assert_eq!(content_type_for("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type_for("app.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type_for("style.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("logo.png"), "image/png");
        assert_eq!(content_type_for("data.json"), "application/json");
        assert_eq!(
            content_type_for("thing.unknownext"),
            "application/octet-stream"
        );
        assert_eq!(content_type_for("noext"), "application/octet-stream");
    }

    #[test]
    fn extensionless_detection() {
        assert!(is_extensionless("/about"));
        assert!(is_extensionless("/users/42"));
        assert!(is_extensionless("/v1.2/thing"));
        assert!(!is_extensionless("/app.js"));
        assert!(!is_extensionless("/img/logo.png"));
    }
}
