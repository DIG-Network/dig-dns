//! Regression guard for the reusable build workflow (`.github/workflows/build-binaries.yml`).
//!
//! `digd` is a first-class alias binary (dig_ecosystem #548): it MUST be built alongside
//! `dig-dns` and published in the SAME release under its own raw-binary asset stem
//! `digd-<ver>-<os_arch>[.exe]` — byte-for-byte the same shape as `dig-dns-<ver>-<os_arch>[.exe]`
//! — so the dig-installer can later resolve it exactly as it resolves `digs` for digstore.
//!
//! The cross-OS build moved out of `release.yml` into the reusable `build-binaries.yml` (#592, so
//! the stable + nightly channels share ONE build); this guard follows it there. It asserts the
//! committed build workflow still builds and stages `digd`, so a well-meaning edit that drops the
//! alias from the release is caught at PR time — long before a tag release would silently ship
//! without the `digd` asset. It mirrors the repo's existing committed-artifact guard
//! (`wix_manifest_wellformed.rs`).

use std::path::PathBuf;

/// The reusable build workflow source, resolved from the crate root.
fn release_workflow() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/build-binaries.yml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// The build step compiles BOTH the primary and the alias binary in one invocation.
#[test]
fn release_builds_both_binaries() {
    let yml = release_workflow();
    assert!(
        yml.contains("--bin dig-dns --bin digd"),
        "release.yml must build both bins (`--bin dig-dns --bin digd`) so the alias ships"
    );
}

/// The staging step publishes the `digd` raw binary under its own `digd-<ver>-<os_arch>` stem,
/// alongside the primary `dig-dns-<ver>-<os_arch>` asset.
#[test]
fn release_stages_the_digd_raw_binary_asset() {
    let yml = release_workflow();
    assert!(
        yml.contains("dist/dig-dns-${VER}-${{ matrix.out_name }}"),
        "release.yml must still stage the primary dig-dns raw binary"
    );
    assert!(
        yml.contains("dist/digd-${VER}-${{ matrix.out_name }}"),
        "release.yml must stage the digd alias raw binary under the `digd-<ver>-<os_arch>` stem"
    );
}
