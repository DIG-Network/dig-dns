//! Build script: on Windows, compile `assets/dig.rc` (the branded DIG application
//! icon) into a Windows resource and link it into every shipped binary in this
//! crate (`dig-dns`, `digd`).
//!
//! `embed_resource::compile` emits `cargo:rustc-link-arg-bins`, which reaches
//! every `[[bin]]` in this crate — there is no bin here that must stay
//! unbranded, so the plain (non-scoped) `compile` call is correct.
//!
//! The result is checked rather than discarded: an environment that cannot
//! compile a resource would otherwise silently ship an unbranded binary, which
//! is precisely the failure this build step exists to prevent.
//!
//! dig-dns declares no RT_MANIFEST of its own (see `assets/dig.rc`'s header),
//! so there is no manifest-ordering concern here — just the icon.
//!
//! No-op on non-Windows.

fn main() {
    #[cfg(windows)]
    embed_icon();
}

#[cfg(windows)]
fn embed_icon() {
    embed_resource::compile("assets/dig.rc", embed_resource::NONE)
        .manifest_required()
        .expect("failed to compile assets/dig.rc — no usable Windows resource compiler?");

    println!("cargo:rerun-if-changed=assets/dig.rc");
    println!("cargo:rerun-if-changed=assets/dig.ico");
}
