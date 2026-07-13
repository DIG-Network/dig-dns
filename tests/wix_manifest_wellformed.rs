//! Regression guard for the WiX MSI source (`wix/main.wxs`).
//!
//! The v0.11.0 tag release failed its `build (windows-x64.exe)` job at the "Build Windows .msi
//! (WiX)" step (dig_ecosystem #530): the #530 comment additions put a literal `--browser-policy`
//! flag inside the file's top XML comment block. Per the XML specification a comment body may not
//! contain the sequence `--`, so `wix build` rejected the manifest with
//! `WIX0104: An XML comment cannot contain '--', and '-' cannot be the last character`, and no MSI
//! was produced — sinking the whole release pipeline.
//!
//! This test parses every XML comment in the manifest and asserts each one obeys those two rules,
//! so a malformed comment fails here (fast, on every OS) long before it reaches the Windows-only
//! WiX build in CI.

use std::path::PathBuf;

/// Absolute path to the WiX manifest under test, resolved from the crate root.
fn wix_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wix/main.wxs")
}

/// A single XML comment located in the source, kept with its 1-based start line for diagnostics.
struct XmlComment {
    /// Line (1-based) where the opening `<!--` sits — so a failure points at the exact comment.
    start_line: usize,
    /// The text strictly between `<!--` and `-->` (the comment body the XML spec constrains).
    body: String,
}

/// Extracts every `<!-- ... -->` comment from `source`, in document order.
///
/// The scan is delimiter-driven rather than a full XML parse: it is the minimal, dependency-free
/// way to reproduce exactly what `wix build` checks (WIX0104), and it never confuses the
/// `<!--`/`-->` delimiters with a `--` inside a comment body.
fn extract_xml_comments(source: &str) -> Vec<XmlComment> {
    let mut comments = Vec::new();
    let mut rest = source;
    let mut consumed = 0usize;

    while let Some(open) = rest.find("<!--") {
        let body_start = consumed + open + "<!--".len();
        let after_open = &source[body_start..];
        let close = after_open
            .find("-->")
            .expect("unterminated XML comment in wix/main.wxs");
        let body = after_open[..close].to_string();

        comments.push(XmlComment {
            start_line: source[..body_start].lines().count(),
            body,
        });

        let advance = open + "<!--".len() + close + "-->".len();
        consumed += advance;
        rest = &source[consumed..];
    }

    comments
}

#[test]
fn wix_manifest_has_no_malformed_xml_comments() {
    let path = wix_manifest_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

    for comment in extract_xml_comments(&source) {
        assert!(
            !comment.body.contains("--"),
            "wix/main.wxs comment starting at line {} contains '--', which WiX rejects (WIX0104): {:?}",
            comment.start_line,
            comment.body.trim(),
        );
        assert!(
            !comment.body.ends_with('-'),
            "wix/main.wxs comment starting at line {} ends with '-', which WiX rejects (WIX0104): {:?}",
            comment.start_line,
            comment.body.trim(),
        );
    }
}
