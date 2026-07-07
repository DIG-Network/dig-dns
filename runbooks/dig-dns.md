# dig-dns runbook

## What it is

`dig-dns` is the local `*.dig` resolver: a DNS responder + HTTP gateway that resolves
`<label>.dig` to DIG store content fetched from a dig-node. Normative contract: `SPEC.md`.

## Local running

**Prereqs:** a stable Rust toolchain (`rustup`), and — for actually serving content — a
reachable dig-node (the local node on `127.0.0.1:9778`, or fall back to `rpc.dig.net`).

**Build + test:**

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo llvm-cov --fail-under-lines 80 --summary-only
```

**Run (Phase 1 CLI):**

```sh
dig-dns label encode <64-hex-store-id>     # -> <base32>.dig
dig-dns label decode <label|host>          # -> <64-hex>
dig-dns config [--json]                     # resolved config
```

`serve` (the DNS responder + HTTP gateway) and `doctor` land in Phases 2–4. When present,
`serve` binds `127.0.0.5:53` (DNS) + `127.0.0.5:80` (HTTP, fallback `:8053`) — binding `:53`
and `:80` requires elevation / `CAP_NET_BIND_SERVICE`, which the installer arranges.

**Config** is defaults + environment overrides (see `SPEC.md §7`): `DIG_DNS_IP`,
`DIG_DNS_DNS_PORT`, `DIG_DNS_HTTP_PORT`, `DIG_DNS_HTTP_FALLBACK_PORT`, `DIG_DNS_TLD`,
`DIG_DNS_TTL`, and `DIG_NODE_URL` (node endpoint override; empty ⇒ the
`dig.local → localhost:9778 → rpc.dig.net` ladder).

## Deployment / release

Tag-driven, per CLAUDE.md §3.6:

1. A PR to `main` bumps `[package].version` in `Cargo.toml` and passes the CI gate set
   (Rustfmt, Clippy, Test + coverage ≥80%, Build, Lint commit messages, Check version
   increment).
2. On merge to `main`, `.github/workflows/changelog-tag.yml` regenerates `CHANGELOG.md` with
   git-cliff, commits it (`chore(release): vX.Y.Z`), and pushes the `vX.Y.Z` tag — using
   `secrets.RELEASE_TOKEN` (a classic PAT) so the tag triggers the deploy-on-tag workflow and
   the changelog commit is allowed past branch protection.
3. The pushed tag fires `.github/workflows/release.yml`, which builds the `dig-dns` binary for
   windows-x64 / linux-x64 / macos-arm64 / macos-x64 and attaches them to a GitHub Release as
   `dig-dns-<ver>-<os-arch>[.exe]`.

**Secrets:** `RELEASE_TOKEN` (repo or org secret) is REQUIRED for the tag-on-merge release to
fire. **Verify a release:** confirm the `vX.Y.Z` tag exists, the `Release dig-dns` run is
green, and the GitHub Release has the four binaries attached.

**Consumers:** the dig-installer resolves these release binaries and installs `dig-dns` as an
OS service (Component B — a separate unit of work in the dig-installer repo).
