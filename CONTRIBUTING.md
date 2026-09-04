# Contributing to dig-dns

`dig-dns` is the local `*.dig` name resolver for the DIG Network — a standalone OS service
that lets a browser open `http://<storeId>.dig/<path>` by resolving the store's latest
chain-anchored root and serving its resources, fetched from a **dig-node** over its public
JSON-RPC read surface.

## Reporting an issue

File it at [DIG-Network/dig-dns/issues](https://github.com/DIG-Network/dig-dns/issues) with
what you observed, what you expected, and steps to reproduce (OS + `dig-dns doctor --json`
output are especially useful here, since most bugs are "which resolution path is live").

## Prerequisites

- Stable Rust (no `rust-toolchain.toml` pin in this repo — CI installs via
  `dtolnay/rust-toolchain@stable`, so a current stable toolchain via [rustup](https://rustup.rs)
  is enough).
- No OS-service install is needed for ordinary development. The library (`dig_dns`) and its
  integration tests are unit-testable in the foreground: the gateway/DNS-responder tests spin
  up real listeners on ephemeral loopback ports and a **stub dig-node** (a tiny in-process
  `hyper` server answering canned `dig.getAnchoredRoot`/`dig.getContent` responses) — nothing
  reads real chain state or calls `rpc.dig.net`. `cargo test` needs no privilege and no network.
- Registering the real OS service (`dig-dns install`) is only needed if you're changing
  `src/service.rs` / `src/os_config.rs` and want to hand-verify the SCM/launchd/systemd
  integration locally; CI's `service-smoke` and `configure-os-smoke` jobs already cover this
  end-to-end on Windows/macOS/Linux runners (with root/sudo where the OS requires it for the
  privileged `:53`/`:80` binds), so a local install is optional, not required to pass the gate.

## Build & test

```sh
cargo build
cargo test
```

## The gate (must pass before a PR is merged)

CI runs these on every PR (`.github/workflows/ci.yml`); reproduce the core ones locally first:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --fail-under-lines 80 --summary-only   # coverage gated >=80%, CLAUDE.md §2.3
cargo build --all-targets --locked
```

CI's `test` job runs the coverage-gated suite via `cargo-nextest` with 2 retries
(`cargo llvm-cov nextest --all-features --fail-under-lines 80 --summary-only --retries 2`) so a
flaky test is reported as flaky rather than a hard failure — the plain `cargo test`/
`cargo llvm-cov` commands above are equivalent for local iteration.

Beyond those four jobs, CI also runs three heavier smoke jobs you don't need to reproduce
locally unless you're touching what they cover: **`service-smoke`** (real `dig-dns install` /
`status` / `uninstall` against the real Windows SCM / macOS launchd / Linux systemd, on all
three OSes), **`configure-os-smoke`** (Linux-only: `configure-os` actually flips OS split-DNS
live via systemd-resolved, then `unconfigure-os` leaves zero residue), and **`deb-hooks-smoke`**
(builds the real `.deb` and proves its postinst/prerm enable+configure and remove+unconfigure
cleanly). All three build and drive the real release binary, so they're slow — CI is the
right place to let them run.

## PR conventions

- **Conventional Commits**, commitlint-enforced on both the PR title and its commits
  (`.github/workflows/commitlint.yml`, config in `commitlint.config.mjs`) — e.g.
  `feat(gateway): …`, `fix(service): …`, `docs: …`.
- **Bump `[package].version` in `Cargo.toml`** as part of the PR — `ensure-version-increment.yml`
  fails any PR that doesn't strictly increase it versus `main`.
- `main` is protected: every GitHub Flow PR must have all required checks green (Rustfmt,
  Clippy, Test + coverage, Build, plus the version-increment and commitlint gates) and every
  review thread resolved before it can be squash-merged. No direct pushes to `main`.
- **Releases are cron-driven, not merge-driven.** `.github/workflows/nightly-release.yml` runs
  at midnight UTC and also accepts a manual `workflow_dispatch`. Verified directly from this
  repo's own workflow file rather than assumed from the ecosystem default: the `stable` job's
  condition is
  `github.event_name == 'schedule' || inputs.channel == 'stable' || inputs.channel == 'both'`
  — so **the midnight cron cuts a real stable `vX.Y.Z` release automatically** whenever
  `Cargo.toml`'s version has changed since the last tag (it's a no-op otherwise), it isn't
  gated behind a manual dispatch. The same run also publishes a nightly pre-release
  (`nightly-YYYYMMDD` + a rolling `nightly` tag) unconditionally, built from `main` HEAD. In
  practice this means: once your PR merges with a bumped version, the very next midnight cron
  publishes it as a stable release without further action — merge only versions you're ready
  to ship.
