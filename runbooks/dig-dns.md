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

**Run — CLI:**

```sh
dig-dns label encode <64-hex-store-id>     # -> <base32>.dig
dig-dns label decode <label|host>          # -> <64-hex>
dig-dns config [--json]                     # resolved config
dig-dns serve [--node <URL>]               # run the gateway + DNS responder (Ctrl-C to stop)
dig-dns fetch <host|url> [path] [--json]    # one-shot: resolve a .dig resource + print it
dig-dns doctor [--json]                     # diagnose both paths; nonzero if no path can load
```

**`doctor`** checks each link of both resolution paths independently and prints pass/fail + a
fix hint (exit non-zero when a `.dig` URL cannot load): loopback IP up, DNS responder answers
directly, OS routes `.dig` to the loopback IP (Path A), the gateway answers (Path B, primary vs
`:8053` fallback), the gateway can reach a dig-node, the browser DoH/built-in-resolver policy
(informational — explains Path A bypass), and who holds `:80`. `--json` for machine consumption.
Run it to triage after an install.

**Service (`serve`).** Runs BOTH resolution paths on the dedicated loopback IP:

- **HTTP gateway** — `127.0.0.5:80` (deterministic fallback `127.0.0.5:8053` when `:80` is held
  — logged loudly + reported by `/.dig/health`).
- **DNS responder** — `127.0.0.5:53` (UDP + TCP): `*.dig`/apex → `A 127.0.0.5` (TTL 2s,
  0x20-preserved), `AAAA`/other types → NODATA, non-`.dig` → REFUSED, EDNS0/TC → TCP fallback.

Binding `:53` and `:80` on the dedicated IP requires elevation / `CAP_NET_BIND_SERVICE` and that
`127.0.0.5` be up (the installer, Component B, arranges both). The two paths are **independent**:
if the DNS `:53` bind fails (unprivileged, or `:53` held), `serve` logs a warning and continues
gateway-only (Path B via the PAC still serves `.dig`); `/.dig/health` reports `paths.dns`. For an
unprivileged local run, override the binds:

```sh
DIG_DNS_IP=127.0.0.1 DIG_DNS_HTTP_PORT=8080 DIG_DNS_DNS_PORT=5353 \
  dig-dns serve --node http://localhost:9778
# then, in another shell:
curl -s http://127.0.0.1:8080/.dig/health | jq .          # service state (paths.dns, bound_port)
curl -s http://127.0.0.1:8080/.dig/proxy.pac              # PAC (advertises the bound port)
curl -H 'Host: <label>.dig' http://127.0.0.1:8080/        # origin-form (Path A)
curl -x http://127.0.0.1:8080 http://<label>.dig/         # absolute-form proxy (Path B)
dig-dns fetch <label>.dig / --node http://localhost:9778  # curl-free fetch
dig @127.0.0.1 -p 5353 <label>.dig                        # DNS: A 127.0.0.5 (needs BIND tools)
# Windows without BIND tools: Resolve-DnsName -Server 127.0.0.5 <label>.dig
```

Control endpoints (also directly on the IP): `GET /.dig/health` (JSON), `GET /.dig/proxy.pac`
(the PAC with the actually-bound port), `GET /.dig/resolve-probe` (`204`). The gateway is
loopback-only, never an open proxy (a non-`.dig` proxy target → `403`), never tunnels CONNECT,
and never intercepts TLS.

**Acceptance:** `scripts/gateway-acceptance.sh` proves the gateway with curl (control endpoints
+ open-proxy `403` + bad-host `404` need no node; set `STORE_LABEL`/`ROOT_LABEL` + `NODE` for the
content + pinned-vs-latest checks). The Rust integration test `tests/gateway_stub_node.rs` proves
all of it deterministically (both request forms, SPA, ranges, and the pinned-vs-latest proof)
against a stub node.

The PAC CLI + README + per-OS acceptance scripts (Phase 5) land next.

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
