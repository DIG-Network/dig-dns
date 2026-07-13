# dig-dns

Local `*.dig` name resolution for the DIG Network. `dig-dns` is a standalone OS service that
lets any browser open `http://<storeId>.dig/<path>` on the machine: it resolves the store's
latest chain-anchored root and serves its resources (SPA bundle — `/index.html` + assets),
fetching content from a **dig-node** over the node's public JSON-RPC read surface. `dig-dns`
is a client of the node, exactly as `digstore` is.

Reliability-first: **two independent resolution paths** — an OS split-DNS responder AND a PAC
proxy the browser can be pointed at — plus a `doctor` diagnostic, so a `.dig` URL still loads
when one path is blocked (e.g. a browser forcing DNS-over-HTTPS).

`SPEC.md` is the normative contract. `dig-dns` registers itself as an OS service via
`dig-dns install` — service id `net.dignetwork.dig-dns`, Windows display name "DIG NETWORK:
DNS", with a clean-reinstall (stop → delete → recreate) so a re-run never hits `CreateService
1073` (SPEC §13). **dig-installer** invokes `dig-dns install` and arranges the OS split-DNS +
loopback alias + browser PAC policy around it.

## How a `.dig` URL resolves

```
http://<label>.dig/<path>
        │  <label> = lowercase RFC 4648 base32 (no padding, 52 chars) of the 32-byte store id
        ▼
   127.0.0.5   (Path A: DNS responder answers *.dig → A 127.0.0.5;  Path B: browser proxies via PAC)
        ▼
   HTTP gateway on 127.0.0.5:80  →  decode label → store id (64-hex)
        │                            path → resource_key ("/" ⇒ index.html; SPA catch-all)
        │                            retrieval_key = SHA-256("urn:dig:chia:<store_id>/<key>")
        ▼
   dig-node  (dig.local → localhost:9778 → rpc.dig.net)
        dig.getAnchoredRoot → latest root   (a <root>.<store>.dig host pins that exact root)
        dig.getContent      → ciphertext + inclusion proof + chunk_lens
        ▼
   verify (merkle inclusion vs the anchored root) → decrypt (AES-256-GCM-SIV) → serve plaintext
```

The store id is 64 hex characters — too long for a 63-char DNS label — so the `.dig` label is
its base32 form. See `SPEC.md §2` for the codec and `§8` for the read-crypto.

**Host forms.** `<store>.dig` serves the store's LATEST anchored root; `<root>.<store>.dig`
(two base32 labels) pins that EXACT root — a capsule (`SPEC §2.1`).

## The two paths — and when each carries traffic

A browser can bypass the OS resolver (DNS-over-HTTPS, its own built-in resolver), so `dig-dns`
offers two independent paths; **either alone** makes a `.dig` URL load:

- **Path A — OS split-DNS.** The installer points the OS resolver for `.dig` at the responder
  (`127.0.0.5:53`), which answers `A 127.0.0.5`; the browser then makes an ordinary origin-form
  request to the gateway. Carries traffic whenever the browser honours the OS resolver.
- **Path B — PAC proxy.** The browser is pointed at the PAC (`/.dig/proxy.pac`, or a file the
  installer writes) that routes `*.dig` through the gateway as an HTTP **proxy** (absolute-form),
  needing no DNS at all. Carries traffic when the browser bypasses OS DNS (forced DoH) — the
  reliable fallback.

Run `dig-dns doctor` to see which path(s) are live.

## What the installer sets up per OS (Component B, dig-installer)

The runtime only binds sockets + answers; the installer (elevated, idempotent, reversible)
wires the OS. It never edits `/etc/hosts`, never URL-rewrites, never intercepts TLS.

- **macOS** — `127.0.0.5` alias on `lo0` (boot-persistent); `/etc/resolver/dig` → `127.0.0.5`;
  a LaunchDaemon runs `dig-dns serve`; a Chrome managed pref points at the PAC.
- **Ubuntu/Linux** — a systemd unit runs `dig-dns serve` as a dedicated user with
  `CAP_NET_BIND_SERVICE`; split-DNS via the detected resolv.conf owner (systemd-resolved `~dig`
  drop-in / NetworkManager-dnsmasq); Chrome/Chromium policy JSON points at the PAC. (`127.0.0.0/8`
  is already up.)
- **Windows** — a Windows Service runs `dig-dns serve`; an NRPT rule
  (`Add-DnsClientNrptRule -Namespace .dig -NameServers 127.0.0.5`) routes `.dig`; Chrome + Edge
  HKLM policy points at the PAC. (`127.0.0.0/8` loopback answers already.)

## The `:80` fallback

Binding `:80` can fail (e.g. Windows `http.sys`, or another server). `dig-dns` then binds the
deterministic fallback `127.0.0.5:8053`, logs it loudly, and reports it in `/.dig/health`
(`bound_port`, `using_fallback`). Path A (origin-form) reaches a browser's default `:80`, so on a
fallback you rely on **Path B** — and the PAC (`/.dig/proxy.pac`, `dig-dns pac`) always advertises
the ACTUAL bound port. `dig-dns` never scans random ports.

## Secure-context caveat

`http://<label>.dig/` is a **plain-HTTP origin** (no TLS interception — by design). Browsers do
NOT treat a `http://…dig` origin as a [secure context](https://developer.mozilla.org/docs/Web/Security/Secure_Contexts)
(only `https://` and `http://localhost` are), so a `.dig` page cannot use secure-context-gated
web APIs: **Service Workers, `crypto.subtle` (Web Crypto), `navigator.geolocation`, camera/mic**,
etc. A `.dig` SPA must not depend on those. (This is a browser policy, not a `dig-dns` limitation;
`dig-dns` never terminates TLS on loopback.)

## CLI

```sh
# Base32 label codec
dig-dns label encode <64-hex-store-id> [--json]   # -> <52-char-base32>.dig
dig-dns label decode <label|host>     [--json]    # -> 64-hex store id

# Config (defaults + environment overrides)
dig-dns config [--json]

# Run the service (HTTP gateway + DNS responder) until Ctrl-C
dig-dns serve [--node <URL>]

# One-shot: resolve a single .dig resource through the pipeline and print it
dig-dns fetch <host|url> [path] [--json]

# Diagnose both paths (exit non-zero if a .dig URL cannot load)
dig-dns doctor [--json]

# Generate the PAC file (uses the actual bound port: --port, else the running gateway, else config)
dig-dns pac [--port <PORT>] [--json]
```

## Configuration — change the IP / ports / TLD

All settings have defaults and are environment-overridable (`SPEC.md §7`):

| Setting | Env var | Default |
|---|---|---|
| loopback bind IP (must be `127.0.0.0/8`) | `DIG_DNS_IP` | `127.0.0.5` |
| DNS port (UDP+TCP) | `DIG_DNS_DNS_PORT` | `53` |
| HTTP port | `DIG_DNS_HTTP_PORT` | `80` |
| HTTP fallback port | `DIG_DNS_HTTP_FALLBACK_PORT` | `8053` |
| browsable TLD | `DIG_DNS_TLD` | `dig` |
| DNS answer TTL (s) | `DIG_DNS_TTL` | `2` |
| dig-node endpoint override | `DIG_NODE_URL` (or `--node`) | ladder |

```sh
# Example: run unprivileged on 127.0.0.1 with a custom TLD + node
DIG_DNS_IP=127.0.0.1 DIG_DNS_HTTP_PORT=8080 DIG_DNS_DNS_PORT=5353 DIG_DNS_TLD=web3 \
  dig-dns serve --node http://localhost:9778
```

## Troubleshooting — keyed to `doctor` checks

`dig-dns doctor` reports one line per check (id in brackets). Fixes:

| `doctor` check | Meaning when it FAILs/WARNs | Fix |
|---|---|---|
| `loopback_ip` | the bind IP is not up locally | installer aliases `127.0.0.5` (`ifconfig lo0 alias` on macOS; `127/8` is usually up on Linux/Windows) |
| `dns_direct` | the DNS responder does not answer on `:53` | start `dig-dns serve` (needs privilege for `:53`); check `DIG_DNS_IP`/`DIG_DNS_DNS_PORT` |
| `os_routing` | the OS does not send `.dig` to the responder (Path A off) | installer configures split-DNS (`/etc/resolver/dig`, NRPT, systemd-resolved) — or rely on Path B |
| `gateway_port` | no gateway on `:80`/`:8053` | start `dig-dns serve`; if it bound the fallback, use the PAC (advertises the bound port) |
| `node_reachable` | gateway is up but no dig-node reachable → content 502s | start your dig-node (`localhost:9778`) or set `--node`/`DIG_NODE_URL` |
| `browser_doh` | browser may auto-enable DoH, bypassing Path A | point the browser at the PAC (Path B) — the installer sets the managed policy |
| `port80_holder` | another process holds `:80` | free `:80`, or keep the `:8053` fallback + PAC |

A `.dig` URL loads iff `loopback_ip` is up AND at least one of Path A (`os_routing`) or Path B
(`gateway_port`) is live. `doctor` exits non-zero otherwise.

## Acceptance scripts

- `scripts/acceptance-unix.sh` — macOS/Linux: starts `dig-dns serve` (unprivileged high ports),
  runs `doctor`, the `/.dig/` control endpoints, the open-proxy `403` + bad-host `404` checks,
  and the DNS-direct probe; optional content + pinned-vs-latest checks with a live node.
- `scripts/acceptance-windows.ps1` — the Windows (PowerShell) equivalent.

## Build & test

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo llvm-cov --fail-under-lines 80 --summary-only
```

## Security

Loopback-only binds (`127.0.0.0/8`), never `0.0.0.0`. Never an open proxy (only `.dig`
authorities are served; `CONNECT` is refused). No TLS interception. No hosts-file / OS-resolver
edits at runtime (those are the installer's job). Content is verified against the chain-anchored
root before it is decrypted and served (fail-closed). See `SPEC.md §5`.

## License

GPL-2.0-only.
