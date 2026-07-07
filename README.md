# dig-dns

Local `*.dig` name resolution for the DIG Network. `dig-dns` is a standalone OS service that
lets any browser open `http://<storeId>.dig/<path>` on the machine: it resolves the store's
latest chain-anchored root and serves its resources (SPA bundle — `/index.html` + assets),
fetching content from a **dig-node** over the node's public JSON-RPC read surface. `dig-dns`
is a client of the node, exactly as `digstore` is.

Reliability-first: **two independent resolution paths** — an OS split-DNS responder AND a PAC
proxy the browser can be pointed at — plus a `doctor` diagnostic, so a `.dig` URL still loads
when one path is blocked (e.g. a browser forcing DNS-over-HTTPS).

`SPEC.md` is the normative contract. `dig-dns` is installed as an OS service by
**dig-installer** (a separate unit of work).

## How a `.dig` URL resolves

```
http://<label>.dig/<path>
        │
        │  <label> = lowercase RFC 4648 base32 (no padding, 52 chars) of the 32-byte store id
        ▼
   127.0.0.5  (DNS responder answers *.dig → A 127.0.0.5, or the browser proxies via PAC)
        │
        ▼
   HTTP gateway on 127.0.0.5:80  →  decode label → store id (64-hex)
        │                            path → resource_key ("/" ⇒ index.html; SPA catch-all)
        │                            retrieval_key = SHA-256("urn:dig:chia:<store_id>/<key>")
        ▼
   dig-node  (dig.local → localhost:9778 → rpc.dig.net)
        dig.getAnchoredRoot → latest root
        dig.getContent      → ciphertext + inclusion proof + chunk_lens
        │
        ▼
   verify (merkle inclusion vs anchored root) → decrypt (AES-256-GCM-SIV) → serve plaintext
```

The store id is 64 hex characters — too long for a 63-char DNS label — so the `.dig` label is
its base32 form. See `SPEC.md §2` for the codec and `§8` for the read-crypto.

## Status (phased delivery)

| Phase | Scope | State |
|---|---|---|
| 1 | SPEC + scaffold + full CI gate set + base32 label codec + config | this release |
| 2 | HTTP gateway core (origin + proxy forms, SPA catch-all, `/.dig/` endpoints) | next |
| 3 | DNS responder (UDP + TCP `*.dig`) | next |
| 4 | `doctor` diagnostic | next |
| 5 | PAC generation + per-OS acceptance scripts | next |

Per-OS installer integration (Component B) lives in **dig-installer**; the browser proxy
fallback extension (Component C) is tracked separately.

## CLI (Phase 1)

```sh
# Encode a 64-hex store id to its browsable .dig host:
dig-dns label encode <64-hex-store-id>          # -> <52-char-base32>.dig
dig-dns label encode <64-hex-store-id> --json   # -> {"store_id_hex","label","host"}

# Decode a .dig label (or a full <label>.dig host) back to the 64-hex store id:
dig-dns label decode <label|host>
dig-dns label decode <label|host> --json

# Show the resolved configuration (defaults + environment overrides):
dig-dns config
dig-dns config --json
```

## Configuration

All settings have defaults and are environment-overridable (see `SPEC.md §7`): bind IP
(`DIG_DNS_IP`, default `127.0.0.5`, must be loopback), DNS port (`DIG_DNS_DNS_PORT`, `53`),
HTTP port (`DIG_DNS_HTTP_PORT`, `80`) + fallback (`DIG_DNS_HTTP_FALLBACK_PORT`, `8053`), TLD
(`DIG_DNS_TLD`, `dig`), DNS TTL (`DIG_DNS_TTL`, `2`), and the dig-node endpoint override
(`DIG_NODE_URL`; empty ⇒ the `dig.local → localhost:9778 → rpc.dig.net` ladder).

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
