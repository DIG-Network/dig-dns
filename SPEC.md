# dig-dns — normative specification

`dig-dns` is a standalone OS service that gives the local machine `*.dig` name resolution:
a browser opening `http://<label>.dig/<path>` loads DIG store content. This document is the
authoritative contract an independent reimplementation MUST satisfy. Key words **MUST**,
**MUST NOT**, **SHOULD**, **MAY** are used per RFC 2119.

`dig-dns` is a **client** of a **dig-node** (the local DIG node, or `rpc.dig.net`): it holds
no content and does no chain I/O of its own — it resolves and serves content the node
provides, exactly as the `digstore` CLI relates to the node. The `.dig` read-crypto it
performs is byte-identical to `digstore-core` / `dig-client-wasm` (§8).

---

## 1. Roles and the two independent paths

`dig-dns` runs two cooperating servers on a dedicated loopback IP (default `127.0.0.5`):

1. a **DNS responder** (UDP + TCP, port 53) that answers `*.dig` with `A 127.0.0.5`; and
2. an **HTTP gateway** (port 80, deterministic fallback 8053) that resolves the store id
   from the request host, fetches content from the dig-node, verifies + decrypts it, and
   serves it.

Because a browser can bypass the OS resolver (DNS-over-HTTPS, its own built-in resolver),
`dig-dns` MUST support **two independent resolution paths**, either of which alone makes a
`.dig` URL load:

- **Path A — OS split-DNS.** The OS is configured (by the installer, out of scope here) to
  send `.dig` queries to the DNS responder, which returns `127.0.0.5`; the browser then
  makes an ordinary origin-form request to the gateway.
- **Path B — PAC proxy.** The browser is pointed at a PAC file (served at
  `/.dig/proxy.pac`) that routes `*.dig` to the gateway as an HTTP **proxy**; the gateway
  handles the absolute-form proxy request directly, needing NO DNS at all.

The `doctor` subcommand (§9) checks each link of each path independently.

`dig-dns` also, independently, ENSURES a THIRD address reaches the local dig-node:
`http://dig.local` (the installer-mapped control host, default `127.0.0.2:80` — distinct from
the dedicated `127.0.0.5` above). This is a plain reverse proxy, not a `.dig` store lookup; see
§12.

---

## 2. The `.dig` DNS-label ↔ storeId codec

A DIG store id is **32 bytes**, canonically **64 lowercase hex** characters
(`digstore_core::Bytes32`). A DNS label is limited to 63 characters (RFC 1035 §2.3.4), so a
64-hex label does not fit. `dig-dns` therefore encodes the store id in the DNS label as:

- **lowercase RFC 4648 base32, no padding** — exactly **52 characters** (`ceil(256/5) = 52`).

### 2.1 Host forms — latest vs pinned root (capsule)

A `.dig` host carries ONE or TWO store labels, selecting which root to serve (aligns with the
#128 URN grammar: a capsule is `storeId:rootHash`):

- **`<storeId>.dig`** (one label before the TLD) → serve the store's LATEST chain-anchored
  root.
- **`<rootId>.<storeId>.dig`** (two labels; the LEFTMOST is the pinned root, the next is the
  store) → serve that EXACT root — a capsule. A literal `storeId:rootHash` colon is only the
  logical/URN form: `:` is not a valid DNS label character and a browser parses `host:NNN` as
  a port, so the pinned root is carried as a left-most subdomain label instead.

Both labels use the SAME 52-char base32 codec (§2, a 32-byte id each; each well under the
63-char label limit). The custom DNS responder answers ANY name ending in `.<tld>` (§3), so a
two-label host resolves fine — it is not bound by real-DNS single-label wildcard semantics.
More than two labels, an empty label, or a label that is not valid base32 is rejected → 404.
Parsing is implemented in `dig_dns::host::parse_dig_host` → `HostTarget::{Latest, Pinned}`.

The browsable host is therefore `<label>.<tld>` (latest) or `<rootLabel>.<storeLabel>.<tld>`
(pinned), e.g. `<52-char-base32>.dig`.

**Rules.**

- Encoding MUST use the RFC 4648 base32 alphabet (`A–Z2–7`) rendered lowercase (`a–z2–7`),
  with padding removed. Base32 (not base64/base32hex) because its alphabet is
  letters-and-digits only (LDH-compatible) and case-insensitive — it survives DNS's
  case-insensitivity and hyphen/label rules; base64 does not.
- Decoding MUST be **case-insensitive**: a resolver applying DNS 0x20 bit-mixing (randomised
  label case, a cache-poisoning defense) MUST still round-trip. Implementations canonicalise
  to the uppercase alphabet before decoding.
- Decoding MUST reject: a label that is not exactly 52 characters; any character outside the
  base32 alphabet; a base32 string that does not decode to exactly 32 bytes. A rejected label
  is not a valid store and MUST NOT be resolved (fast 404 / NXDOMAIN).
- The decoded 32 bytes are the store id; they are rendered back to **64 lowercase hex** for
  the dig-node RPC `store_id`, matching `Bytes32::to_hex`.

This codec is the ONLY representation change between the DNS name and the node lookup. It is
implemented in `dig_dns::label` (`store_hex_to_label`, `label_to_store_hex`,
`store_bytes_to_label`, `label_to_store_bytes`, `is_valid_label`).

---

## 3. DNS responder contract

The responder binds **UDP and TCP on `<loopback_ip>:53`** (default `127.0.0.5:53`). It MUST
NOT bind `0.0.0.0` or any routable interface (§5).

Answering policy, by query:

| Query | Response |
|---|---|
| `<label>.dig` or the apex `dig`, type **A** | `A <loopback_ip>` (default `127.0.0.5`), TTL 1–5 s (default 2) |
| any `*.dig` name, type **AAAA** | NODATA (`NOERROR`, empty answer) — no IPv6 loopback answer |
| any `*.dig` name, any other type (MX, TXT, …) | NODATA (`NOERROR`, empty answer) |
| any name NOT under `.dig` | **REFUSED** — `dig-dns` is authoritative only for `.dig`; it is not a recursive resolver |

Additional requirements:

- The responder MUST answer regardless of the base32 label's validity for an **A** query
  (return `127.0.0.5`); an invalid label is rejected later by the gateway with a fast 404,
  so DNS stays a cheap constant-time wildcard. It MUST NOT perform node I/O to answer DNS.
- It MUST preserve the exact case of the queried name in the answer (0x20 echo).
- It MUST support **EDNS0**: echo an OPT record when present; it MUST NOT expand the
  answer beyond the negotiated UDP payload size — on overflow it sets **TC** so the client
  retries over **TCP**, and it MUST serve the same answer over TCP.
- It MUST NOT ever answer with `0.0.0.0` or a non-loopback address.
- TTL MUST be short (1–5 s) so an uninstall / re-point takes effect quickly.

Verify (no installer needed): `dig @127.0.0.5 -p 53 <label>.dig` → `127.0.0.5`;
`dig @127.0.0.5 -p 53 <label>.dig AAAA` → NOERROR/empty; `dig @127.0.0.5 -p 53 example.com` →
REFUSED. On Windows without BIND tools: `Resolve-DnsName -Server 127.0.0.5 <label>.dig`.

---

## 4. HTTP gateway contract

The gateway binds **`<loopback_ip>:80`** (default `127.0.0.5:80`). If `:80` cannot be bound
(e.g. held by `http.sys` or another server) it MUST fall back deterministically to
`<loopback_ip>:8053` and report the actually-bound port via `/.dig/health` and the PAC file.
It MUST NOT bind `0.0.0.0` (§5).

### 4.1 Request forms

The gateway accepts exactly two request shapes and MUST reject everything else:

- **Origin-form** (Path A): a normal request with `Host: <label>.<tld>` and a path
  (`GET /assets/app.js HTTP/1.1`). Used after OS DNS points the host at `127.0.0.5`.
- **Absolute-form** (Path B): an HTTP proxy request whose target is an absolute URI
  (`GET http://<label>.<tld>/assets/app.js HTTP/1.1`). Used when the browser proxies via the
  PAC file.

The store label is taken from the `Host` header (origin-form) or the absolute-URI authority
(absolute-form); the resource path is the request path in both.

### 4.2 Not an open proxy (§5)

- A **CONNECT** request MUST be rejected (`405`/`403`) — `dig-dns` never tunnels; it does no
  TLS interception.
- An absolute-form request whose authority is **not** under `.<tld>` MUST be rejected with
  **403** and MUST NOT be forwarded anywhere. `dig-dns` is a `.dig`-only gateway, never a
  general forward proxy.
- A request whose host is not a syntactically valid `<label>.<tld>` (bad/oversized label)
  MUST get a fast **404** without any node I/O.

### 4.3 Resolution + serving

For a valid `.dig` host and request path `/<path>`:

1. Parse the host into a `HostTarget` (§2.1): `Latest { store_id }` (one label) or
   `Pinned { store_id, root }` (two labels; the pinned root).
2. Map the path to a **resource_key** (§4.4) and derive its `retrieval_key` (§8).
3. Determine the trusted root:
   - **Latest** → call `dig.getAnchoredRoot { store_id }` to get the current chain-anchored
     root (§6.1);
   - **Pinned** → use the root from the host directly (no `getAnchoredRoot`).
4. Fetch the resource via `dig.getContent { store_id, retrieval_key, root }` (§6.2) and
   verify + decrypt against the trusted root (§8). This yields plaintext bytes or a "not
   found in this store" outcome (a decoy/decrypt failure, or a `-32004`/`-32005` node error).
   For a pinned root, `dig.getContent` serves that exact generation; the served proof MUST
   fold to the pinned root or the response is refused.
5. **SPA catch-all** (§4.5) decides, for a not-found path, whether to serve `/index.html` or
   return 404.
6. Serve the plaintext with a correct `Content-Type` (§4.6), supporting `GET`, `HEAD`, and
   byte-`Range` requests.

A pinned-root host therefore serves that exact generation even after the store has advanced,
whereas a bare-store host always tracks the latest anchored root.

### 4.4 Path → resource_key

- Strip the leading `/`.
- An empty path (`/`) maps to the default resource key **`index.html`**
  (`digstore_core::DEFAULT_RESOURCE_KEY`).
- Otherwise the resource_key is the remaining path, forward-slash separated, verbatim
  (e.g. `/assets/app.js` → `assets/app.js`). This matches the producer's key convention.
- The gateway MUST reject/normalise path traversal (`..`, encoded `%2e%2e`, backslashes,
  NUL) so a resource_key can never escape the store namespace (§5). A traversal attempt is a
  400/404, never a filesystem read (the gateway holds no filesystem content — but the
  resource_key MUST still be normalised before it is hashed into a retrieval key).

### 4.5 SPA catch-all (bundle model)

DIG stores that back a `.dig` site are single-page-app bundles. A "not found" resource — a
decrypt/tag failure (the DIG decoy behaviour: an unknown key returns indistinguishable
ciphertext that fails to decrypt, §8), or an explicit node `-32004`/`-32005` — is resolved as:

- if the request path has **no file extension** (a client-side route, e.g. `/about`,
  `/users/42`) → serve `/index.html` with `200` so the SPA router handles it (deep links
  survive a hard reload);
- if the request path **has** a file extension (e.g. `/missing.js`, `/img/x.png`) → return
  **404**.

`/index.html` itself failing to resolve is a genuine `404`/`502` (nothing to fall back to).

### 4.6 Response headers

- `Content-Type` MUST be inferred from the resource_key's extension (a built-in extension
  map; `application/octet-stream` when unknown). HTML is `text/html; charset=utf-8`.
- `HEAD` MUST return the same headers as `GET` with no body.
- Byte-`Range` (`Range: bytes=…`) MUST be honoured with `206 Partial Content` +
  `Content-Range` + `Accept-Ranges: bytes` (the gateway holds the whole decrypted resource
  in memory for a request and slices it).
- **Caching:** because a resource is addressed by a content-hash root, per-root content is
  immutable. The gateway MAY send `Cache-Control: immutable` ONLY when the response is pinned
  to a concrete root it resolved this request; the default (root resolved fresh each request)
  uses a short/`no-cache` policy so a new generation is picked up promptly.
- **Origin isolation:** the gateway MUST NOT set permissive CORS (`Access-Control-Allow-Origin: *`)
  — each `<label>.dig` is its own web origin and MUST stay isolated from every other store.

### 4.7 `/.dig/` control endpoints

Reserved under every `.dig` host AND directly on the loopback IP:

- `GET /.dig/health` → `200` JSON `{ "status": "ok", "version": "<semver>", "bound_port":
  <u16>, "loopback_ip": "127.0.0.5", "tld": "dig", "node": { … resolved node info … },
  "paths": { "dns": <bool>, "gateway": <bool> } }`. Machine-readable service state (§6.2).
- `GET /.dig/proxy.pac` → `200 application/x-ns-proxy-autoconfig` — a PAC file whose
  `FindProxyForURL` routes `*.<tld>` to `PROXY <loopback_ip>:<actual bound port>` and
  everything else `DIRECT`. It MUST embed the ACTUAL bound gateway port (§4, fallback-aware).
- `GET /.dig/resolve-probe` → `204 No Content` — a zero-body liveness probe used by `doctor`
  and health checks to confirm the gateway answers without triggering a store fetch.

These endpoints MUST be answerable even when the host label is invalid/absent (they describe
the service, not a store).

---

## 5. Security constraints (HARD)

- **Loopback-only.** Every listener (DNS 53, gateway 80/8053) MUST bind a loopback address
  (`127.0.0.0/8`, default `127.0.0.5`). `dig-dns` MUST NEVER bind `0.0.0.0` or a routable
  interface. Config that names a non-loopback bind IP MUST be refused at startup.
- **Never an open proxy.** The absolute-form handler serves ONLY `.<tld>` authorities; any
  other authority is `403` and is never forwarded. `CONNECT` is refused. There is no
  general forward-proxy path.
- **No TLS interception.** `dig-dns` serves plain HTTP on loopback and never terminates or
  man-in-the-middles TLS. `.dig` is an `http://` origin on the local machine.
- **No hosts-file edits, no OS DNS reconfiguration at runtime.** The runtime MUST NOT modify
  `/etc/hosts`, `/etc/resolver`, NRPT rules, or any OS resolver configuration. Those are the
  installer's concern (Component B); the runtime only binds its sockets and answers.
- **DNS-rebinding defense.** The gateway MUST reject a request whose host is not a valid
  `<label>.<tld>` (a public domain pointed at `127.0.0.5` is refused), so even though it binds
  loopback it never serves a foreign-named request.
- **Verify-then-decrypt, fail-closed (§8).** Content served to the browser MUST have passed
  merkle-inclusion verification against the resolved anchored root before it is decrypted and
  returned. A verification or decryption failure MUST NOT serve bytes.
- **No secrets.** `dig-dns` handles no private keys and no wallet material; it serves only
  public store content (public stores decrypt from the URN alone — no secret salt, §8).

The IPv6-first rule (CLAUDE.md §5.2) targets peer↔peer node comms; `dig-dns`'s listeners are
deliberately IPv4 loopback (`127.0.0.5`) local endpoints and are out of that rule's scope.

---

## 6. dig-node dependency — the read contract

`dig-dns` speaks the dig-node control JSON-RPC (JSON-RPC 2.0 over HTTP `POST /`). It uses two
methods, both on the node's **unauthenticated public read** surface (no mTLS / no §21.9
signed-request headers required):

### 6.1 `dig.getAnchoredRoot` — latest root

```
POST <node>/   {"jsonrpc":"2.0","id":1,"method":"dig.getAnchoredRoot",
                "params":{"store_id":"<64-hex>"}}
-> {"jsonrpc":"2.0","id":1,"result":{"store_id":"<64-hex>","root":"<64-hex>"}}
```

The node resolves the tip by walking the CHIP-0035 DataStore singleton lineage on chain; it
fails closed if the chain can't confirm.

### 6.2 `dig.getContent` — windowed ciphertext + proof

```
POST <node>/   {"jsonrpc":"2.0","id":1,"method":"dig.getContent",
                "params":{"store_id":"<64-hex>","retrieval_key":"<64-hex>","offset":<u64>
                          /*, "root":"<64-hex>" optional; omitted ⇒ node pins the tip */}}
-> {"jsonrpc":"2.0","id":1,"result":{
     "ciphertext":"<base64 window>",
     "root":"<64-hex served generation root>",
     "complete":<bool>,
     "next_offset":<u64>,               // present only when !complete
     "inclusion_proof":"<base64>",      // FIRST window only (offset==0)
     "chunk_lens":[<u64>,...]           // FIRST window only
   }}
```

`dig-dns` MUST page by re-requesting with `offset = next_offset` until `complete` is true,
concatenating `ciphertext`, and MUST keep the `inclusion_proof` + `chunk_lens` from the first
window. The content is **ciphertext, not plaintext** — the node is a blind server; `dig-dns`
verifies + decrypts (§8).

Node error codes `dig-dns` branches on (by the symbolic `data.code`, not the number):
`-32004 RESOURCE_UNAVAILABLE` (not at this root) and `-32005 ROOT_NOT_ANCHORED` are treated as
"not found" → SPA catch-all (§4.5). `-32008 CONTENT_REDIRECT` MAY be surfaced as an HTTP 302.

### 6.3 Node endpoint resolution (§5.3 ladder)

`dig-dns` MUST resolve the node endpoint in this fixed order, using the first that answers a
`GET <base>/health` within a short timeout:

1. an **explicit override** — the `--node` flag, `$DIG_NODE_URL`, or the persisted config
   `node.url` (precedence flag > env > config) — which wins entirely, no probing;
2. `http://dig.local` (the installed local node, best-effort `127.0.0.2:80`);
3. `http://localhost:9778` (the local node's always-on loopback listener, plain HTTP);
4. `https://rpc.dig.net` (the public gateway) — the terminal fallback.

The local node serves plain **HTTP** on loopback; only `rpc.dig.net` is HTTPS. The resolved
choice SHOULD be cached for the session. A user-facing way to set a custom node
(flag + env + config) is REQUIRED (§5.3).

The `9778` port is sourced from `dig_constants::DIG_NODE_PORT` — the ecosystem-wide single
source of truth shared with dig-node, dig-installer and dig-sdk — never a value dig-dns
hardcodes independently (`src/node.rs::DEFAULT_LOCAL_NODE_PORT`).

`dig.getManifest {store_id, root}` (the store's public path list) exists on the node but is
served only for a **public store whose module is locally cached**; `dig-dns` MUST NOT depend
on it for correctness (it uses the decoy/decrypt-fail + extension heuristic of §4.5 instead).
It MAY use it opportunistically to answer `/.dig/`-style introspection.

---

## 7. Configuration

All values have defaults and are overridable by environment variable (and, for the node
endpoint, a CLI flag). Values are validated on load; an invalid value is a startup error.

| Setting | Default | Env var | Notes |
|---|---|---|---|
| loopback bind IP | `127.0.0.5` | `DIG_DNS_IP` | MUST be `127.0.0.0/8` |
| DNS port | `53` | `DIG_DNS_DNS_PORT` | UDP + TCP |
| HTTP port | `80` | `DIG_DNS_HTTP_PORT` | primary |
| HTTP fallback port | `8053` | `DIG_DNS_HTTP_FALLBACK_PORT` | used when `:80` is held |
| TLD | `dig` | `DIG_DNS_TLD` | normalised: trim, strip leading `.`, lowercase |
| DNS TTL (s) | `2` | `DIG_DNS_TTL` | 1–5 |
| node endpoint override | (ladder) | `DIG_NODE_URL` | empty ⇒ use the §6.3 ladder |
| `dig.local` bind IP | `127.0.0.2` | `DIG_DNS_LOCAL_IP` | MUST be `127.0.0.0/8`; matches the installer's `dig.local` hosts registration (#91) and dig-node's own best-effort bind (§12) |
| `dig.local` bind port | `80` | `DIG_DNS_LOCAL_PORT` | `http://dig.local` has no port suffix, so this MUST stay `80` in production; overridable for unprivileged local testing (§12) |

---

## 8. `.dig` read-crypto (verify-then-decrypt)

`dig-dns` performs the same read pipeline as `dig-client-wasm::decryptResource`, reusing
`digstore-core` primitives (`Urn`, `sha256`, `derive_decryption_key`, `decrypt_chunk`,
`resource_leaf`, `MerkleProof`, `DEFAULT_RESOURCE_KEY`, `CHAIN`). For a store id, resource_key,
and served ciphertext:

1. **retrieval_key** — build the canonical **root-independent** resource URN
   `urn:dig:chia:<store_id_hex>/<resource_key>` (root dropped so the key is stable across
   generations) and take `retrieval_key = SHA-256(urn)`, lowercase hex. This is the only
   URN-derived value sent to the node (§6.2). An empty resource_key uses `index.html`.
2. **Integrity gate** — `leaf = SHA-256(ciphertext)` MUST equal the proof's leaf; the proof
   MUST fold to its declared root; that root MUST equal the trusted anchored root. Any failure
   ⇒ refuse (no bytes served).
3. **Confidentiality** — derive the AES key with HKDF over the canonical URN
   (`derive_decryption_key(urn, salt)`; public stores pass `salt = None`), split the
   concatenated ciphertext by `chunk_lens` (which MUST sum to the ciphertext length), and
   AES-256-GCM-SIV-open each chunk, concatenating plaintext in order.

**Trust boundary.** The strongest model resolves the trusted root **from chain** independently
of the serving node. `dig-dns` targeting the local trusted node (the user's own machine, the
common case) uses `dig.getAnchoredRoot` from the resolved node as the trusted root and verifies
served content against it — the node is the user's own device. Independent on-chain root
verification (via coinset `current_root`) is an OPTIONAL hardening for the `rpc.dig.net`
fallback tier and is a documented future enhancement, not required for the local-node MVP. A
GCM tag failure is indistinguishable from a decoy (unknown key); it MUST be surfaced as
"not found in this store" (→ §4.5), never as "corrupt".

`dig-dns` serves **public** stores only (URN-derivable, no secret salt). A private store's
salt is not available to `dig-dns`.

---

## 9. `doctor` diagnostic

`doctor` checks each link of each path INDEPENDENTLY and reports pass/fail + a suggested fix;
it exits non-zero if any REQUIRED check fails, and supports `--json` (§6.2). Checks:

- loopback IP is up / bindable;
- DNS responder answers `<label>.dig` directly at `<loopback_ip>:53` → `127.0.0.5`;
- OS resolution of `<label>.dig` returns `127.0.0.5` (Path A end-to-end — may be "not
  configured", which is informational unless Path A is the only path);
- gateway `/.dig/resolve-probe` → `204` on the bound port;
- gateway serves a real `.dig` end-to-end (`/.dig/health` reports node reachable);
- browser policy state relevant to Path B (DoH / built-in-resolver) — informational;
- who holds `:80` (informational; explains an `:8053` fallback).

At least one of {Path A end-to-end, Path B (PAC + gateway)} passing means a `.dig` URL loads;
`doctor` MUST make clear which path(s) are live.

---

## 10. Machine-friendliness (§6.2)

- `doctor` and `/.dig/health` provide `--json` / JSON output with stable field names.
- Errors are catalogued with stable meanings; the gateway uses standard HTTP status codes:
  **405** CONNECT or any non-`GET`/`HEAD` method; **403** an absolute-form proxy authority not
  under `.<tld>`; **404** an invalid `<label>.<tld>` host, a missing extensioned resource, or a
  store with no anchored root; **400** a traversing request path; **200** a served resource or
  an SPA `/index.html` fallback; **206** a satisfied byte range; **416** an unsatisfiable range;
  **502** the node is unreachable OR it served content that failed merkle verification against
  the trusted root (fail-closed — never serve unverified bytes).
- Modules are small and single-purpose with doc-comments; the library (`dig_dns`) is fully
  unit-tested and the binary is a thin shell over it.

---

## 11. Conformance references

- The base32 label codec + the gateway↔node contract + ports are mirrored in the superproject
  `SYSTEM.md` (the cross-repo interaction map).
- The read-crypto (URN, retrieval-key, verify+decrypt) is byte-identical to `digstore-core`
  and `dig-client-wasm`; the node RPC shapes conform to dig-node's `SPEC.md` and the canonical
  `dig-rpc-types` type contract.
- User documentation of `*.dig` local resolution lives at docs.dig.net.

---

## 12. Ensuring `http://dig.local` reaches the local dig-node

`dig.local` is the OS-hosts-mapped name for "the user's own dig-node" (§5.3/§6.3 tier 1 of the
client→node ladder; the installer registers it, out of scope here — #91). DNS resolves a name
to an IP only, never a port, so `http://dig.local` implies port **80** at whatever IP the hosts
file maps it to (default `127.0.0.2`, matching dig-node's own best-effort bind, SYSTEM.md).
`dig-dns` — already the service responsible for making a hostname reach the node over HTTP for
`.dig` — additionally ENSURES this specific mapping too, idempotently.

### 12.1 Mechanism: an ensured transparent reverse proxy

On `serve` startup (and thereafter on a retry interval if needed), `dig-dns`:

1. Probes `GET http://<dig_local_ip>:<dig_local_port>/health` (default `127.0.0.2:80`) with a
   short timeout. ANY HTTP response (even non-2xx) means something is already answering there —
   dig-node's own best-effort bind, or `dig-dns`'s own reverse proxy still running from an
   earlier start — and `dig-dns` does **nothing further** (idempotent no-op:
   [`EnsureOutcome::AlreadyMapped`]).
2. If nothing answers, `dig-dns` binds a listener at `<dig_local_ip>:<dig_local_port>` itself
   and serves a TRANSPARENT reverse proxy there ([`EnsureOutcome::Established`]): every request
   (any method, path+query, headers minus hop-by-hop, body) is forwarded byte-for-byte to the
   discovered local dig-node target (§12.2) and the response relayed back unmodified. Unlike
   the `.dig` gateway (§4), this is NOT the verify-then-decrypt content path — `dig.local` is
   the node's OWN control/root host (JSON-RPC `POST /`, `GET /health`, …), so `dig-dns` only
   relays bytes.
3. If the bind itself fails ([`EnsureOutcome::Unavailable`] — the address genuinely held by
   something unrelated, or insufficient privilege), `dig-dns` logs a warning and retries on a
   fixed interval (30s) until it either binds or detects the address already answering. It
   never crashes the service; the `.dig` gateway + DNS responder keep serving regardless.

Because step 1 always precedes step 2, and step 2's own listener answers `/health` via
passthrough (or `502` when the node is down), a second `ensure` attempt — a restart, or a retry
tick — always finds "already mapped" and never double-binds. This is also RACE-SAFE against
dig-node's own best-effort bind: whichever of the two gets there first serves `dig.local`, and
either way requests reach the node (directly, or via `dig-dns`'s transparent proxy).

A node that is down (or not yet started) is handled gracefully: the listener still binds (it
does not need the node to be up), and each proxied request independently attempts the target,
`502`-ing "dig-node unreachable" until the node appears — the mapping self-heals with no
restart and no separate liveness loop.

### 12.2 Target discovery — the local node ONLY, never `rpc.dig.net`

The reverse-proxy TARGET is resolved like the §6.3 ladder's override tier, but WITHOUT the
`rpc.dig.net` terminal fallback — `dig.local` names the user's OWN node; proxying it to the
public gateway would defeat the purpose of an ensured LOCAL mapping:

1. an explicit override (`--node` / `DIG_NODE_URL` / config `node.url`) wins entirely; else
2. `http://localhost:<DEFAULT_LOCAL_NODE_PORT>` (`9778`) — the local node's always-on port.

Implemented in `dig_local::local_node_target`.

### 12.3 No fallback port

Unlike the `.dig` gateway (§4, deterministic `:8053` fallback advertised via the PAC file), the
`dig.local` reverse proxy has **no fallback port**: a plain `http://dig.local` URL has no
proxy indirection to advertise an alternate port to, so a bind must succeed on the CONFIGURED
port (§7) or the retry loop (§12.1 step 3) keeps trying the same port.

---

## 13. OS-service registration

`dig-dns` installs as an auto-starting OS service that runs the **headless service run mode**
(§13.4): `dig-dns run-service` on Windows (the SCM-protocol entrypoint), `dig-dns serve` on
Linux/macOS (systemd/launchd exec the foreground process directly). The `dig-dns` binary owns
BOTH this run mode AND its registration (via the `service-manager` crate — Windows SCM, Linux
systemd, macOS launchd).

Registration MUST point the OS service manager at the `dig-dns` binary's OWN run mode — i.e. the
service program is `dig-dns` with args `run-service` (Windows) / `serve` (elsewhere). A
registration MUST NOT interpose a separate host process that re-launches `dig-dns` as a child:
there is exactly ONE service process (`dig-dns` itself), mirroring the sibling `dig-node`
service. Whichever component performs the registration — the installer, or `dig-dns install` —
registers this identical program+args under the canonical identity (§13.1), so the two paths are
interchangeable and idempotent (the clean-reinstall, §13.2, makes a re-run safe).

### 13.1 Canonical identity

| | Value |
|---|---|
| Service id (name) | `net.dignetwork.dig-dns` |
| Windows display name | `DIG NETWORK: DNS` |

- The **service id** is a reverse-DNS name used VERBATIM as the Windows SCM service name
  (`sc create`/`query`/`start`/`stop`/`delete`) and the launchd plist label. It MUST match the
  sibling convention `net.dignetwork.dig-node` used by the dig-node service.
- **systemd unit filename — two registration paths, two names.** The native `.deb` package
  (§14) ships its OWN unit file at the fixed path `/lib/systemd/system/net.dignetwork.dig-dns.service`
  — the service id used verbatim. `dig-dns install`'s systemd registration goes through the
  `service_manager` crate instead, which names the unit file with `ServiceLabel::to_script_name()`
  (`{organization}-{application}`, i.e. `dignetwork-dig-dns.service`) rather than the qualified id
  — it DROPS the `net` qualifier and joins with `-`, not `.`. Both paths register the SAME program
  (`dig-dns serve`) and are functionally interchangeable (§13, §13.2's clean-reinstall still
  applies to the CLI path), but a script/monitoring tool addressing the unit by name must use the
  name matching HOW it was installed. `src/service.rs::query_installed`'s Linux probe resolves
  the `dignetwork-dig-dns.service` form to match what it actually registers (dig_ecosystem #502).
- The **display name** is the human-friendly name shown in the Windows Services console. On
  Windows it is set with `sc config <id> displayname= "DIG NETWORK: DNS"` AFTER create (the
  underlying `sc create` sets the display name to the id). On launchd/systemd the service id is
  the visible name, so the display name is Windows-facing.

### 13.2 Clean-reinstall (normative)

`install` performs a CLEAN RECREATE, never a reconfigure-in-place. If the service ALREADY
EXISTS, it MUST:

1. **stop** the running service (best-effort — a stopped service is not an error);
2. **delete** (deregister) it;
3. **wait** for the removal to take effect (a Windows deletion can linger until open handles
   close), bounded by a timeout;
4. **create** it afresh (with the display name on Windows);
5. **start** it.

When no prior registration exists it simply creates + starts. Deleting before creating is what
prevents Windows `CreateService 1073 "the specified service already exists"` on an installer
re-run. Per OS the primitives are: Windows `sc stop`/`sc delete`/`sc create`/`sc start`; macOS
launchd `bootout`/`bootstrap`; Linux systemd `stop`+`disable` then reinstall the unit +
`enable --now` — all provided by `service-manager` plus the Windows display-name override.

### 13.3 Command surface

| Command | Effect |
|---|---|
| `dig-dns install [--node URL]` | Register (clean-reinstall) + start the service; bakes the resolved config into the service environment. Windows requires an elevated console. |
| `dig-dns uninstall` | Stop + deregister the service. Windows requires elevation. |
| `dig-dns start` / `dig-dns stop` | Start / stop the registered service. |
| `dig-dns status` | Report whether the resolver is serving (probes `GET /.dig/resolve-probe` on the bound port) + whether it is registered, PLUS the running service's `pid` and ACTUALLY-bound port read from the machine-wide runtime file (§13.5). Exits non-zero when nothing is serving. |
| `dig-dns run-service` | (hidden, Windows only) The SCM protocol entrypoint the installed service launches; speaks `StartServiceCtrlDispatcher` and reports `SERVICE_RUNNING` before any startup work so the SCM does not kill it with error 1053 (§13.4). Behaves like `serve` off Windows. |

Every command supports `--json` (§10). Install level: user-level (no elevation) on Linux/macOS;
system-level on Windows (SCM has no per-user services).

### 13.4 Headless run mode & the SCM report-running contract (the 1053 fix)

On Windows, the SCM launches the registered program and expects it to connect
(`StartServiceCtrlDispatcher`) and report `SERVICE_RUNNING` within the SCM start timeout (~30s).
Failing to do so is Windows **error 1053** ("the service did not respond … in a timely fashion").
`dig-dns run-service` is that connection and MUST:

1. **Report `SERVICE_RUNNING` FIRST — before ANY slow or fallible startup work.** Config load,
   the tokio-runtime build, node-endpoint resolution (§6.3 ladder), and the `:80`/`:53` socket
   binds all happen AFTER the `RUNNING` signal. No bind, no network probe, and no fallible load
   may precede it. (The control handler is registered before `RUNNING` only so an immediate
   `Stop` is not lost; registration is a constant-time SCM call, not startup work.)
2. **Never hang on bring-up.** The gateway bind uses the deterministic `:8053` fallback (§4.3);
   the DNS `:53` bind is best-effort (a failure is non-fatal — Path B still serves). If BOTH the
   primary and fallback gateway binds fail, bring-up fails FAST with a clear error naming both
   addresses — never a hang.
3. **Surface a bring-up failure as a clean stop.** A hard failure after `RUNNING` reports
   `SERVICE_STOPPED` with a non-zero Win32 exit code (so `sc query` reflects it) and returns —
   never a hang, never a silent success.

This ordering is implemented behind a platform-independent seam (`report RUNNING` → run body →
`report STOPPED(exit)`) that is unit-tested with a recording status reporter on every platform,
so the contract holds without a real SCM and cannot silently regress. On Linux/macOS the run
mode is a plain foreground serve loop shutting down on `SIGTERM`/Ctrl-C (systemd/launchd own the
lifecycle), so no SCM handshake applies.

### 13.5 Machine-wide state dir & targeting the running service (#501)

The `dig-dns` service runs as a system account (Windows LocalSystem, Linux/macOS root); its CLI
counterpart (`status`, …) may be invoked by ANY user. So any state the CLI shares with the
running service lives in a MACHINE-WIDE, identity-independent directory — NEVER a per-user
profile dir — so the observation/control path does not vary by who runs the CLI (mirroring the
sibling `dig-node` machine-wide state model):

| OS | Default state dir |
|----|-------------------|
| Windows | `%PROGRAMDATA%\DigDns` (typically `C:\ProgramData\DigDns`) |
| macOS | `/Library/Application Support/DigDns` |
| Linux | `/var/lib/dig-dns` |

The `DIG_DNS_STATE_DIR` environment variable overrides the default; the service and the CLI both
honour it, so they always agree. On startup (after binding) the service records a non-secret
`runtime.json` in this dir — `{ pid, loopback_ip, http_port (the ACTUALLY-bound port, which may
be the `:8053` fallback), dns_active }` — and removes it on graceful shutdown; the CLI reads it
to locate + identify the exact running process and its real port regardless of the invoking user.
Writing is best-effort: a non-admin foreground `dig-dns serve` that cannot write the system dir
still serves, and the CLI falls back to probing the fixed loopback port.

`dig-dns` holds NO control-token or auth secret (its gateway is loopback-only and
unauthenticated), so the state dir carries no secret material and `runtime.json` is non-sensitive.
The installer creates the dir and applies its ACL (SYSTEM + Administrators full control,
install-user read; Unix `0640`/`0600`); `dig-dns` only RESOLVES the path and best-effort
reads/writes `runtime.json` within it.

---

## 14. Native OS install packages

`dig-dns` COMPILES its own native OS install packages that install it **as a service** (dig_ecosystem
#503). The `dig-installer` downloads + runs them; it does NOT hand-roll service registration. Each
package registers the SAME canonical identity (§13.1) running the SAME entrypoint, and creates the
SAME machine-wide state dir (§13.5), as a manual `dig-dns install` — the packaged and manual paths
are interchangeable and idempotent. A package installs ONLY the service; `dig-dns` owns `*.dig`
resolution, so it registers NO OS scheme handler (that is dig-node's job for `chia://`/`urn:dig:chia:`).

Per OS the release workflow (`.github/workflows/release.yml`) builds one package on the matching
runner OS and attaches it to the `vX.Y.Z` GitHub Release alongside the raw binaries.

| OS | Package | Built by | Service mechanism | Binary path | State dir |
|---|---|---|---|---|---|
| Windows | `dig-dns-<ver>-windows-x64.msi` | WiX (`wix/main.wxs`) | SCM `ServiceInstall`/`ServiceControl` | `C:\Program Files\DIG Network\DIG DNS\dig-dns.exe` | `C:\ProgramData\DigDns` |
| macOS | `dig-dns-<ver>-macos-{arm64,x64}.pkg` | `pkgbuild`/`productbuild` (`packaging/macos`) | LaunchDaemon | `/usr/local/bin/dig-dns` | `/Library/Application Support/DigDns` |
| Ubuntu | `dig-dns_<ver>_amd64.deb` | `cargo-deb` (`Cargo.toml` metadata + `packaging/linux`) | systemd unit | `/usr/bin/dig-dns` | `/var/lib/dig-dns` |

### 14.1 Windows `.msi` (WiX)

- Registers the service **`net.dignetwork.dig-dns`** (display **`DIG NETWORK: DNS`**, §13.1) via
  `ServiceInstall`, `Type=ownProcess`, `Start=auto`, `Account=LocalSystem`, `Arguments=run-service`
  — the SCM-protocol entrypoint (§13.4), NOT a host shim.
- `ServiceControl` **starts** the service on install and **stops + removes** it on uninstall, with
  `Wait=no` so a busy `:53` never wedges `msiexec` (the service reports `SERVICE_RUNNING` before its
  binds, then degrades — §13.4 / #499).
- Creates `C:\ProgramData\DigDns` (§13.5). It inherits ProgramData's ACL — SYSTEM + Administrators
  full control, Users (incl. the installing user) read — which satisfies the "SYSTEM+Administrators
  full, installing user READ" requirement; no custom ACL is applied (the dir holds no secret).
- Adds the install dir to the system `PATH`; a fixed `UpgradeCode` + `MajorUpgrade` gives clean
  in-place upgrade and uninstall.

### 14.2 macOS `.pkg`

- Installs the binary at `/usr/local/bin/dig-dns` and a LaunchDaemon
  `/Library/LaunchDaemons/net.dignetwork.dig-dns.plist` (`RunAtLoad` + `KeepAlive`) running
  `dig-dns serve`.
- `postinstall` creates `/Library/Application Support/DigDns`, then `launchctl bootstrap system` +
  `launchctl enable` the daemon; `preinstall` `launchctl bootout`s any existing daemon first so an
  upgrade re-bootstraps cleanly (§13.2).

### 14.3 Ubuntu `.deb`

- Installs the binary at `/usr/bin/dig-dns` and the systemd unit
  `/lib/systemd/system/net.dignetwork.dig-dns.service` running `dig-dns serve`.
- The unit grants **`AmbientCapabilities=CAP_NET_BIND_SERVICE`** (+ `CapabilityBoundingSet`) — the
  ONLY privilege `dig-dns` needs, to bind `:53`/`:80` on the loopback IP — and uses
  `StateDirectory=dig-dns` so systemd creates `/var/lib/dig-dns` (§13.5).
- Maintainer scripts (auto-generated by `cargo-deb`) run `systemctl daemon-reload`, **enable**, and
  **start** the unit on install, **stop** it on removal, and **unmask + purge** its enable state on
  purge. `cargo-deb` only emits these scripts when `maintainer-scripts` is set in
  `[package.metadata.deb]` (alongside `[package.metadata.deb.systemd-units]`); without it the unit
  file is still installed but no postinst is generated, so the service would never be enabled or
  started (dig_ecosystem #525).
- Control metadata is apt-correct + stable (`Package: dig-dns`, `Architecture: amd64`, auto-computed
  `Depends`, `Section: net`), so `apt.dig.net` ingests the release-asset `.deb` and GPG-signs it into
  the apt repo (#425).

---

## Appendix A — default ports / addresses

| Service | Address | Transport |
|---|---|---|
| dig-dns DNS responder | `127.0.0.5:53` | UDP + TCP |
| dig-dns HTTP gateway | `127.0.0.5:80` (fallback `127.0.0.5:8053`) | HTTP |
| dig-node control RPC (localhost tier) | `127.0.0.1:9778` | HTTP (JSON-RPC) |
| dig-node `dig.local` tier — dig-node's own best-effort bind, OR `dig-dns`'s ensured reverse proxy (§12) | `127.0.0.2:80` | HTTP |
| public gateway fallback | `rpc.dig.net:443` | HTTPS |

## Appendix B — machine-wide state dir (§13.5)

| OS | State dir | Runtime file |
|---|---|---|
| Windows | `%PROGRAMDATA%\DigDns` (default `C:\ProgramData\DigDns`) | `runtime.json` |
| macOS | `/Library/Application Support/DigDns` | `runtime.json` |
| Linux | `/var/lib/dig-dns` | `runtime.json` |

Overridable via `DIG_DNS_STATE_DIR` (honoured by both the service and the CLI). `runtime.json`
is `{ pid, loopback_ip, http_port, dns_active }` — non-secret; written by the service on startup,
removed on graceful shutdown, read by the CLI to target the running service regardless of user.
