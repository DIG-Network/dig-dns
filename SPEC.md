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

## Appendix A — default ports / addresses

| Service | Address | Transport |
|---|---|---|
| dig-dns DNS responder | `127.0.0.5:53` | UDP + TCP |
| dig-dns HTTP gateway | `127.0.0.5:80` (fallback `127.0.0.5:8053`) | HTTP |
| dig-node control RPC (localhost tier) | `127.0.0.1:9778` | HTTP (JSON-RPC) |
| dig-node `dig.local` tier | `127.0.0.2:80` | HTTP |
| public gateway fallback | `rpc.dig.net:443` | HTTPS |
