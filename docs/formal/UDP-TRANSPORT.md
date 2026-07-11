# UDP Transport — Native Client

Status: **implemented — now the only transport.** This document records the move
from the original browser/HTTP flavor to a raw-UDP command transport for a
platform-native client (the SwiftUI app), and specifies that transport. The
device carries the *existing* command envelope over UDP; the firmware lives
behind the `udp-transport` cargo feature (flash with `./flash-udp.sh`); the
reference client is in [`clients/apple`](../../clients/apple).

> **The browser/WebAuthn HTTP flavor has been removed.** References below to the
> "HTTP flavor", the Leptos/WASM dashboard, or WebAuthn-PRF passkeys are historical
> — they describe the *before* state this migration replaced. The device now speaks
> UDP only, and clients authenticate with **P-256** (Secure Enclave / PIV).

## 0. Why this exists

The dashboard is a browser app. Browsers cannot open raw sockets — only
WebSocket / WebRTC / WebTransport — so today the device speaks HTTP/1.1 on
`:8080/tcp` purely to be reachable from a `fetch()` call (see `http.rs`). A
native client has no such limit.

The important property of this codebase makes the change small: **the command
envelope is already transport-agnostic.** It is a self-contained,
end-to-end-encrypted-and-signed ASCII string. HTTP contributes exactly two
things around it — a message boundary (`Content-Length`) and the browser-only
CORS / Private-Network-Access preflight. UDP supplies the boundary for free
(one datagram = one message) and needs no CORS. So the UDP flavor is mostly
**subtraction**.

The migration replaced one transport with another (same crates, same envelope):

| Flavor | Transport | Client | Purpose |
| --- | --- | --- | --- |
| `http` (removed) | HTTP/1.1 · `:8080/tcp` | browser dashboard (Leptos/WASM) | cross-platform, zero-install |
| `udp` (current) | raw UDP · `:8080/udp` | native app (SwiftUI, …) | lightweight, hardware-crypto client |

## 1. Unchanged: the crypto envelope (single source of truth)

**The UDP flavor does not alter the envelope, the crypto, the replay guard, the
RBAC model, or the command set.** All of that is reused byte-for-byte. It is
restated here only so this spec is self-contained; `crypto.rs` / `commands.rs` /
`shared/src/lib.rs` remain authoritative.

### 1.1 Request envelope (client → device), ASCII

```
EPH_PUB_HEX ";" IV_HEX ";" CT_HEX
```

| Field | Bytes | Hex chars | Meaning |
| --- | --- | --- | --- |
| `EPH_PUB_HEX` | 32 | 64 | client per-request X25519 ephemeral public key |
| `IV_HEX` | 12 | 24 | AES-GCM nonce |
| `CT_HEX` | var | var | `AES-256-GCM(...)` ciphertext **with 16-byte tag appended** |

- `aes_key = SHA256( X25519(eph_secret, DEVICE_X25519_pub) )`, empty AAD.
- Inner plaintext (after decrypt), `;`-split into 3:

  ```
  TS ";" CMD ";" SIG_HEX
  ```

  | Field | Meaning |
  | --- | --- |
  | `TS` | decimal `u64` **milliseconds**, strictly greater than the device's last accepted timestamp (monotonic replay guard) |
  | `CMD` | one of the command strings in §1.3 |
  | `SIG_HEX` | 128 hex = Ed25519 signature over ASCII **`"TS\|CMD"`** (pipe separator) with the caller's role key |

### 1.2 Response envelope (device → client), ASCII — same shape

```
RESP_EPH_PUB_HEX ";" IV_HEX ";" CT_HEX
```

- Device generates a fresh X25519 ephemeral keypair per response (forward secrecy);
  `aes_key = SHA256( X25519(device_resp_secret, client_request_eph_pub) )`.
- Inner plaintext: `RESP_TS ";" MESSAGE ";" RSIG_HEX`
  - `RESP_TS` = the request's `TS`, echoed back (binds response to request).
  - `RSIG_HEX` = Ed25519 signature over ASCII **`"resp|RESP_TS|MESSAGE"`** with the
    device signing key.
- Client accepts iff `RSIG` verifies against the device Ed25519 signing pubkey
  **and** `RESP_TS == request TS`.

### 1.3 Command set (from `shared::terminology`, unchanged)

`WHOAMI` · `READ_SENSOR` · `SET_THRESHOLD <f32>` · `CLEAR_ALARM` ·
`COLOR green|yellow|red` · `ADD_ROLE <role> <pk_hex64> <cert_hex128>` ·
`REVOKE_ROLE <role>` · `LIST_ROLES`. RBAC per command is unchanged; the caller's
role is decided by *which* Ed25519 pubkey verifies the signature, never by any
field the client asserts.

## 2. UDP transport layer (the only new part)

### 2.1 Endpoint

- **UDP port 8080** (mirrors the HTTP flavor for config parity; `:8080/udp` is a
  distinct L4 socket from `:8080/tcp`, so a future dual-stack ROM could bind both).
- Proposal: promote the port to a shared SSOT constant
  `shared::terminology::SUPERVISOR_PORT: u16 = 8080`, since it is currently
  hard-coded on both sides.

### 2.2 Framing

**One datagram = one message.** The request datagram payload is exactly the ASCII
request envelope (§1.1); the response datagram payload is exactly the ASCII
response envelope (§1.2). No HTTP, no headers, no length prefix — the datagram
*is* the frame. Reject any datagram that does not split into exactly three
`;`-fields.

### 2.3 Sizes and MTU

Worst-case envelope sizes (LAN, typical MTU 1500):

| Message | Approx. bytes | Fits one 1500 datagram? |
| --- | --- | --- |
| `READ_SENSOR` / `WHOAMI` request | ~430 | yes |
| `ADD_ROLE` request (max) | ~850 | yes |
| typical response | ~490 | yes |
| **`LIST_ROLES` response, 10 roles** | **~2060** | **no** |

Everything except `LIST_ROLES` fits a single datagram comfortably. Because the
device's stack (smoltcp, via embassy-net) does **not** perform IPv4 TX
fragmentation, the UDP flavor fragments replies **at the application layer**, so
the transport is size-agnostic like TCP — no truncation, no dropped reply, no
"keep the role set small" caveat:

- **Reply framing:** the device sends the reply as 1+ datagrams, each
  `[total: u8][seq: u8][payload…]`, splitting the response envelope at
  `UDP_CHUNK_PAYLOAD = 1024` bytes. The client reassembles by `seq` until it has
  `total` chunks, then decrypts the concatenated envelope as usual.
- **Requests are always a single datagram** (the largest, `ADD_ROLE`, is ~850 B),
  so only replies are framed; the client sends unframed.
- **Loss** of any chunk means the client never completes reassembly, so its
  receive times out and the existing command-level retry (§2.4) re-issues the
  whole command with a fresh timestamp. No per-chunk reliability is added.

This keeps fragmentation entirely inside the transport: `process_envelope` and the
command set are unchanged, and the HTTP flavor (TCP streams) is untouched. The
reassembler is unit-tested (`ChunkAssemblerTests`).

### 2.4 Reliability — retransmission

UDP may drop, duplicate, or reorder. The client is **serial**: one outstanding
command at a time (matching the current UI model). On no response within a
receive timeout, retransmit. Mirror the dashboard's existing policy
(`state.rs`: `MAX_ATTEMPTS = 4`, `RETRY_DELAY_MS = 300`):

- receive timeout ≈ **1 s**, up to **4 attempts**;
- **each retransmit re-signs with a fresh `TS`** — never resend identical bytes.

Why fresh `TS`, not a plain resend: the device's monotonic replay guard rejects a
duplicate `TS` it has already accepted. If the *request* was lost, the device
never advanced its counter and any `TS > last` is accepted; if the *response* was
lost, a fresh higher-`TS` re-issue is still safe because all commands are
idempotent (`READ_SENSOR`, `WHOAMI`, re-setting the same threshold, re-adding a
role, etc.). This is exactly what the web client already does on retry.

**Native (P-256 / Touch ID) exception:** the Secure Enclave client signs the
command **once** (one Touch ID) and resends the *same* datagram — re-signing per
retry would prompt Touch ID on every retransmit. Tradeoff: if the device accepted
the command but the reply was lost, the retry returns a signed "Replay Attack
Detected"; rare on a LAN, and the command did execute. Fresh-`TS` retry is only
worth it where signing is free (the web / Ed25519 client).

### 2.5 Correlation and de-duplication

The response echoes the request `TS` (§1.2). The client matches an incoming
datagram to its outstanding request by `RESP_TS == last_sent_TS`, and **drops any
datagram whose echoed `TS` is not the one it is waiting for** (late duplicate /
reordered straggler). This gives request/response correlation and dup-suppression
with no extra header — `TS` doubles as the correlation id.

### 2.6 Ordering / replay interaction

The device's monotonic `LAST_TIMESTAMP` already discards reordered or duplicated
*old* datagrams for free (older `TS` ≤ last → "Replay Attack Detected"). A serial
client never reorders its own traffic, so the only reordering is network-induced
and is handled by §2.5 + the replay guard together.

### 2.7 What is deleted vs. the HTTP flavor

- No CORS headers, no `OPTIONS` preflight, no Private-Network-Access — all of
  `write_preflight` and the `Request::Preflight` path go away.
- No `Content-Length` parsing, no header scan — `read_request` collapses to a
  single `recv_from`.
- `Connection: close` / socket re-accept loop → a bound `UdpSocket` that just
  `recv_from` → dispatch → `send_to`.

## 3. Firmware changes (UDP flavor)

Scoped, and enabled behind a cargo feature so both flavors build from one tree
(e.g. `--features udp-transport`, mutually exclusive with the default HTTP path):

1. Replace the `TcpSocket::accept(8080)` loop (`main.rs` ~184–251, 503) with an
   `embassy_net::udp::UdpSocket` bound to `:8080`; `recv_from` a datagram →
   existing `dispatch()` (unchanged) → `send_to` the response envelope back to the
   sender's `(ip, port)`. `embassy-net`'s `udp` feature is **already enabled**
   (`Cargo.toml` line 30) — no new dependency.
2. Drop `http.rs` from the UDP build (CORS/preflight/`Content-Length` are
   browser-only).
3. **Fix the `REVOKE_ROLE` argument bug while here** (`commands.rs` ~95–134):
   today `REVOKE_ROLE` / `LIST_ROLES` read their argument from an *outer*
   `;`-field of the raw HTTP body, but the client puts the role name *inside* the
   encrypted `CMD`, so `REVOKE_ROLE` currently no-ops. With HTTP's body-split gone
   there is no outer field at all — the UDP flavor **must** parse the revoke
   target from the decrypted `CMD` via `split_whitespace()` (as `ADD_ROLE` /
   `SET_THRESHOLD` already do). Recommend fixing it in shared dispatch so the HTTP
   flavor benefits too.

Everything else — identity, key hierarchy, replay guard, flash persistence,
sensor read, LED policy — is untouched.

## 4. Native client (SwiftUI reference implementation)

- **Transport:** `Network.framework` — `NWConnection(host:port:using: .udp)`;
  `send` the request envelope, `receiveMessage` the response datagram; wrap
  §2.4/§2.5 (timeout, 4 retries with fresh `TS`, match on echoed `TS`).
- **Envelope crypto:** CryptoKit, all in software (this is fine — the envelope's
  X25519 key is *ephemeral*, per-message; there is no persistent secret to protect
  in hardware here):
  - `Curve25519.KeyAgreement` for the ephemeral X25519 ECDH,
  - `SHA256`, `AES.GCM` for the payload,
  - `Curve25519.Signing` to **verify** the device's Ed25519 response signature.
- **Client signing key:** P-256 in the Secure Enclave (Touch ID per command) —
  see §5. A hardware security key (PIV) is a drop-in alternative.

## 5. Client identity — P-256 in the Secure Enclave (implemented)

Clients authenticate with P-256 (the removed HTTP flavor used Ed25519 WebAuthn
passkeys — see the status note at the top):

| Client key | Where it lives | Firmware verifies |
| --- | --- | --- |
| **P-256 ECDSA** | **Mac Secure Enclave** (or a PIV hardware key) | **P-256** (`clientauth`) |

Why P-256 for UDP: the point of the native flavor is a hardware-held key with no
domain/passkey ceremony. The Secure Enclave — and domainless hardware security
keys (PIV) — are **P-256 only**, so the wire signature is P-256 and the UDP-flavor
firmware verifies P-256 (the `clientauth` module; the `p256` crate, no_std,
feature-gated to `udp-transport`). The HTTP flavor stays 100 % Ed25519. This is
confined to `clientauth`; the rest of the firmware handles opaque pubkey/sig bytes.

- **Key:** `SecureEnclave.P256.Signing.PrivateKey` with a `.userPresence` access
  control — non-exportable, and **every `sign` prompts Touch ID**. Its 33-byte
  compressed public key (66 hex) is provisioned as `SUPERVISOR_PUBKEY` (baked at
  flash time) or via `ADD_ROLE`. Role/supervisor pubkeys are stored as a
  `heapless::Vec<u8, 33>` (32 for Ed25519, 33 for P-256 compressed).
- **Signature:** `.rawRepresentation` → 64 bytes (r‖s), the same 128-hex wire
  field as Ed25519, so nothing else in the envelope changes.
- **Nothing extractable at rest:** the private key never leaves the enclave; only
  an opaque, enclave-bound reference blob sits in the Keychain.
- **One Touch ID per command:** the command is signed once and the datagram is
  retried on the wire without re-signing.

### 5.1 What stays Ed25519 / X25519
- The **device's response signature** is still Ed25519 (device key), verified by
  the client with CryptoKit `Curve25519.Signing`.
- The **envelope encryption** is still ephemeral X25519 + AES-256-GCM — no
  persistent secret, so no benefit to enclave-binding it (and the enclave can't do
  X25519 anyway).

### 5.2 Hardware security keys (PIV) — implemented & hardware-validated
A hardware key in **PIV** mode signs the same P-256 over `"TS|CMD"`, so it drops in
behind the same `CommandSigner` protocol with **no firmware change** — the device
can't tell whether the P-256 signature came from the Secure Enclave or a stick.
(FIDO2/WebAuthn mode is deliberately *not* used — that reintroduces the
rp-id/domain requirement.) Unlike an enclave key (bolted to one Mac), a PIV key is
a **portable, hardware-bound supervisor**: the same stick authorizes from any Mac
and the private key never leaves the card.

`PIVSigner` reaches the card through macOS **CryptoTokenKit** (a keychain
`SecKey` under `kSecAttrAccessGroupToken`), signs with
`SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)`, and reshapes the DER
result to the 64-byte r‖s the firmware's `p256` verifier expects. Validated
end-to-end against a **main token (PIV+FIDO+CCID)**: card sign → DER→raw64 →
`clientauth::verify` accepts (identical bytes to the enclave path).

**Provisioning (e.g. main token, slot 9c):**
- Generate an **ECCP256** key + **self-signed certificate** in slot **9c** (Digital
  Signature → PIN on *every* signature). The cert is mandatory — macOS only
  surfaces a card key to the keychain when a matching cert is present.
- **Discovery caveat:** some vendors (main token) ship their own CCID driver + smart-card
  daemon, so the card is **not** auto-published to CryptoTokenKit. A *fresh physical
  insert* is required for Apple's `pivtoken` to attach; confirm with
  `security list-smartcards` (it must list a `com.apple.pivtoken:<GUID>` token).
- Read the compressed pubkey to bake as `SUPERVISOR_PUBKEY` — the app's **Copy**
  button, or straight from the 9c cert:
  ```sh
  pkcs15-tool --read-certificate 02 | openssl x509 -noout -pubkey \
    | openssl ec -pubin -conv_form compressed -outform DER | tail -c 33 | xxd -p -c 33
  ```
  Then **verify the firmware boot log's `SSOT Supervisor PubKey` line matches** —
  a baked/card key mismatch rejects every command as "Unknown Role".

### 5.3 Tamarin
Unaffected: the model abstracts "a signature," not the curve. Swapping the client
auth signature Ed25519 → P-256 does not change the symbolic protocol.

## 6. Open decisions checklist

- [x] Client identity: **P-256 in the Secure Enclave** (Touch ID per command),
      firmware verifies P-256 via `clientauth`, feature-gated to `udp-transport`;
      HTTP flavor stays Ed25519 (§5). A **PIV hardware key** (main token) is an
      implemented, hardware-validated drop-in supervisor — same P-256, no firmware
      change (§5.2).
- [x] Port: **reused `8080/udp`**, promoted to `shared::terminology::SUPERVISOR_PORT`.
- [x] Fixed `REVOKE_ROLE` to parse its target from the decrypted `CMD` (shared
      `commands::dispatch`, so the HTTP flavor benefits too).
- [x] `LIST_ROLES` over-MTU: solved by app-level reply framing in the UDP
      transport (`[total][seq][payload]`, reassembled + unit-tested client-side;
      §2.3). The transport is now size-agnostic — no truncation, no dropped reply.
