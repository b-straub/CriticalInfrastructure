# Post-Quantum Cryptography — Follow-Up

**Status:** deferred. The current implementation uses classical primitives
(X25519, Ed25519, AES-256-GCM, SHA-256). That is already a strong bar — the
protocol is machine-checked (`dashboard.spthy`) for command authenticity, replay
freedom, response unforgeability, and forward secrecy against a Dolev-Yao
attacker. This document records the post-quantum concerns and a concrete
migration path so PQC can be added later without redesign.

## What a quantum attacker breaks

| Primitive | Role in the stack | Quantum impact |
|-----------|-------------------|----------------|
| **X25519** (ECDH) | command + response key exchange | **Broken** by Shor — confidentiality lost |
| **Ed25519** (signatures) | role/supervisor command signatures, ESP response signatures, role certs | **Broken** by Shor — forgery possible |
| **AES-256-GCM** | envelope encryption + integrity tag | Grover only — ~128-bit effective, **still safe** |
| **SHA-256** | key derivation, hashing | Grover only — **still safe** |

So the **symmetric core needs no change**. The exposure is the asymmetric
layer: key exchange and signatures.

## Threat prioritisation

1. **Harvest-now-decrypt-later (urgent).** An adversary can record traffic today
   and decrypt it once a cryptographically relevant quantum computer (CRQC)
   exists. This targets **confidentiality**, i.e. the key exchange. It is the
   most pressing PQ concern, and it is amplified here because the device identity
   keys are **burned into eFuse for the device's whole lifetime**.
2. **Signature forgery (less urgent).** Forging a command/response/cert requires
   a CRQC *at the time of the attack* — past traffic cannot be retroactively
   forged. But the long-lived eFuse identity and certificate keys still warrant
   PQ signatures.

## Migration: hybrid, not replacement

Follow the industry consensus (NIST, IETF TLS, Signal PQXDH, Apple iMessage
PQ3): run classical and PQC **in combination**, so the channel is secure if
*either* holds. This protects against both a quantum break of the classical
scheme and a future classical break of the (younger) lattice schemes.

- **Key exchange → X25519 + ML-KEM-768** (FIPS 203). Derive the session key from
  the KDF of *both* shared secrets. Mirrors TLS `X25519MLKEM768`.
- **Signatures → Ed25519 + ML-DSA-65** (FIPS 204) for commands, responses, and
  role certificates. Optionally **SLH-DSA** (FIPS 205, hash-based — leans only on
  SHA) for the rarely-used root eFuse identity.
- **Symmetric → unchanged** (AES-256-GCM, SHA-256/HKDF).

## ESP32-S3 feasibility notes

- **ML-KEM-768** — pubkey ~1184 B, ciphertext ~1088 B; NTT math runs in low
  milliseconds on the S3. RustCrypto `ml-kem` is `no_std`. Feasible.
- **ML-DSA-65** — pubkey ~1952 B, **signature ~3309 B**. This is the heavy part:
  the response envelope buffers (currently `heapless::String::<…>` sized for a
  64-byte Ed25519 signature) must grow ~10×, and signing stack usage is
  non-trivial. Doable on the S3's 512 KB SRAM, but it is real surgery.
- **SLH-DSA** — signatures 8–30 KB; only viable for a root cert signed once, not
  per-message.
- **WebApp** — `ml-kem` / `ml-dsa` compile to WASM cleanly.

## Assurance layers — what is machine-checked, what is inherited

Formal verification is not one thing. Different tools prove different layers, and
no single tool spans them. Being explicit about where each guarantee comes from
keeps the security story honest.

| Layer | Question it answers | Tool / source | Status here |
|-------|--------------------|---------------|-------------|
| **Protocol / composition** | Does the message flow achieve authentication, replay-freedom, forward secrecy against a network attacker? | Tamarin (symbolic, Dolev-Yao) | **Proven** in `dashboard.spthy` |
| **Primitive security** | Is ML-KEM IND-CCA, ML-DSA EUF-CMA? | EasyCrypt (Formosa / Kyber) | Inherited from the literature |
| **Primitive implementation** | Does the code compute ML-KEM/ML-DSA exactly per FIPS, on all inputs? | SAW+Cryptol+Isabelle (Apple corecrypto); F\*/hax (libcrux) | To be **inherited** from a verified library, not re-proven |
| **Constant-time / side-channel** | Does execution leak secrets via timing or cache? | Jasmin CT proofs, ct-verif, dudect | Separate effort; not covered above |

The Tamarin model treats every primitive as a perfect black box (an unforgeable
signature, hard DH). It proves the *composition* is sound — it cannot see an
implementation bug inside a primitive. Conversely, an implementation proof
(Apple-style) cannot see a protocol-level attack such as the response-forgery
this model caught. **The layers are complementary, not substitutes.**

Practical consequence for the PQC step: do **not** hand-roll or re-verify
ML-KEM / ML-DSA. Inherit a formally-verified implementation —

- **libcrux** (Cryspen) ships a formally verified ML-KEM in Rust (via `hax` →
  F\*), with ML-DSA in progress — the Rust-ecosystem analogue of Apple's
  corecrypto verification.

— and let the Tamarin model keep covering only what it can: the protocol
composition and the hybrid combiner.

## Formal-verification plan

Symbolic Tamarin cannot show a "quantum advantage" (symbolic crypto is perfect),
but it *can* model the **hybrid combiner** as two independent primitives and
prove the property that matters:

> the session key stays secret unless **both** the classical and the PQC secret
> are revealed.

Add `RevealClassical` / `RevealPQ` rules and a lemma of the form
`SessionKey(k) & K(k) ==> RevealClassical & RevealPQ`. This machine-checks the
core promise of hybrid KEM/signature constructions.

## Concrete task checklist

- [ ] Add ML-KEM-768 to command + response key establishment (hybrid with
      X25519); direction-separated KDF (`c2s` / `s2c`).
- [ ] Add ML-DSA-65 to command + response signatures (hybrid with Ed25519).
- [ ] Grow the ESP response/command envelope + `heapless` buffers for PQ sizes.
- [ ] Extend role certificates to carry PQ public keys; supervisor dual-signs.
- [ ] eFuse: provision PQ identity keys (or derive from the identity seed).
- [ ] Model the hybrid combiner in Tamarin; prove "secure if either holds".

## References

- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- TLS hybrid key exchange (`X25519MLKEM768`)
- Signal PQXDH; Apple iMessage PQ3
- RustCrypto `ml-kem`, `ml-dsa` (`no_std`-capable)
