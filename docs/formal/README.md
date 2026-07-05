# Formal Models

This directory holds machine-checked symbolic models for the security-sensitive
parts of the Critical Infrastructure Dashboard. Each `.spthy` is a self-contained
Tamarin theory that encodes the intended security properties as `lemma` clauses
and is verifiable with [Tamarin Prover](https://tamarin-prover.com/).

## Models

- `dashboard.spthy` — Tamarin model for the Dashboard command protocol. It
  encodes the X25519 ephemeral key exchanges (ECDH), the AES-GCM envelope, the
  Ed25519 role signatures on commands, the ESP's Ed25519 signature on responses,
  and the device's monotonic-timestamp replay guard. Against a Dolev-Yao
  attacker it proves:
  - **command authentication** — no command executes without a matching signed
    command from the role;
  - **replay freedom** (`no_replay`, backed by `clock_monotonic`) — a device
    never executes the same timestamp twice; this is *proven* from the monotonic
    clock, not assumed;
  - **response authentication** — the WebApp accepts a response only if the ESP
    actually produced it (the response carries the ESP's signature, unforgeable
    without the ESP signing key); this closes an active-MITM response-forgery
    gap that an earlier ephemeral-only design left open;
  - **key secrecy** — the long-term ROM, role, and ESP signing keys never leak;
  - **forward secrecy** — responses are encrypted under an ephemeral×ephemeral
    DH key, so no long-term key compromise decrypts a past response.

  The command timestamp is modeled as an attacker-known public natural (it is
  `Date.now()` in reality), so replay protection rests on the device clock, not
  on timestamp secrecy.

## Running

From the repository root, you can execute the verification script:

```sh
./docs/formal/verify.sh
```

Or run the prover manually:

```sh
tamarin-prover --prove docs/formal/dashboard.spthy
```

Each invocation reports `verified` for every `lemma` clause when the model holds
against a Dolev-Yao attacker.

## Post-quantum

The current model and implementation use classical primitives (X25519, Ed25519,
AES-256-GCM, SHA-256). Post-quantum hardening is a documented follow-up — see
[`PQC-FOLLOWUP.md`](./PQC-FOLLOWUP.md) for the threat analysis and a concrete
hybrid (ML-KEM / ML-DSA) migration path.

---

*The formal models, the response-authentication fix, and the accompanying
analysis in this directory were developed with [Claude](https://claude.com/claude-code).*
