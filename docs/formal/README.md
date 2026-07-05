# Formal Models

This directory holds machine-checked symbolic models for the security-sensitive
parts of the Critical Infrastructure Dashboard. Each `.spthy` is a self-contained 
Tamarin theory that encodes the intended security properties as `lemma` clauses 
and is verifiable with [Tamarin Prover](https://tamarin-prover.com/).

## Models

- `dashboard.spthy` — Tamarin model for the Dashboard command protocol:
  Encodes the X25519 ephemeral key exchanges (ECDH), the AES-GCM 
  authenticated envelope, and the Ed25519 WebAuthn Role signatures.
  Verifies that a Dolev-Yao attacker cannot execute unauthenticated commands,
  forge responses, or extract the long-term static ROM/Role keys.

## Running

From the repository root, you can execute the verification script:

```sh
./docs/formal/verify.sh
```

Or run the prover manually:

```sh
tamarin-prover --prove docs/formal/dashboard.spthy
```

Each invocation reports `verified` for every `lemma` clause when the model
holds against a Dolev-Yao attacker over the encrypted at-rest channel.
