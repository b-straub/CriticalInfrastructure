# eFuse Key Hardening on the ESP32-S3

**Goal.** A device identity key burned into **read-protected eFuse** must be
usable *only by hardware* — software can never read it out. That is the whole
point of read-protection: physical access or a software exploit cannot extract
the key. This document records what the ESP32-S3 hardware can and cannot do for
this protocol, and how the firmware realizes the hardware-rooted identity.

## Key & trust model

Three independent trust domains, each anchored in its own hardware — no key is
ever shared between them:

| Key | Home | Role |
|-----|------|------|
| **Supervisor identity** | authenticator — **FIDO2 / WebAuthn-PRF** | derives the Ed25519 key that signs commands and issues role certificates |
| **Firmware secure-boot** | authenticator — **PIV, RSA-3072** | signs the Secure Boot v2 firmware image; eFuse stores only its public-key digest |
| **Device identity + flash key** | **ESP32 eFuse** (HMAC-KDF root + XTS-AES) | per-device X25519/Ed25519 seeds and the flash-encryption key; hardware-only, never leaves the chip |

The reference build uses a single **Token2 T2F2 (release 3.3)** authenticator for
the first two domains: its FIDO2 side backs the supervisor passkey, and its PIV
applet (NIST SP 800-73-4, RSA-3072-capable) holds the secure-boot signing key.
`always_uv` is on, so every operation requires user verification. In production
you would split these onto separate keys (a daily-use identity vs. a rarely-used
release-signing key); for this demo one device is fine.

### Secure-boot signing (RSA-3072)

ESP32-S3 Secure Boot v2 requires **RSA-3072-PSS** — the S3 has no ECDSA
secure-boot path, so the signing key *must* be RSA-3072:

- The key lives in a **PIV slot** and never leaves the authenticator. Sign
  firmware via OpenSC PKCS#11 → `espsecure.py sign_data --hsm …`.
- **macOS/Linux:** the vendor companion app is still under development, but PIV
  signing is standards-based — reach the key through OpenSC's generic PKCS#11
  module. Provision the on-card RSA-3072 key where tooling is easiest (Windows
  companion app, or `pkcs11-tool` / `piv-tool`), then sign from any OS.
- **Enroll a backup signer.** Secure Boot v2 trusts up to **three** signing-key
  digests in eFuse — burn a second key's digest (on a backup authenticator) so a
  lost key never leaves the device unable to accept signed firmware.
- A Mac's Secure Enclave can't substitute here: it holds only P-256 EC keys (no
  RSA), so an RSA-3072 secure-boot key can only live on a PIV/HSM device.

## What the ESP32-S3 offers for eFuse-bound crypto

| Hardware | eFuse-key bound? | Use here |
|----------|------------------|----------|
| **HMAC-SHA256** (`esp-hal::hmac`) | **Yes** — HMAC over a read-protected eFuse key; key never leaves hardware | **Identity KDF root** (implemented) |
| **Flash encryption** (XTS-AES-256) | **Yes** — read-protected eFuse key, transparent hardware decrypt via the IDF bootloader | Encrypt stored data at rest (ROLES table, etc.) |
| **Secure Boot v2** | eFuse-stored key digest | Only signed firmware runs (closes the RAM-scrape path) |
| RSA **Digital Signature** peripheral | Yes (eFuse-wrapped key) | Not exposed by `esp-hal`; RSA, not Ed25519 |
| **AES** accelerator | No GCM (ECB/CBC/CTR/CFB/OFB only) | GCM stays in constant-time software |
| **ECC** accelerator | P-192 / P-256 only | **No Curve25519** — cannot do Ed25519/X25519 |

**The key constraint:** the ESP32-S3 has **no Curve25519 hardware** and no
ECDSA peripheral. The protocol uses Ed25519 (signing) and X25519 (ECDH), so the
device keys cannot be operated on entirely inside hardware the way an RSA DS key
or an XTS flash key can. Hardware crypto still anchors the identity — via a
hardware-only **root** from which the Curve25519 seeds are derived.

## The realized design: HMAC-KDF from a read-protected eFuse root

Implemented behind the `efuse-hmac-identity` Cargo feature
(`target-esp32s3/src/main.rs`):

1. Burn a 256-bit key into **eFuse block 0**, **read-protected**, with key
   purpose **`HMAC_UP`** (HMAC upstream / user-readable output).
2. At boot the firmware uses the **HMAC-SHA256 peripheral** to compute
   - `x25519_seed  = HMAC(eFuse_key, "esp-x25519-identity-v1")`
   - `ed25519_seed = HMAC(eFuse_key, "esp-ed25519-signing-v1")`
   The HMAC engine reads the key straight from eFuse; **software never sees it.**
3. The derived seeds feed software Ed25519/X25519. They live only in RAM and are
   re-derived every boot — **nothing is written to flash.**

Properties:

- **Root secret is hardware-only and unclonable.** You cannot extract it or
  clone the device's identity, even with physical access.
- **No plain-flash key.** The insecure "generate → store in flash" path is gone
  in this mode (it remains only in the default dev build, which shouts a
  NOT-PRODUCTION-SAFE banner).
- **No silent fallback.** With the feature on and no eFuse key provisioned, the
  firmware panics loudly rather than deriving a software key.
- **Residual:** the derived Curve25519 seed is in RAM during operation, so a
  runtime memory-disclosure exploit on unsigned firmware could read it. Enable
  **Secure Boot v2** (only signed firmware runs) + **flash encryption** to close
  that path.

## Provisioning checklist (production)

- [ ] Generate a 256-bit random HMAC key; burn into eFuse **block 0** as
      `HMAC_UP`, then **read-protect** the block (`espefuse.py burn_key`).
- [ ] Build with `--features efuse-hmac-identity`.
- [ ] Read the `ESP32 Ed25519 Response-Signing PubKey` printed at boot; provision
      it into the WebApp "ESP32 Sig Pubkey" field.
- [ ] Enable **flash encryption** (XTS-AES-256, eFuse key) so the ROLES table and
      any stored data are encrypted at rest.
- [ ] Enable **Secure Boot v2** so only signed firmware can run.

## If you need a key that is *never* in software

Curve25519 can't provide that on the S3. Two options, both larger changes:

- **RSA via the Digital Signature peripheral** — the private key is stored
  eFuse-wrapped and signing happens entirely in hardware. Requires switching the
  response signature from Ed25519 to RSA and a `ds` driver (not in `esp-hal`
  today).
- **A chip with an ECDSA peripheral** (ESP32-C6 / H2 / P4) — signs with a
  read-protected eFuse P-256 key in hardware. Requires Ed25519 → ECDSA-P256 and a
  target change.

For this project the HMAC-KDF root + Secure Boot + flash encryption is the
pragmatic, strong hardening that keeps the Ed25519/X25519 protocol intact.
