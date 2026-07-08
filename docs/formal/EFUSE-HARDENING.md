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
| **Supervisor identity** | **WebAuthn-PRF** passkey (web flavor) · **Token2 PIV ECCP256** slot 9c, or Mac Secure Enclave (native flavor) | signs commands, issues role certificates |
| **Firmware secure-boot** | **Token2 PIV, RSA-3072** slot 9a | signs the Secure Boot v2 firmware image; eFuse stores only its public-key digest |
| **Device identity + flash key** | **ESP32 eFuse** (HMAC-KDF root + XTS-AES) | per-device X25519/Ed25519 seeds and the flash-encryption key; hardware-only, never leaves the chip |

On the reference board a single **Token2 PIN+ (release 3.3)** holds two of these
domains on its **PIV** applet — both validated end-to-end: the **native-flavor
supervisor** (ECCP256, slot 9c) and the **secure-boot signer** (RSA-3072, slot 9a).
The *web* flavor's supervisor is a WebAuthn-PRF passkey instead; the device-identity
and secure-boot domains are identical for both flavors. In production you would
split the rarely-used release-signing key onto its own token; for this demo one
device is fine.

### Secure-boot signing — RSA-3072 on the Token2 PIV (validated)

ESP32-S3 Secure Boot v2 requires **RSA-3072-PSS** (SHA-256) — the S3 has no ECDSA
secure-boot path, so the signing key *must* be RSA-3072. Only the **SHA-256 digest
of the public key** is burned into eFuse (`SECURE_BOOT_DIGEST0`, up to 3 keys); the
private key stays on the authenticator. A Mac's Secure Enclave can't substitute
(P-256 only, no RSA), which is why this key lives on the Token2 PIV.

**The Token2 PIV applet does this — validated end-to-end on the reference board.**
Its `SELECT AID` response advertises RSA 1024/2048/**3072**/4096 (the Windows
Companion App's PIV *generate* dialog only exposes 2048/4096, but the applet
supports 3072), and OpenSC's PKCS#11 module exposes the exact primitive:

```
$ pkcs11-tool --module /opt/homebrew/lib/opensc-pkcs11.so -M | grep -i pss
  RSA-PKCS-PSS         keySize={1024,3072}  hw, sign
  SHA256-RSA-PKCS-PSS  keySize={1024,3072}  sign        ← RSA-3072-PSS-SHA256
```
PIV RSA is a raw modexp on host-padded input, so the PSS encoding happens
host-side — the same reason a YubiKey PIV works as the reference HSM.

**Provision (PIV slot 9a, leaving 9c for the supervisor):** the Companion App can't
*generate* 3072 for PIV, so generate off-card and **import**:
```sh
openssl genrsa -out sb_key.pem 3072
openssl req -new -x509 -key sb_key.pem -sha256 -days 7300 \
  -subj "/CN=ESP32-S3 Secure Boot Signer" -out sb_cert.pem
openssl pkcs12 -export -inkey sb_key.pem -in sb_cert.pem -out sb_key.p12 -passout pass:CHANGEME
#  → import sb_key.p12 into PIV slot 9a via the Token2 Companion App, then:
rm -P sb_key.pem sb_key.p12        # destroy the off-card copy — key is now hardware-bound
```
The private key existed off-card only during generation/import; afterwards it's
card-only. Since it's then unrecoverable, **enroll a second key's digest for
backup** (Secure Boot v2 trusts up to 3) rather than keeping an off-card copy.

**Sign (validated):**
```sh
pip install 'esptool[hsm]'         # esp_hsm_sign + python-pkcs11
cat > hsm.ini <<'EOF'
[hsm_config]
pkcs11_lib = /opt/homebrew/lib/opensc-pkcs11.so
slot = 0
label = PIV AUTH key               # PIV slot 9a private key
label_pubkey = PIV AUTH pubkey
EOF
# 'credentials' omitted on purpose → espsecure prompts for the PIV PIN (never on disk)
espsecure sign-data --version 2 --hsm --hsm-config hsm.ini --output signed.bin app.bin
espsecure verify-signature --version 2 --keyfile sb_pub.pem signed.bin        # "Signature block 0 … successful"
espsecure digest-sbv2-public-key --keyfile sb_pub.pem --output sb_digest.bin  # the 32-byte SECURE_BOOT_DIGEST0
```
`esp_hsm_sign` signs with `RSA_PKCS_PSS(SHA256, MGF1-SHA256, salt=32)` — exactly the
mechanism above. Confirmed on hardware: the Token2 produced a Secure Boot v2
signature that `verify-signature` accepts.

**Enabling Secure Boot v2 is a separate, brick-prone step** beyond signing: the
second-stage bootloader must also be signed and verified, i.e. building the
**ESP-IDF bootloader** (not the bare esp-hal image espflash produces), then the
irreversible `SECURE_BOOT_DIGEST0` + `SECURE_BOOT_EN` burns. Do it last, on a final
image, with a backup key enrolled.

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

1. Burn a 256-bit key into **key block `BLOCK_KEY0`** (the firmware's
   `KeyId::Key0` — *not* the `BLOCK0` system block) with key purpose **`HMAC_UP`**
   (HMAC upstream / user-readable output). `burn-key … HMAC_UP` **auto
   read-protects** the block (sets `RD_DIS` for BLOCK4 — verified via an
   `espefuse --virt` dry-run), so software can never read the root; the HMAC
   peripheral still reads it internally.
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

## Provisioning runbook (production)

> **Every `burn-*` is irreversible** — eFuse bits only go 0 → 1, and espefuse makes
> you type `BURN` to confirm. Do the stages **in order**: the identity + JTAG burns
> keep the chip re-flashable; the external-read lockdown (Stage 4) blocks memory/
> eFuse dumps, so run it only once the hardware identity is verified working.
> `espefuse` ships with `esptool` (`brew install esptool` / `pip install esptool`).
> On esptool ≥ 5 every **real-device** command needs `--port <PORT>` (e.g.
> `/dev/cu.usbmodemXXXX`) with the chip in download mode — `--virt` does not. The
> examples below omit `--port` for brevity; add it, or use `./efuse-harden.sh`
> (which auto-detects the port).

**Rehearse first — no hardware, no burns.** `--virt` runs the whole sequence
against a virtual eFuse; this entire runbook was validated this way (it corrected a
docs claim — `HMAC_UP` *is* auto read-protected on the S3):

```sh
espefuse --virt --chip esp32s3 --path-efuse-file /tmp/virt.json --do-not-confirm \
  burn-key BLOCK_KEY0 hmac_key.bin HMAC_UP \
  burn-efuse DIS_PAD_JTAG 1 DIS_USB_JTAG 1 ENABLE_SECURITY_DOWNLOAD 1  summary
# expect: RD_DIS=1 (BLOCK4) · DIS_PAD_JTAG/DIS_USB_JTAG/ENABLE_SECURITY_DOWNLOAD = True
```

### Stage 0 — inspect (read-only)
```sh
espefuse summary                 # chip = ESP32-S3, nothing critical pre-burned
```

### Stage 1 — hardware identity root (HMAC-KDF key)
```sh
head -c 32 /dev/urandom > hmac_key.bin
espefuse burn-key BLOCK_KEY0 hmac_key.bin HMAC_UP   # auto read-protects (RD_DIS)
espefuse summary | grep RD_DIS                      # verify BLOCK4 read-disabled (=1)
rm -P hmac_key.bin                                     # macOS overwrite+delete (Linux: shred -u) — the raw root is clonable, destroy it
```

### Stage 2 — flash hardened firmware and VERIFY (still re-flashable)
```sh
cd target-esp32s3 && source ~/export-esp.sh
cargo espflash flash --release --no-default-features \
  --features "udp-transport,efuse-hmac-identity" --monitor
```
Boot log must show *"Deriving device identity from read-protected eFuse HMAC key"*
and a **new** `ESP32 Ed25519 Response-Signing PubKey` (not a panic). Provision that
pubkey into the client (it differs from the dev key), run a full command
round-trip. **Do not proceed until identity + a command verify.**

### Stage 3 — disable JTAG (irreversible; still re-flashable)
```sh
espefuse burn-efuse DIS_PAD_JTAG 1     # hard-disable pin JTAG
espefuse burn-efuse DIS_USB_JTAG 1     # disable USB-Serial-JTAG's JTAG (USB-CDC logs still work)
```

### Stage 4 — lock external read (POINT OF NO RETURN for dumps)
```sh
espefuse burn-efuse ENABLE_SECURITY_DOWNLOAD 1
```
Secure download still **flashes** firmware but disables all SRAM/register/flash/
eFuse **reads** over the download path — no external dump of anything. Two
consequences: `espefuse summary` (and all reads) stop working, and reflashing
becomes **stubless** (`esptool write_flash --no-stub`; verify `cargo espflash`
still works before relying on it). So do this **last**, when the image is final —
it's the seal. (For units that must never be re-flashed at all, use `burn-efuse
DIS_DOWNLOAD_MODE 1` instead — updates then only via a signed OTA path you build.)

### Stage 5 — (heavier) encrypt at rest + only-signed-firmware
Flash encryption (XTS-AES-256) and Secure Boot v2 (RSA-3072) close the last
residual — a RAM/flash disclosure on unsigned firmware. Both need the second-stage
bootloader to do transparent decrypt / signature verification, so on a bare esp-hal
image flashed with espflash they require the IDF bootloader + `espsecure` signing
(§ "Secure-boot signing" — the RSA-3072 signer lives on the PIV card).

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
