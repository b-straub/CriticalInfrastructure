# CriticalInfra — Apple native client (UDP flavor)

Native macOS client for the **UDP ROM flavor**. Its signing identity is a P-256
key in this Mac's **Secure Enclave** — the private key never leaves the enclave,
and **every command requires Touch ID**. No passkeys, no domains, no Associated
Domains: it just works locally, which is what makes it a clean demo.

A hardware security key (e.g. a Token2 in **PIV** mode) produces the same P-256
signature, so it drops in behind the same `CommandSigner` protocol with **zero
firmware change** — see [Hardware-key supervisor](#hardware-key-supervisor-piv--token2)
below (implemented and hardware-validated).

This is reference client #1 for the wire protocol in
[`docs/formal/UDP-TRANSPORT.md`](../../docs/formal/UDP-TRANSPORT.md).

## Architecture (library vs. app)

- **`CriticalInfraKit`** — a **UI-free** SwiftPM library (`swift build` / `swift test`):
  crypto (`CommandEnvelope`), UDP transport + reassembly (`UdpTransport`),
  `DeviceClient`, `DeviceConfig`, `Commands`, and the `EnclaveSigner`
  (`CommandSigner`). No SwiftUI.
- **`AppSources/`** — the **Xcode app target** (SwiftUI views, `AppModel`,
  `@main`). Owned by the app, *not* the package, so Xcode Previews work. Managed
  as a plain Xcode project (`CriticalInfra.xcodeproj`) — no code generation.

## Verify the core

```sh
cd clients/apple
swift build
swift test        # includes the P-256 ⇄ firmware interop round-trip
```

## Build & run the app

Open the Xcode project and run on **My Mac**:

```sh
cd clients/apple
open CriticalInfra.xcodeproj    # ⌘R to run (destination: My Mac)
```

Set your signing team once under **Target → Signing & Capabilities → Team** — the
app must be **signed** to use the Secure Enclave / Touch ID (an ad-hoc/unsigned
binary can't). For a standalone double-clickable app: **Product → Archive →
Distribute App → Custom → Copy App**.

On the first UDP send, macOS prompts for **Local Network** access — allow it, or
datagrams are dropped (System Settings → Privacy & Security → Local Network).

## Demo flow (no domains, no passkeys)

Identities are Secure Enclave keys, one per role. The **Supervisor** is the role
authority (create / list / revoke roles) and does *not* operate the device;
**Admin / Operator / Observer** run operational commands.

1. **Register Supervisor** — the first launch has no identity; create the
   Supervisor key and **Copy** its 66-hex P-256 public key.
2. **Flash** it as the supervisor:
   `./flash-udp.sh "<SSID>" "<PASS>" "<66-hex-supervisor-pubkey>"`. Note the
   device's X25519 ROM pubkey, Ed25519 sig pubkey, and IP.
3. **Settings** ⚙︎ → device IP + those two device keys → Save.
4. **Act as Supervisor** → *Roles* → **Register Admin / Operator / Observer**.
   Each creates that role's enclave key and provisions it on the device (Touch ID
   for the certificate + the command). The Supervisor can only do role CRUD.
5. **Switch** → pick **Admin** (or Operator / Observer) → run the role's
   operational commands (Read Sensor, Threshold, Clear/Test Alarm), each gated by
   Touch ID.

On one Mac you can hold all four keys and pick between them; in a real deployment
each role's key lives on that person's own Mac.

Touch ID is prompted **once per command** (the datagram is retried without
re-signing). Relax that to per-session later if desired.

> **Touch ID vs. password:** the enclave roles use `.userPresence` — Touch ID
> when a fingerprint is **enrolled**, otherwise the login password. If you only
> get password prompts, enroll a finger in *System Settings → Touch ID &
> Password* (no re-registration needed — `.userPresence` keys aren't bound to a
> specific enrollment). Touch ID also needs the **signed** (Xcode-built) app.

## Hardware-key supervisor (PIV / Token2)

The Supervisor identity can live on a **portable hardware security key** in PIV
mode instead of this Mac's enclave — the same P-256 `CommandSigner`, so **zero
firmware change**. Unlike an enclave key (bound to one Mac), the stick authorizes
from any Mac and its private key never leaves the card (PIN-gated). Validated
end-to-end against a **Token2 (PIV+FIDO+CCID)**.

1. **Provision the card:** generate an **ECCP256** key + **self-signed cert** in
   slot **9c** (Digital Signature — PIN per signature). The cert is required —
   macOS only surfaces a card key that has one.
2. **Insert the key** so macOS's native PIV driver (`pivtoken`) picks it up. Some
   vendors (Token2) ship their own CCID driver, so the card is *not* auto-published
   — a **fresh physical insert** is needed. Confirm:
   ```sh
   security list-smartcards          # must list com.apple.pivtoken:<GUID>
   ```
3. **Read its pubkey and flash it** as the supervisor — the app shows it under
   *Act as Supervisor* → **Copy**, or read it from the 9c cert directly:
   ```sh
   pkcs15-tool --read-certificate 02 | openssl x509 -noout -pubkey \
     | openssl ec -pubin -conv_form compressed -outform DER | tail -c 33 | xxd -p -c 33
   ```
   `./flash-udp.sh "<SSID>" "<PASS>" "<66-hex>"`, then **verify the boot log's
   `SSOT Supervisor PubKey` line matches** — a baked/card mismatch rejects every
   command as *"Signature verification failed or Unknown Role"*.
4. In the picker the inserted key shows as **Hardware Key** → **Act as Supervisor**
   → register roles / provision keys (a card **PIN** per signature; slot 9c does
   not cache).

> **Same card, two roles.** The Token2's PIV applet also holds the device's
> **RSA-3072 Secure Boot v2 signing key** in slot **9a** (ECC supervisor in 9c,
> RSA release-signer in 9a) — validated end-to-end. See
> [`docs/formal/EFUSE-HARDENING.md`](../../docs/formal/EFUSE-HARDENING.md).
