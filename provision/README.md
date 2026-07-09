# provision/ — clone → running secure app, one script per stage

Each stage of the provisioning pipeline is a single parameterized bash script. Run
them in order for a fresh board; run just the one you need to iterate. All share
`lib.sh` (paths, port finder, supervisor PEM→hex, `espsecure[hsm]` resolver). Pass
`--help` to any script for its flags. Irreversible stages (2, 4) default to a **dry
run** and only burn with `--yes-burn`.

| # | Script | Does | Scope | Reversible |
|---|--------|------|-------|-----------|
| 0 | `0-toolchains.sh` | check/install espup, ESP-IDF, `esptool[hsm]`, OpenSC | per machine | ✅ |
| 1 | `1-enroll-key.sh` | export an inserted token's pubkey + hsm config + SBv2 digest | per key | ✅ |
| 2 | `2-efuse-harden.sh` | burn HMAC identity, JTAG off, secure download | per board | ❌ burn |
| 3 | `3-build-sign.sh` | build IDF bootloader + esp-hal app, HSM-sign both | per release | ✅ |
| 4 | `4-flash-enable-secureboot.sh` | flash signed chain + burn digests + `SECURE_BOOT_EN` | per board | ❌ enable |
| 5 | `5-flash-app.sh` | rebuild + sign + flash **just the app** (iterate loop) | runtime | ✅ |

Enrolled-key artifacts and signing config live in `../secure-boot/` (gitignored):
`hsm-<name>.ini`, `<name>_pub.pem`, `<name>_digest.bin`, optional `hsm-<name>.driver`.

Depth / background: [`../docs/formal/EFUSE-HARDENING.md`](../docs/formal/EFUSE-HARDENING.md)
(stage 2) and [`../docs/formal/SECURE-BOOT-V2.md`](../docs/formal/SECURE-BOOT-V2.md)
(stages 3–4). Stage 5 replaces the old `secure-boot/flash-signed-app.sh`. Stage 2 is
the guided burn; the root `efuse-harden.sh` still offers the read-only `check` and
`genkey` helpers.

> North star: the SwiftUI app (`../clients/apple`) drives stages 1–5 and takes the
> Wi-Fi password from Keychain instead of `--pass`. For now we run the stages by hand.
