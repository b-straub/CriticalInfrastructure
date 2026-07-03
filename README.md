# Secure Critical Infrastructure Remote Control

A modern, state-of-the-art educational project demonstrating how to build a production-level secured remote control system for critical infrastructure.

## The Problem
Many industrial control systems rely on specifications that are over a decade old. As cyber-physical attacks become more sophisticated, relying on outdated network perimeters, unencrypted transports, or legacy C code is no longer sufficient. 

## The Solution
This project demonstrates a modern approach using **Rust** for memory safety and the **ESP32-S3** for hardware-backed cryptography.

### Key Security Features Demonstrated:
1. **Application-Layer Cryptography (Ed25519)**: Every command sent to the hardware is cryptographically signed using modern elliptic-curve cryptography. Even if the transport network is compromised, the command payload cannot be forged or altered.
2. **Hardware Security (ESP32-S3)**: We utilize a microcontroller that supports **Secure Boot V2**, **Flash Encryption**, and hardware cryptographic accelerators, defending against attackers who have physical access to the device.
3. **Memory Safety (Rust)**: By using the Rust programming language, we eliminate entire classes of vulnerabilities (like buffer overflows and use-after-free errors) that have historically plagued C/C++ industrial firmware.

## Minimal Shopping List
To build this demo, you only need one item:
*   [Freenove Ultimate Starter Kit for ESP32-S3](https://www.amazon.de/FREENOVE-Ultimate-ESP32-S3-WROOM-Included-Compatible/dp/B0BMQ2CPQN) 
    *   *Includes the ESP32-S3 microcontroller, breadboard, LEDs, resistors, and an I2C LCD display.*

## Project Architecture
*   `master-cli/`: A PC-based command-line tool that generates the cryptographic keys and creates signed commands.
*   `target-esp32s3/`: The firmware running on the ESP32-S3. It verifies the Ed25519 signatures, checks authorization roles, and controls the physical hardware.
*   `shared/`: Shared cryptographic payload definitions ensuring both sides speak the exact same binary protocol.

## Getting Started
*(Full step-by-step guide coming soon!)*
