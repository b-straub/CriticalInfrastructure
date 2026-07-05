# Critical Infrastructure Hardware Lockdown

A modern, highly secure blueprint for IoT and embedded devices in critical infrastructure environments.

## The Rationale

Critical infrastructure worldwide is currently facing an unprecedented vulnerability crisis. The security posture of operational technology and industrial control systems is often inadequate due to a combination of systemic challenges:

1. **Outdated Standards:** Many deployments rely on legacy security standards that were designed before the era of persistent, well-funded nation-state threat actors. 
2. **Slow Pace in Industry:** The physical engineering and industrial sectors historically move slowly. Hardware iterations take years, and updating protocols in production environments is treated as a high-risk liability.
3. **Failure to Adopt Modern Tech:** The industry has been overwhelmingly slow to adopt recent, massive leaps in both Artificial Intelligence (for threat modeling and automated security auditing) and embedded software (such as memory-safe languages like Rust).
4. **The Talent Gap & AI Acceleration:** There is a well-documented shortage of cybersecurity and embedded engineering talent globally. However, this gap can now be bridged. By leveraging advanced AI coding assistants, teams can rapidly deploy highly complex hardware security paradigms (like Hardware Security Module signing and PKCS#11 integration) that would have previously required entire teams of specialized cryptographers.

## Project Vision

This project demonstrates that it is now possible to build *impenetrable* embedded devices using commercially available microcontrollers (ESP32-S3), modern memory-safe systems languages (Rust), and enterprise-grade hardware cryptography (PIV Smart Cards) — all accelerated by AI.

### Features
*   **Memory-Safe Firmware:** Written in 100% Rust (`no_std`) to eliminate buffer overflows and memory corruption vulnerabilities.
*   **Hardware Cryptographic RBAC:** All commands are signed using Ed25519 signatures, ensuring strict Role-Based Access Control.
*   **True Hardware Security Module (HSM) Boot:** The ESP-IDF bootloader and Rust firmware are signed offline using an air-gapped PKCS#11 Smart Card token (such as a Token2 T2F2). 
*   **Irreversible eFuse Lockdown:** Bootloader verification hashes and AES-256 Flash Encryption keys are permanently burned into the silicon, making physical tampering impossible.

## Hardware Schematic

```mermaid
graph TD
    %% Define styles
    classDef esp fill:#2c3e50,stroke:#34495e,stroke-width:2px,color:#fff;
    classDef display fill:#2980b9,stroke:#2980b9,stroke-width:2px,color:#fff;
    classDef leds fill:#27ae60,stroke:#2ecc71,stroke-width:2px,color:#fff;
    classDef usb fill:#8e44ad,stroke:#9b59b6,stroke-width:2px,color:#fff;
    classDef action fill:#e67e22,stroke:#d35400,stroke-width:2px,color:#fff;
    classDef sensor fill:#16a085,stroke:#1abc9c,stroke-width:2px,color:#fff;

    %% Components
    ESP["Freenove ESP32-S3 WROOM Board<br>(Hardware Crypto Engine)"]:::esp
    Ring["8-LED WS2812 Ring<br>(Status Indicator)"]:::leds
    LCD["I2C 16x2 LCD Display<br>(Status / IP Address)"]:::display
    DHT11["DHT11 Temp / Humidity Sensor<br>(10kΩ DATA pull-up)"]:::sensor
    USB["USB-C Power / Data<br>(Secure Flashing)"]:::usb

    %% Connections
    USB -->|"Power / Firmware"| ESP
    
    %% LED Ring Connection Bundle
    ESP -->|"<b>LED Ring Header</b><br>⬛ Black: GND<br>🟥 Red: VCC<br>🟨 Yellow: DIN (GPIO 4)"| Ring
    
    %% Display Connection Bundle
    ESP -->|"<b>Display Header</b><br>🟫 Brown: GND<br>🟥 Red: VDD<br>🟧 Orange: SDA (GPIO 8)<br>🟨 Yellow: SCL (GPIO 9)"| LCD

    %% DHT11 Sensor Connection Bundle
    ESP -->|"<b>Sensor Header</b><br>🟥 Red: VCC (3V3)<br>⬛ Black: GND<br>⬜ White: DATA (GPIO 21)<br>↕️ 10kΩ pull-up (VCC ↔ DATA)"| DHT11
    
    %% Action Blocks (Styled instead of grey self-loops)
    RingAction("Illuminates based on RBAC Command Escalation:<br>🟩 Green -> Read Sensor Data<br>🟨 Yellow -> Override Safety Thresholds<br>🟥 Red -> Initiate Emergency Shutdown"):::action
    LCDAction("Displays: IP & Auth Result<br>Line 1: 192.168.x.x (DHCP)<br>Line 2: 'User Green Pass'<br>or 'Yellow Rejected'"):::action
    SensorAction("READ_SENSOR command:<br>🟩 Reads temperature + humidity from DHT11<br>Shown on LCD: 'Temp: 24.9C, RH: 47%'<br>🟥 Raises alarm if temp exceeds SET_THRESHOLD"):::action
    
    Ring ===> RingAction
    LCD ===> LCDAction
    DHT11 ===> SensorAction
```

![Hardware Setup](assets/hardware_setup.jpg)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Made with [**Google Antigravity**](https://antigravity.google) (Antigravity CLI `agy`) 🚀*
