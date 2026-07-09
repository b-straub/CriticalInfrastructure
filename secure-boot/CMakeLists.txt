cmake_minimum_required(VERSION 3.16)
# Minimal ESP-IDF project whose only job is `idf.py bootloader` — a Secure Boot v2,
# externally/HSM-signed second-stage bootloader for the ESP32-S3. The real firmware
# is the esp-hal Rust image; see docs/formal/SECURE-BOOT-V2.md.
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(sb_bootloader)
