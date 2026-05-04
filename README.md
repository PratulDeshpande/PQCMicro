<div align="center">
  
# 🛡️ PQCMicro
**Post-Quantum Cryptography Toolkit for Microcontrollers**

[![Arduino Library](https://img.shields.io/badge/Arduino-Library-00979D.svg?logo=arduino)](https://github.com/arduino/library-registry)
[![PlatformIO](https://img.shields.io/badge/PlatformIO-Compatible-orange.svg?logo=platformio)](https://platformio.org)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-Native-red.svg?logo=espressif)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/)
[![NIST Standards](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204-blue)](#)
[![License: Apache](https://img.shields.io/badge/License-Apache-green.svg)](#)

*Future-proof your IoT devices against quantum computing threats with a simple, memory-safe API.*

</div>

<br/>

## 📖 Overview

**PQCMicro** is an advanced, production-ready C++ library that brings the latest NIST Post-Quantum Cryptography standards to highly constrained embedded devices (ESP32, STM32, Arduino).

Ported from the robust [PQClean](https://github.com/PQClean/PQClean) project, this library abstracts away the extreme memory requirements of lattice-based cryptography, allowing you to establish quantum-safe key exchanges and digital signatures with just three lines of code.

### Supported Standards
* **NIST FIPS 203 (ML-KEM / Kyber):** Module-Lattice-Based Key-Encapsulation Mechanism (Level 1 / 512).
* **NIST FIPS 204 (ML-DSA / Dilithium):** Module-Lattice-Based Digital Signature Algorithm (Level 2 / 44).

---

## ✨ Key Features

* **🧩 "EasyMode" OOP API:** No manual array sizing or byte-shuffling. The `PQCKyber` and `PQCDilithium` classes handle everything automatically.
* **🧠 Transparent Memory Management:** PQC keys are massive (up to 2.4KB). PQCMicro dynamically allocates keys on the Heap to completely prevent MCU stack-overflow crashes.
* **⚙️ FreeRTOS Aware:** On ESP32/ESP-IDF, the library automatically spawns high-capacity background tasks for heavy matrix math, making it 100% invisible to the user and non-blocking to your network stack.
* **🛡️ Watchdog Survival Engine:** Heavily optimized `fips202` (Keccak/SHA-3) loops yield to the hardware scheduler, preventing the dreaded Hardware WDT panic resets on slower microcontrollers.
* **💾 Deep-Sleep Persistence:** Built-in ESP32 Non-Volatile Storage (NVS) support to save keys to flash memory, saving massive amounts of battery and compute time across reboots.
* **📡 IoT Network Ready:** Extract public keys as Base16/Hex strings instantly, or use built-in chunking iterators to safely transmit keys over strict LoRaWAN or BLE MTU limits.

---

## ⚡ Quick Start

### 1. Key Exchange (ML-KEM)
Securely establish a shared secret over an insecure channel (WiFi, LoRa, BLE) without the risk of future decryption.

```cpp
#include <PQCMicro.h>

PQCKyber alice;
PQCKyber bob;

void setup() {
    // 1. Alice generates her keys
    alice.generateKeys();

    // 2. Bob encapsulates a shared secret using Alice's Public Key
    bob.encapsulate(alice.getPublicKey());

    // 3. Alice decapsulates the received ciphertext
    alice.decapsulate(bob.getCiphertext());

    // Alice and Bob now have the exact same 32-byte Quantum-Safe Shared Secret!
    const uint8_t* secret = alice.getSharedSecret();
}
```

### 2. Digital Signatures (ML-DSA)
Sign messages to prove authenticity against quantum forgery.

```cpp
#include <PQCMicro.h>

PQCDilithium signer;
const char* msg = "Firmware Update Data...";

void setup() {
    // Generate Keys
    signer.generateKeys();

    // Sign the message
    signer.sign((const uint8_t*)msg, strlen(msg));

    // Verify the signature
    bool isValid = signer.verify(
        (const uint8_t*)msg, 
        strlen(msg), 
        signer.getPublicKey(), 
        signer.getSignature(), 
        signer.getSignatureLength()
    );
}
```

---

## 🛠️ Advanced Usage

### Serialization & LoRa Chunking
Standard IoT protocols require strings or tiny packets.

```cpp
// Get Hex String for JSON/HTTP
String hexKey = alice.getPublicKeyHex(); 

// Transmit a massive 800-byte key over 200-byte LoRa packets
uint8_t buffer[200];
size_t bytesRead = alice.getPublicKeyChunk(buffer, 0, 200);
```

### Persistent Key Storage (ESP32)
Generating Dilithium keys drains IoT batteries. Generate it once, save it, and load it on the next boot.

```cpp
signer.generateKeys();
signer.saveKeysToFlash("device_key"); 

// After Deep Sleep wake-up:
signer.loadKeysFromFlash("device_key");
```

---

## 📦 Installation

### Arduino IDE
1. Open the Arduino IDE.
2. Go to **Sketch** -> **Include Library** -> **Manage Libraries...**
3. Search for **PQCMicro** and click Install.

### PlatformIO
Add the following to your `platformio.ini`:
```ini
lib_deps =
  PratulDeshpande/PQCMicro
```

### ESP-IDF
Add via the IDF Component Manager:
```bash
idf.py add-dependency "PratulDeshpande/pqcmicro"
```

---

## 💻 Hardware Compatibility

| Architecture | Platform | Status | Notes |
| :--- | :--- | :--- | :--- |
| **ESP32** (Xtensa/RISC-V) | Arduino / ESP-IDF | 🟢 Highly Optimized | Auto-tasking & NVS supported |
| **STM32** (ARM Cortex-M) | Arduino / STM32Cube | 🟢 Supported | Fast Keccak performance |
| **RP2040** (Raspberry Pi Pico) | Arduino / SDK | 🟢 Supported | Dual-core processing available |
| **AVR** (Arduino Uno/Mega) | Arduino | 🔴 Not Supported | Insufficient RAM (Requires >10KB SRAM) |

---

## 👨‍💻 Author

**Pratul Deshpande**
* 🌐 Website: [pratuldeshpande.com](https://pratuldeshpande.com/)
* 🐙 GitHub: [@PratulDeshpande](https://github.com/PratulDeshpande)

*Special thanks to the [PQClean](https://github.com/PQClean/PQClean) project for the underlying core cryptographic implementations.*

---
<div align="center">
  <i>If you use PQCMicro in your research or commercial project, please consider starring the repository! ⭐</i>
</div>
