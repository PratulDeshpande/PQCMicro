/**
 * @file KeyExchange.ino
 * @brief Easy API Example for Post-Quantum Key Exchange (ML-KEM-512)
 * 
 * @author Pratul Deshpande
 * @contact https://pratuldeshpande.com/
 * @github https://github.com/PratulDeshpande
 * 
 * @details
 * This example demonstrates how to securely establish a shared quantum-safe 
 * secret over an insecure channel. It uses the `PQCKyber` wrapper class which 
 * automatically manages all heavy memory allocations and FreeRTOS task handling.
 * 
 * @note
 * Alternative Implementation Suggestion:
 * To transmit the `alice.getPublicKeyHex()` string over LoRaWAN or BLE, you 
 * will exceed the network MTU limits. You must implement a chunking mechanism.
 * The library provides `alice.getPublicKeyChunk(buffer, offset, size)` to securely
 * loop through the key and transmit it in 200-byte packets.
 */

#include <Arduino.h>
#include <PQCMicro.h>

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("--- PQC ML-KEM-512 (Kyber) Easy API Example ---");

  // 1. Create two Kyber objects to simulate Alice and Bob.
  // Memory is dynamically allocated safely in the background (Heap).
  PQCKyber alice;
  PQCKyber bob;

  // 2. Alice generates her Keypair
  // On ESP32, this automatically spawns a FreeRTOS task with a 32KB stack to 
  // prevent the MCU from crashing during heavy lattice math.
  Serial.println("\n1. Alice is generating keys...");
  unsigned long t0 = millis();
  if (!alice.generateKeys()) {
    Serial.println("Alice Keygen Failed!");
    return;
  }
  Serial.print("   Generated in ");
  Serial.print(millis() - t0);
  Serial.println(" ms");
  
#if defined(ARDUINO)
  // The Public Key is serialized to a standard Hex string for easy IoT transmission
  Serial.println("   Alice Public Key (Start): " + alice.getPublicKeyHex().substring(0, 32) + "...");
#endif

  // 3. Bob uses Alice's Public Key to create an Encapsulated Shared Secret
  Serial.println("\n2. Bob is encapsulating a shared secret...");
  t0 = millis();
  if (!bob.encapsulate(alice.getPublicKey())) {
    Serial.println("Bob Encapsulation Failed!");
    return;
  }
  Serial.print("   Encapsulated in ");
  Serial.print(millis() - t0);
  Serial.println(" ms");

  // 4. Alice receives the Ciphertext from Bob and decapsulates her own Shared Secret
  Serial.println("\n3. Alice is decapsulating the shared secret...");
  t0 = millis();
  if (!alice.decapsulate(bob.getCiphertext())) {
    Serial.println("Alice Decapsulation Failed!");
    return;
  }
  Serial.print("   Decapsulated in ");
  Serial.print(millis() - t0);
  Serial.println(" ms");

  // 5. Verify they both successfully negotiated the exact same secret keys
  bool match = true;
  for (size_t i = 0; i < MLKEM512::SHAREDKEYBYTES; i++) {
    if (alice.getSharedSecret()[i] != bob.getSharedSecret()[i]) {
      match = false;
      break;
    }
  }

  Serial.println("\n--- RESULT ---");
  if (match) {
    Serial.println("SUCCESS! Alice and Bob share the identical quantum-safe key!");
  } else {
    Serial.println("FAILURE! The shared secrets do not match.");
  }
}

void loop() { }
