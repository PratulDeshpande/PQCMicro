/**
 * @file SignVerify.ino
 * @brief Easy API Example for Post-Quantum Digital Signatures (ML-DSA-44)
 * 
 * @author Pratul Deshpande
 * @contact https://pratuldeshpande.com/
 * @github https://github.com/PratulDeshpande
 * 
 * @details
 * This example demonstrates how to sign a message and verify its authenticity 
 * against future Quantum Computer attacks. It uses the `PQCDilithium` wrapper 
 * class, which manages Dilithium's massive (2.4KB) signatures securely on the 
 * heap and utilizes the FreeRTOS scheduler on ESP32 to prevent memory panics.
 * 
 * @note
 * Alternative Implementation Suggestion:
 * Generating a Dilithium Keypair is computationally expensive and drains IoT 
 * batteries. In production firmware, you should generate the keypair ONLY ONCE 
 * on first boot, and then use the library's NVS flash storage to save the keys.
 * Example: `signer.saveKeysToFlash("myDeviceID");`
 * Next reboot: `signer.loadKeysFromFlash("myDeviceID");`
 */

#include <Arduino.h>
#include <PQCMicro.h>

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("--- PQC ML-DSA-44 (Dilithium) Easy API Example ---");

  // 1. Create a Dilithium object
  // Memory is dynamically allocated safely in the background.
  PQCDilithium signer;

  // The message we want to sign
  const char* msg = "Hello, Post-Quantum World!";
  size_t msglen = strlen(msg);

  // 2. Generate Keypair
  // On ESP32, this automatically spawns a FreeRTOS task with a massive stack 
  // to prevent the MCU from crashing during signature generation.
  Serial.println("\n1. Generating Keys...");
  unsigned long t0 = millis();
  if (!signer.generateKeys()) {
    Serial.println("Keygen Failed!");
    return;
  }
  Serial.print("   Generated in ");
  Serial.print(millis() - t0);
  Serial.println(" ms");

  // 3. Sign the message
  Serial.println("\n2. Signing Message...");
  t0 = millis();
  if (!signer.sign((const uint8_t*)msg, msglen)) {
    Serial.println("Signing Failed!");
    return;
  }
  Serial.print("   Signature generated in ");
  Serial.print(millis() - t0);
  Serial.println(" ms");
  Serial.print("   Signature length: ");
  Serial.println(signer.getSignatureLength());

  // 4. Verify the signature
  Serial.println("\n3. Verifying Signature...");
  t0 = millis();
  
  // Note: We use the signature and public key from the 'signer' object directly 
  // here for demonstration, but in reality, these would have been transmitted 
  // over a network to a remote verification server.
  bool isValid = signer.verify((const uint8_t*)msg, msglen, signer.getPublicKey(), signer.getSignature(), signer.getSignatureLength());
  
  Serial.print("   Verification took ");
  Serial.print(millis() - t0);
  Serial.println(" ms");

  Serial.println("\n--- RESULT ---");
  if (isValid) {
    Serial.println("SUCCESS! The message signature is valid!");
  } else {
    Serial.println("FAILURE! The message signature is invalid.");
  }
}

void loop() { }
