/**
 * @file PQCMicro.h
 * @brief PQCMicro - Post-Quantum Cryptography for Microcontrollers
 * 
 * @author Pratul Deshpande
 * @contact https://pratuldeshpande.com/
 * @github https://github.com/PratulDeshpande
 * 
 * @details 
 * This library provides a memory-optimized, FreeRTOS-aware C++ wrapper around 
 * NIST FIPS 203 (ML-KEM/Kyber) and FIPS 204 (ML-DSA/Dilithium) implementations 
 * (originally derived from PQClean). It is specifically engineered to bypass 
 * memory bottlenecks (stack overflows) and watchdog constraints on resource-limited 
 * IoT devices like the ESP32 and STM32.
 * 
 * Key Features:
 * - Transparent Heap Allocation: Prevents MCU stack crashes from massive PQC arrays.
 * - FreeRTOS Integration: Automatically spawns large-stack tasks on ESP32/ESP-IDF.
 * - IoT Serialization: Built-in Base16/Hex strings and LoRa chunking utilities.
 * 
 * @note 
 * Alternative Implementation Suggestion: 
 * If you are running this on a microcontroller equipped with a hardware Keccak/SHA-3 
 * accelerator (e.g. certain high-end STM32s), you should modify the `src/crypto/common/fips202.c` 
 * backend to route calls directly to your Hardware Abstraction Layer (HAL) to save 
 * power and significantly speed up key generation.
 */

#ifndef PQCMICRO_H
#define PQCMICRO_H

#include <stdint.h>
#include <stddef.h>

#if defined(ARDUINO)
#include <Arduino.h>
#endif

// ==============================================================================
// FIPS 203: ML-KEM-512 (Kyber) Definitions
// ==============================================================================
#ifndef PQCMICRO_DISABLE_MLKEM
extern "C" {
#include "crypto/ml-kem-512/api.h"
}

/**
 * @class MLKEM512
 * @brief Raw static wrapper for ML-KEM-512 (Kyber).
 * 
 * Use this only if you want to manage memory (stack/heap) yourself. 
 * Warning: Allocating these keys on a local function stack will crash an ESP32.
 */
class MLKEM512 {
public:
    static const size_t PUBLICKEYBYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    static const size_t SECRETKEYBYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES;
    static const size_t CIPHERTEXTBYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    static const size_t SHAREDKEYBYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES;

    static int keypair(uint8_t *pk, uint8_t *sk);
    static int encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    static int decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
};

/**
 * @class PQCKyber
 * @brief The "EasyMode" OOP API for ML-KEM-512.
 * 
 * This class automatically handles all heap allocations, FreeRTOS background 
 * tasking, string serialization, and LoRa chunking. Just instantiate and use!
 */
class PQCKyber {
private:
    uint8_t* pk; // Dynamically allocated Public Key buffer
    uint8_t* sk; // Dynamically allocated Secret Key buffer
    uint8_t* ct; // Dynamically allocated Ciphertext buffer
    uint8_t* ss; // Dynamically allocated Shared Secret buffer
    
    // State flags
    bool has_pk;
    bool has_sk;
    bool has_ct;
    bool has_ss;

    void allocateBuffers();
    void freeBuffers();
    static void bytesToHex(const uint8_t* in, size_t inlen, char* out);
    static bool hexToBytes(const char* in, uint8_t* out, size_t outlen);

public:
    /**
     * @brief Constructor. Automatically allocates all required PQC buffers safely on the heap.
     */
    PQCKyber();
    ~PQCKyber();

    // Prevent Double-Free Heap Corruption (Rule of Three)
    PQCKyber(const PQCKyber&) = delete;
    PQCKyber& operator=(const PQCKyber&) = delete;

    // ---------------- High-Level Cryptography ----------------
    
    /**
     * @brief Generates a Public and Secret Key pair. 
     * @details On ESP32, this transparently spawns a 32KB FreeRTOS task, calculates the keys, 
     * syncs the result, and destroys the task. This prevents stack overflow.
     * @return true on success.
     */
    bool generateKeys();
    
    /**
     * @brief Encapsulates a shared secret using someone else's public key.
     * @param peer_pk A pointer to the peer's public key array.
     * @return true on success.
     */
    bool encapsulate(const uint8_t* peer_pk);
    
    /**
     * @brief Decapsulates the ciphertext received from a peer to establish the shared secret.
     * @param peer_ct A pointer to the peer's ciphertext array.
     * @return true on success.
     */
    bool decapsulate(const uint8_t* peer_ct);

    // ---------------- Standard Getters ----------------
    const uint8_t* getPublicKey() const { return pk; }
    const uint8_t* getSecretKey() const { return sk; }
    const uint8_t* getCiphertext() const { return ct; }
    const uint8_t* getSharedSecret() const { return ss; }

    bool hasPublicKey() const { return has_pk; }
    bool hasSecretKey() const { return has_sk; }
    bool hasCiphertext() const { return has_ct; }
    bool hasSharedSecret() const { return has_ss; }

    // ---------------- Serialization & Network ----------------
    
    /**
     * @brief Writes the public key as a standard Hex string to the provided buffer.
     * @param outBuffer Must be at least (PUBLICKEYBYTES * 2) + 1 bytes long.
     */
    void getPublicKeyHex(char* outBuffer) const;
    void getCiphertextHex(char* outBuffer) const;
    bool setPublicKeyHex(const char* hexString);

    /**
     * @brief Extracts a specific chunk of the key for transmission over constrained networks (LoRa/BLE).
     * @param buffer Output buffer.
     * @param offset The starting byte offset.
     * @param max_chunk_size The maximum size your network (MTU) allows per packet.
     * @return Number of bytes actually copied.
     */
    size_t getPublicKeyChunk(uint8_t* buffer, size_t offset, size_t max_chunk_size) const;
    size_t getCiphertextChunk(uint8_t* buffer, size_t offset, size_t max_chunk_size) const;

#if defined(ARDUINO)
    // Arduino-native string returning methods
    String getPublicKeyHex() const;
    String getCiphertextHex() const;
#endif

#if defined(ESP32) || defined(ESP_PLATFORM)
    // ---------------- Persistent Storage ----------------
    // Generates a keypair once and saves it to Non-Volatile Storage (NVS) to save battery 
    // across deep sleep reboots.
    bool saveKeysToFlash(const char* label);
    bool loadKeysFromFlash(const char* label);
#endif
};
#endif


// ==============================================================================
// FIPS 204: ML-DSA-44 (Dilithium) Definitions
// ==============================================================================
#ifndef PQCMICRO_DISABLE_MLDSA
extern "C" {
#include "crypto/ml-dsa-44/api.h"
}

/**
 * @class MLDSA44
 * @brief Raw static wrapper for ML-DSA-44 (Dilithium).
 */
class MLDSA44 {
public:
    static const size_t PUBLICKEYBYTES = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
    static const size_t SECRETKEYBYTES = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
    static const size_t SIGNATUREBYTES = PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;

    static int keypair(uint8_t *pk, uint8_t *sk);
    static int sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
    static int verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
};

/**
 * @class PQCDilithium
 * @brief The "EasyMode" OOP API for ML-DSA-44.
 * 
 * Automatically manages Dilithium's massive (2.4KB) signatures on the heap, 
 * bypassing constraints on standard microcontrollers.
 */
class PQCDilithium {
private:
    uint8_t* pk;
    uint8_t* sk;
    uint8_t* sig;
    size_t siglen;
    
    bool has_pk;
    bool has_sk;

    void allocateBuffers();
    void freeBuffers();
    static void bytesToHex(const uint8_t* in, size_t inlen, char* out);

public:
    PQCDilithium();
    ~PQCDilithium();

    // Prevent Double-Free Heap Corruption (Rule of Three)
    PQCDilithium(const PQCDilithium&) = delete;
    PQCDilithium& operator=(const PQCDilithium&) = delete;

    // ---------------- High-Level Cryptography ----------------
    bool generateKeys();
    bool sign(const uint8_t* msg, size_t msglen);
    bool verify(const uint8_t* msg, size_t msglen, const uint8_t* peer_pk, const uint8_t* signature, size_t signature_len);

    // ---------------- Standard Getters ----------------
    const uint8_t* getPublicKey() const { return pk; }
    const uint8_t* getSecretKey() const { return sk; }
    const uint8_t* getSignature() const { return sig; }
    size_t getSignatureLength() const { return siglen; }

    bool hasPublicKey() const { return has_pk; }
    bool hasSecretKey() const { return has_sk; }

    // ---------------- Serialization & Network ----------------
    void getPublicKeyHex(char* outBuffer) const;

#if defined(ARDUINO)
    String getPublicKeyHex() const;
#endif

#if defined(ESP32) || defined(ESP_PLATFORM)
    // ---------------- Persistent Storage ----------------
    bool saveKeysToFlash(const char* label);
    bool loadKeysFromFlash(const char* label);
#endif
};
#endif

#endif // PQCMICRO_H
