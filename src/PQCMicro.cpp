/**
 * @file PQCMicro.cpp
 * @brief Implementation of PQCMicro "EasyMode" OOP wrapper.
 * 
 * @author Pratul Deshpande
 * @contact https://pratuldeshpande.com/
 * @github https://github.com/PratulDeshpande
 * 
 * @details
 * This file contains the implementation of the memory-managed wrappers for ML-KEM 
 * and ML-DSA. It includes advanced FreeRTOS Task Spawning for ESP32 devices to 
 * bypass the default 8KB stack limit, which is insufficient for Quantum math.
 */

#include "PQCMicro.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(ESP32) || defined(ESP_PLATFORM)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#if defined(ARDUINO)
#include <Preferences.h>
#endif
#endif

// =========================================================
// FIPS 203: ML-KEM-512 (Kyber)
// =========================================================
#ifndef PQCMICRO_DISABLE_MLKEM

// Raw Core implementations
int MLKEM512::keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}

int MLKEM512::encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int MLKEM512::decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
}

// ---------------------------------------------------------
// PQCKyber "EasyMode" OOP API
// ---------------------------------------------------------

PQCKyber::PQCKyber() {
    allocateBuffers();
    has_pk = false;
    has_sk = false;
    has_ct = false;
    has_ss = false;
}

PQCKyber::~PQCKyber() {
    freeBuffers();
}

/**
 * @brief Dynamically allocates memory for the Keys on the HEAP.
 * @note This is critical for microcontrollers because allocating a 1632-byte 
 * secret key on a small function stack will trigger a Stack Overflow Panic.
 */
void PQCKyber::allocateBuffers() {
    pk = (uint8_t*)malloc(MLKEM512::PUBLICKEYBYTES);
    sk = (uint8_t*)malloc(MLKEM512::SECRETKEYBYTES);
    ct = (uint8_t*)malloc(MLKEM512::CIPHERTEXTBYTES);
    ss = (uint8_t*)malloc(MLKEM512::SHAREDKEYBYTES);
}

void PQCKyber::freeBuffers() {
    if (pk) free(pk);
    if (sk) free(sk);
    if (ct) free(ct);
    if (ss) free(ss);
}

// ESP32 Task Helpers - Transparent FreeRTOS execution
#if defined(ESP32) || defined(ESP_PLATFORM)
struct KyberTaskArgs {
    PQCKyber* instance;
    SemaphoreHandle_t sem;
    const uint8_t* peer_pk_ct;
    int result;
    int operation; // 0 = gen, 1 = enc, 2 = dec
};

static void kyber_task(void* pvParameters) {
    KyberTaskArgs* args = (KyberTaskArgs*)pvParameters;
    if (args->operation == 0) {
        args->result = MLKEM512::keypair((uint8_t*)args->instance->getPublicKey(), (uint8_t*)args->instance->getSecretKey());
    } else if (args->operation == 1) {
        args->result = MLKEM512::encapsulate((uint8_t*)args->instance->getCiphertext(), (uint8_t*)args->instance->getSharedSecret(), args->peer_pk_ct);
    } else if (args->operation == 2) {
        args->result = MLKEM512::decapsulate((uint8_t*)args->instance->getSharedSecret(), args->peer_pk_ct, args->instance->getSecretKey());
    }
    xSemaphoreGive(args->sem);
    vTaskDelete(NULL);
}
#endif

bool PQCKyber::generateKeys() {
    int res = -1;
#if defined(ESP32) || defined(ESP_PLATFORM)
    // Spawn a huge 32KB stack task specifically for the heavy matrix math
    KyberTaskArgs args = {this, xSemaphoreCreateBinary(), NULL, -1, 0};
    xTaskCreatePinnedToCore(kyber_task, "kyber_gen", 32768, &args, 1, NULL, 1);
    if (xSemaphoreTake(args.sem, pdMS_TO_TICKS(30000)) == pdTRUE) {
        res = args.result;
    } else {
        res = -1;
    }
    vSemaphoreDelete(args.sem);
#else
    // For standard generic boards
    res = MLKEM512::keypair(pk, sk);
#endif
    if (res == 0) {
        has_pk = true;
        has_sk = true;
        return true;
    }
    return false;
}

bool PQCKyber::encapsulate(const uint8_t* peer_pk) {
    if (!peer_pk) return false;
    int res = -1;
#if defined(ESP32) || defined(ESP_PLATFORM)
    KyberTaskArgs args = {this, xSemaphoreCreateBinary(), peer_pk, -1, 1};
    xTaskCreatePinnedToCore(kyber_task, "kyber_enc", 32768, &args, 1, NULL, 1);
    if (xSemaphoreTake(args.sem, pdMS_TO_TICKS(30000)) == pdTRUE) {
        res = args.result;
    } else {
        res = -1;
    }
    vSemaphoreDelete(args.sem);
#else
    res = MLKEM512::encapsulate(ct, ss, peer_pk);
#endif
    if (res == 0) {
        has_ct = true;
        has_ss = true;
        return true;
    }
    return false;
}

bool PQCKyber::decapsulate(const uint8_t* peer_ct) {
    if (!peer_ct || !has_sk) return false;
    int res = -1;
#if defined(ESP32) || defined(ESP_PLATFORM)
    KyberTaskArgs args = {this, xSemaphoreCreateBinary(), peer_ct, -1, 2};
    xTaskCreatePinnedToCore(kyber_task, "kyber_dec", 32768, &args, 1, NULL, 1);
    if (xSemaphoreTake(args.sem, pdMS_TO_TICKS(30000)) == pdTRUE) {
        res = args.result;
    } else {
        res = -1;
    }
    vSemaphoreDelete(args.sem);
#else
    res = MLKEM512::decapsulate(ss, peer_ct, sk);
#endif
    if (res == 0) {
        has_ss = true;
        return true;
    }
    return false;
}

// ---------------- Serialization Utilities ----------------

void PQCKyber::bytesToHex(const uint8_t* in, size_t inlen, char* out) {
    for (size_t i = 0; i < inlen; i++) {
        sprintf(out + (i * 2), "%02X", in[i]);
    }
}

bool PQCKyber::hexToBytes(const char* in, uint8_t* out, size_t outlen) {
    if (strlen(in) != outlen * 2) return false;
    for (size_t i = 0; i < outlen; i++) {
        sscanf(in + (i * 2), "%2hhx", &out[i]);
    }
    return true;
}

void PQCKyber::getPublicKeyHex(char* outBuffer) const {
    if (has_pk) bytesToHex(pk, MLKEM512::PUBLICKEYBYTES, outBuffer);
}

void PQCKyber::getCiphertextHex(char* outBuffer) const {
    if (has_ct) bytesToHex(ct, MLKEM512::CIPHERTEXTBYTES, outBuffer);
}

bool PQCKyber::setPublicKeyHex(const char* hexString) {
    if (hexToBytes(hexString, pk, MLKEM512::PUBLICKEYBYTES)) {
        has_pk = true;
        return true;
    }
    return false;
}

size_t PQCKyber::getPublicKeyChunk(uint8_t* buffer, size_t offset, size_t max_chunk_size) const {
    if (!has_pk || offset >= MLKEM512::PUBLICKEYBYTES) return 0;
    size_t size_to_copy = MLKEM512::PUBLICKEYBYTES - offset;
    if (size_to_copy > max_chunk_size) size_to_copy = max_chunk_size;
    memcpy(buffer, pk + offset, size_to_copy);
    return size_to_copy;
}

size_t PQCKyber::getCiphertextChunk(uint8_t* buffer, size_t offset, size_t max_chunk_size) const {
    if (!has_ct || offset >= MLKEM512::CIPHERTEXTBYTES) return 0;
    size_t size_to_copy = MLKEM512::CIPHERTEXTBYTES - offset;
    if (size_to_copy > max_chunk_size) size_to_copy = max_chunk_size;
    memcpy(buffer, ct + offset, size_to_copy);
    return size_to_copy;
}

#if defined(ARDUINO)
String PQCKyber::getPublicKeyHex() const {
    if (!has_pk) return String();
    char* hexBuf = (char*)malloc(MLKEM512::PUBLICKEYBYTES * 2 + 1);
    bytesToHex(pk, MLKEM512::PUBLICKEYBYTES, hexBuf);
    hexBuf[MLKEM512::PUBLICKEYBYTES * 2] = '\0';
    String s = String(hexBuf);
    free(hexBuf);
    return s;
}

String PQCKyber::getCiphertextHex() const {
    if (!has_ct) return String();
    char* hexBuf = (char*)malloc(MLKEM512::CIPHERTEXTBYTES * 2 + 1);
    bytesToHex(ct, MLKEM512::CIPHERTEXTBYTES, hexBuf);
    hexBuf[MLKEM512::CIPHERTEXTBYTES * 2] = '\0';
    String s = String(hexBuf);
    free(hexBuf);
    return s;
}
#endif

// ---------------- Persistent NVS Storage ----------------

#if defined(ESP32) && defined(ARDUINO)
bool PQCKyber::saveKeysToFlash(const char* label) {
    if (!has_pk || !has_sk) return false;
    Preferences prefs;
    prefs.begin(label, false);
    prefs.putBytes("pk", pk, MLKEM512::PUBLICKEYBYTES);
    prefs.putBytes("sk", sk, MLKEM512::SECRETKEYBYTES);
    prefs.end();
    return true;
}

bool PQCKyber::loadKeysFromFlash(const char* label) {
    Preferences prefs;
    prefs.begin(label, true);
    size_t pk_len = prefs.getBytesLength("pk");
    size_t sk_len = prefs.getBytesLength("sk");
    if (pk_len != MLKEM512::PUBLICKEYBYTES || sk_len != MLKEM512::SECRETKEYBYTES) {
        prefs.end();
        return false;
    }
    prefs.getBytes("pk", pk, MLKEM512::PUBLICKEYBYTES);
    prefs.getBytes("sk", sk, MLKEM512::SECRETKEYBYTES);
    prefs.end();
    has_pk = true;
    has_sk = true;
    return true;
}
#elif defined(ESP32)
// Fallback for raw ESP-IDF
bool PQCKyber::saveKeysToFlash(const char* label) { return false; }
bool PQCKyber::loadKeysFromFlash(const char* label) { return false; }
#endif

#endif // PQCMICRO_DISABLE_MLKEM


// =========================================================
// FIPS 204: ML-DSA-44 (Dilithium)
// =========================================================
#ifndef PQCMICRO_DISABLE_MLDSA

int MLDSA44::keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
}

int MLDSA44::sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

int MLDSA44::verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

// ---------------------------------------------------------
// PQCDilithium "EasyMode" OOP API
// ---------------------------------------------------------

PQCDilithium::PQCDilithium() {
    allocateBuffers();
    has_pk = false;
    has_sk = false;
    siglen = 0;
}

PQCDilithium::~PQCDilithium() {
    freeBuffers();
}

void PQCDilithium::allocateBuffers() {
    pk = (uint8_t*)malloc(MLDSA44::PUBLICKEYBYTES);
    sk = (uint8_t*)malloc(MLDSA44::SECRETKEYBYTES);
    sig = (uint8_t*)malloc(MLDSA44::SIGNATUREBYTES);
}

void PQCDilithium::freeBuffers() {
    if (pk) free(pk);
    if (sk) free(sk);
    if (sig) free(sig);
}

#if defined(ESP32) || defined(ESP_PLATFORM)
struct DilithiumTaskArgs {
    PQCDilithium* instance;
    SemaphoreHandle_t sem;
    const uint8_t* msg;
    size_t msglen;
    const uint8_t* peer_pk;
    const uint8_t* signature;
    size_t signature_len;
    int result;
    int operation; // 0 = gen, 1 = sign, 2 = verify
};

static void dilithium_task(void* pvParameters) {
    DilithiumTaskArgs* args = (DilithiumTaskArgs*)pvParameters;
    if (args->operation == 0) {
        args->result = MLDSA44::keypair((uint8_t*)args->instance->getPublicKey(), (uint8_t*)args->instance->getSecretKey());
    } else if (args->operation == 1) {
        size_t slen = 0;
        args->result = MLDSA44::sign((uint8_t*)args->instance->getSignature(), &slen, args->msg, args->msglen, args->instance->getSecretKey());
    } else if (args->operation == 2) {
        args->result = MLDSA44::verify(args->signature, args->signature_len, args->msg, args->msglen, args->peer_pk);
    }
    xSemaphoreGive(args->sem);
    vTaskDelete(NULL);
}
#endif

bool PQCDilithium::generateKeys() {
    int res = -1;
#if defined(ESP32) || defined(ESP_PLATFORM)
    DilithiumTaskArgs args = {this, xSemaphoreCreateBinary(), NULL, 0, NULL, NULL, 0, -1, 0};
    xTaskCreatePinnedToCore(dilithium_task, "dilithium_gen", 49152, &args, 1, NULL, 1);
    if (xSemaphoreTake(args.sem, pdMS_TO_TICKS(30000)) == pdTRUE) {
        res = args.result;
    } else {
        res = -1;
    }
    vSemaphoreDelete(args.sem);
#else
    res = MLDSA44::keypair(pk, sk);
#endif
    if (res == 0) {
        has_pk = true;
        has_sk = true;
        return true;
    }
    return false;
}

bool PQCDilithium::sign(const uint8_t* msg, size_t msglen) {
    if (!has_sk) return false;
    int res = -1;
#if defined(ESP32) || defined(ESP_PLATFORM)
    DilithiumTaskArgs args = {this, xSemaphoreCreateBinary(), msg, msglen, NULL, NULL, 0, -1, 1};
    xTaskCreatePinnedToCore(dilithium_task, "dilithium_sig", 49152, &args, 1, NULL, 1);
    if (xSemaphoreTake(args.sem, pdMS_TO_TICKS(30000)) == pdTRUE) {
        res = args.result;
    } else {
        res = -1;
    }
    vSemaphoreDelete(args.sem);
    siglen = MLDSA44::SIGNATUREBYTES; 
#else
    res = MLDSA44::sign(sig, &siglen, msg, msglen, sk);
#endif
    return (res == 0);
}

bool PQCDilithium::verify(const uint8_t* msg, size_t msglen, const uint8_t* peer_pk, const uint8_t* signature, size_t signature_len) {
    if (!peer_pk || !signature) return false;
    int res = -1;
#if defined(ESP32) || defined(ESP_PLATFORM)
    DilithiumTaskArgs args = {this, xSemaphoreCreateBinary(), msg, msglen, peer_pk, signature, signature_len, -1, 2};
    xTaskCreatePinnedToCore(dilithium_task, "dilithium_ver", 49152, &args, 1, NULL, 1);
    if (xSemaphoreTake(args.sem, pdMS_TO_TICKS(30000)) == pdTRUE) {
        res = args.result;
    } else {
        res = -1;
    }
    vSemaphoreDelete(args.sem);
#else
    res = MLDSA44::verify(signature, signature_len, msg, msglen, peer_pk);
#endif
    return (res == 0);
}

void PQCDilithium::bytesToHex(const uint8_t* in, size_t inlen, char* out) {
    for (size_t i = 0; i < inlen; i++) {
        sprintf(out + (i * 2), "%02X", in[i]);
    }
}

void PQCDilithium::getPublicKeyHex(char* outBuffer) const {
    if (has_pk) bytesToHex(pk, MLDSA44::PUBLICKEYBYTES, outBuffer);
}

#if defined(ARDUINO)
String PQCDilithium::getPublicKeyHex() const {
    if (!has_pk) return String();
    char* hexBuf = (char*)malloc(MLDSA44::PUBLICKEYBYTES * 2 + 1);
    bytesToHex(pk, MLDSA44::PUBLICKEYBYTES, hexBuf);
    hexBuf[MLDSA44::PUBLICKEYBYTES * 2] = '\0';
    String s = String(hexBuf);
    free(hexBuf);
    return s;
}
#endif

#if defined(ESP32) && defined(ARDUINO)
bool PQCDilithium::saveKeysToFlash(const char* label) {
    if (!has_pk || !has_sk) return false;
    Preferences prefs;
    prefs.begin(label, false);
    prefs.putBytes("pk", pk, MLDSA44::PUBLICKEYBYTES);
    prefs.putBytes("sk", sk, MLDSA44::SECRETKEYBYTES);
    prefs.end();
    return true;
}

bool PQCDilithium::loadKeysFromFlash(const char* label) {
    Preferences prefs;
    prefs.begin(label, true);
    size_t pk_len = prefs.getBytesLength("pk");
    size_t sk_len = prefs.getBytesLength("sk");
    if (pk_len != MLDSA44::PUBLICKEYBYTES || sk_len != MLDSA44::SECRETKEYBYTES) {
        prefs.end();
        return false;
    }
    prefs.getBytes("pk", pk, MLDSA44::PUBLICKEYBYTES);
    prefs.getBytes("sk", sk, MLDSA44::SECRETKEYBYTES);
    prefs.end();
    has_pk = true;
    has_sk = true;
    return true;
}
#elif defined(ESP32)
bool PQCDilithium::saveKeysToFlash(const char* label) { return false; }
bool PQCDilithium::loadKeysFromFlash(const char* label) { return false; }
#endif

#endif // PQCMICRO_DISABLE_MLDSA
