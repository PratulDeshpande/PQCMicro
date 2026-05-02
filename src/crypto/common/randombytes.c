#include "randombytes.h"
#include <stdint.h>

#if defined(ESP_PLATFORM) || defined(ESP32)
#include "esp_system.h"
#include "esp_random.h"

int randombytes(uint8_t *buf, size_t n) {
    esp_fill_random(buf, n);
    return 0;
}

#elif defined(ARDUINO)
#include "Arduino.h"

static bool seeded = false;

int randombytes(uint8_t *buf, size_t n) {
    if (!seeded) {
        // Collect environmental noise from unconnected analog pins to seed PRNG
        unsigned long seed = 0;
        for (int i = 0; i < 32; i++) {
            seed ^= (analogRead(A0) << (i % 8));
            delay(1); // Give ADC time to fluctuate
        }
        randomSeed(seed);
        seeded = true;
    }
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(random(256));
    }
    return 0;
}

#elif defined(STM32_CORE) || defined(STM32G4xx) || defined(STM32F4xx)
#include "stm32_def.h" // Fallback depending on framework
#include <stdlib.h>

int randombytes(uint8_t *buf, size_t n) {
    // Basic fallback using stdlib. In a real highly-secure app, 
    // tie this to HAL_RNG_GenerateRandomNumber
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
}

#else
// Generic fallback
#include <stdlib.h>

int randombytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
}
#endif
