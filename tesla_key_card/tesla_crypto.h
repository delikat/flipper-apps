#pragma once

#include "tesla_apdu.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TESLA_PRIVATE_KEY_SIZE 32U

typedef struct TeslaCrypto TeslaCrypto;

TeslaCrypto* tesla_crypto_alloc(void);
void tesla_crypto_free(TeslaCrypto* crypto);

bool tesla_crypto_generate_private_key(
    TeslaCrypto* crypto,
    uint8_t private_key[TESLA_PRIVATE_KEY_SIZE]);

bool tesla_crypto_set_private_key(
    TeslaCrypto* crypto,
    const uint8_t private_key[TESLA_PRIVATE_KEY_SIZE]);

const uint8_t* tesla_crypto_get_public_key(const TeslaCrypto* crypto);

bool tesla_crypto_authenticate(
    TeslaCrypto* crypto,
    const uint8_t peer_public_key[TESLA_PUBLIC_KEY_SIZE],
    const uint8_t challenge[TESLA_CHALLENGE_SIZE],
    uint8_t response[TESLA_AUTH_RESPONSE_SIZE]);

#ifdef __cplusplus
}
#endif
