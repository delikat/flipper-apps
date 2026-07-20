#pragma once

#include "tesla_crypto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TESLA_NFC_UID_SIZE 4U

typedef struct {
    uint8_t uid[TESLA_NFC_UID_SIZE];
    uint8_t private_key[TESLA_PRIVATE_KEY_SIZE];
} TeslaIdentity;

typedef enum {
    TeslaIdentityLoadOk,
    TeslaIdentityLoadNotFound,
    TeslaIdentityLoadCorrupt,
    TeslaIdentityLoadStorageError,
    TeslaIdentityLoadCryptoError,
} TeslaIdentityLoadResult;

TeslaIdentityLoadResult tesla_identity_load(TeslaIdentity* identity);
bool tesla_identity_save(const TeslaIdentity* identity);
bool tesla_identity_delete(void);
void tesla_identity_generate_uid(uint8_t uid[TESLA_NFC_UID_SIZE]);
void tesla_identity_clear(TeslaIdentity* identity);

#ifdef __cplusplus
}
#endif
