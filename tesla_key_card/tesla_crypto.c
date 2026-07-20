#include "tesla_crypto.h"

#include "tesla_secure.h"

#include <furi.h>
#include <furi_hal_random.h>

#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha1.h>

#include <string.h>

#define TAG "TeslaCrypto"

#define TESLA_SHARED_X_SIZE 32U
#define TESLA_SHA1_SIZE     20U
#define TESLA_AES_KEY_SIZE  16U
#define TESLA_SALT_SIZE     4U

/* FW 089's bundled mbedTLS archive references this constant-time helper but
 * does not include its constant_time.c object. Keep the ABI-compatible shim
 * local to the FAP so P-256 point multiplication can link on API 87.8. */
void mbedtls_ct_memcpy_if(
    void* destination,
    const void* source,
    size_t size,
    unsigned char condition) {
    uint8_t* dst = destination;
    const uint8_t* src = source;
    const uint8_t mask = (uint8_t)(0U - (condition != 0U));
    for(size_t i = 0; i < size; ++i) {
        dst[i] = (uint8_t)((dst[i] & (uint8_t)~mask) | (src[i] & mask));
    }
}

struct TeslaCrypto {
    mbedtls_ecp_group group;
    mbedtls_mpi private_key;
    mbedtls_ecp_point public_key_point;
    uint8_t public_key[TESLA_PUBLIC_KEY_SIZE];
    bool group_ready;
    bool key_ready;
};

static int tesla_crypto_random(void* context, unsigned char* output, size_t size) {
    UNUSED(context);
    furi_hal_random_fill_buf(output, size);
    return 0;
}

TeslaCrypto* tesla_crypto_alloc(void) {
    TeslaCrypto* crypto = malloc(sizeof(TeslaCrypto));
    if(!crypto) return NULL;
    memset(crypto, 0, sizeof(TeslaCrypto));

    mbedtls_ecp_group_init(&crypto->group);
    mbedtls_mpi_init(&crypto->private_key);
    mbedtls_ecp_point_init(&crypto->public_key_point);

    if(mbedtls_ecp_group_load(&crypto->group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        FURI_LOG_E(TAG, "Unable to load P-256");
        tesla_crypto_free(crypto);
        return NULL;
    }

    crypto->group_ready = true;
    return crypto;
}

void tesla_crypto_free(TeslaCrypto* crypto) {
    if(!crypto) return;

    tesla_secure_zero(crypto->public_key, sizeof(crypto->public_key));
    mbedtls_ecp_point_free(&crypto->public_key_point);
    mbedtls_mpi_free(&crypto->private_key);
    mbedtls_ecp_group_free(&crypto->group);
    tesla_secure_zero(crypto, sizeof(TeslaCrypto));
    free(crypto);
}

bool tesla_crypto_set_private_key(
    TeslaCrypto* crypto,
    const uint8_t private_key[TESLA_PRIVATE_KEY_SIZE]) {
    furi_assert(crypto);
    furi_assert(private_key);

    if(!crypto->group_ready) return false;
    crypto->key_ready = false;
    tesla_secure_zero(crypto->public_key, sizeof(crypto->public_key));

    mbedtls_mpi_free(&crypto->private_key);
    mbedtls_mpi_init(&crypto->private_key);
    mbedtls_ecp_point_free(&crypto->public_key_point);
    mbedtls_ecp_point_init(&crypto->public_key_point);

    int error = mbedtls_mpi_read_binary(&crypto->private_key, private_key, TESLA_PRIVATE_KEY_SIZE);
    if(error == 0) error = mbedtls_ecp_check_privkey(&crypto->group, &crypto->private_key);
    if(error == 0) {
        error = mbedtls_ecp_mul(
            &crypto->group,
            &crypto->public_key_point,
            &crypto->private_key,
            &crypto->group.G,
            tesla_crypto_random,
            NULL);
    }

    size_t public_key_size = 0;
    if(error == 0) {
        error = mbedtls_ecp_point_write_binary(
            &crypto->group,
            &crypto->public_key_point,
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            &public_key_size,
            crypto->public_key,
            sizeof(crypto->public_key));
    }

    if(error != 0 || public_key_size != TESLA_PUBLIC_KEY_SIZE) {
        FURI_LOG_E(TAG, "Invalid private key (%d)", error);
        return false;
    }

    crypto->key_ready = true;
    return true;
}

bool tesla_crypto_generate_private_key(
    TeslaCrypto* crypto,
    uint8_t private_key[TESLA_PRIVATE_KEY_SIZE]) {
    furi_assert(crypto);
    furi_assert(private_key);

    mbedtls_mpi generated;
    mbedtls_mpi_init(&generated);

    int error = mbedtls_ecp_gen_privkey(&crypto->group, &generated, tesla_crypto_random, NULL);
    if(error == 0) {
        error = mbedtls_mpi_write_binary(&generated, private_key, TESLA_PRIVATE_KEY_SIZE);
    }
    mbedtls_mpi_free(&generated);

    if(error != 0) {
        FURI_LOG_E(TAG, "Private-key generation failed (%d)", error);
        tesla_secure_zero(private_key, TESLA_PRIVATE_KEY_SIZE);
        return false;
    }

    if(!tesla_crypto_set_private_key(crypto, private_key)) {
        tesla_secure_zero(private_key, TESLA_PRIVATE_KEY_SIZE);
        return false;
    }

    return true;
}

const uint8_t* tesla_crypto_get_public_key(const TeslaCrypto* crypto) {
    furi_assert(crypto);
    return crypto->key_ready ? crypto->public_key : NULL;
}

static bool tesla_crypto_authenticate_with_salt(
    TeslaCrypto* crypto,
    const uint8_t peer_public_key[TESLA_PUBLIC_KEY_SIZE],
    const uint8_t challenge[TESLA_CHALLENGE_SIZE],
    const uint8_t salt[TESLA_SALT_SIZE],
    uint8_t response[TESLA_AUTH_RESPONSE_SIZE]) {
    bool success = false;
    int error = 0;
    mbedtls_ecp_point peer_point;
    mbedtls_ecp_point shared_point;
    mbedtls_aes_context aes;
    uint8_t shared_x[TESLA_SHARED_X_SIZE] = {0};
    uint8_t shared_encoded[TESLA_PUBLIC_KEY_SIZE] = {0};
    uint8_t digest[TESLA_SHA1_SIZE] = {0};
    uint8_t plaintext[TESLA_CHALLENGE_SIZE] = {0};

    mbedtls_ecp_point_init(&peer_point);
    mbedtls_ecp_point_init(&shared_point);
    mbedtls_aes_init(&aes);

    if(!crypto->key_ready || peer_public_key[0] != 0x04U) {
        error = -1;
        goto cleanup;
    }

    error = mbedtls_ecp_point_read_binary(
        &crypto->group, &peer_point, peer_public_key, TESLA_PUBLIC_KEY_SIZE);
    if(error != 0) goto cleanup;

    error = mbedtls_ecp_check_pubkey(&crypto->group, &peer_point);
    if(error != 0) goto cleanup;

    error = mbedtls_ecp_mul(
        &crypto->group,
        &shared_point,
        &crypto->private_key,
        &peer_point,
        tesla_crypto_random,
        NULL);
    if(error != 0) goto cleanup;

    size_t shared_encoded_size = 0;
    error = mbedtls_ecp_point_write_binary(
        &crypto->group,
        &shared_point,
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        &shared_encoded_size,
        shared_encoded,
        sizeof(shared_encoded));
    if(error != 0 || shared_encoded_size != TESLA_PUBLIC_KEY_SIZE) goto cleanup;
    memcpy(shared_x, &shared_encoded[1], sizeof(shared_x));

    error = mbedtls_sha1(shared_x, sizeof(shared_x), digest);
    if(error != 0) goto cleanup;

    memcpy(plaintext, challenge, sizeof(plaintext));
    memcpy(plaintext, salt, TESLA_SALT_SIZE);

    error = mbedtls_aes_setkey_enc(&aes, digest, TESLA_AES_KEY_SIZE * 8U);
    if(error != 0) goto cleanup;

    error = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, response);
    if(error != 0) goto cleanup;

    success = true;

cleanup:
    if(!success) {
        FURI_LOG_W(TAG, "Authentication calculation failed (%d)", error);
        tesla_secure_zero(response, TESLA_AUTH_RESPONSE_SIZE);
    }
    tesla_secure_zero(plaintext, sizeof(plaintext));
    tesla_secure_zero(digest, sizeof(digest));
    tesla_secure_zero(shared_x, sizeof(shared_x));
    tesla_secure_zero(shared_encoded, sizeof(shared_encoded));
    mbedtls_aes_free(&aes);
    mbedtls_ecp_point_free(&shared_point);
    mbedtls_ecp_point_free(&peer_point);
    return success;
}

bool tesla_crypto_authenticate(
    TeslaCrypto* crypto,
    const uint8_t peer_public_key[TESLA_PUBLIC_KEY_SIZE],
    const uint8_t challenge[TESLA_CHALLENGE_SIZE],
    uint8_t response[TESLA_AUTH_RESPONSE_SIZE]) {
    furi_assert(crypto);
    furi_assert(peer_public_key);
    furi_assert(challenge);
    furi_assert(response);

    uint8_t salt[TESLA_SALT_SIZE];
    furi_hal_random_fill_buf(salt, sizeof(salt));
    const bool success =
        tesla_crypto_authenticate_with_salt(crypto, peer_public_key, challenge, salt, response);
    tesla_secure_zero(salt, sizeof(salt));
    return success;
}
