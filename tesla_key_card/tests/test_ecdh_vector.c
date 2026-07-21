/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Host correctness guard for the vendored mbedTLS (lib/mbedtls) used by the
 * FAP's P-256 ECDH. The app's other host test (test_crypto_vector.py) pins the
 * MATH in Python; this one links the ACTUAL vendored C engine and asserts it
 * still produces the same shared secret. Its job is to catch a botched vendoring
 * or a config change that accidentally alters the arithmetic result — the whole
 * point of the fast-crypto change is that it must NOT.
 *
 * Vector (identical to test_crypto_vector.py):
 *   card_private    = 1
 *   vehicle_private = 2  ->  vehicle_public = 2*G
 *   shared          = card_private * vehicle_public = 2*G
 *   shared_x        = 7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978
 *
 * This mirrors tesla_crypto.c's path exactly: mbedtls_ecp_mul with a non-NULL
 * f_rng (point blinding on), then the uncompressed X coordinate.
 */

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* constant_time.c is intentionally not vendored (the firmware's curated mbedtls
 * omits it too); tesla_crypto.c supplies this same ABI-compatible shim on device. */
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

/* Deterministic non-zero filler. Only feeds ecp_mul's blinding, which never
 * changes the result — so the test stays reproducible without real entropy. */
static int test_rng(void* ctx, unsigned char* out, size_t len) {
    (void)ctx;
    for(size_t i = 0; i < len; ++i) out[i] = (unsigned char)(i * 7u + 1u);
    return 0;
}

static const char* EXPECTED_SHARED_X =
    "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";

int main(void) {
    int rc = 1;
    mbedtls_ecp_group grp;
    mbedtls_mpi d_card, d_vehicle;
    mbedtls_ecp_point vehicle_pub, shared;
    uint8_t encoded[65] = {0};
    char hex[65] = {0};

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d_card);
    mbedtls_mpi_init(&d_vehicle);
    mbedtls_ecp_point_init(&vehicle_pub);
    mbedtls_ecp_point_init(&shared);

    if(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        fprintf(stderr, "group_load failed\n");
        goto done;
    }
    if(mbedtls_mpi_lset(&d_card, 1) != 0 || mbedtls_mpi_lset(&d_vehicle, 2) != 0) {
        fprintf(stderr, "mpi_lset failed\n");
        goto done;
    }

    /* vehicle_public = 2 * G */
    if(mbedtls_ecp_mul(&grp, &vehicle_pub, &d_vehicle, &grp.G, test_rng, NULL) != 0) {
        fprintf(stderr, "ecp_mul (vehicle pub) failed\n");
        goto done;
    }
    /* shared = card_private (1) * vehicle_public (2G) = 2G */
    if(mbedtls_ecp_mul(&grp, &shared, &d_card, &vehicle_pub, test_rng, NULL) != 0) {
        fprintf(stderr, "ecp_mul (shared) failed\n");
        goto done;
    }

    size_t olen = 0;
    if(mbedtls_ecp_point_write_binary(
           &grp, &shared, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, encoded, sizeof(encoded)) != 0 ||
       olen != 65 || encoded[0] != 0x04) {
        fprintf(stderr, "point_write_binary failed (olen=%zu)\n", olen);
        goto done;
    }

    for(size_t i = 0; i < 32; ++i) snprintf(&hex[i * 2], 3, "%02x", encoded[1 + i]);

    if(strcmp(hex, EXPECTED_SHARED_X) != 0) {
        fprintf(stderr, "shared_x MISMATCH\n  got:      %s\n  expected: %s\n", hex, EXPECTED_SHARED_X);
        goto done;
    }

    printf("ECDH vendored-engine vector passed (shared_x=%s)\n", hex);
    rc = 0;

done:
    mbedtls_ecp_point_free(&shared);
    mbedtls_ecp_point_free(&vehicle_pub);
    mbedtls_mpi_free(&d_vehicle);
    mbedtls_mpi_free(&d_card);
    mbedtls_ecp_group_free(&grp);
    return rc;
}
