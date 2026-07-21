#pragma once

/**
* tesla_key_card FAP-local mbedTLS config.
*
* This is the Unleashed firmware's stock `lib/mbedtls_cfg.h` (the config the
* shared, fap_libs-linkable "mbedtls" is built from) copied verbatim, with ONE
* deliberate deviation: the two portability flags that force mbedTLS onto its
* slow bignum fallbacks are disabled here, and the ECP window is widened.
*
* Rationale: the shared firmware mbedtls builds P-256 variable-base scalar
* multiply (the ECDH in tesla_crypto.c) in ~471 ms on device, which is on the
* edge of the Tesla reader's ~500 ms activation window. The STM32WB55 CPU1 is a
* Cortex-M4 with a single-cycle 32x32->64 multiplier (UMAAL); NO_64BIT_MULTIPLICATION
* forces the ~3x-slower 32x32->32 double path instead. Re-enabling 64-bit multiply
* and 64-bit division, plus a larger comb window, is a config-only change: it alters
* HOW the bignum arithmetic is computed, never WHAT it computes, so the ECDH output
* is bit-identical (guarded by the host vector in tests/, priv=1,peer=pub(2) ->
* shared_x 7cf27b18...). Same mbedTLS 3.6.2 sources as the firmware; only these
* three lines differ.
**/

#define MBEDTLS_HAVE_ASM

/* Firmware sets these to stay portable to 32-bit-only targets; the WB55's M4 has
 * the wider multiply/divide, so leave them off for the ~3x P-256 speedup. */
// #define MBEDTLS_NO_UDBL_DIVISION
// #define MBEDTLS_NO_64BIT_MULTIPLICATION

#define MBEDTLS_DEPRECATED_WARNING

#define MBEDTLS_AES_FEWER_TABLES
// #define MBEDTLS_CHECK_RETURN_WARNING

#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_OFB
#define MBEDTLS_CIPHER_MODE_XTS

#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS

/* Short Weierstrass curves (supporting ECP, ECDH, ECDSA) */
// #define MBEDTLS_ECP_DP_SECP192R1_ENABLED
// #define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
// #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
// #define MBEDTLS_ECP_DP_SECP521R1_ENABLED
// #define MBEDTLS_ECP_DP_SECP192K1_ENABLED
// #define MBEDTLS_ECP_DP_SECP224K1_ENABLED
// #define MBEDTLS_ECP_DP_SECP256K1_ENABLED
// #define MBEDTLS_ECP_DP_BP256R1_ENABLED
// #define MBEDTLS_ECP_DP_BP384R1_ENABLED
// #define MBEDTLS_ECP_DP_BP512R1_ENABLED
/* Montgomery curves (supporting ECP) */
// #define MBEDTLS_ECP_DP_CURVE25519_ENABLED
// #define MBEDTLS_ECP_DP_CURVE448_ENABLED

#define MBEDTLS_ECP_NIST_OPTIM

/* Widen the sliding-comb window for variable-base scalar multiply (default 4).
 * 6 is the practical max; trades a few KB of heap for the precomputed table
 * against fewer point additions per ECDH. */
#define MBEDTLS_ECP_WINDOW_SIZE 6

#define MBEDTLS_GENPRIME
// #define MBEDTLS_PKCS1_V15
// #define MBEDTLS_PKCS1_V21

#define MBEDTLS_MD_C

#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C

// #define MBEDTLS_CHACHA20_C
// #define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_DES_C
#define MBEDTLS_DHM_C

#define MBEDTLS_ECDH_C

#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C

#define MBEDTLS_GCM_C

#define MBEDTLS_AES_C
#define MBEDTLS_MD5_C

// #define MBEDTLS_PEM_PARSE_C
// #define MBEDTLS_PEM_WRITE_C

// #define MBEDTLS_PLATFORM_MEMORY
// #define MBEDTLS_PLATFORM_C

// #define MBEDTLS_RIPEMD160_C
// #define MBEDTLS_RSA_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA1_C

#define MBEDTLS_ERROR_C