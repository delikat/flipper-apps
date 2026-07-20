/*
 * Host-side unit tests for the pure NDEF-format layout logic (ndef_layout.c).
 *
 * These assert that the block templates, 1K geometry, and key selection match
 * the Proxmark3 `hf mf ndefformat` reference byte-for-byte. The expected values
 * below are transcribed INDEPENDENTLY from the Proxmark source, so this is a
 * genuine cross-check rather than a re-read of the same table.
 *
 * Build/run: tests/run_tests.sh  (plain host cc, no Flipper dependency).
 */
#include "../ndef_layout.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned g_checks = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        ++g_checks;                                                       \
        if(!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            assert(cond);                                                 \
        }                                                                 \
    } while(0)

/* ---- Expected values, transcribed by hand from the Proxmark reference ---- */

static const uint8_t EXP_KEY_DEFAULT[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t EXP_KEY_MAD_A[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
static const uint8_t EXP_KEY_MAD_B[6] = {0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A};
static const uint8_t EXP_KEY_NDEF_A[6] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};

static const uint8_t EXP_ZERO[16] = {0};
static const uint8_t EXP_BLK1[16] =
    {0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1};
static const uint8_t EXP_BLK2[16] =
    {0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1};
static const uint8_t EXP_MAD_TRAILER[16] = /* block 3 */
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A};
static const uint8_t EXP_EMPTY_NDEF[16] = /* block 4 */
    {0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t EXP_NDEF_TRAILER[16] = /* block 7 and all later trailers */
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0x7F, 0x07, 0x88, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* Independently re-derived expectation for any block (mirrors the spec, not
 * the implementation's control flow). */
static const uint8_t* expected_block(uint8_t b, bool* should_write) {
    if(b == 0) {
        *should_write = false;
        return EXP_ZERO;
    }
    *should_write = true;
    switch(b) {
    case 1:
        return EXP_BLK1;
    case 2:
        return EXP_BLK2;
    case 3:
        return EXP_MAD_TRAILER;
    case 4:
        return EXP_EMPTY_NDEF;
    case 5:
    case 6:
        return EXP_ZERO;
    case 7:
        return EXP_NDEF_TRAILER;
    default:
        // Blocks 8..63: trailers get the NDEF trailer, data blocks are zeroed.
        return ((b % 4) == 3) ? EXP_NDEF_TRAILER : EXP_ZERO;
    }
}

static void test_geometry(void) {
    // Sector = block / 4 for 1K; trailers are blocks 3, 7, 11, ..., 63.
    for(uint8_t b = 0; b < MFC_NDEF_BLOCKS_1K; b++) {
        CHECK(mfc_ndef_sector_of_block(b) == (uint8_t)(b / 4));
        CHECK(mfc_ndef_block_is_trailer(b) == ((b % 4) == 3));
    }
    CHECK(mfc_ndef_sector_of_block(0) == 0);
    CHECK(mfc_ndef_sector_of_block(63) == 15);
    CHECK(mfc_ndef_block_is_trailer(3));
    CHECK(mfc_ndef_block_is_trailer(63));
    CHECK(!mfc_ndef_block_is_trailer(0));
    CHECK(!mfc_ndef_block_is_trailer(4));
}

static void test_build_block_spotchecks(void) {
    uint8_t out[16];
    bool w;

    // Block 0 is never written; buffer must be left zeroed.
    memset(out, 0xAA, sizeof(out));
    w = mfc_ndef_build_block(0, out);
    CHECK(w == false);
    CHECK(memcmp(out, EXP_ZERO, 16) == 0);

    CHECK(mfc_ndef_build_block(1, out) && memcmp(out, EXP_BLK1, 16) == 0);
    CHECK(mfc_ndef_build_block(2, out) && memcmp(out, EXP_BLK2, 16) == 0);
    CHECK(mfc_ndef_build_block(3, out) && memcmp(out, EXP_MAD_TRAILER, 16) == 0);
    CHECK(mfc_ndef_build_block(4, out) && memcmp(out, EXP_EMPTY_NDEF, 16) == 0);
    CHECK(mfc_ndef_build_block(5, out) && memcmp(out, EXP_ZERO, 16) == 0);
    CHECK(mfc_ndef_build_block(6, out) && memcmp(out, EXP_ZERO, 16) == 0);
    CHECK(mfc_ndef_build_block(7, out) && memcmp(out, EXP_NDEF_TRAILER, 16) == 0);

    // Later sector trailers reuse the NDEF trailer template.
    CHECK(mfc_ndef_build_block(11, out) && memcmp(out, EXP_NDEF_TRAILER, 16) == 0);
    CHECK(mfc_ndef_build_block(63, out) && memcmp(out, EXP_NDEF_TRAILER, 16) == 0);
    // A mid-sector data block is zeroed.
    CHECK(mfc_ndef_build_block(8, out) && memcmp(out, EXP_ZERO, 16) == 0);
    CHECK(mfc_ndef_build_block(62, out) && memcmp(out, EXP_ZERO, 16) == 0);
}

static void test_build_block_all(void) {
    // Exhaustive check across every 1K block against the independent expectation.
    for(uint8_t b = 0; b < MFC_NDEF_BLOCKS_1K; b++) {
        uint8_t out[16];
        bool exp_w;
        const uint8_t* exp = expected_block(b, &exp_w);
        bool got_w = mfc_ndef_build_block(b, out);
        CHECK(got_w == exp_w);
        CHECK(memcmp(out, exp, 16) == 0);
    }
}

static void test_keys_blank(void) {
    // Blank card: every sector uses default keys for both A and B.
    for(uint8_t s = 0; s < MFC_NDEF_SECTORS_1K; s++) {
        uint8_t ka[6], kb[6];
        mfc_ndef_sector_keys(false, s, ka, kb);
        CHECK(memcmp(ka, EXP_KEY_DEFAULT, 6) == 0);
        CHECK(memcmp(kb, EXP_KEY_DEFAULT, 6) == 0);
    }
}

static void test_keys_formatted(void) {
    uint8_t ka[6], kb[6];

    // Already formatted: sector 0 uses MAD keys...
    mfc_ndef_sector_keys(true, 0, ka, kb);
    CHECK(memcmp(ka, EXP_KEY_MAD_A, 6) == 0);
    CHECK(memcmp(kb, EXP_KEY_MAD_B, 6) == 0);

    // ...and every other sector uses NDEF key A with a default key B.
    for(uint8_t s = 1; s < MFC_NDEF_SECTORS_1K; s++) {
        mfc_ndef_sector_keys(true, s, ka, kb);
        CHECK(memcmp(ka, EXP_KEY_NDEF_A, 6) == 0);
        CHECK(memcmp(kb, EXP_KEY_DEFAULT, 6) == 0);
    }
}

int main(void) {
    test_geometry();
    test_build_block_spotchecks();
    test_build_block_all();
    test_keys_blank();
    test_keys_formatted();

    printf("ndef_layout: all %u checks passed\n", g_checks);
    return 0;
}
