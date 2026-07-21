// SPDX-License-Identifier: GPL-3.0-or-later
//
// Host unit tests for gen4_dump_core.c. Plain cc, no Flipper/device dependency.
// Expected values are transcribed independently from the Proxmark3 Gen4/UMC
// documentation, not copied from the implementation.

#include "../gen4_dump_core.h"

#include <stdio.h>
#include <string.h>

static int g_checks = 0;
static int g_fails = 0;

#define CHECK(cond)                                                    \
    do {                                                               \
        g_checks++;                                                    \
        if(!(cond)) {                                                  \
            g_fails++;                                                 \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
        }                                                              \
    } while(0)

#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        g_checks++;                                                             \
        long _va = (long)(a);                                                   \
        long _vb = (long)(b);                                                   \
        if(_va != _vb) {                                                        \
            g_fails++;                                                          \
            printf(                                                             \
                "FAIL %s:%d: %s (%ld) != %s (%ld)\n",                           \
                __FILE__,                                                       \
                __LINE__,                                                       \
                #a,                                                            \
                _va,                                                            \
                #b,                                                            \
                _vb);                                                          \
        }                                                                       \
    } while(0)

static const uint8_t PWD[4] = {0x00, 0x00, 0x00, 0x00};
static const uint8_t PWD2[4] = {0xDE, 0xAD, 0xBE, 0xEF};

static void test_build_frames(void) {
    uint8_t out[GEN4_DUMP_MAX_FRAME];

    // get_config: CF | pwd | C6
    size_t n = gen4_dump_build_get_config(PWD2, out, sizeof(out));
    CHECK_EQ(n, 6);
    CHECK_EQ(out[0], 0xCF);
    CHECK_EQ(out[1], 0xDE);
    CHECK_EQ(out[2], 0xAD);
    CHECK_EQ(out[3], 0xBE);
    CHECK_EQ(out[4], 0xEF);
    CHECK_EQ(out[5], 0xC6);

    // get_revision: CF | pwd | CC
    n = gen4_dump_build_get_revision(PWD, out, sizeof(out));
    CHECK_EQ(n, 6);
    CHECK_EQ(out[0], 0xCF);
    CHECK_EQ(out[5], 0xCC);

    // read block 0x1A: CF | pwd | CE | 1A
    n = gen4_dump_build_read(PWD2, 0x1A, out, sizeof(out));
    CHECK_EQ(n, 7);
    CHECK_EQ(out[0], 0xCF);
    CHECK_EQ(out[1], 0xDE);
    CHECK_EQ(out[5], 0xCE);
    CHECK_EQ(out[6], 0x1A);

    // Overflow: a read frame needs 7 bytes; a 6-byte buffer must refuse.
    uint8_t tiny[6];
    CHECK_EQ(gen4_dump_build_read(PWD, 0x00, tiny, sizeof(tiny)), 0);
    // ...but 7 is exactly enough.
    uint8_t seven[7];
    CHECK_EQ(gen4_dump_build_read(PWD, 0x00, seven, sizeof(seven)), 7);

    // NULL guards.
    CHECK_EQ(gen4_dump_build_get_config(NULL, out, sizeof(out)), 0);
    CHECK_EQ(gen4_dump_build_get_config(PWD, NULL, sizeof(out)), 0);
    uint8_t args_dummy = 0;
    CHECK_EQ(gen4_dump_build_cmd(PWD, 0xCE, NULL, 1, out, sizeof(out)), 0);
    CHECK_EQ(gen4_dump_build_cmd(PWD, 0xCE, &args_dummy, 1, out, sizeof(out)), 7);
}

static void test_parse_config(void) {
    // Proxmark documented default UMC config:
    // 00 00 00 00 00 00 02 00 09 78 00 91 02 DA BC 19
    // 10 10 11 12 13 14 15 16 04 00 08 00 6B 02 4F 6B
    const uint8_t raw[GEN4_DUMP_CONFIG_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x09, 0x78, 0x00,
        0x91, 0x02, 0xDA, 0xBC, 0x19, 0x10, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x04, 0x00, 0x08, 0x00, 0x6B, 0x02, 0x4F, 0x6B};

    Gen4DumpConfig cfg;
    CHECK(gen4_dump_parse_config(raw, &cfg));
    CHECK_EQ(cfg.protocol, Gen4DumpProtocolMfClassic); // [0] 0x00
    CHECK_EQ(cfg.uid_len_code, 0x00); // [1]
    CHECK_EQ(cfg.gtu_mode, 0x02); // [6]
    CHECK_EQ(cfg.ats_len, 0x00); // [7]
    CHECK_EQ(cfg.atqa[0], 0x04); // [24]
    CHECK_EQ(cfg.atqa[1], 0x00); // [25]
    CHECK_EQ(cfg.sak, 0x08); // [26]
    CHECK_EQ(cfg.mfu_mode, 0x00); // [27]
    CHECK_EQ(cfg.total_blocks, 0x6B); // [28]
    CHECK_EQ(cfg.direct_write, 0x02); // [29]

    // ats_len must be clamped: a card returning 0xFF must not leak a bogus bound.
    uint8_t raw2[GEN4_DUMP_CONFIG_SIZE];
    memcpy(raw2, raw, sizeof(raw2));
    raw2[7] = 0xFF;
    CHECK(gen4_dump_parse_config(raw2, &cfg));
    CHECK_EQ(cfg.ats_len, GEN4_DUMP_ATS_MAX_LEN); // clamped to 16

    raw2[7] = 0x05;
    CHECK(gen4_dump_parse_config(raw2, &cfg));
    CHECK_EQ(cfg.ats_len, 0x05); // in range, preserved

    // An Ultralight/NTAG-emulating config: protocol 0x01, mfu_mode NTAG (0x01).
    uint8_t raw_ul[GEN4_DUMP_CONFIG_SIZE];
    memcpy(raw_ul, raw, sizeof(raw_ul));
    raw_ul[0] = 0x01;
    raw_ul[27] = 0x01;
    CHECK(gen4_dump_parse_config(raw_ul, &cfg));
    CHECK_EQ(cfg.protocol, Gen4DumpProtocolMfUltralight);
    CHECK_EQ(cfg.mfu_mode, 0x01);

    // NULL guards.
    CHECK(!gen4_dump_parse_config(NULL, &cfg));
    CHECK(!gen4_dump_parse_config(raw, NULL));
}

static void test_classic_kind(void) {
    uint16_t blocks = 0xFFFF;

    CHECK_EQ(gen4_dump_classic_kind_from_sak(0x08, &blocks), Gen4DumpKindMfClassic1K);
    CHECK_EQ(blocks, 64);
    CHECK_EQ(gen4_dump_classic_kind_from_sak(0x18, &blocks), Gen4DumpKindMfClassic4K);
    CHECK_EQ(blocks, 256);
    CHECK_EQ(gen4_dump_classic_kind_from_sak(0x09, &blocks), Gen4DumpKindMfClassicMini);
    CHECK_EQ(blocks, 20);

    // Cascade / ISO14443-4 bits set must not change the capacity decision.
    CHECK_EQ(gen4_dump_classic_kind_from_sak(0x08 | 0x04, &blocks), Gen4DumpKindMfClassic1K);
    CHECK_EQ(blocks, 64);
    CHECK_EQ(gen4_dump_classic_kind_from_sak(0x18 | 0x20, &blocks), Gen4DumpKindMfClassic4K);
    CHECK_EQ(blocks, 256);

    // Unknown SAK.
    CHECK_EQ(gen4_dump_classic_kind_from_sak(0x00, &blocks), Gen4DumpKindUnknown);
    CHECK_EQ(blocks, 0);

    // block_count may be NULL.
    CHECK_EQ(gen4_dump_classic_kind_from_sak(0x08, NULL), Gen4DumpKindMfClassic1K);
}

static void test_ul_type_from_version(void) {
    uint16_t pages = 0xFFFF;

    // NTAG213 (this is the real Wevo EV-tag GET_VERSION).
    const uint8_t ntag213[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03};
    CHECK_EQ(gen4_dump_ul_type_from_version(ntag213, &pages), Gen4DumpUlNTAG213);
    CHECK_EQ(pages, 45);

    const uint8_t ntag215[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03};
    CHECK_EQ(gen4_dump_ul_type_from_version(ntag215, &pages), Gen4DumpUlNTAG215);
    CHECK_EQ(pages, 135);

    const uint8_t ntag216[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03};
    CHECK_EQ(gen4_dump_ul_type_from_version(ntag216, &pages), Gen4DumpUlNTAG216);
    CHECK_EQ(pages, 231);

    const uint8_t ul11[8] = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03};
    CHECK_EQ(gen4_dump_ul_type_from_version(ul11, &pages), Gen4DumpUlUL11);
    CHECK_EQ(pages, 20);

    const uint8_t ul21[8] = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0E, 0x03};
    CHECK_EQ(gen4_dump_ul_type_from_version(ul21, &pages), Gen4DumpUlUL21);
    CHECK_EQ(pages, 41);

    // Non-NXP vendor -> unknown.
    const uint8_t other[8] = {0x00, 0x02, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03};
    CHECK_EQ(gen4_dump_ul_type_from_version(other, &pages), Gen4DumpUlUnknown);
    CHECK_EQ(pages, 0);

    // Unknown NTAG storage size -> unknown.
    const uint8_t weird[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x7F, 0x03};
    CHECK_EQ(gen4_dump_ul_type_from_version(weird, &pages), Gen4DumpUlUnknown);

    CHECK_EQ(gen4_dump_ul_type_from_version(NULL, &pages), Gen4DumpUlUnknown);
}

static void test_ul_type_from_mode(void) {
    uint16_t pages = 0xFFFF;

    CHECK_EQ(gen4_dump_ul_type_from_mode(0x02, &pages), Gen4DumpUlULC);
    CHECK_EQ(pages, 48);
    CHECK_EQ(gen4_dump_ul_type_from_mode(0x03, &pages), Gen4DumpUlUL);
    CHECK_EQ(pages, 16);

    // UL_EV1 (0x00) and NTAG (0x01) are not sizeable from mode alone.
    CHECK_EQ(gen4_dump_ul_type_from_mode(0x00, &pages), Gen4DumpUlUnknown);
    CHECK_EQ(pages, 0);
    CHECK_EQ(gen4_dump_ul_type_from_mode(0x01, &pages), Gen4DumpUlUnknown);
}

static void test_reads_needed(void) {
    CHECK_EQ(gen4_dump_reads_needed(0), 0);
    CHECK_EQ(gen4_dump_reads_needed(16), 1);
    CHECK_EQ(gen4_dump_reads_needed(17), 2);
    CHECK_EQ(gen4_dump_reads_needed(64 * 16), 64); // Classic 1K
    CHECK_EQ(gen4_dump_reads_needed(256 * 16), 256); // Classic 4K
    CHECK_EQ(gen4_dump_reads_needed(45 * 4), 12); // NTAG213: 180 bytes -> 12 reads
    CHECK_EQ(gen4_dump_reads_needed(135 * 4), 34); // NTAG215: 540 bytes -> 34 reads
}

static void test_key_and_uid(void) {
    const uint8_t key[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    CHECK_EQ(gen4_dump_key_to_u64(key), 0xA0A1A2A3A4A5ULL);
    const uint8_t ff[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CHECK_EQ(gen4_dump_key_to_u64(ff), 0xFFFFFFFFFFFFULL);
    CHECK_EQ(gen4_dump_key_to_u64(NULL), 0);

    // Classic block 0: uid(4) bcc sak atqa ...  -> 4-byte UID is block0[0..3].
    const uint8_t block0[16] = {
        0x04, 0x05, 0xBC, 0x5A, 0xEF, 0x08, 0x04, 0x00, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
    uint8_t uid[10] = {0};
    gen4_dump_uid_from_classic_block0(block0, 4, uid);
    CHECK_EQ(uid[0], 0x04);
    CHECK_EQ(uid[1], 0x05);
    CHECK_EQ(uid[2], 0xBC);
    CHECK_EQ(uid[3], 0x5A);
    CHECK_EQ(uid[4], 0x00); // untouched

    // uid_len clamp: never copy more than 10.
    uint8_t uid2[10] = {0};
    gen4_dump_uid_from_classic_block0(block0, 200, uid2);
    CHECK_EQ(uid2[9], 0x63); // exactly 10 bytes copied (block0[9]), no overflow

    // NTAG/UL 7-byte UID from pages 0 and 1 (Wevo: 04 05 BC 5A 16 1E 91).
    const uint8_t page0[4] = {0x04, 0x05, 0xBC, 0x48}; // [3] = BCC0, skipped
    const uint8_t page1[4] = {0x5A, 0x16, 0x1E, 0x91};
    uint8_t uid7[7] = {0};
    gen4_dump_uid_from_ul_pages(page0, page1, uid7);
    CHECK_EQ(uid7[0], 0x04);
    CHECK_EQ(uid7[1], 0x05);
    CHECK_EQ(uid7[2], 0xBC);
    CHECK_EQ(uid7[3], 0x5A);
    CHECK_EQ(uid7[4], 0x16);
    CHECK_EQ(uid7[5], 0x1E);
    CHECK_EQ(uid7[6], 0x91);
}

int main(void) {
    test_build_frames();
    test_parse_config();
    test_classic_kind();
    test_ul_type_from_version();
    test_ul_type_from_mode();
    test_reads_needed();
    test_key_and_uid();

    printf("\n%d checks, %d failures\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
