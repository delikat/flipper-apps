// SPDX-License-Identifier: GPL-3.0-or-later
//
// Gen4 "Ultimate Magic Card" (UMC) backdoor dump — pure protocol/layout logic.
// See gen4_dump_core.h for the module contract and licensing/attribution notes.

#include "gen4_dump_core.h"

#include <string.h>

// GTU config-block byte offsets (Proxmark doc/magic_cards_notes.md).
#define CFG_OFF_PROTOCOL     (0)
#define CFG_OFF_UID_LEN      (1)
#define CFG_OFF_GTU_MODE     (6)
#define CFG_OFF_ATS_LEN      (7)
#define CFG_OFF_ATQA         (24)
#define CFG_OFF_SAK          (26)
#define CFG_OFF_MFU_MODE     (27)
#define CFG_OFF_TOTAL_BLOCKS (28)
#define CFG_OFF_DIRECT_WRITE (29)

size_t gen4_dump_build_cmd(
    const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN],
    uint8_t cmd,
    const uint8_t* args,
    size_t args_len,
    uint8_t* out,
    size_t out_cap) {
    if(pwd == NULL || out == NULL) return 0;
    if(args == NULL && args_len > 0) return 0;

    const size_t frame_len = 1 + GEN4_DUMP_PASSWORD_LEN + 1 + args_len;
    if(frame_len > out_cap) return 0;

    size_t i = 0;
    out[i++] = GEN4_DUMP_CMD_PREFIX;
    memcpy(&out[i], pwd, GEN4_DUMP_PASSWORD_LEN);
    i += GEN4_DUMP_PASSWORD_LEN;
    out[i++] = cmd;
    if(args_len > 0) {
        memcpy(&out[i], args, args_len);
        i += args_len;
    }
    return i;
}

size_t gen4_dump_build_get_config(
    const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN],
    uint8_t* out,
    size_t out_cap) {
    return gen4_dump_build_cmd(pwd, GEN4_DUMP_CMD_GET_CFG, NULL, 0, out, out_cap);
}

size_t gen4_dump_build_get_revision(
    const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN],
    uint8_t* out,
    size_t out_cap) {
    return gen4_dump_build_cmd(pwd, GEN4_DUMP_CMD_GET_REVISION, NULL, 0, out, out_cap);
}

size_t gen4_dump_build_read(
    const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN],
    uint8_t block,
    uint8_t* out,
    size_t out_cap) {
    return gen4_dump_build_cmd(pwd, GEN4_DUMP_CMD_READ, &block, 1, out, out_cap);
}

bool gen4_dump_parse_config(const uint8_t raw[GEN4_DUMP_CONFIG_SIZE], Gen4DumpConfig* out) {
    if(raw == NULL || out == NULL) return false;

    out->protocol = raw[CFG_OFF_PROTOCOL];
    out->uid_len_code = raw[CFG_OFF_UID_LEN];
    out->gtu_mode = raw[CFG_OFF_GTU_MODE];

    // Never trust the card's ATS length byte — clamp before any consumer uses it
    // as a loop/copy bound (see NFC Magic show_info OOB-read class of bug).
    uint8_t ats_len = raw[CFG_OFF_ATS_LEN];
    out->ats_len = (ats_len > GEN4_DUMP_ATS_MAX_LEN) ? GEN4_DUMP_ATS_MAX_LEN : ats_len;

    out->atqa[0] = raw[CFG_OFF_ATQA];
    out->atqa[1] = raw[CFG_OFF_ATQA + 1];
    out->sak = raw[CFG_OFF_SAK];
    out->mfu_mode = raw[CFG_OFF_MFU_MODE];
    out->total_blocks = raw[CFG_OFF_TOTAL_BLOCKS];
    out->direct_write = raw[CFG_OFF_DIRECT_WRITE];
    return true;
}

Gen4DumpKind gen4_dump_classic_kind_from_sak(uint8_t sak, uint16_t* block_count) {
    Gen4DumpKind kind;
    uint16_t blocks;

    // Mask the ISO14443-4 / cascade-in-progress bits (0x20 / 0x04) that some
    // cards assert; the remaining SAK selects the Classic capacity.
    switch(sak & ~0x24) {
    case 0x09: // MIFARE Mini (S20): 5 sectors, 20 blocks
        kind = Gen4DumpKindMfClassicMini;
        blocks = 20;
        break;
    case 0x08: // MIFARE Classic 1K (S50): 16 sectors, 64 blocks
        kind = Gen4DumpKindMfClassic1K;
        blocks = 64;
        break;
    case 0x18: // MIFARE Classic 4K (S70): 40 sectors, 256 blocks
        kind = Gen4DumpKindMfClassic4K;
        blocks = 256;
        break;
    default:
        kind = Gen4DumpKindUnknown;
        blocks = 0;
        break;
    }

    if(block_count != NULL) *block_count = blocks;
    return kind;
}

Gen4DumpUlType gen4_dump_ul_type_from_version(
    const uint8_t version[GEN4_DUMP_VERSION_SIZE],
    uint16_t* page_count) {
    Gen4DumpUlType type = Gen4DumpUlUnknown;
    uint16_t pages = 0;

    // GET_VERSION layout: [0]=0x00 [1]=vendor [2]=product type [3]=subtype
    // [4]=major [5]=minor [6]=storage size [7]=protocol type. NXP vendor = 0x04.
    if(version != NULL && version[1] == 0x04) {
        const uint8_t product = version[2];
        const uint8_t storage = version[6];
        if(product == 0x04) { // NTAG21x
            switch(storage) {
            case 0x0F:
                type = Gen4DumpUlNTAG213;
                pages = 45;
                break;
            case 0x11:
                type = Gen4DumpUlNTAG215;
                pages = 135;
                break;
            case 0x13:
                type = Gen4DumpUlNTAG216;
                pages = 231;
                break;
            default:
                break;
            }
        } else if(product == 0x03) { // Ultralight EV1
            switch(storage) {
            case 0x0B:
                type = Gen4DumpUlUL11;
                pages = 20;
                break;
            case 0x0E:
                type = Gen4DumpUlUL21;
                pages = 41;
                break;
            default:
                break;
            }
        }
    }

    if(page_count != NULL) *page_count = pages;
    return type;
}

Gen4DumpUlType gen4_dump_ul_type_from_mode(uint8_t mfu_mode, uint16_t* page_count) {
    Gen4DumpUlType type;
    uint16_t pages;

    switch(mfu_mode) {
    case 0x02: // Ultralight-C
        type = Gen4DumpUlULC;
        pages = 48;
        break;
    case 0x03: // original Ultralight (no GET_VERSION)
        type = Gen4DumpUlUL;
        pages = 16;
        break;
    default:
        // UL_EV1 (0x00) / NTAG (0x01) sizes are only knowable from GET_VERSION;
        // callers should prefer gen4_dump_ul_type_from_version for those.
        type = Gen4DumpUlUnknown;
        pages = 0;
        break;
    }

    if(page_count != NULL) *page_count = pages;
    return type;
}

uint16_t gen4_dump_reads_needed(uint32_t total_bytes) {
    return (uint16_t)((total_bytes + GEN4_DUMP_BLOCK_SIZE - 1) / GEN4_DUMP_BLOCK_SIZE);
}

uint64_t gen4_dump_key_to_u64(const uint8_t key[6]) {
    if(key == NULL) return 0;
    uint64_t value = 0;
    for(int i = 0; i < 6; i++) {
        value = (value << 8) | key[i];
    }
    return value;
}

void gen4_dump_uid_from_classic_block0(
    const uint8_t block0[GEN4_DUMP_BLOCK_SIZE],
    uint8_t uid_len,
    uint8_t uid_out[10]) {
    if(block0 == NULL || uid_out == NULL) return;
    if(uid_len > 10) uid_len = 10;
    memcpy(uid_out, block0, uid_len);
}

void gen4_dump_uid_from_ul_pages(
    const uint8_t page0[GEN4_DUMP_UL_PAGE_SIZE],
    const uint8_t page1[GEN4_DUMP_UL_PAGE_SIZE],
    uint8_t uid_out[7]) {
    if(page0 == NULL || page1 == NULL || uid_out == NULL) return;
    // NTAG/UL 7-byte UID skips the BCC0 byte at page0[3].
    uid_out[0] = page0[0];
    uid_out[1] = page0[1];
    uid_out[2] = page0[2];
    uid_out[3] = page1[0];
    uid_out[4] = page1[1];
    uid_out[5] = page1[2];
    uid_out[6] = page1[3];
}
