// SPDX-License-Identifier: GPL-3.0-or-later
//
// Ported from Proxmark3 `hf mf ndefformat` (client/src/cmdhfmf.c,
// CmdHFMFNDEFFormat), Copyright (C) the Proxmark3 project contributors,
// licensed GPL-3.0-or-later. The firstblocks[] templates and key/layout logic
// are transcribed from that source.

#include "ndef_layout.h"

#include <string.h>

/*
 * Keys, matching the Proxmark3 defaults:
 *   default  FF FF FF FF FF FF   (blank/factory card)
 *   MAD A    A0 A1 A2 A3 A4 A5   (sector 0 key A once formatted)
 *   MAD B    89 EC A9 7F 8C 2A   (sector 0 key B once formatted)
 *   NDEF A   D3 F7 D3 F7 D3 F7   (data sectors key A once formatted)
 */
static const uint8_t mfc_ndef_key_default[MFC_NDEF_KEY_SIZE] =
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t mfc_ndef_key_mad_a[MFC_NDEF_KEY_SIZE] =
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
static const uint8_t mfc_ndef_key_mad_b[MFC_NDEF_KEY_SIZE] =
    {0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A};
static const uint8_t mfc_ndef_key_ndef_a[MFC_NDEF_KEY_SIZE] =
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};

/*
 * Fixed on-card template for the first eight blocks, verbatim from the
 * Proxmark source. Indexed by absolute block number 0..7:
 *   [0] block 0  - manufacturer block, never written (skipped)
 *   [1] block 1  - MAD1, entry pointing NDEF AID (03 E1) at every sector
 *   [2] block 2  - MAD1 continued
 *   [3] block 3  - sector 0 trailer: MAD key A + access 78 77 88 + GPB C1 + MAD key B
 *   [4] block 4  - empty NDEF TLV (03 00 FE ...)
 *   [5] block 5  - zeros
 *   [6] block 6  - zeros
 *   [7] block 7  - NDEF sector trailer: NDEF key A + access 7F 07 88 + GPB 40 + key B FF
 * For every sector trailer beyond block 7, template [7] is reused.
 */
static const uint8_t mfc_ndef_firstblocks[8][MFC_NDEF_BLOCK_SIZE] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1},
    {0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A},
    {0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0x7F, 0x07, 0x88, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
};

uint8_t mfc_ndef_sector_of_block(uint8_t block) {
    // 1K: every sector is 4 blocks.
    return block / 4;
}

bool mfc_ndef_block_is_trailer(uint8_t block) {
    // 1K: the trailer is the last (4th) block of each sector.
    return (block % 4) == 3;
}

bool mfc_ndef_build_block(uint8_t block, uint8_t out[MFC_NDEF_BLOCK_SIZE]) {
    memset(out, 0, MFC_NDEF_BLOCK_SIZE);

    if(block == 0) {
        // Manufacturer block: never written.
        return false;
    }

    if(block <= 7) {
        memcpy(out, mfc_ndef_firstblocks[block], MFC_NDEF_BLOCK_SIZE);
    } else if(mfc_ndef_block_is_trailer(block)) {
        memcpy(out, mfc_ndef_firstblocks[7], MFC_NDEF_BLOCK_SIZE);
    }
    // else: leave zeroed

    return true;
}

void mfc_ndef_sector_keys(
    bool already_formatted,
    uint8_t sector,
    uint8_t key_a[MFC_NDEF_KEY_SIZE],
    uint8_t key_b[MFC_NDEF_KEY_SIZE]) {
    if(!already_formatted) {
        memcpy(key_a, mfc_ndef_key_default, MFC_NDEF_KEY_SIZE);
        memcpy(key_b, mfc_ndef_key_default, MFC_NDEF_KEY_SIZE);
        return;
    }

    if(sector == 0) {
        memcpy(key_a, mfc_ndef_key_mad_a, MFC_NDEF_KEY_SIZE);
        memcpy(key_b, mfc_ndef_key_mad_b, MFC_NDEF_KEY_SIZE);
    } else {
        memcpy(key_a, mfc_ndef_key_ndef_a, MFC_NDEF_KEY_SIZE);
        memcpy(key_b, mfc_ndef_key_default, MFC_NDEF_KEY_SIZE);
    }
}
