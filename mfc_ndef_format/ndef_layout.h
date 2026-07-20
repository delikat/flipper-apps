// SPDX-License-Identifier: GPL-3.0-or-later
//
// Ported from Proxmark3 `hf mf ndefformat` (client/src/cmdhfmf.c,
// CmdHFMFNDEFFormat), Copyright (C) the Proxmark3 project contributors,
// licensed GPL-3.0-or-later.

/**
 * @file ndef_layout.h
 * @brief Pure, hardware-free NDEF-format layout logic for MIFARE Classic 1K.
 *
 * This module contains the deterministic half of the Proxmark3 `hf mf
 * ndefformat` port: the fixed on-card block templates, the 1K sector/block
 * geometry, and the per-sector key selection. It has NO dependency on the
 * Flipper NFC stack, so it can be compiled and unit-tested on the host
 * (see tests/). The NFC transport lives in ndef_format.c.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** MIFARE Classic 1K geometry (this tool is 1K-only). */
#define MFC_NDEF_SECTORS_1K (16)
#define MFC_NDEF_BLOCKS_1K  (64)
#define MFC_NDEF_KEY_SIZE   (6)
#define MFC_NDEF_BLOCK_SIZE (16)

/**
 * @brief Sector number that a given absolute block belongs to (1K geometry).
 *
 * @param block  absolute block number 0..63
 * @return       sector number 0..15
 */
uint8_t mfc_ndef_sector_of_block(uint8_t block);

/**
 * @brief Whether an absolute block is a sector trailer (1K geometry).
 *
 * @param block  absolute block number 0..63
 * @return       true if the block is the last block of its sector
 */
bool mfc_ndef_block_is_trailer(uint8_t block);

/**
 * @brief Produce the target contents for an absolute block.
 *
 * Block 0 (manufacturer block) is never written. Blocks 1..7 take the fixed
 * MAD / empty-NDEF templates; any other sector trailer takes the NDEF trailer
 * template; every other block is zeroed.
 *
 * @param      block  absolute block number 0..63
 * @param[out] out    16-byte buffer filled with the target contents
 * @return     true if the block should be written, false to skip (block 0)
 */
bool mfc_ndef_build_block(uint8_t block, uint8_t out[MFC_NDEF_BLOCK_SIZE]);

/**
 * @brief Select the key A / key B to use for a sector.
 *
 * On a blank card both keys are the default FF FF FF FF FF FF. If the card is
 * already NDEF-formatted, sector 0 uses the MAD keys and all other sectors use
 * the NDEF key A (their key B stays default).
 *
 * @param      already_formatted  true if the MAD key already authenticates the card
 * @param      sector             sector number 0..15
 * @param[out] key_a              6-byte buffer filled with key A
 * @param[out] key_b              6-byte buffer filled with key B
 */
void mfc_ndef_sector_keys(
    bool already_formatted,
    uint8_t sector,
    uint8_t key_a[MFC_NDEF_KEY_SIZE],
    uint8_t key_b[MFC_NDEF_KEY_SIZE]);

#ifdef __cplusplus
}
#endif
