// SPDX-License-Identifier: GPL-3.0-or-later
//
// Gen4 "Ultimate Magic Card" (UMC) backdoor dump — pure protocol/layout logic.
//
// The Gen4 backdoor command set (CF-prefixed) and the GTU config-block layout
// are documented by the Proxmark3 project (doc/magic_cards_notes.md,
// GPL-3.0-or-later) and mirrored in the Flipper NFC Magic app's gen4 poller
// (also GPL-3.0-or-later). This module reimplements only the deterministic,
// hardware-free half so it can be host-unit-tested (see tests/): backdoor frame
// construction, config parsing, and card-type/size derivation. The NFC transport
// lives in gen4_dump_poller.c.

/**
 * @file gen4_dump_core.h
 * @brief Pure, hardware-free Gen4/UMC backdoor-dump logic.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GEN4_DUMP_PASSWORD_LEN (4)
#define GEN4_DUMP_CONFIG_SIZE  (32)
#define GEN4_DUMP_BLOCK_SIZE   (16)
#define GEN4_DUMP_ATS_MAX_LEN  (16)
#define GEN4_DUMP_UL_PAGE_SIZE (4)
#define GEN4_DUMP_VERSION_SIZE (8)

/** Backdoor command opcodes, sent as: CF <pwd0..3> <cmd> [args...]. */
#define GEN4_DUMP_CMD_PREFIX       (0xCF)
#define GEN4_DUMP_CMD_GET_CFG      (0xC6)
#define GEN4_DUMP_CMD_GET_REVISION (0xCC)
#define GEN4_DUMP_CMD_READ         (0xCE)

/** Largest backdoor frame: prefix + pwd(4) + cmd + up to 32 config bytes. */
#define GEN4_DUMP_MAX_FRAME (1 + GEN4_DUMP_PASSWORD_LEN + 1 + GEN4_DUMP_CONFIG_SIZE)

/** Small dictionary of common backdoor passwords auto-tried during a dump. */
#define GEN4_DUMP_COMMON_PASSWORD_COUNT (8)
extern const uint8_t
    gen4_dump_common_passwords[GEN4_DUMP_COMMON_PASSWORD_COUNT][GEN4_DUMP_PASSWORD_LEN];

typedef enum {
    Gen4DumpProtocolMfClassic = 0x00,
    Gen4DumpProtocolMfUltralight = 0x01,
} Gen4DumpProtocol;

/** Parsed Gen4 GTU config block (byte offsets per Proxmark/UMC docs). */
typedef struct {
    uint8_t protocol; // [0]  Gen4DumpProtocol
    uint8_t uid_len_code; // [1]  0=4B, 1=7B, 2=10B
    uint8_t gtu_mode; // [6]  shadow mode
    uint8_t ats_len; // [7]  clamped to GEN4_DUMP_ATS_MAX_LEN
    uint8_t atqa[2]; // [24..25]
    uint8_t sak; // [26]
    uint8_t mfu_mode; // [27] 0=UL_EV1, 1=NTAG, 2=UL_C, 3=UL
    uint8_t total_blocks; // [28] configured max R/W block count
    uint8_t direct_write; // [29]
} Gen4DumpConfig;

typedef enum {
    Gen4DumpKindUnknown = 0,
    Gen4DumpKindMfClassicMini, // 20 blocks (5 sectors)
    Gen4DumpKindMfClassic1K, // 64 blocks (16 sectors)
    Gen4DumpKindMfClassic4K, // 256 blocks (40 sectors)
    Gen4DumpKindMfUltralight, // specific UL/NTAG type from GET_VERSION / mode
} Gen4DumpKind;

typedef enum {
    Gen4DumpUlUnknown = 0,
    Gen4DumpUlUL, // original Ultralight (no GET_VERSION), 16 pages
    Gen4DumpUlULC, // Ultralight C, 48 pages
    Gen4DumpUlUL11, // UL EV1 MF0UL11, 20 pages
    Gen4DumpUlUL21, // UL EV1 MF0UL21, 41 pages
    Gen4DumpUlNTAG213, // 45 pages
    Gen4DumpUlNTAG215, // 135 pages
    Gen4DumpUlNTAG216, // 231 pages
} Gen4DumpUlType;

/**
 * Build a backdoor command frame: CF | pwd[4] | cmd | args.
 * @return frame length written to `out`, or 0 if it would exceed `out_cap`
 *         (or if pwd/out is NULL, or args is NULL while args_len > 0).
 */
size_t gen4_dump_build_cmd(
    const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN],
    uint8_t cmd,
    const uint8_t* args,
    size_t args_len,
    uint8_t* out,
    size_t out_cap);

/** CF | pwd | C6 — request the 32-byte config block. */
size_t
    gen4_dump_build_get_config(const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN], uint8_t* out, size_t out_cap);

/** CF | pwd | CC — request the 5-byte revision string. */
size_t gen4_dump_build_get_revision(
    const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN],
    uint8_t* out,
    size_t out_cap);

/** CF | pwd | CE | block — backdoor read of one 16-byte block. */
size_t gen4_dump_build_read(
    const uint8_t pwd[GEN4_DUMP_PASSWORD_LEN],
    uint8_t block,
    uint8_t* out,
    size_t out_cap);

/**
 * Parse a raw 32-byte config block into named fields.
 * @return false if raw or out is NULL. `ats_len` is clamped to
 *         GEN4_DUMP_ATS_MAX_LEN — the card's length byte is never trusted.
 */
bool gen4_dump_parse_config(const uint8_t raw[GEN4_DUMP_CONFIG_SIZE], Gen4DumpConfig* out);

/**
 * MIFARE Classic kind + block count from SAK (standard type detection).
 * @param block_count out: number of 16-byte blocks (0 if unknown). May be NULL.
 * @return Gen4DumpKindMfClassic* or Gen4DumpKindUnknown for a non-MFC SAK.
 */
Gen4DumpKind gen4_dump_classic_kind_from_sak(uint8_t sak, uint16_t* block_count);

/**
 * Ultralight/NTAG type + page count from an 8-byte GET_VERSION response.
 * @param page_count out: number of 4-byte pages (0 if unknown). May be NULL.
 * @return the specific type, or Gen4DumpUlUnknown if the version is unrecognized.
 */
Gen4DumpUlType
    gen4_dump_ul_type_from_version(const uint8_t version[GEN4_DUMP_VERSION_SIZE], uint16_t* page_count);

/**
 * Fallback UL/NTAG type + page count from the config `mfu_mode` byte, for cards
 * that do not answer GET_VERSION (original Ultralight, Ultralight-C).
 * @param page_count out: number of 4-byte pages (0 if unknown). May be NULL.
 */
Gen4DumpUlType gen4_dump_ul_type_from_mode(uint8_t mfu_mode, uint16_t* page_count);

/** Number of 16-byte backdoor reads needed to cover `total_bytes`. */
uint16_t gen4_dump_reads_needed(uint32_t total_bytes);

/** Big-endian 6-byte MIFARE Classic key -> uint64 (for mf_classic_set_key_found). */
uint64_t gen4_dump_key_to_u64(const uint8_t key[6]);

/**
 * Extract the card UID from a Classic block 0 (the first `uid_len` bytes).
 * `uid_len` is clamped to 10; no-op if either pointer is NULL.
 */
void gen4_dump_uid_from_classic_block0(
    const uint8_t block0[GEN4_DUMP_BLOCK_SIZE],
    uint8_t uid_len,
    uint8_t uid_out[10]);

/**
 * Reconstruct a 7-byte Ultralight/NTAG UID from pages 0 and 1
 * (uid0..2 = page0[0..2], uid3..6 = page1[0..3]); no-op on any NULL pointer.
 */
void gen4_dump_uid_from_ul_pages(
    const uint8_t page0[GEN4_DUMP_UL_PAGE_SIZE],
    const uint8_t page1[GEN4_DUMP_UL_PAGE_SIZE],
    uint8_t uid_out[7]);

#ifdef __cplusplus
}
#endif
