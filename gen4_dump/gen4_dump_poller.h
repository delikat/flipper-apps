// SPDX-License-Identifier: GPL-3.0-or-later
//
// Gen4/UMC backdoor dump — NFC transport. Drives the ISO14443-3A poller and the
// Gen4 backdoor read (0xCE) to dump a card into an NfcDevice. The transport
// design (nfc_poller + iso14443_3a_poller_send_standard_frame inside the poller
// callback) mirrors the GPL-3.0-or-later Flipper NFC Magic gen4 poller. All the
// deterministic byte logic lives in gen4_dump_core.c.

/**
 * @file gen4_dump_poller.h
 * @brief Blocking Gen4/UMC dump transport. Run on a worker thread, never on the
 *        GUI thread — each call blocks through a full activate/read/halt cycle.
 */
#pragma once

#include <furi.h>
#include <nfc/nfc.h>
#include <nfc/nfc_device.h>

#include "gen4_dump_core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    Gen4DumpResultOk,
    Gen4DumpResultNoCard, // no ISO14443-3A card in the field
    Gen4DumpResultNotGen4, // a card is present but the backdoor did not answer
    Gen4DumpResultUnsupported, // Gen4 card, but an emulated type we can't dump
    Gen4DumpResultReadFailed, // backdoor read failed mid-dump (card removed?)
    Gen4DumpResultCanceled, // stop flag was raised
} Gen4DumpResult;

typedef struct Gen4Dump Gen4Dump;

/** Progress during a dump: `done` of `total` units (blocks or pages) read. */
typedef void (*Gen4DumpProgressCb)(void* context, uint16_t done, uint16_t total);

Gen4Dump* gen4_dump_alloc(Nfc* nfc);

void gen4_dump_free(Gen4Dump* dump);

/** Set the 4-byte backdoor password tried first (default all-zero). A dump also
 *  auto-tries a small common list, so this is only needed for an unusual one. */
void gen4_dump_set_password(Gen4Dump* dump, const uint8_t password[GEN4_DUMP_PASSWORD_LEN]);

/** The 4-byte backdoor password that unlocked the card on the last successful
 *  run — i.e. the recovered password when auto-recovery found it. */
const uint8_t* gen4_dump_get_password(const Gen4Dump* dump);

void gen4_dump_set_progress_callback(Gen4Dump* dump, Gen4DumpProgressCb callback, void* context);

/** Optional cancel flag polled between blocks; NULL disables cancellation.
 *  Declared volatile: it is written from the GUI thread and read here. */
void gen4_dump_set_stop_flag(Gen4Dump* dump, const volatile bool* stop);

/** Blocking full dump. Returns the outcome; on Ok the device is available via
 *  gen4_dump_get_device(). */
Gen4DumpResult gen4_dump_run(Gen4Dump* dump);

/** The dumped NfcDevice after Gen4DumpResultOk (owned by `dump`; valid until the
 *  next gen4_dump_run or gen4_dump_free). NULL if the last run did not succeed. */
NfcDevice* gen4_dump_get_device(Gen4Dump* dump);

/** Human-readable emulated card kind, e.g. "MIFARE Classic 1K" or "NTAG213". */
const char* gen4_dump_get_kind_name(const Gen4Dump* dump);

/** Number of blocks (Classic) or pages (Ultralight) read by the last run. */
uint16_t gen4_dump_get_unit_count(const Gen4Dump* dump);

#ifdef __cplusplus
}
#endif
