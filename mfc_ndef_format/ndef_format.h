/**
 * @file ndef_format.h
 * @brief MIFARE Classic 1K -> empty NDEF (NFC) formatter (NFC transport).
 *
 * Port of the Proxmark3 client command `hf mf ndefformat`
 * (client/src/cmdhfmf.c, CmdHFMFNDEFFormat). Given an allocated Nfc
 * instance and a 1K card on the field, it writes the MAD + empty-NDEF
 * on-card layout so the tag reads as a blank NDEF tag.
 *
 * The deterministic layout logic (templates, geometry, key selection) lives
 * in ndef_layout.h/.c; this header is only the hardware-facing entry point.
 * All I/O goes through the blocking mf_classic_poller_sync_* API, so
 * mfc_ndef_format_run() MUST be called from a worker thread, never the
 * GUI thread.
 */
#pragma once

#include "ndef_layout.h"

#include <nfc/nfc.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Outcome of a format run. */
typedef enum {
    MfcNdefResultOk, /**< All blocks written. */
    MfcNdefResultNoCard, /**< No card / lost field / timeout. */
    MfcNdefResultNotClassic1k, /**< A card is present but it is not a Classic 1K. */
    MfcNdefResultWriteFailed, /**< A block could not be written with either key. */
    MfcNdefResultCanceled, /**< Caller asked to stop between blocks. */
} MfcNdefResult;

/** Progress callback: invoked after each block is handled (0..63). */
typedef void (*MfcNdefProgressCallback)(void* context, uint8_t block);

/** Parameters and results for a single format run. */
typedef struct {
    Nfc* nfc; /**< Allocated, idle Nfc instance (input). */
    MfcNdefProgressCallback progress_cb; /**< Optional, may be NULL. */
    void* progress_context; /**< Passed to progress_cb. */
    const volatile bool* stop; /**< Optional cancel flag, may be NULL. */
    uint8_t fail_block; /**< Output: block that failed (valid on WriteFailed). */
} MfcNdefFormat;

/**
 * @brief Run the NDEF format on the card currently on the field.
 *
 * @param      fmt  populated MfcNdefFormat (nfc required, rest optional)
 * @return     the run outcome
 */
MfcNdefResult mfc_ndef_format_run(MfcNdefFormat* fmt);

#ifdef __cplusplus
}
#endif
