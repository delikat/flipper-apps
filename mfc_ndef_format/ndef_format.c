// SPDX-License-Identifier: GPL-3.0-or-later
//
// Ported from Proxmark3 `hf mf ndefformat` (client/src/cmdhfmf.c,
// CmdHFMFNDEFFormat), Copyright (C) the Proxmark3 project contributors,
// licensed GPL-3.0-or-later.

#include "ndef_format.h"

#include <furi.h>
#include <string.h>

#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>

/*
 * NFC transport for the Proxmark3 `hf mf ndefformat` port. The byte-level
 * decisions (which template, which key) come from ndef_layout.c; this file
 * only drives the blocking sync poller and maps its errors to results.
 */

/** Copy 6 raw key bytes into an MfClassicKey. */
static inline MfClassicKey mfc_ndef_make_key(const uint8_t bytes[MFC_NDEF_KEY_SIZE]) {
    MfClassicKey key;
    memcpy(key.data, bytes, MF_CLASSIC_KEY_SIZE);
    return key;
}

MfcNdefResult mfc_ndef_format_run(MfcNdefFormat* fmt) {
    furi_assert(fmt);
    furi_assert(fmt->nfc);
    Nfc* nfc = fmt->nfc;

    // Confirm a card is present and that it is a Classic 1K.
    MfClassicType type;
    MfClassicError err = mf_classic_poller_sync_detect_type(nfc, &type);
    if(err != MfClassicErrorNone) {
        return MfcNdefResultNoCard;
    }
    if(type != MfClassicType1k) {
        return MfcNdefResultNotClassic1k;
    }

    // Probe: if the MAD key A already authenticates sector 0, the card is
    // already NDEF-formatted and the MAD/NDEF key set must be used instead of
    // the default keys. The MAD key A is simply "sector 0 key A when formatted".
    uint8_t probe_a[MFC_NDEF_KEY_SIZE];
    uint8_t probe_b[MFC_NDEF_KEY_SIZE];
    mfc_ndef_sector_keys(true, 0, probe_a, probe_b);
    MfClassicKey mad_key_a = mfc_ndef_make_key(probe_a);
    MfClassicAuthContext auth = {0};
    const bool already_formatted =
        mf_classic_poller_sync_auth(nfc, 0, &mad_key_a, MfClassicKeyTypeA, &auth) ==
        MfClassicErrorNone;

    // Main loop over all 1K blocks.
    for(uint8_t b = 0; b < MFC_NDEF_BLOCKS_1K; b++) {
        if(fmt->stop && *fmt->stop) {
            return MfcNdefResultCanceled;
        }

        uint8_t bytes[MFC_NDEF_BLOCK_SIZE];
        const bool should_write = mfc_ndef_build_block(b, bytes);
        if(!should_write) {
            // Block 0 is skipped.
            if(fmt->progress_cb) fmt->progress_cb(fmt->progress_context, b);
            continue;
        }

        uint8_t sector = mfc_ndef_sector_of_block(b);
        uint8_t key_a_bytes[MFC_NDEF_KEY_SIZE];
        uint8_t key_b_bytes[MFC_NDEF_KEY_SIZE];
        mfc_ndef_sector_keys(already_formatted, sector, key_a_bytes, key_b_bytes);

        MfClassicBlock block;
        memcpy(block.data, bytes, MF_CLASSIC_BLOCK_SIZE);
        MfClassicKey key_a = mfc_ndef_make_key(key_a_bytes);
        MfClassicKey key_b = mfc_ndef_make_key(key_b_bytes);

        // Write trying key B first, then key A (key A is what a blank card's
        // default access bits allow for the trailer).
        MfClassicError werr =
            mf_classic_poller_sync_write_block(nfc, b, &key_b, MfClassicKeyTypeB, &block);
        if(werr != MfClassicErrorNone) {
            werr = mf_classic_poller_sync_write_block(nfc, b, &key_a, MfClassicKeyTypeA, &block);
        }

        if(werr != MfClassicErrorNone) {
            fmt->fail_block = b;
            if(werr == MfClassicErrorNotPresent || werr == MfClassicErrorTimeout) {
                return MfcNdefResultNoCard;
            }
            return MfcNdefResultWriteFailed;
        }

        if(fmt->progress_cb) fmt->progress_cb(fmt->progress_context, b);
    }

    return MfcNdefResultOk;
}
