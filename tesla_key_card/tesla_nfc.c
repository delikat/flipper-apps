#include "tesla_nfc.h"

#include "tesla_secure.h"

#include <furi.h>
#include <furi_hal.h>

#include <nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_listener.h>

#include <toolbox/bit_buffer.h>
#include <toolbox/simple_array.h>

#include <string.h>

#define TAG "TeslaNfc"

/* Present a fuller, real-card-like ATS: 04 38 77 E1.
 *   T0  = 0x38  -> TA1 and TB1 present; FSCI = 8 (256-byte frame). NOT TC1.
 *   TA1 = 0x77  -> the bit-rate capability byte an official Tesla card uses.
 *   TB1 = 0xE1  -> FWI = 14 (max, ~4.9 s), SFGI = 1.
 *
 * On-device capture showed the vehicle SELECT our applet, get 9000, then drop
 * the field ~500 ms later WITHOUT ever sending GET_PUBLIC_KEY -- so it validates
 * the card at ISO-DEP activation, and our earlier minimal ATS (03 26 E0: no TA1,
 * FSCI=6) did not look like a real card. This restores the richer presentation.
 *
 * FWI deviates from the official card's 0x91/FWI=9 (~155 ms) ON PURPOSE. A real
 * card answers AUTHENTICATE from hardware crypto in tens of ms, so 155 ms is
 * plenty for it. Our AUTHENTICATE runs a software P-256 ECDH measured at ~471 ms
 * (startup self-test), and the firmware listener cannot send S(WTX) to extend
 * time -- so the advertised FWT is our ONLY lever to buy the slow reply room.
 * Advertise the maximum (FWI=14). This does not affect SELECT (an earlier
 * FWI=14 build still SELECTed fine, and the reader ignored the 4.9 s wait,
 * dropping the field at its own ~500 ms), and a larger FWT can never hurt.
 *
 * We deliberately DO NOT advertise CID (TC1 bit 1), even though a real card
 * does. The reader is demonstrably sending UNTAGGED I-blocks: SELECT already
 * succeeds with the no-CID ATS, and the firmware only delivers an untagged
 * I-block when no CID was bound. If we claim CID, the RATS handler binds
 * instance->cid to the reader's CID nibble, and iso14443_4_layer.c then SKIPS
 * an untagged I-block whenever that nibble is non-zero -- which would drop the
 * very SELECT that currently works. Claiming CID cannot unblock anything here
 * (the reader is not tagging frames) and is pure downside on a one-shot trip;
 * revisit only after a confirmed on-device SELECT with CID advertised. */
#define TESLA_ATS_TL  4U
#define TESLA_ATS_T0  0x38U
#define TESLA_ATS_TA1 0x77U
#define TESLA_ATS_TB1 0xE1U

/* Number of received APDU bytes to hex-dump in the diagnostic log line. */
#define TESLA_NFC_LOG_HEX_BYTES 24U

struct TeslaNfc {
    TeslaCrypto* crypto;
    TeslaNfcEventCallback callback;
    void* callback_context;
    Nfc* nfc;
    NfcListener* listener;
    Iso14443_4aData* data;
    BitBuffer* tx_buffer;
    TeslaApdu apdu;
    uint32_t crypto_time_ms;
};

static bool tesla_nfc_authenticate(
    void* context,
    const uint8_t peer_public_key[TESLA_PUBLIC_KEY_SIZE],
    const uint8_t challenge[TESLA_CHALLENGE_SIZE],
    uint8_t response[TESLA_AUTH_RESPONSE_SIZE]) {
    TeslaNfc* nfc = context;
    const uint32_t start = furi_get_tick();
    const bool success =
        tesla_crypto_authenticate(nfc->crypto, peer_public_key, challenge, response);
    const uint32_t elapsed_ticks = furi_get_tick() - start;
    const uint32_t tick_frequency = furi_kernel_get_tick_frequency();
    nfc->crypto_time_ms = tick_frequency == 0U ? 0U : (elapsed_ticks * 1000U) / tick_frequency;
    return success;
}

static void tesla_nfc_emit(TeslaNfc* nfc, const TeslaNfcEventInfo* info) {
    if(nfc->callback) nfc->callback(info, nfc->callback_context);
}

/* Emit an event that carries no APDU (field off / halt). */
static void tesla_nfc_emit_event(TeslaNfc* nfc, TeslaNfcEvent event) {
    const TeslaNfcEventInfo info = {.event = event};
    tesla_nfc_emit(nfc, &info);
}

/* Hex-encode up to `size` bytes into `out` as space-separated pairs, truncating
 * to fit `out_size`. Used only for diagnostic logging; bounded so it is safe to
 * build on the NFC worker stack alongside the P-256 calculation. */
static void tesla_nfc_format_hex(const uint8_t* data, size_t size, char* out, size_t out_size) {
    static const char digits[] = "0123456789ABCDEF";
    size_t written = 0;
    for(size_t i = 0; i < size && written + 3U < out_size; ++i) {
        out[written++] = digits[data[i] >> 4U];
        out[written++] = digits[data[i] & 0x0FU];
        out[written++] = ' ';
    }
    out[written] = '\0';
}

static NfcCommand tesla_nfc_listener_callback(NfcGenericEvent event, void* context) {
    furi_assert(context);
    furi_assert(event.protocol == NfcProtocolIso14443_4a);
    furi_assert(event.event_data);

    TeslaNfc* nfc = context;
    Iso14443_4aListenerEvent* listener_event = event.event_data;

    if(listener_event->type == Iso14443_4aListenerEventTypeReceivedData) {
        const BitBuffer* rx = listener_event->data->buffer;
        const size_t rx_size = bit_buffer_get_size_bytes(rx);
        const uint8_t* rx_data = bit_buffer_get_data(rx);
        uint8_t response[TESLA_APDU_RESPONSE_MAX] = {0};

        char rx_hex[3U * TESLA_NFC_LOG_HEX_BYTES + 1U];
        const size_t rx_hex_bytes =
            rx_size < TESLA_NFC_LOG_HEX_BYTES ? rx_size : TESLA_NFC_LOG_HEX_BYTES;
        tesla_nfc_format_hex(rx_data, rx_hex_bytes, rx_hex, sizeof(rx_hex));
        FURI_LOG_I(
            TAG, "RX %u B: %s%s", (unsigned)rx_size, rx_hex, rx_size > rx_hex_bytes ? "..." : "");

        /* Cleared each frame so the log line below reports 0 ms for every command
         * except AUTHENTICATE, which sets it from the ECDH timing. */
        nfc->crypto_time_ms = 0U;
        const TeslaApduResult result =
            tesla_apdu_process(&nfc->apdu, rx_data, rx_size, response, sizeof(response));

        bit_buffer_reset(nfc->tx_buffer);
        bit_buffer_append_bytes(nfc->tx_buffer, response, result.response_size);
        const Iso14443_4aError send_error =
            iso14443_4a_listener_send_block((Iso14443_4aListener*)event.instance, nfc->tx_buffer);
        tesla_secure_zero(response, sizeof(response));

        FURI_LOG_I(
            TAG,
            "cmd=%d SW=%04X resp=%uB ecdh=%ums send=%d",
            (int)result.command,
            (unsigned)result.status_word,
            (unsigned)result.response_size,
            (unsigned)nfc->crypto_time_ms,
            (int)send_error);

        /* Carry the raw request bytes, status word and sizes up to the GUI
         * thread so the on-SD trace shows exactly what the reader sent and how
         * we answered every frame -- essential for diagnosing a stall that the
         * coarse event alone cannot localize. */
        TeslaNfcEventInfo info = {
            .crypto_time_ms = (uint16_t)nfc->crypto_time_ms,
            .status_word = result.status_word,
            .apdu_len = rx_size > 0xFFU ? 0xFFU : (uint8_t)rx_size,
            .preview_len =
                rx_size < TESLA_NFC_APDU_PREVIEW ? (uint8_t)rx_size : TESLA_NFC_APDU_PREVIEW,
            .response_len = result.response_size > 0xFFU ? 0xFFU : (uint8_t)result.response_size,
        };
        memcpy(info.preview, rx_data, info.preview_len);

        if(send_error != Iso14443_4aErrorNone) {
            info.event = TeslaNfcEventTransmitError;
        } else if(result.command == TeslaApduCommandSelect && result.status_word == 0x9000U) {
            info.event = TeslaNfcEventSelect;
        } else if(result.command == TeslaApduCommandGetPublicKey && result.status_word == 0x9000U) {
            info.event = TeslaNfcEventGetPublicKey;
        } else if(result.command == TeslaApduCommandAuthenticate && result.status_word == 0x9000U) {
            info.event = TeslaNfcEventAuthenticate;
        } else if(result.command == TeslaApduCommandGetCardInfo && result.status_word == 0x9000U) {
            info.event = TeslaNfcEventGetCardInfo;
        } else {
            info.event = TeslaNfcEventProtocolError;
        }
        tesla_nfc_emit(nfc, &info);
    } else if(listener_event->type == Iso14443_4aListenerEventTypeFieldOff) {
        FURI_LOG_I(TAG, "field off");
        tesla_apdu_reset_session(&nfc->apdu);
        tesla_nfc_emit_event(nfc, TeslaNfcEventFieldOff);
    } else if(listener_event->type == Iso14443_4aListenerEventTypeHalted) {
        FURI_LOG_I(TAG, "halted");
        tesla_apdu_reset_session(&nfc->apdu);
        tesla_nfc_emit_event(nfc, TeslaNfcEventHalted);
    }

    return NfcCommandContinue;
}

size_t tesla_nfc_ats_bytes(uint8_t* out, size_t capacity) {
    /* Keep in sync with the ats_data assignments in tesla_nfc_alloc below. */
    const uint8_t ats[] = {TESLA_ATS_TL, TESLA_ATS_T0, TESLA_ATS_TA1, TESLA_ATS_TB1};
    if(capacity < sizeof(ats)) return 0;
    memcpy(out, ats, sizeof(ats));
    return sizeof(ats);
}

TeslaNfc* tesla_nfc_alloc(
    TeslaCrypto* crypto,
    const uint8_t uid[TESLA_NFC_UID_SIZE],
    TeslaNfcEventCallback callback,
    void* callback_context) {
    furi_assert(crypto);
    furi_assert(uid);

    TeslaNfc* nfc = malloc(sizeof(TeslaNfc));
    memset(nfc, 0, sizeof(TeslaNfc));
    nfc->crypto = crypto;
    nfc->callback = callback;
    nfc->callback_context = callback_context;
    nfc->nfc = nfc_alloc();
    nfc->data = iso14443_4a_alloc();
    iso14443_4a_reset(nfc->data);

    furi_check(iso14443_4a_set_uid(nfc->data, uid, TESLA_NFC_UID_SIZE));
    Iso14443_3aData* base_data = iso14443_4a_get_base_data(nfc->data);
    const uint8_t atqa[2] = {0x04U, 0x00U};
    iso14443_3a_set_atqa(base_data, atqa);
    iso14443_3a_set_sak(base_data, 0x20U);

    nfc->data->ats_data.tl = TESLA_ATS_TL;
    nfc->data->ats_data.t0 = TESLA_ATS_T0;
    nfc->data->ats_data.ta_1 = TESLA_ATS_TA1;
    nfc->data->ats_data.tb_1 = TESLA_ATS_TB1;
    nfc->tx_buffer = bit_buffer_alloc(96U);
    tesla_apdu_init(&nfc->apdu, tesla_crypto_get_public_key(crypto), tesla_nfc_authenticate, nfc);
    return nfc;
}

void tesla_nfc_free(TeslaNfc* nfc) {
    if(!nfc) return;
    tesla_nfc_stop(nfc);
    bit_buffer_free(nfc->tx_buffer);
    iso14443_4a_free(nfc->data);
    nfc_free(nfc->nfc);
    free(nfc);
}

bool tesla_nfc_start(TeslaNfc* nfc) {
    furi_assert(nfc);
    if(nfc->listener) return true;

    tesla_apdu_reset_session(&nfc->apdu);
    nfc->listener =
        nfc_listener_alloc(nfc->nfc, NfcProtocolIso14443_4a, (const NfcDeviceData*)nfc->data);
    if(!nfc->listener) return false;
    nfc_listener_start(nfc->listener, tesla_nfc_listener_callback, nfc);
    return true;
}

void tesla_nfc_stop(TeslaNfc* nfc) {
    furi_assert(nfc);
    if(nfc->listener) {
        nfc_listener_stop(nfc->listener);
        nfc_listener_free(nfc->listener);
        nfc->listener = NULL;
    }
    tesla_apdu_reset_session(&nfc->apdu);
}
