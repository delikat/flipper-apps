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

/* FSCI=6 gives a 96-byte frame, enough for Tesla's 86-byte auth APDU plus
 * ISO-DEP overhead. TB1 advertises FWI=14 (~4.9 s frame waiting time). The
 * AUTHENTICATE reply requires a software P-256 ECDH that runs synchronously on
 * the NFC worker thread and can take several hundred ms on the F7, and the
 * firmware listener has no card-side S(WTX) path, so the whole calculation must
 * finish inside FWT or the reader times out and restarts from SELECT (the
 * "flashing between reading and ready" failure). FWI=14 is the ISO14443-4
 * maximum (15 is RFU) and gives the widest timing margin; the reader still
 * proceeds the instant the reply arrives, so a large FWT costs nothing when the
 * card is fast. TA1 and TC1 are omitted: FW 089 acknowledges PPS but does not
 * change radio bit rates, and CID/NAD are not required by the Tesla exchange. */
#define TESLA_ATS_TL  3U
#define TESLA_ATS_T0  0x26U
#define TESLA_ATS_TB1 0xE0U

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
