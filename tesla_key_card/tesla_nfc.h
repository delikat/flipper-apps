#pragma once

#include "tesla_apdu.h"
#include "tesla_crypto.h"
#include "tesla_identity.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct TeslaNfc TeslaNfc;

typedef enum {
    TeslaNfcEventFieldOff,
    TeslaNfcEventHalted,
    TeslaNfcEventSelect,
    TeslaNfcEventGetPublicKey,
    TeslaNfcEventAuthenticate,
    TeslaNfcEventGetCardInfo,
    TeslaNfcEventProtocolError,
    TeslaNfcEventTransmitError,
} TeslaNfcEvent;

/* Leading APDU bytes captured for the diagnostic trace (CLA INS P1 P2 Lc ...). */
#define TESLA_NFC_APDU_PREVIEW 10U

typedef struct {
    TeslaNfcEvent event;
    uint16_t crypto_time_ms; /* ECDH wall time; AUTHENTICATE only, else 0 */
    uint16_t status_word; /* APDU status word for data frames, else 0 */
    uint8_t apdu_len; /* full received APDU length, capped at 255 */
    uint8_t preview_len; /* valid bytes in preview[] */
    uint8_t preview[TESLA_NFC_APDU_PREVIEW];
    uint8_t response_len; /* bytes sent back, capped at 255 */
} TeslaNfcEventInfo;

typedef void (*TeslaNfcEventCallback)(const TeslaNfcEventInfo* info, void* context);

TeslaNfc* tesla_nfc_alloc(
    TeslaCrypto* crypto,
    const uint8_t uid[TESLA_NFC_UID_SIZE],
    TeslaNfcEventCallback callback,
    void* callback_context);

void tesla_nfc_free(TeslaNfc* nfc);
bool tesla_nfc_start(TeslaNfc* nfc);
void tesla_nfc_stop(TeslaNfc* nfc);
