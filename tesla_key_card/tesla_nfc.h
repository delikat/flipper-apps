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

typedef void (*TeslaNfcEventCallback)(TeslaNfcEvent event, uint16_t crypto_time_ms, void* context);

TeslaNfc* tesla_nfc_alloc(
    TeslaCrypto* crypto,
    const uint8_t uid[TESLA_NFC_UID_SIZE],
    TeslaNfcEventCallback callback,
    void* callback_context);

void tesla_nfc_free(TeslaNfc* nfc);
bool tesla_nfc_start(TeslaNfc* nfc);
void tesla_nfc_stop(TeslaNfc* nfc);
