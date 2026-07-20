#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TESLA_PUBLIC_KEY_SIZE       65U
#define TESLA_CHALLENGE_SIZE        16U
#define TESLA_AUTH_RESPONSE_SIZE    16U
#define TESLA_AUTHENTICATE_DATA_LEN (TESLA_PUBLIC_KEY_SIZE + TESLA_CHALLENGE_SIZE)
#define TESLA_APDU_RESPONSE_MAX     (TESLA_PUBLIC_KEY_SIZE + 2U)

typedef bool (*TeslaApduAuthenticateCallback)(
    void* context,
    const uint8_t peer_public_key[TESLA_PUBLIC_KEY_SIZE],
    const uint8_t challenge[TESLA_CHALLENGE_SIZE],
    uint8_t response[TESLA_AUTH_RESPONSE_SIZE]);

typedef enum {
    TeslaApduCommandNone,
    TeslaApduCommandSelect,
    TeslaApduCommandGetPublicKey,
    TeslaApduCommandAuthenticate,
    TeslaApduCommandGetCardInfo,
    TeslaApduCommandUnsupported,
} TeslaApduCommand;

typedef struct {
    bool selected;
    uint8_t public_key[TESLA_PUBLIC_KEY_SIZE];
    TeslaApduAuthenticateCallback authenticate_callback;
    void* authenticate_context;
} TeslaApdu;

typedef struct {
    TeslaApduCommand command;
    uint16_t status_word;
    size_t response_size;
} TeslaApduResult;

void tesla_apdu_init(
    TeslaApdu* apdu,
    const uint8_t public_key[TESLA_PUBLIC_KEY_SIZE],
    TeslaApduAuthenticateCallback authenticate_callback,
    void* authenticate_context);

void tesla_apdu_reset_session(TeslaApdu* apdu);

TeslaApduResult tesla_apdu_process(
    TeslaApdu* apdu,
    const uint8_t* request,
    size_t request_size,
    uint8_t* response,
    size_t response_capacity);

#ifdef __cplusplus
}
#endif
