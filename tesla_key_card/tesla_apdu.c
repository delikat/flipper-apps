#include "tesla_apdu.h"

#include <string.h>

#define ISO7816_INS_SELECT        0xA4U
#define ISO7816_SELECT_BY_DF_NAME 0x04U
#define TESLA_INS_GET_PUBLIC_KEY  0x04U
#define TESLA_INS_AUTHENTICATE    0x11U
#define TESLA_INS_GET_CARD_INFO   0x14U

#define ISO7816_SW_SUCCESS           0x9000U
#define ISO7816_SW_WRONG_LENGTH      0x6700U
#define ISO7816_SW_COMMAND_NOT_ALLOW 0x6999U
#define ISO7816_SW_WRONG_DATA        0x6A80U
#define ISO7816_SW_FILE_NOT_FOUND    0x6A82U
#define ISO7816_SW_INS_NOT_SUPPORTED 0x6D00U
#define ISO7816_SW_CLA_NOT_SUPPORTED 0x6E00U
#define ISO7816_SW_UNKNOWN           0x6F00U

static const uint8_t tesla_aid[] = {
    0x74,
    0x65,
    0x73,
    0x6C,
    0x61,
    0x4C,
    0x6F,
    0x67,
    0x69,
    0x63,
};

static const uint8_t tesla_phone_key_aid[] = {
    0xF4,
    0x65,
    0x73,
    0x6C,
    0x61,
    0x4C,
    0x6F,
    0x67,
    0x69,
    0x63,
};

static bool tesla_apdu_aid_matches(const uint8_t* aid, size_t aid_size) {
    if(aid_size < sizeof(tesla_aid)) return false;

    return memcmp(aid, tesla_aid, sizeof(tesla_aid)) == 0 ||
           memcmp(aid, tesla_phone_key_aid, sizeof(tesla_phone_key_aid)) == 0;
}

static TeslaApduResult tesla_apdu_write_response(
    TeslaApduCommand command,
    uint16_t status_word,
    const uint8_t* data,
    size_t data_size,
    uint8_t* response,
    size_t response_capacity) {
    TeslaApduResult result = {
        .command = command,
        .status_word = status_word,
        .response_size = 0,
    };

    if(response_capacity < data_size + 2U) {
        status_word = ISO7816_SW_WRONG_LENGTH;
        data_size = 0;
        if(response_capacity < 2U) return result;
        result.status_word = status_word;
    }

    if(data_size != 0U) memcpy(response, data, data_size);
    response[data_size] = (uint8_t)(status_word >> 8U);
    response[data_size + 1U] = (uint8_t)status_word;
    result.response_size = data_size + 2U;

    return result;
}

static size_t tesla_apdu_apply_le(const uint8_t* request, size_t request_size, size_t size) {
    if(request_size == 5U && request[4] != 0U && request[4] < size) return request[4];
    return size;
}

static size_t tesla_apdu_apply_case4_le(
    const uint8_t* request,
    size_t request_size,
    size_t data_end,
    size_t size) {
    if(request_size == data_end + 1U && request[data_end] != 0U && request[data_end] < size) {
        return request[data_end];
    }
    return size;
}

void tesla_apdu_init(
    TeslaApdu* apdu,
    const uint8_t public_key[TESLA_PUBLIC_KEY_SIZE],
    TeslaApduAuthenticateCallback authenticate_callback,
    void* authenticate_context) {
    memset(apdu, 0, sizeof(TeslaApdu));
    memcpy(apdu->public_key, public_key, TESLA_PUBLIC_KEY_SIZE);
    apdu->authenticate_callback = authenticate_callback;
    apdu->authenticate_context = authenticate_context;
}

void tesla_apdu_reset_session(TeslaApdu* apdu) {
    apdu->selected = false;
}

TeslaApduResult tesla_apdu_process(
    TeslaApdu* apdu,
    const uint8_t* request,
    size_t request_size,
    uint8_t* response,
    size_t response_capacity) {
    if(request_size < 4U) {
        return tesla_apdu_write_response(
            TeslaApduCommandNone, ISO7816_SW_WRONG_LENGTH, NULL, 0, response, response_capacity);
    }

    if(request[0] == 0x00U && request[1] == ISO7816_INS_SELECT &&
       request[2] == ISO7816_SELECT_BY_DF_NAME) {
        bool matches = false;
        if(request_size >= 5U) {
            const size_t aid_size = request[4];
            if(aid_size <= request_size - 5U) {
                matches = tesla_apdu_aid_matches(&request[5], aid_size);
            }
        }

        apdu->selected = matches;
        return tesla_apdu_write_response(
            TeslaApduCommandSelect,
            matches ? ISO7816_SW_SUCCESS : ISO7816_SW_FILE_NOT_FOUND,
            NULL,
            0,
            response,
            response_capacity);
    }

    if(!apdu->selected) {
        return tesla_apdu_write_response(
            TeslaApduCommandUnsupported,
            ISO7816_SW_COMMAND_NOT_ALLOW,
            NULL,
            0,
            response,
            response_capacity);
    }

    if((request[0] & 0x80U) == 0U) {
        return tesla_apdu_write_response(
            TeslaApduCommandUnsupported,
            ISO7816_SW_CLA_NOT_SUPPORTED,
            NULL,
            0,
            response,
            response_capacity);
    }

    switch(request[1]) {
    case TESLA_INS_GET_PUBLIC_KEY: {
        const size_t data_size = tesla_apdu_apply_le(request, request_size, TESLA_PUBLIC_KEY_SIZE);
        return tesla_apdu_write_response(
            TeslaApduCommandGetPublicKey,
            ISO7816_SW_SUCCESS,
            apdu->public_key,
            data_size,
            response,
            response_capacity);
    }

    case TESLA_INS_AUTHENTICATE: {
        if(request_size < 5U || request[4] < TESLA_AUTHENTICATE_DATA_LEN ||
           request_size < 5U + request[4]) {
            return tesla_apdu_write_response(
                TeslaApduCommandAuthenticate,
                ISO7816_SW_WRONG_LENGTH,
                NULL,
                0,
                response,
                response_capacity);
        }

        uint8_t auth_response[TESLA_AUTH_RESPONSE_SIZE];
        const bool authenticated = apdu->authenticate_callback &&
                                   apdu->authenticate_callback(
                                       apdu->authenticate_context,
                                       &request[5],
                                       &request[5U + TESLA_PUBLIC_KEY_SIZE],
                                       auth_response);

        const size_t response_data_size = tesla_apdu_apply_case4_le(
            request, request_size, 5U + request[4], TESLA_AUTH_RESPONSE_SIZE);

        TeslaApduResult result = tesla_apdu_write_response(
            TeslaApduCommandAuthenticate,
            authenticated ? ISO7816_SW_SUCCESS : ISO7816_SW_UNKNOWN,
            authenticated ? auth_response : NULL,
            authenticated ? response_data_size : 0,
            response,
            response_capacity);
        memset(auth_response, 0, sizeof(auth_response));
        return result;
    }

    case TESLA_INS_GET_CARD_INFO: {
        static const uint8_t card_info[] = {0x00, 0x01};
        const size_t data_size = tesla_apdu_apply_le(request, request_size, sizeof(card_info));
        return tesla_apdu_write_response(
            TeslaApduCommandGetCardInfo,
            ISO7816_SW_SUCCESS,
            card_info,
            data_size,
            response,
            response_capacity);
    }

    default:
        return tesla_apdu_write_response(
            TeslaApduCommandUnsupported,
            ISO7816_SW_INS_NOT_SUPPORTED,
            NULL,
            0,
            response,
            response_capacity);
    }
}
