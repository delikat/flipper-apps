#include "../tesla_apdu.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    bool succeed;
    unsigned calls;
    uint8_t peer[TESLA_PUBLIC_KEY_SIZE];
    uint8_t challenge[TESLA_CHALLENGE_SIZE];
} AuthStub;

static bool auth_stub(
    void* context,
    const uint8_t peer[TESLA_PUBLIC_KEY_SIZE],
    const uint8_t challenge[TESLA_CHALLENGE_SIZE],
    uint8_t response[TESLA_AUTH_RESPONSE_SIZE]) {
    AuthStub* stub = context;
    ++stub->calls;
    memcpy(stub->peer, peer, sizeof(stub->peer));
    memcpy(stub->challenge, challenge, sizeof(stub->challenge));
    for(size_t i = 0; i < TESLA_AUTH_RESPONSE_SIZE; ++i)
        response[i] = (uint8_t)(0xA0U + i);
    return stub->succeed;
}

static void expect_sw(const uint8_t* response, TeslaApduResult result, uint16_t sw) {
    assert(result.response_size >= 2U);
    assert(result.status_word == sw);
    assert(response[result.response_size - 2U] == (uint8_t)(sw >> 8U));
    assert(response[result.response_size - 1U] == (uint8_t)sw);
}

static TeslaApduResult select_gauss(TeslaApdu* apdu, uint8_t* response) {
    static const uint8_t select[] = {
        0x00,
        0xA4,
        0x04,
        0x00,
        0x0A,
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
    return tesla_apdu_process(apdu, select, sizeof(select), response, TESLA_APDU_RESPONSE_MAX);
}

int main(void) {
    uint8_t public_key[TESLA_PUBLIC_KEY_SIZE];
    for(size_t i = 0; i < sizeof(public_key); ++i)
        public_key[i] = (uint8_t)i;
    public_key[0] = 0x04;

    AuthStub stub = {.succeed = true};
    TeslaApdu apdu;
    tesla_apdu_init(&apdu, public_key, auth_stub, &stub);

    uint8_t response[TESLA_APDU_RESPONSE_MAX] = {0};
    static const uint8_t get_public[] = {0x80, 0x04, 0x00, 0x00, 0x00};
    TeslaApduResult result =
        tesla_apdu_process(&apdu, get_public, sizeof(get_public), response, sizeof(response));
    expect_sw(response, result, 0x6999);

    result = select_gauss(&apdu, response);
    expect_sw(response, result, 0x9000);
    assert(apdu.selected);

    result = tesla_apdu_process(&apdu, get_public, sizeof(get_public), response, sizeof(response));
    expect_sw(response, result, 0x9000);
    assert(result.response_size == TESLA_PUBLIC_KEY_SIZE + 2U);
    assert(memcmp(response, public_key, TESLA_PUBLIC_KEY_SIZE) == 0);

    static const uint8_t get_public_short[] = {0x80, 0x04, 0x00, 0x00, 0x10};
    result = tesla_apdu_process(
        &apdu, get_public_short, sizeof(get_public_short), response, sizeof(response));
    expect_sw(response, result, 0x9000);
    assert(result.response_size == 18U);
    assert(memcmp(response, public_key, 16U) == 0);

    static const uint8_t get_info[] = {0x80, 0x14, 0x00, 0x00};
    result = tesla_apdu_process(&apdu, get_info, sizeof(get_info), response, sizeof(response));
    expect_sw(response, result, 0x9000);
    assert(result.response_size == 4U);
    assert(response[0] == 0x00 && response[1] == 0x01);

    uint8_t authenticate[5U + TESLA_AUTHENTICATE_DATA_LEN] = {
        0x80,
        0x11,
        0x00,
        0x00,
        TESLA_AUTHENTICATE_DATA_LEN,
    };
    for(size_t i = 0; i < TESLA_PUBLIC_KEY_SIZE; ++i)
        authenticate[5U + i] = (uint8_t)i;
    for(size_t i = 0; i < TESLA_CHALLENGE_SIZE; ++i) {
        authenticate[5U + TESLA_PUBLIC_KEY_SIZE + i] = (uint8_t)(0xF0U + i);
    }
    authenticate[5] = 0x04;

    result =
        tesla_apdu_process(&apdu, authenticate, sizeof(authenticate), response, sizeof(response));
    expect_sw(response, result, 0x9000);
    assert(stub.calls == 1U);
    assert(memcmp(stub.peer, &authenticate[5], TESLA_PUBLIC_KEY_SIZE) == 0);
    assert(
        memcmp(stub.challenge, &authenticate[5U + TESLA_PUBLIC_KEY_SIZE], TESLA_CHALLENGE_SIZE) ==
        0);
    assert(result.response_size == TESLA_AUTH_RESPONSE_SIZE + 2U);
    for(size_t i = 0; i < TESLA_AUTH_RESPONSE_SIZE; ++i) {
        assert(response[i] == (uint8_t)(0xA0U + i));
    }

    uint8_t authenticate_with_le[sizeof(authenticate) + 1U];
    memcpy(authenticate_with_le, authenticate, sizeof(authenticate));
    authenticate_with_le[sizeof(authenticate)] = 0x01U;
    result = tesla_apdu_process(
        &apdu, authenticate_with_le, sizeof(authenticate_with_le), response, sizeof(response));
    expect_sw(response, result, 0x9000);
    assert(stub.calls == 2U);
    assert(result.response_size == 3U);
    assert(response[0] == 0xA0U);

    authenticate[4] = TESLA_AUTHENTICATE_DATA_LEN - 1U;
    result =
        tesla_apdu_process(&apdu, authenticate, sizeof(authenticate), response, sizeof(response));
    expect_sw(response, result, 0x6700);
    assert(stub.calls == 2U);
    authenticate[4] = TESLA_AUTHENTICATE_DATA_LEN;

    stub.succeed = false;
    result =
        tesla_apdu_process(&apdu, authenticate, sizeof(authenticate), response, sizeof(response));
    expect_sw(response, result, 0x6F00);
    assert(stub.calls == 3U);

    static const uint8_t bad_cla[] = {0x00, 0x04, 0x00, 0x00, 0x00};
    result = tesla_apdu_process(&apdu, bad_cla, sizeof(bad_cla), response, sizeof(response));
    expect_sw(response, result, 0x6E00);

    static const uint8_t bad_ins[] = {0x80, 0x99, 0x00, 0x00};
    result = tesla_apdu_process(&apdu, bad_ins, sizeof(bad_ins), response, sizeof(response));
    expect_sw(response, result, 0x6D00);

    tesla_apdu_reset_session(&apdu);
    assert(!apdu.selected);

    static const uint8_t select_official[] = {
        0x00,
        0xA4,
        0x04,
        0x00,
        0x0A,
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
    result = tesla_apdu_process(
        &apdu, select_official, sizeof(select_official), response, sizeof(response));
    expect_sw(response, result, 0x9000);

    uint8_t bad_select[sizeof(select_official)];
    memcpy(bad_select, select_official, sizeof(bad_select));
    bad_select[5] = 0x01;
    result = tesla_apdu_process(&apdu, bad_select, sizeof(bad_select), response, sizeof(response));
    expect_sw(response, result, 0x6A82);
    assert(!apdu.selected);

    puts("APDU tests passed");
    return 0;
}
