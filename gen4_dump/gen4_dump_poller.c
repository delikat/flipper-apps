// SPDX-License-Identifier: GPL-3.0-or-later
//
// Gen4/UMC backdoor dump — NFC transport. See gen4_dump_poller.h for the
// contract and attribution. Byte-level decisions live in gen4_dump_core.c.

#include "gen4_dump_poller.h"

#include <furi.h>
#include <string.h>

#include <nfc/nfc_poller.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <toolbox/bit_buffer.h>

#define TAG "Gen4Dump"

#define GEN4_DUMP_FWT         (200000U)
#define GEN4_DUMP_BUFFER_SIZE (64U)
#define GEN4_DUMP_FLAG_DONE   (1UL << 0)

// Standard (non-backdoor) ISO14443-3A / Ultralight commands, issued against the
// card's emulated identity to capture non-secret metadata.
#define UL_CMD_READ         (0x30)
#define GEN4_CMD_SET_MAX_RW (0x6B)

// UMC Ultralight special-page addresses (exposed after raising max R/W).
#define UL_PAGE_VERSION (0xFA) // VERSION at 0xFA-0xFB (8 bytes)
#define UL_PAGE_SIG_LO  (0xF2) // SIGNATURE at 0xF2-0xF9 (32 bytes, two reads)
#define UL_PAGE_SIG_HI  (0xF6)
#define UL_PAGE_PWD     (0xE5) // PWD at 0xE5 (4 bytes), PACK at 0xE6 (2 bytes)
#define UL_MAX_RW_FULL  (0xFB) // expose pages up to 251

// The backdoor block address is a single byte, so only the first 256 units are
// reachable; NTAG-I2C parts (>256 pages) fall outside this dumper's scope.
#define GEN4_DUMP_MAX_ADDR (256U)

// Each field cycle runs one of two jobs: probe a candidate password, or dump.
typedef enum {
    Gen4DumpPhaseUnlock,
    Gen4DumpPhaseDump,
} Gen4DumpPhase;

struct Gen4Dump {
    Nfc* nfc;
    uint8_t password[GEN4_DUMP_PASSWORD_LEN];
    Gen4DumpProgressCb progress_cb;
    void* progress_ctx;
    const volatile bool* stop;

    NfcPoller* poller;
    BitBuffer* tx;
    BitBuffer* rx;
    FuriThreadId thread_id;

    Gen4DumpPhase phase;
    bool unlock_ok; // the current password read the config
    bool saw_card; // a card was activated in the last cycle
    uint8_t cfg_raw[GEN4_DUMP_CONFIG_SIZE];

    Gen4DumpResult result;
    NfcDevice* device;
    char kind_name[40];
    uint16_t unit_count;
};

Gen4Dump* gen4_dump_alloc(Nfc* nfc) {
    furi_assert(nfc);
    Gen4Dump* dump = malloc(sizeof(Gen4Dump));
    memset(dump, 0, sizeof(Gen4Dump));
    dump->nfc = nfc;
    dump->tx = bit_buffer_alloc(GEN4_DUMP_BUFFER_SIZE);
    dump->rx = bit_buffer_alloc(GEN4_DUMP_BUFFER_SIZE);
    strncpy(dump->kind_name, "Unknown", sizeof(dump->kind_name) - 1);
    return dump;
}

void gen4_dump_free(Gen4Dump* dump) {
    furi_assert(dump);
    if(dump->device) nfc_device_free(dump->device);
    bit_buffer_free(dump->tx);
    bit_buffer_free(dump->rx);
    free(dump);
}

void gen4_dump_set_password(Gen4Dump* dump, const uint8_t password[GEN4_DUMP_PASSWORD_LEN]) {
    furi_assert(dump);
    furi_assert(password);
    memcpy(dump->password, password, GEN4_DUMP_PASSWORD_LEN);
}

void gen4_dump_set_progress_callback(Gen4Dump* dump, Gen4DumpProgressCb callback, void* context) {
    furi_assert(dump);
    dump->progress_cb = callback;
    dump->progress_ctx = context;
}

void gen4_dump_set_stop_flag(Gen4Dump* dump, const volatile bool* stop) {
    furi_assert(dump);
    dump->stop = stop;
}

NfcDevice* gen4_dump_get_device(Gen4Dump* dump) {
    furi_assert(dump);
    return dump->device;
}

const char* gen4_dump_get_kind_name(const Gen4Dump* dump) {
    furi_assert(dump);
    return dump->kind_name;
}

uint16_t gen4_dump_get_unit_count(const Gen4Dump* dump) {
    furi_assert(dump);
    return dump->unit_count;
}

// --- low-level transfer helpers (run inside the poller callback) --------------

// Send an already-built frame (no CRC — send_standard_frame adds/checks it) and
// copy up to resp_cap response bytes. Returns false on any transport error.
static bool gen4_dump_xfer(
    Gen4Dump* dump,
    Iso14443_3aPoller* poller,
    const uint8_t* frame,
    size_t frame_len,
    uint8_t* resp,
    size_t resp_cap,
    size_t* resp_len) {
    bit_buffer_reset(dump->tx);
    bit_buffer_append_bytes(dump->tx, frame, frame_len);

    Iso14443_3aError error =
        iso14443_3a_poller_send_standard_frame(poller, dump->tx, dump->rx, GEN4_DUMP_FWT);
    if(error != Iso14443_3aErrorNone) return false;

    size_t n = bit_buffer_get_size_bytes(dump->rx);
    if(n > resp_cap) n = resp_cap;
    if(resp != NULL && n > 0) memcpy(resp, bit_buffer_get_data(dump->rx), n);
    if(resp_len != NULL) *resp_len = n;
    return true;
}

static bool
    gen4_dump_get_config(Gen4Dump* dump, Iso14443_3aPoller* poller, uint8_t cfg[GEN4_DUMP_CONFIG_SIZE]) {
    uint8_t frame[GEN4_DUMP_MAX_FRAME];
    size_t frame_len = gen4_dump_build_get_config(dump->password, frame, sizeof(frame));

    uint8_t resp[GEN4_DUMP_CONFIG_SIZE];
    size_t resp_len = 0;
    if(!gen4_dump_xfer(dump, poller, frame, frame_len, resp, sizeof(resp), &resp_len)) return false;
    if(resp_len != GEN4_DUMP_CONFIG_SIZE) return false;
    memcpy(cfg, resp, GEN4_DUMP_CONFIG_SIZE);
    return true;
}

// Backdoor read of a 16-byte Classic block.
static bool gen4_dump_read_block16(
    Gen4Dump* dump,
    Iso14443_3aPoller* poller,
    uint8_t block,
    uint8_t out[GEN4_DUMP_BLOCK_SIZE]) {
    uint8_t frame[GEN4_DUMP_MAX_FRAME];
    size_t frame_len = gen4_dump_build_read(dump->password, block, frame, sizeof(frame));

    uint8_t resp[GEN4_DUMP_BLOCK_SIZE];
    size_t resp_len = 0;
    if(!gen4_dump_xfer(dump, poller, frame, frame_len, resp, sizeof(resp), &resp_len)) return false;
    if(resp_len < GEN4_DUMP_BLOCK_SIZE) return false;
    memcpy(out, resp, GEN4_DUMP_BLOCK_SIZE);
    return true;
}

// Read four consecutive Ultralight/NTAG pages with the standard READ (0x30),
// which returns 16 bytes = 4 pages. The UMC answers this against its emulated
// identity, so it works where the Classic-only 0xCE backdoor read does not.
static bool gen4_dump_ul_read_4pages(
    Gen4Dump* dump,
    Iso14443_3aPoller* poller,
    uint8_t start_page,
    uint8_t out[GEN4_DUMP_BLOCK_SIZE]) {
    const uint8_t frame[2] = {UL_CMD_READ, start_page};
    uint8_t resp[GEN4_DUMP_BLOCK_SIZE];
    size_t resp_len = 0;
    if(!gen4_dump_xfer(dump, poller, frame, sizeof(frame), resp, sizeof(resp), &resp_len))
        return false;
    if(resp_len < GEN4_DUMP_BLOCK_SIZE) return false;
    memcpy(out, resp, GEN4_DUMP_BLOCK_SIZE);
    return true;
}

// Set the UMC's "max R/W sectors" (backdoor 0x6B). Raising it to UL_MAX_RW_FULL
// exposes the special high pages (version/signature/pwd/pack) to plain 0x30
// reads; restoring it afterwards keeps the dump non-destructive. Best-effort —
// some cards ignore it, in which case only the normal pages read back.
static bool gen4_dump_ul_set_max_rw(Gen4Dump* dump, Iso14443_3aPoller* poller, uint8_t value) {
    const uint8_t args[1] = {value};
    uint8_t frame[GEN4_DUMP_MAX_FRAME];
    size_t frame_len =
        gen4_dump_build_cmd(dump->password, GEN4_CMD_SET_MAX_RW, args, 1, frame, sizeof(frame));
    return gen4_dump_xfer(dump, poller, frame, frame_len, NULL, 0, NULL);
}

// --- per-protocol dump routines ----------------------------------------------

static void gen4_dump_report_progress(Gen4Dump* dump, uint16_t done, uint16_t total) {
    dump->unit_count = done;
    if(dump->progress_cb) dump->progress_cb(dump->progress_ctx, done, total);
}

static uint8_t gen4_dump_uid_len_from_code(uint8_t uid_len_code) {
    switch(uid_len_code) {
    case 0x01:
        return 7;
    case 0x02:
        return 10;
    case 0x00:
    default:
        return 4;
    }
}

static Gen4DumpResult
    gen4_dump_do_classic(Gen4Dump* dump, Iso14443_3aPoller* poller, const Gen4DumpConfig* cfg) {
    uint16_t sak_blocks = 0;
    Gen4DumpKind kind = gen4_dump_classic_kind_from_sak(cfg->sak, &sak_blocks);

    MfClassicType type;
    switch(kind) {
    case Gen4DumpKindMfClassicMini:
        type = MfClassicTypeMini;
        strncpy(dump->kind_name, "MIFARE Classic Mini", sizeof(dump->kind_name) - 1);
        break;
    case Gen4DumpKindMfClassic1K:
        type = MfClassicType1k;
        strncpy(dump->kind_name, "MIFARE Classic 1K", sizeof(dump->kind_name) - 1);
        break;
    case Gen4DumpKindMfClassic4K:
        type = MfClassicType4k;
        strncpy(dump->kind_name, "MIFARE Classic 4K", sizeof(dump->kind_name) - 1);
        break;
    default:
        return Gen4DumpResultUnsupported;
    }

    const uint16_t block_count = mf_classic_get_total_block_num(type);
    MfClassicData* data = mf_classic_alloc();
    data->type = type;

    uint8_t block0[GEN4_DUMP_BLOCK_SIZE] = {0};

    for(uint16_t b = 0; b < block_count; b++) {
        if(dump->stop && *dump->stop) {
            mf_classic_free(data);
            return Gen4DumpResultCanceled;
        }

        uint8_t raw[GEN4_DUMP_BLOCK_SIZE];
        if(!gen4_dump_read_block16(dump, poller, (uint8_t)b, raw)) {
            mf_classic_free(data);
            return Gen4DumpResultReadFailed;
        }
        if(b == 0) memcpy(block0, raw, sizeof(block0));

        MfClassicBlock mb;
        memcpy(mb.data, raw, MF_CLASSIC_BLOCK_SIZE);
        mf_classic_set_block_read(data, (uint8_t)b, &mb);

        // Sector trailers carry both keys in the clear over the backdoor.
        if(mf_classic_is_sector_trailer((uint8_t)b)) {
            const uint8_t sector = mf_classic_get_sector_by_block((uint8_t)b);
            mf_classic_set_key_found(
                data, sector, MfClassicKeyTypeA, gen4_dump_key_to_u64(&raw[0]));
            mf_classic_set_key_found(
                data, sector, MfClassicKeyTypeB, gen4_dump_key_to_u64(&raw[10]));
        }

        gen4_dump_report_progress(dump, b + 1, block_count);
    }

    // Card identity: ATQA/SAK/UID-length from the config it presents, UID from
    // the manufacturer block we just read.
    Iso14443_3aData* iso3 = data->iso14443_3a_data;
    const uint8_t uid_len = gen4_dump_uid_len_from_code(cfg->uid_len_code);
    gen4_dump_uid_from_classic_block0(block0, uid_len, iso3->uid);
    iso3->uid_len = uid_len;
    iso3->atqa[0] = cfg->atqa[0];
    iso3->atqa[1] = cfg->atqa[1];
    iso3->sak = cfg->sak;

    dump->device = nfc_device_alloc();
    nfc_device_set_data(dump->device, NfcProtocolMfClassic, data);
    mf_classic_free(data);
    return Gen4DumpResultOk;
}

static void gen4_dump_ul_kind_name(Gen4Dump* dump, MfUltralightType type) {
    const char* name;
    switch(type) {
    case MfUltralightTypeNTAG213:
        name = "NTAG213";
        break;
    case MfUltralightTypeNTAG215:
        name = "NTAG215";
        break;
    case MfUltralightTypeNTAG216:
        name = "NTAG216";
        break;
    case MfUltralightTypeNTAG203:
        name = "NTAG203";
        break;
    case MfUltralightTypeUL11:
        name = "Ultralight EV1 (11)";
        break;
    case MfUltralightTypeUL21:
        name = "Ultralight EV1 (21)";
        break;
    case MfUltralightTypeMfulC:
        name = "Ultralight C";
        break;
    case MfUltralightTypeOrigin:
        name = "Ultralight";
        break;
    default:
        name = "Ultralight/NTAG";
        break;
    }
    strncpy(dump->kind_name, name, sizeof(dump->kind_name) - 1);
}

static Gen4DumpResult
    gen4_dump_do_ultralight(Gen4Dump* dump, Iso14443_3aPoller* poller, const Gen4DumpConfig* cfg) {
    MfUltralightData* data = mf_ultralight_alloc();

    // Expose the special high pages (version/signature/pwd/pack) to plain 0x30
    // reads; remember the original limit so we can restore it afterwards.
    const uint8_t orig_max_rw = cfg->total_blocks;
    gen4_dump_ul_set_max_rw(dump, poller, UL_MAX_RW_FULL);

    // Type + version from the UMC's VERSION page (0xFA), validated by the NXP
    // vendor byte. Fall back to the configured UL mode for parts without one.
    uint8_t quad[GEN4_DUMP_BLOCK_SIZE];
    MfUltralightType type;
    bool have_version = false;
    if(gen4_dump_ul_read_4pages(dump, poller, UL_PAGE_VERSION, quad)) {
        memcpy(&data->version, quad, sizeof(data->version)); // VERSION = pages 0xFA-0xFB
        if(data->version.vendor_id == 0x04) { // NXP
            type = mf_ultralight_get_type_by_version(&data->version);
            have_version = true;
        }
    }
    if(!have_version) {
        memset(&data->version, 0, sizeof(data->version));
        uint16_t unused = 0;
        switch(gen4_dump_ul_type_from_mode(cfg->mfu_mode, &unused)) {
        case Gen4DumpUlULC:
            type = MfUltralightTypeMfulC;
            break;
        case Gen4DumpUlUL:
        default:
            type = MfUltralightTypeOrigin;
            break;
        }
    }
    data->type = type;
    gen4_dump_ul_kind_name(dump, type);

    uint16_t pages_total = mf_ultralight_get_pages_total(type);
    if(pages_total == 0 || pages_total > MF_ULTRALIGHT_MAX_PAGE_NUM) pages_total = 16;

    const uint32_t features = mf_ultralight_get_feature_support_set(type);

    // SIGNATURE = pages 0xF2-0xF9 (two 16-byte reads).
    if(have_version &&
       mf_ultralight_support_feature(features, MfUltralightFeatureSupportReadSignature)) {
        uint8_t sig_lo[GEN4_DUMP_BLOCK_SIZE];
        uint8_t sig_hi[GEN4_DUMP_BLOCK_SIZE];
        if(gen4_dump_ul_read_4pages(dump, poller, UL_PAGE_SIG_LO, sig_lo) &&
           gen4_dump_ul_read_4pages(dump, poller, UL_PAGE_SIG_HI, sig_hi)) {
            memcpy(&data->signature.data[0], sig_lo, GEN4_DUMP_BLOCK_SIZE);
            memcpy(&data->signature.data[GEN4_DUMP_BLOCK_SIZE], sig_hi, GEN4_DUMP_BLOCK_SIZE);
        }
    }

    // Normal user/config pages via standard reads (4 per read, end wrap handled).
    uint8_t page0[GEN4_DUMP_UL_PAGE_SIZE] = {0};
    uint8_t page1[GEN4_DUMP_UL_PAGE_SIZE] = {0};

    uint16_t pages_read = 0;
    for(uint16_t base = 0; base < pages_total && base < GEN4_DUMP_MAX_ADDR; base += 4) {
        if(dump->stop && *dump->stop) {
            mf_ultralight_free(data);
            return Gen4DumpResultCanceled;
        }

        if(!gen4_dump_ul_read_4pages(dump, poller, (uint8_t)base, quad)) {
            mf_ultralight_free(data);
            return Gen4DumpResultReadFailed;
        }

        // A standard READ near the end of memory wraps around, so keep only the
        // pages that actually belong to this card.
        uint16_t in_this = pages_total - base;
        if(in_this > 4) in_this = 4;
        for(uint16_t k = 0; k < in_this; k++) {
            const uint16_t pg = base + k;
            const uint8_t* src = &quad[k * GEN4_DUMP_UL_PAGE_SIZE];
            memcpy(data->page[pg].data, src, GEN4_DUMP_UL_PAGE_SIZE);
            if(pg == 0) memcpy(page0, src, sizeof(page0));
            if(pg == 1) memcpy(page1, src, sizeof(page1));
            pages_read = pg + 1;
        }
        gen4_dump_report_progress(dump, pages_read, pages_total);
    }
    data->pages_read = pages_read;
    data->pages_total = pages_total;

    // Recover the real PWD (0xE5) and PACK (0xE6) — a normal NTAG read returns
    // these masked — and place them in the config pages so the dump is complete.
    if(have_version &&
       mf_ultralight_support_feature(features, MfUltralightFeatureSupportPasswordAuth)) {
        uint8_t pp[GEN4_DUMP_BLOCK_SIZE];
        if(gen4_dump_ul_read_4pages(dump, poller, UL_PAGE_PWD, pp)) {
            MfUltralightConfigPages* config = NULL;
            if(mf_ultralight_get_config_page(data, &config)) {
                memcpy(config->password.data, &pp[0], sizeof(config->password.data)); // 0xE5
                memcpy(config->pack.data, &pp[GEN4_DUMP_UL_PAGE_SIZE], sizeof(config->pack.data));
            }
        }
    }

    // Restore the original max R/W so the card is left as we found it.
    gen4_dump_ul_set_max_rw(dump, poller, orig_max_rw);

    // 7-byte UID from the first two pages; ATQA/SAK from the presented config.
    Iso14443_3aData* iso3 = data->iso14443_3a_data;
    gen4_dump_uid_from_ul_pages(page0, page1, iso3->uid);
    iso3->uid_len = 7;
    iso3->atqa[0] = cfg->atqa[0];
    iso3->atqa[1] = cfg->atqa[1];
    iso3->sak = cfg->sak;

    dump->device = nfc_device_alloc();
    nfc_device_set_data(dump->device, NfcProtocolMfUltralight, data);
    mf_ultralight_free(data);
    return Gen4DumpResultOk;
}

// --- poller driver -----------------------------------------------------------

static NfcCommand gen4_dump_poller_callback(NfcGenericEvent event, void* context) {
    furi_assert(context);
    furi_assert(event.protocol == NfcProtocolIso14443_3a);
    furi_assert(event.instance);
    furi_assert(event.event_data);

    Gen4Dump* dump = context;
    Iso14443_3aPoller* poller = event.instance;
    Iso14443_3aPollerEvent* iso3_event = event.event_data;

    dump->saw_card = (iso3_event->type == Iso14443_3aPollerEventTypeReady);

    if(dump->phase == Gen4DumpPhaseUnlock) {
        // Just probe whether the current password reads the config block.
        dump->unlock_ok = dump->saw_card && gen4_dump_get_config(dump, poller, dump->cfg_raw);
    } else if(dump->saw_card) {
        Gen4DumpConfig cfg;
        gen4_dump_parse_config(dump->cfg_raw, &cfg);
        if(cfg.protocol == Gen4DumpProtocolMfClassic) {
            dump->result = gen4_dump_do_classic(dump, poller, &cfg);
        } else if(cfg.protocol == Gen4DumpProtocolMfUltralight) {
            dump->result = gen4_dump_do_ultralight(dump, poller, &cfg);
        } else {
            dump->result = Gen4DumpResultUnsupported;
        }
    } else {
        dump->result = Gen4DumpResultNoCard;
    }

    furi_thread_flags_set(dump->thread_id, GEN4_DUMP_FLAG_DONE);
    return NfcCommandStop;
}

// One activate/work/halt field cycle running the current phase.
static void gen4_dump_field_cycle(Gen4Dump* dump) {
    dump->thread_id = furi_thread_get_current_id();
    dump->poller = nfc_poller_alloc(dump->nfc, NfcProtocolIso14443_3a);
    nfc_poller_start(dump->poller, gen4_dump_poller_callback, dump);
    furi_thread_flags_wait(GEN4_DUMP_FLAG_DONE, FuriFlagWaitAny, FuriWaitForever);
    furi_thread_flags_clear(GEN4_DUMP_FLAG_DONE);
    nfc_poller_stop(dump->poller);
    nfc_poller_free(dump->poller);
    dump->poller = NULL;
}

Gen4DumpResult gen4_dump_run(Gen4Dump* dump) {
    furi_assert(dump);

    if(dump->device) {
        nfc_device_free(dump->device);
        dump->device = NULL;
    }
    dump->result = Gen4DumpResultNoCard;
    dump->unit_count = 0;

    // Phase 1: find the working backdoor password. Try the user-supplied one
    // first, then the common list. Each probe is its own field cycle so a wrong
    // password can't leave the card wedged for the next attempt.
    uint8_t user_pwd[GEN4_DUMP_PASSWORD_LEN];
    memcpy(user_pwd, dump->password, sizeof(user_pwd));

    dump->phase = Gen4DumpPhaseUnlock;
    dump->unlock_ok = false;
    bool card_present = false;

    for(size_t i = 0; i <= GEN4_DUMP_COMMON_PASSWORD_COUNT; i++) {
        if(dump->stop && *dump->stop) return Gen4DumpResultCanceled;

        if(i == 0) {
            memcpy(dump->password, user_pwd, GEN4_DUMP_PASSWORD_LEN);
        } else {
            const uint8_t* candidate = gen4_dump_common_passwords[i - 1];
            if(memcmp(candidate, user_pwd, GEN4_DUMP_PASSWORD_LEN) == 0) continue;
            memcpy(dump->password, candidate, GEN4_DUMP_PASSWORD_LEN);
        }

        gen4_dump_field_cycle(dump);
        if(dump->saw_card) card_present = true;
        if(dump->unlock_ok) break;
        if(!dump->saw_card) break; // no card in the field — stop probing
    }

    if(!dump->unlock_ok) {
        memcpy(dump->password, user_pwd, GEN4_DUMP_PASSWORD_LEN);
        return card_present ? Gen4DumpResultNotGen4 : Gen4DumpResultNoCard;
    }

    // Phase 2: full dump with the password that unlocked the card.
    dump->phase = Gen4DumpPhaseDump;
    gen4_dump_field_cycle(dump);
    return dump->result;
}

const uint8_t* gen4_dump_get_password(const Gen4Dump* dump) {
    furi_assert(dump);
    return dump->password;
}
