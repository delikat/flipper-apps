#include "tesla_apdu.h"
#include "tesla_crypto.h"
#include "tesla_identity.h"
#include "tesla_nfc.h"

#include <furi.h>

#include <storage/storage.h>

#include <gui/elements.h>
#include <gui/gui.h>
#include <gui/modules/dialog_ex.h>
#include <gui/view_dispatcher.h>
#include <gui/view.h>

#include <stdio.h>
#include <string.h>

#define TAG "TeslaKeyCard"

#define TESLA_APP_EVENT_RESET_REQUEST 0x00000001U
#define TESLA_APP_EVENT_RESET_CANCEL  0x00000002U
#define TESLA_APP_EVENT_RESET_CONFIRM 0x00000003U

#define TESLA_NFC_EVENT_QUEUE_SIZE 16U
#define TESLA_NFC_EVENTS_PER_TICK  8U
#define TESLA_UI_TICK_MS           100U

/* Persistent trace of the NFC exchange, written from the GUI thread (never the
 * NFC worker) so SD latency stays off the ISO-DEP critical path. Truncated each
 * launch. Read it back with: ufbt cli -> storage read /ext/apps_data/tesla_key_card/nfc_debug.log */
#define TESLA_DEBUG_LOG_PATH APP_DATA_PATH("nfc_debug.log")

typedef enum {
    TeslaUiStateInitializing,
    TeslaUiStateReady,
    TeslaUiStatePresent,
    TeslaUiStateReadingKey,
    TeslaUiStateAuthenticated,
    TeslaUiStateError,
    TeslaUiStateResetting,
} TeslaUiState;

typedef struct {
    TeslaUiState state;
    uint32_t sessions;
    uint32_t authentications;
    uint16_t last_crypto_time_ms;
    uint8_t uid[TESLA_NFC_UID_SIZE];
} TeslaKeyCardViewModel;

typedef struct {
    TeslaNfcEvent event;
    uint16_t crypto_time_ms;
} TeslaKeyCardNfcEvent;

typedef enum {
    TeslaKeyCardScreenMain,
    TeslaKeyCardScreenReset,
} TeslaKeyCardScreen;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    View* main_view;
    DialogEx* reset_dialog;
    FuriMessageQueue* nfc_event_queue;
    TeslaKeyCardScreen screen;
    TeslaIdentity identity;
    TeslaCrypto* crypto;
    TeslaNfc* nfc;
    Storage* storage;
    File* debug_log;
} TeslaKeyCardApp;

/* Append one timestamped line to the on-SD trace. No-op if the log failed to
 * open. Called only from the GUI thread (tick handler), so the storage_file_sync
 * cannot stall the NFC worker. */
static void tesla_key_card_debug_log(TeslaKeyCardApp* app, const char* text) {
    if(!app->debug_log) return;
    char line[64];
    const int length =
        snprintf(line, sizeof(line), "%lu %s\n", (unsigned long)furi_get_tick(), text);
    if(length <= 0) return;
    const size_t to_write =
        length >= (int)sizeof(line) ? sizeof(line) - 1U : (size_t)length;
    storage_file_write(app->debug_log, line, to_write);
    storage_file_sync(app->debug_log);
}

static const char* tesla_key_card_state_text(TeslaUiState state) {
    switch(state) {
    case TeslaUiStateInitializing:
        return "Starting...";
    case TeslaUiStateReady:
        return "Ready - present to Tesla";
    case TeslaUiStatePresent:
        return "Tesla is reading card";
    case TeslaUiStateReadingKey:
        return "Sending card key...";
    case TeslaUiStateAuthenticated:
        return "Authenticated";
    case TeslaUiStateError:
        return "Error - check logs or reset";
    case TeslaUiStateResetting:
        return "Generating new key...";
    default:
        return "Unknown";
    }
}

static void tesla_key_card_draw_callback(Canvas* canvas, void* model_context) {
    TeslaKeyCardViewModel* model = model_context;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 11, "Tesla Key Card");

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 4, 23, tesla_key_card_state_text(model->state));

    char uid_text[20];
    snprintf(
        uid_text,
        sizeof(uid_text),
        "UID: %02X %02X %02X %02X",
        model->uid[0],
        model->uid[1],
        model->uid[2],
        model->uid[3]);
    canvas_draw_str(canvas, 4, 35, uid_text);

    char stats_text[32];
    snprintf(
        stats_text,
        sizeof(stats_text),
        "Sessions %lu  Auth %lu",
        (unsigned long)model->sessions,
        (unsigned long)model->authentications);
    canvas_draw_str(canvas, 4, 47, stats_text);

    char timing_text[32];
    if(model->last_crypto_time_ms != 0U) {
        snprintf(
            timing_text,
            sizeof(timing_text),
            "Last ECDH: %u ms",
            (unsigned)model->last_crypto_time_ms);
        canvas_draw_str(canvas, 4, 58, timing_text);
    }

    elements_button_left(canvas, "Exit");
    elements_button_center(canvas, "Reset");
}

static bool tesla_key_card_main_input_callback(InputEvent* event, void* context) {
    TeslaKeyCardApp* app = context;
    if(event->type == InputTypeShort && event->key == InputKeyOk) {
        view_dispatcher_send_custom_event(app->view_dispatcher, TESLA_APP_EVENT_RESET_REQUEST);
        return true;
    }
    return false;
}

static void tesla_key_card_reset_dialog_callback(DialogExResult result, void* context) {
    TeslaKeyCardApp* app = context;
    if(result == DialogExResultLeft) {
        view_dispatcher_send_custom_event(app->view_dispatcher, TESLA_APP_EVENT_RESET_CANCEL);
    } else if(result == DialogExResultRight) {
        view_dispatcher_send_custom_event(app->view_dispatcher, TESLA_APP_EVENT_RESET_CONFIRM);
    }
}

static void tesla_key_card_show_reset_dialog(TeslaKeyCardApp* app) {
    dialog_ex_set_header(app->reset_dialog, "Generate New Key?", 64, 2, AlignCenter, AlignTop);
    dialog_ex_set_text(
        app->reset_dialog,
        "The current Tesla pairing\nwill stop working.",
        64,
        20,
        AlignCenter,
        AlignTop);
    dialog_ex_set_left_button_text(app->reset_dialog, "Cancel");
    dialog_ex_set_right_button_text(app->reset_dialog, "Reset");
    dialog_ex_set_context(app->reset_dialog, app);
    dialog_ex_set_result_callback(app->reset_dialog, tesla_key_card_reset_dialog_callback);
}

static void tesla_key_card_nfc_event(TeslaNfcEvent event, uint16_t crypto_time_ms, void* context) {
    TeslaKeyCardApp* app = context;
    const TeslaKeyCardNfcEvent nfc_event = {
        .event = event,
        .crypto_time_ms = crypto_time_ms,
    };

    /* The NFC callback runs on the high-priority listener worker. Never wait
     * for GUI work here: status updates are best-effort diagnostics only. */
    furi_message_queue_put(app->nfc_event_queue, &nfc_event, 0U);
}

static void
    tesla_key_card_set_model(TeslaKeyCardApp* app, TeslaUiState state, bool clear_counters) {
    with_view_model(
        app->main_view,
        TeslaKeyCardViewModel * model,
        {
            model->state = state;
            if(clear_counters) {
                model->sessions = 0;
                model->authentications = 0;
                model->last_crypto_time_ms = 0;
            }
        },
        true);
}

static void tesla_key_card_handle_nfc_event(
    TeslaKeyCardApp* app,
    TeslaNfcEvent nfc_event,
    uint16_t crypto_time_ms) {
    char label[40];
    switch(nfc_event) {
    case TeslaNfcEventSelect:
        snprintf(label, sizeof(label), "SELECT ok (9000)");
        break;
    case TeslaNfcEventGetPublicKey:
        snprintf(label, sizeof(label), "GET_PUBLIC_KEY ok (9000)");
        break;
    case TeslaNfcEventAuthenticate:
        snprintf(label, sizeof(label), "AUTHENTICATE ok (9000) ecdh=%ums", (unsigned)crypto_time_ms);
        break;
    case TeslaNfcEventGetCardInfo:
        snprintf(label, sizeof(label), "GET_CARD_INFO ok (9000)");
        break;
    case TeslaNfcEventProtocolError:
        snprintf(label, sizeof(label), "PROTOCOL_ERR (SW != 9000)");
        break;
    case TeslaNfcEventTransmitError:
        snprintf(label, sizeof(label), "TRANSMIT_ERR");
        break;
    case TeslaNfcEventFieldOff:
        snprintf(label, sizeof(label), "field off");
        break;
    case TeslaNfcEventHalted:
        snprintf(label, sizeof(label), "halted");
        break;
    default:
        snprintf(label, sizeof(label), "event %d", (int)nfc_event);
        break;
    }
    tesla_key_card_debug_log(app, label);

    with_view_model(
        app->main_view,
        TeslaKeyCardViewModel * model,
        {
            if(nfc_event == TeslaNfcEventSelect) {
                model->sessions++;
                model->state = TeslaUiStatePresent;
            } else if(nfc_event == TeslaNfcEventGetPublicKey) {
                /* The vehicle read our public key, so it advanced past SELECT.
                 * Surfacing this on-screen shows how far the exchange gets when
                 * no USB log is attached (e.g. diagnosing at the vehicle). */
                model->state = TeslaUiStateReadingKey;
            } else if(nfc_event == TeslaNfcEventAuthenticate) {
                model->authentications++;
                model->last_crypto_time_ms = crypto_time_ms;
                model->state = TeslaUiStateAuthenticated;
            } else if(nfc_event == TeslaNfcEventFieldOff || nfc_event == TeslaNfcEventHalted) {
                model->state = TeslaUiStateReady;
            } else if(
                nfc_event == TeslaNfcEventTransmitError ||
                nfc_event == TeslaNfcEventProtocolError) {
                model->state = TeslaUiStateError;
            }
        },
        true);
}

static void tesla_key_card_clear_nfc_events(TeslaKeyCardApp* app) {
    TeslaKeyCardNfcEvent event;
    while(furi_message_queue_get(app->nfc_event_queue, &event, 0U) == FuriStatusOk) {
    }
}

static void tesla_key_card_tick_event_callback(void* context) {
    TeslaKeyCardApp* app = context;
    TeslaKeyCardNfcEvent event;

    for(size_t i = 0; i < TESLA_NFC_EVENTS_PER_TICK; ++i) {
        if(furi_message_queue_get(app->nfc_event_queue, &event, 0U) != FuriStatusOk) break;
        tesla_key_card_handle_nfc_event(app, event.event, event.crypto_time_ms);
    }
}

static bool tesla_key_card_prepare_identity(TeslaKeyCardApp* app) {
    const TeslaIdentityLoadResult load_result = tesla_identity_load(&app->identity);
    if(load_result == TeslaIdentityLoadOk) {
        return tesla_crypto_set_private_key(app->crypto, app->identity.private_key);
    }
    if(load_result != TeslaIdentityLoadNotFound) return false;

    tesla_identity_generate_uid(app->identity.uid);
    if(!tesla_crypto_generate_private_key(app->crypto, app->identity.private_key)) return false;
    return tesla_identity_save(&app->identity);
}

static void tesla_key_card_update_nfc(TeslaKeyCardApp* app) {
    if(app->nfc) {
        tesla_nfc_free(app->nfc);
        app->nfc = NULL;
    }
    if(app->crypto) {
        app->nfc = tesla_nfc_alloc(app->crypto, app->identity.uid, tesla_key_card_nfc_event, app);
        if(!tesla_nfc_start(app->nfc)) {
            tesla_nfc_free(app->nfc);
            app->nfc = NULL;
        }
    }
}

static bool tesla_key_card_resume_nfc(TeslaKeyCardApp* app) {
    if(!app->nfc) return false;
    if(tesla_nfc_start(app->nfc)) return true;

    tesla_nfc_free(app->nfc);
    app->nfc = NULL;
    return false;
}

static bool tesla_key_card_reset_identity(TeslaKeyCardApp* app) {
    tesla_key_card_set_model(app, TeslaUiStateResetting, false);
    if(app->nfc) tesla_nfc_stop(app->nfc);
    tesla_key_card_clear_nfc_events(app);
    if(!tesla_identity_delete()) {
        tesla_key_card_resume_nfc(app);
        tesla_key_card_set_model(app, TeslaUiStateError, false);
        return false;
    }

    if(app->nfc) {
        tesla_nfc_free(app->nfc);
        app->nfc = NULL;
    }
    tesla_crypto_free(app->crypto);
    app->crypto = tesla_crypto_alloc();
    tesla_identity_clear(&app->identity);

    if(!app->crypto || !tesla_key_card_prepare_identity(app)) {
        tesla_key_card_set_model(app, TeslaUiStateError, true);
        return false;
    }

    tesla_key_card_update_nfc(app);
    with_view_model(
        app->main_view,
        TeslaKeyCardViewModel * model,
        {
            memcpy(model->uid, app->identity.uid, sizeof(model->uid));
            model->state = app->nfc ? TeslaUiStateReady : TeslaUiStateError;
            model->sessions = 0;
            model->authentications = 0;
            model->last_crypto_time_ms = 0;
        },
        true);
    return app->nfc != NULL;
}

static bool tesla_key_card_custom_event_callback(void* context, uint32_t event) {
    TeslaKeyCardApp* app = context;

    if(event == TESLA_APP_EVENT_RESET_REQUEST && app->screen == TeslaKeyCardScreenMain) {
        if(app->nfc) tesla_nfc_stop(app->nfc);
        tesla_key_card_clear_nfc_events(app);
        app->screen = TeslaKeyCardScreenReset;
        tesla_key_card_show_reset_dialog(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, 1U);
        return true;
    }

    if(event == TESLA_APP_EVENT_RESET_CANCEL && app->screen == TeslaKeyCardScreenReset) {
        app->screen = TeslaKeyCardScreenMain;
        const bool nfc_ready = tesla_key_card_resume_nfc(app);
        tesla_key_card_set_model(app, nfc_ready ? TeslaUiStateReady : TeslaUiStateError, false);
        view_dispatcher_switch_to_view(app->view_dispatcher, 0U);
        return true;
    }

    if(event == TESLA_APP_EVENT_RESET_CONFIRM && app->screen == TeslaKeyCardScreenReset) {
        app->screen = TeslaKeyCardScreenMain;
        tesla_key_card_reset_identity(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, 0U);
        return true;
    }

    return false;
}

static bool tesla_key_card_navigation_callback(void* context) {
    TeslaKeyCardApp* app = context;
    if(app->screen == TeslaKeyCardScreenReset) {
        view_dispatcher_send_custom_event(app->view_dispatcher, TESLA_APP_EVENT_RESET_CANCEL);
    } else {
        view_dispatcher_stop(app->view_dispatcher);
    }
    return true;
}

static TeslaKeyCardApp* tesla_key_card_app_alloc(void) {
    TeslaKeyCardApp* app = malloc(sizeof(TeslaKeyCardApp));
    memset(app, 0, sizeof(TeslaKeyCardApp));
    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    app->main_view = view_alloc();
    app->reset_dialog = dialog_ex_alloc();
    app->nfc_event_queue =
        furi_message_queue_alloc(TESLA_NFC_EVENT_QUEUE_SIZE, sizeof(TeslaKeyCardNfcEvent));
    app->screen = TeslaKeyCardScreenMain;

    app->storage = furi_record_open(RECORD_STORAGE);
    app->debug_log = storage_file_alloc(app->storage);
    if(!storage_file_open(app->debug_log, TESLA_DEBUG_LOG_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(app->debug_log);
        app->debug_log = NULL;
    }

    view_allocate_model(app->main_view, ViewModelTypeLocking, sizeof(TeslaKeyCardViewModel));
    view_set_draw_callback(app->main_view, tesla_key_card_draw_callback);
    view_set_input_callback(app->main_view, tesla_key_card_main_input_callback);
    view_set_context(app->main_view, app);

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_add_view(app->view_dispatcher, 0U, app->main_view);
    view_dispatcher_add_view(app->view_dispatcher, 1U, dialog_ex_get_view(app->reset_dialog));
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, tesla_key_card_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, tesla_key_card_navigation_callback);
    view_dispatcher_set_tick_event_callback(
        app->view_dispatcher, tesla_key_card_tick_event_callback, TESLA_UI_TICK_MS);
    return app;
}

static void tesla_key_card_app_free(TeslaKeyCardApp* app) {
    if(app->nfc) tesla_nfc_free(app->nfc);
    tesla_crypto_free(app->crypto);
    tesla_identity_clear(&app->identity);
    if(app->debug_log) {
        storage_file_close(app->debug_log);
        storage_file_free(app->debug_log);
    }
    furi_record_close(RECORD_STORAGE);
    furi_message_queue_free(app->nfc_event_queue);
    view_dispatcher_remove_view(app->view_dispatcher, 1U);
    view_dispatcher_remove_view(app->view_dispatcher, 0U);
    view_dispatcher_free(app->view_dispatcher);
    dialog_ex_free(app->reset_dialog);
    view_free(app->main_view);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t tesla_key_card_app(void* context) {
    UNUSED(context);
    TeslaKeyCardApp* app = tesla_key_card_app_alloc();
    app->crypto = tesla_crypto_alloc();

    TeslaUiState initial_state = TeslaUiStateError;
    if(app->crypto && tesla_key_card_prepare_identity(app)) {
        tesla_key_card_update_nfc(app);
        initial_state = app->nfc ? TeslaUiStateReady : TeslaUiStateError;
    }

    with_view_model(
        app->main_view,
        TeslaKeyCardViewModel * model,
        {
            memset(model, 0, sizeof(*model));
            model->state = initial_state;
            memcpy(model->uid, app->identity.uid, sizeof(model->uid));
        },
        true);

    char launch[48];
    snprintf(
        launch,
        sizeof(launch),
        "=== launch uid=%02X%02X%02X%02X nfc=%d ===",
        app->identity.uid[0],
        app->identity.uid[1],
        app->identity.uid[2],
        app->identity.uid[3],
        app->nfc ? 1 : 0);
    tesla_key_card_debug_log(app, launch);

    view_dispatcher_switch_to_view(app->view_dispatcher, 0U);
    view_dispatcher_run(app->view_dispatcher);
    tesla_key_card_app_free(app);
    return 0;
}
