/**
 * @file mfc_ndef_format.c
 * @brief MFC NDEF Format app: UI + worker thread.
 *
 * Formats a MIFARE Classic 1K into an empty NDEF (NFC) tag, mirroring the
 * Proxmark3 `hf mf ndefformat` command. The blocking NFC work runs on a
 * FuriThread so the GUI stays responsive; the worker reports progress and
 * completion back to the view dispatcher via custom events.
 */
#include "ndef_format.h"

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/popup.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>

#include <stdio.h>

#define MFC_NDEF_WORKER_STACK_SIZE (4 * 1024)

typedef enum {
    MfcNdefViewSubmenu,
    MfcNdefViewPopup,
    MfcNdefViewWidget,
} MfcNdefViewId;

typedef enum {
    MfcNdefMenuFormat,
    MfcNdefMenuAbout,
} MfcNdefMenuIndex;

typedef enum {
    MfcNdefCustomEventProgress,
    MfcNdefCustomEventDone,
    MfcNdefCustomEventBackToMenu,
} MfcNdefCustomEvent;

typedef struct {
    Gui* gui;
    NotificationApp* notifications;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    Popup* popup;
    Widget* widget;

    FuriThread* worker;
    volatile bool stop_requested;
    MfcNdefViewId current_view;

    // Shared worker -> GUI state, read only after the matching custom event.
    volatile uint8_t progress_block;
    MfcNdefResult result;
    uint8_t fail_block;
} MfcNdefApp;

/* ------------------------------- Worker -------------------------------- */

static void mfc_ndef_progress_cb(void* context, uint8_t block) {
    MfcNdefApp* app = context;
    app->progress_block = block;
    view_dispatcher_send_custom_event(app->view_dispatcher, MfcNdefCustomEventProgress);
}

static int32_t mfc_ndef_worker(void* context) {
    MfcNdefApp* app = context;

    Nfc* nfc = nfc_alloc();
    MfcNdefFormat fmt = {
        .nfc = nfc,
        .progress_cb = mfc_ndef_progress_cb,
        .progress_context = app,
        .stop = &app->stop_requested,
        .fail_block = 0,
    };

    MfcNdefResult result = mfc_ndef_format_run(&fmt);

    nfc_free(nfc);

    app->result = result;
    app->fail_block = fmt.fail_block;
    view_dispatcher_send_custom_event(app->view_dispatcher, MfcNdefCustomEventDone);
    return 0;
}

static void mfc_ndef_worker_stop(MfcNdefApp* app) {
    if(app->worker) {
        app->stop_requested = true;
        furi_thread_join(app->worker);
        furi_thread_free(app->worker);
        app->worker = NULL;
    }
}

static void mfc_ndef_worker_start(MfcNdefApp* app) {
    // A previous run should already be finished; join it just in case.
    mfc_ndef_worker_stop(app);
    app->stop_requested = false;
    app->worker =
        furi_thread_alloc_ex("MfcNdefWorker", MFC_NDEF_WORKER_STACK_SIZE, mfc_ndef_worker, app);
    furi_thread_start(app->worker);
}

/* -------------------------------- Views -------------------------------- */

static void mfc_ndef_show_menu(MfcNdefApp* app) {
    app->current_view = MfcNdefViewSubmenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, MfcNdefViewSubmenu);
}

static void mfc_ndef_start_format(MfcNdefApp* app) {
    popup_reset(app->popup);
    popup_set_header(app->popup, "Formatting", 64, 6, AlignCenter, AlignTop);
    popup_set_text(
        app->popup, "Hold card still\non the back...", 64, 30, AlignCenter, AlignTop);
    app->current_view = MfcNdefViewPopup;
    view_dispatcher_switch_to_view(app->view_dispatcher, MfcNdefViewPopup);

    notification_message(app->notifications, &sequence_blink_start_cyan);
    mfc_ndef_worker_start(app);
}

static void mfc_ndef_result_ok_button(GuiButtonType button, InputType type, void* context) {
    UNUSED(button);
    if(type != InputTypeShort) return;
    MfcNdefApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, MfcNdefCustomEventBackToMenu);
}

static void mfc_ndef_show_result(MfcNdefApp* app) {
    notification_message(app->notifications, &sequence_blink_stop);

    widget_reset(app->widget);
    char detail[64];

    switch(app->result) {
    case MfcNdefResultOk:
        notification_message(app->notifications, &sequence_success);
        widget_add_string_element(
            app->widget, 64, 6, AlignCenter, AlignTop, FontPrimary, "Success!");
        widget_add_text_box_element(
            app->widget,
            0,
            24,
            128,
            34,
            AlignCenter,
            AlignTop,
            "Card formatted as an\nempty NDEF (NFC) tag.",
            false);
        break;
    case MfcNdefResultNoCard:
        notification_message(app->notifications, &sequence_error);
        widget_add_string_element(
            app->widget, 64, 6, AlignCenter, AlignTop, FontPrimary, "No card");
        widget_add_text_box_element(
            app->widget,
            0,
            24,
            128,
            34,
            AlignCenter,
            AlignTop,
            "Card not found or was\nremoved. Try again.",
            false);
        break;
    case MfcNdefResultNotClassic1k:
        notification_message(app->notifications, &sequence_error);
        widget_add_string_element(
            app->widget, 64, 6, AlignCenter, AlignTop, FontPrimary, "Unsupported");
        widget_add_text_box_element(
            app->widget,
            0,
            24,
            128,
            34,
            AlignCenter,
            AlignTop,
            "Not a MIFARE Classic 1K.\nOnly 1K is supported.",
            false);
        break;
    case MfcNdefResultWriteFailed:
        notification_message(app->notifications, &sequence_error);
        widget_add_string_element(
            app->widget, 64, 6, AlignCenter, AlignTop, FontPrimary, "Write failed");
        snprintf(
            detail,
            sizeof(detail),
            "Block %u could not be\nwritten. Unknown key\nor protected card.",
            app->fail_block);
        widget_add_text_box_element(
            app->widget, 0, 24, 128, 34, AlignCenter, AlignTop, detail, false);
        break;
    case MfcNdefResultCanceled:
    default:
        widget_add_string_element(
            app->widget, 64, 6, AlignCenter, AlignTop, FontPrimary, "Canceled");
        widget_add_text_box_element(
            app->widget,
            0,
            24,
            128,
            34,
            AlignCenter,
            AlignTop,
            "Formatting stopped.\nThe card may be\npartially written.",
            false);
        break;
    }

    widget_add_button_element(
        app->widget, GuiButtonTypeCenter, "OK", mfc_ndef_result_ok_button, app);

    app->current_view = MfcNdefViewWidget;
    view_dispatcher_switch_to_view(app->view_dispatcher, MfcNdefViewWidget);
}

static void mfc_ndef_show_about(MfcNdefApp* app) {
    widget_reset(app->widget);
    widget_add_text_scroll_element(
        app->widget,
        0,
        0,
        128,
        64,
        "\e#MFC NDEF Format\e#\n"
        "Formats a MIFARE Classic\n"
        "1K into an empty NDEF\n"
        "(NFC) tag.\n \n"
        "Writes the MAD and an\n"
        "empty NDEF record using\n"
        "default, MAD and NDEF\n"
        "keys, like Proxmark's\n"
        "'hf mf ndefformat'.\n \n"
        "Use on blank or already\n"
        "NDEF-formatted 1K cards.");
    app->current_view = MfcNdefViewWidget;
    view_dispatcher_switch_to_view(app->view_dispatcher, MfcNdefViewWidget);
}

/* ------------------------------ Callbacks ------------------------------ */

static void mfc_ndef_submenu_callback(void* context, uint32_t index) {
    MfcNdefApp* app = context;
    if(index == MfcNdefMenuFormat) {
        mfc_ndef_start_format(app);
    } else if(index == MfcNdefMenuAbout) {
        mfc_ndef_show_about(app);
    }
}

static bool mfc_ndef_custom_event_callback(void* context, uint32_t event) {
    MfcNdefApp* app = context;
    switch(event) {
    case MfcNdefCustomEventProgress: {
        char buf[24];
        // Block 0 is skipped, so 63 blocks are actually written.
        snprintf(buf, sizeof(buf), "Block %u / 63", app->progress_block);
        popup_set_text(app->popup, buf, 64, 30, AlignCenter, AlignTop);
        return true;
    }
    case MfcNdefCustomEventDone:
        mfc_ndef_show_result(app);
        return true;
    case MfcNdefCustomEventBackToMenu:
        mfc_ndef_show_menu(app);
        return true;
    default:
        return false;
    }
}

static bool mfc_ndef_navigation_callback(void* context) {
    MfcNdefApp* app = context;
    switch(app->current_view) {
    case MfcNdefViewPopup:
        // Formatting in progress: request cancel, keep showing the popup until
        // the worker acknowledges with a Done event.
        app->stop_requested = true;
        return true;
    case MfcNdefViewWidget:
        mfc_ndef_show_menu(app);
        return true;
    case MfcNdefViewSubmenu:
    default:
        // Not consumed: let the dispatcher exit the app.
        return false;
    }
}

/* --------------------------- App lifecycle ----------------------------- */

static MfcNdefApp* mfc_ndef_app_alloc(void) {
    MfcNdefApp* app = malloc(sizeof(MfcNdefApp));
    memset(app, 0, sizeof(MfcNdefApp));

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, mfc_ndef_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, mfc_ndef_navigation_callback);

    app->submenu = submenu_alloc();
    submenu_set_header(app->submenu, "MFC NDEF Format");
    submenu_add_item(
        app->submenu, "Format 1K as NDEF", MfcNdefMenuFormat, mfc_ndef_submenu_callback, app);
    submenu_add_item(app->submenu, "About", MfcNdefMenuAbout, mfc_ndef_submenu_callback, app);

    app->popup = popup_alloc();
    app->widget = widget_alloc();

    view_dispatcher_add_view(
        app->view_dispatcher, MfcNdefViewSubmenu, submenu_get_view(app->submenu));
    view_dispatcher_add_view(app->view_dispatcher, MfcNdefViewPopup, popup_get_view(app->popup));
    view_dispatcher_add_view(
        app->view_dispatcher, MfcNdefViewWidget, widget_get_view(app->widget));

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    return app;
}

static void mfc_ndef_app_free(MfcNdefApp* app) {
    mfc_ndef_worker_stop(app);

    notification_message(app->notifications, &sequence_blink_stop);

    view_dispatcher_remove_view(app->view_dispatcher, MfcNdefViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, MfcNdefViewPopup);
    view_dispatcher_remove_view(app->view_dispatcher, MfcNdefViewWidget);

    submenu_free(app->submenu);
    popup_free(app->popup);
    widget_free(app->widget);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);

    free(app);
}

int32_t mfc_ndef_format_app(void* p) {
    UNUSED(p);
    MfcNdefApp* app = mfc_ndef_app_alloc();

    mfc_ndef_show_menu(app);
    view_dispatcher_run(app->view_dispatcher);

    mfc_ndef_app_free(app);
    return 0;
}
