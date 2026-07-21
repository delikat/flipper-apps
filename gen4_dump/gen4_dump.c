// SPDX-License-Identifier: GPL-3.0-or-later
//
// Gen4 UMC Dump app: UI + worker thread. Reads a Gen4 "Ultimate Magic Card"
// over its backdoor (0xCE) and saves the contents as a standard .nfc file. The
// blocking NFC work runs on a FuriThread so the GUI stays responsive; the worker
// reports progress and completion back through view-dispatcher custom events.

/**
 * @file gen4_dump.c
 * @brief Gen4/UMC backdoor dump app — UI + worker.
 */
#include "gen4_dump_poller.h"

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/popup.h>
#include <gui/modules/widget.h>
#include <gui/modules/text_input.h>
#include <gui/modules/byte_input.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <nfc/nfc.h>
#include <nfc/nfc_device.h>

#include <stdio.h>

#define GEN4_DUMP_WORKER_STACK_SIZE (4 * 1024)
#define GEN4_DUMP_SAVE_NAME_MAX     (48)
#define GEN4_DUMP_NFC_DIR           EXT_PATH("nfc")
#define GEN4_DUMP_NFC_EXTENSION     ".nfc"

typedef enum {
    Gen4DumpViewSubmenu,
    Gen4DumpViewPopup,
    Gen4DumpViewTextInput,
    Gen4DumpViewByteInput,
    Gen4DumpViewWidget,
} Gen4DumpViewId;

typedef enum {
    Gen4DumpMenuDump,
    Gen4DumpMenuPassword,
    Gen4DumpMenuAbout,
} Gen4DumpMenuIndex;

typedef enum {
    Gen4DumpCustomEventProgress,
    Gen4DumpCustomEventDone,
    Gen4DumpCustomEventBackToMenu,
} Gen4DumpCustomEvent;

typedef struct {
    Gui* gui;
    NotificationApp* notifications;
    Storage* storage;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    Popup* popup;
    Widget* widget;
    TextInput* text_input;
    ByteInput* byte_input;

    Nfc* nfc;
    Gen4Dump* dump;
    uint8_t password[GEN4_DUMP_PASSWORD_LEN];

    FuriThread* worker;
    volatile bool stop_requested;
    Gen4DumpViewId current_view;

    // Shared worker -> GUI state, read only after the matching custom event.
    volatile uint16_t progress_done;
    volatile uint16_t progress_total;
    Gen4DumpResult result;

    char save_name[GEN4_DUMP_SAVE_NAME_MAX];
    bool save_ok;
} Gen4DumpApp;

/* ------------------------------- Worker -------------------------------- */

static void gen4_dump_progress_cb(void* context, uint16_t done, uint16_t total) {
    Gen4DumpApp* app = context;
    app->progress_done = done;
    app->progress_total = total;
    view_dispatcher_send_custom_event(app->view_dispatcher, Gen4DumpCustomEventProgress);
}

static int32_t gen4_dump_worker(void* context) {
    Gen4DumpApp* app = context;

    gen4_dump_set_progress_callback(app->dump, gen4_dump_progress_cb, app);
    gen4_dump_set_stop_flag(app->dump, &app->stop_requested);

    app->result = gen4_dump_run(app->dump);

    view_dispatcher_send_custom_event(app->view_dispatcher, Gen4DumpCustomEventDone);
    return 0;
}

static void gen4_dump_worker_stop(Gen4DumpApp* app) {
    if(app->worker) {
        app->stop_requested = true;
        furi_thread_join(app->worker);
        furi_thread_free(app->worker);
        app->worker = NULL;
    }
}

static void gen4_dump_worker_start(Gen4DumpApp* app) {
    gen4_dump_worker_stop(app);
    app->stop_requested = false;
    app->worker =
        furi_thread_alloc_ex("Gen4DumpWorker", GEN4_DUMP_WORKER_STACK_SIZE, gen4_dump_worker, app);
    furi_thread_start(app->worker);
}

/* -------------------------------- Views -------------------------------- */

static void gen4_dump_show_menu(Gen4DumpApp* app) {
    app->current_view = Gen4DumpViewSubmenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, Gen4DumpViewSubmenu);
}

static void gen4_dump_start(Gen4DumpApp* app) {
    gen4_dump_set_password(app->dump, app->password);

    popup_reset(app->popup);
    popup_set_header(app->popup, "Reading", 64, 6, AlignCenter, AlignTop);
    popup_set_text(app->popup, "Hold card still\non the back...", 64, 30, AlignCenter, AlignTop);
    app->current_view = Gen4DumpViewPopup;
    view_dispatcher_switch_to_view(app->view_dispatcher, Gen4DumpViewPopup);

    notification_message(app->notifications, &sequence_blink_start_cyan);
    gen4_dump_worker_start(app);
}

static void gen4_dump_result_ok_button(GuiButtonType button, InputType type, void* context) {
    UNUSED(button);
    if(type != InputTypeShort) return;
    Gen4DumpApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, Gen4DumpCustomEventBackToMenu);
}

static void gen4_dump_show_widget_message(
    Gen4DumpApp* app,
    const char* title,
    const char* body) {
    widget_reset(app->widget);
    widget_add_string_element(app->widget, 64, 6, AlignCenter, AlignTop, FontPrimary, title);
    widget_add_text_box_element(
        app->widget, 0, 24, 128, 34, AlignCenter, AlignTop, body, false);
    widget_add_button_element(
        app->widget, GuiButtonTypeCenter, "OK", gen4_dump_result_ok_button, app);
    app->current_view = Gen4DumpViewWidget;
    view_dispatcher_switch_to_view(app->view_dispatcher, Gen4DumpViewWidget);
}

static void gen4_dump_save(Gen4DumpApp* app) {
    NfcDevice* device = gen4_dump_get_device(app->dump);
    app->save_ok = false;
    if(device != NULL) {
        storage_simply_mkdir(app->storage, GEN4_DUMP_NFC_DIR);
        FuriString* path = furi_string_alloc();
        furi_string_printf(
            path, "%s/%s%s", GEN4_DUMP_NFC_DIR, app->save_name, GEN4_DUMP_NFC_EXTENSION);
        app->save_ok = nfc_device_save(device, furi_string_get_cstr(path));
        furi_string_free(path);
    }

    notification_message(
        app->notifications, app->save_ok ? &sequence_success : &sequence_error);

    char body[128];
    if(app->save_ok) {
        const uint8_t* pwd = gen4_dump_get_password(app->dump);
        snprintf(
            body,
            sizeof(body),
            "%s, %u units\nPwd %02X %02X %02X %02X\nSaved as %s",
            gen4_dump_get_kind_name(app->dump),
            (unsigned)gen4_dump_get_unit_count(app->dump),
            pwd[0],
            pwd[1],
            pwd[2],
            pwd[3],
            app->save_name);
        gen4_dump_show_widget_message(app, "Saved!", body);
    } else {
        gen4_dump_show_widget_message(app, "Save failed", "Could not write the\n.nfc file.");
    }
}

static void gen4_dump_save_name_callback(void* context) {
    Gen4DumpApp* app = context;
    gen4_dump_save(app);
}

static void gen4_dump_show_save_name(Gen4DumpApp* app) {
    // Propose a default filename derived from the card kind, spaces -> '_'.
    snprintf(app->save_name, sizeof(app->save_name), "%s", gen4_dump_get_kind_name(app->dump));
    for(size_t i = 0; app->save_name[i] != '\0'; i++) {
        if(app->save_name[i] == ' ') app->save_name[i] = '_';
    }

    text_input_reset(app->text_input);
    text_input_set_header_text(app->text_input, "Name the dump");
    text_input_set_result_callback(
        app->text_input,
        gen4_dump_save_name_callback,
        app,
        app->save_name,
        sizeof(app->save_name),
        false);

    app->current_view = Gen4DumpViewTextInput;
    view_dispatcher_switch_to_view(app->view_dispatcher, Gen4DumpViewTextInput);
}

static void gen4_dump_show_result(Gen4DumpApp* app) {
    notification_message(app->notifications, &sequence_blink_stop);

    switch(app->result) {
    case Gen4DumpResultOk:
        notification_message(app->notifications, &sequence_success);
        gen4_dump_show_save_name(app);
        return;
    case Gen4DumpResultNoCard:
        notification_message(app->notifications, &sequence_error);
        gen4_dump_show_widget_message(
            app, "No card", "No card found or it was\nremoved. Try again.");
        return;
    case Gen4DumpResultNotGen4:
        notification_message(app->notifications, &sequence_error);
        gen4_dump_show_widget_message(
            app, "Not a Gen4 card", "Backdoor did not answer.\nNot a UMC, or a custom\npassword is set.");
        return;
    case Gen4DumpResultUnsupported:
        notification_message(app->notifications, &sequence_error);
        gen4_dump_show_widget_message(
            app, "Unsupported", "Gen4 card, but its type\nis not supported yet.");
        return;
    case Gen4DumpResultReadFailed:
        notification_message(app->notifications, &sequence_error);
        gen4_dump_show_widget_message(
            app, "Read failed", "A block could not be\nread. Card removed?");
        return;
    case Gen4DumpResultCanceled:
    default:
        gen4_dump_show_widget_message(app, "Canceled", "Reading stopped.");
        return;
    }
}

static void gen4_dump_password_callback(void* context) {
    Gen4DumpApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, Gen4DumpCustomEventBackToMenu);
}

static void gen4_dump_show_password(Gen4DumpApp* app) {
    byte_input_set_header_text(app->byte_input, "Backdoor password (4 bytes)");
    byte_input_set_result_callback(
        app->byte_input,
        gen4_dump_password_callback,
        NULL,
        app,
        app->password,
        GEN4_DUMP_PASSWORD_LEN);
    app->current_view = Gen4DumpViewByteInput;
    view_dispatcher_switch_to_view(app->view_dispatcher, Gen4DumpViewByteInput);
}

static void gen4_dump_show_about(Gen4DumpApp* app) {
    widget_reset(app->widget);
    widget_add_text_scroll_element(
        app->widget,
        0,
        0,
        128,
        64,
        "\e#Gen4 UMC Dump\e#\n"
        "Reads a Gen4 'Ultimate\n"
        "Magic Card' over its\n"
        "backdoor (0xCE) and saves\n"
        "it as a .nfc file.\n \n"
        "Dumps MIFARE Classic via\n"
        "the backdoor (keys and\n"
        "all), and Ultralight/NTAG\n"
        "by reading the emulated\n"
        "tag.\n \n"
        "Auto-tries common backdoor\n"
        "passwords and shows the\n"
        "one that worked. Set a\n"
        "custom one to try first.");
    app->current_view = Gen4DumpViewWidget;
    view_dispatcher_switch_to_view(app->view_dispatcher, Gen4DumpViewWidget);
}

/* ------------------------------ Callbacks ------------------------------ */

static void gen4_dump_submenu_callback(void* context, uint32_t index) {
    Gen4DumpApp* app = context;
    if(index == Gen4DumpMenuDump) {
        gen4_dump_start(app);
    } else if(index == Gen4DumpMenuPassword) {
        gen4_dump_show_password(app);
    } else if(index == Gen4DumpMenuAbout) {
        gen4_dump_show_about(app);
    }
}

static bool gen4_dump_custom_event_callback(void* context, uint32_t event) {
    Gen4DumpApp* app = context;
    switch(event) {
    case Gen4DumpCustomEventProgress: {
        char buf[24];
        snprintf(buf, sizeof(buf), "%u / %u", app->progress_done, app->progress_total);
        popup_set_text(app->popup, buf, 64, 30, AlignCenter, AlignTop);
        return true;
    }
    case Gen4DumpCustomEventDone:
        gen4_dump_show_result(app);
        return true;
    case Gen4DumpCustomEventBackToMenu:
        gen4_dump_show_menu(app);
        return true;
    default:
        return false;
    }
}

static bool gen4_dump_navigation_callback(void* context) {
    Gen4DumpApp* app = context;
    switch(app->current_view) {
    case Gen4DumpViewPopup:
        // Reading in progress: request cancel, keep the popup until the worker
        // acknowledges with a Done event.
        app->stop_requested = true;
        return true;
    case Gen4DumpViewTextInput:
    case Gen4DumpViewByteInput:
    case Gen4DumpViewWidget:
        gen4_dump_show_menu(app);
        return true;
    case Gen4DumpViewSubmenu:
    default:
        return false;
    }
}

/* --------------------------- App lifecycle ----------------------------- */

static Gen4DumpApp* gen4_dump_app_alloc(void) {
    Gen4DumpApp* app = malloc(sizeof(Gen4DumpApp));
    memset(app, 0, sizeof(Gen4DumpApp));

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);

    app->nfc = nfc_alloc();
    app->dump = gen4_dump_alloc(app->nfc);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, gen4_dump_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, gen4_dump_navigation_callback);

    app->submenu = submenu_alloc();
    submenu_set_header(app->submenu, "Gen4 UMC Dump");
    submenu_add_item(
        app->submenu, "Dump card to file", Gen4DumpMenuDump, gen4_dump_submenu_callback, app);
    submenu_add_item(
        app->submenu, "Backdoor password", Gen4DumpMenuPassword, gen4_dump_submenu_callback, app);
    submenu_add_item(app->submenu, "About", Gen4DumpMenuAbout, gen4_dump_submenu_callback, app);

    app->popup = popup_alloc();
    app->widget = widget_alloc();
    app->text_input = text_input_alloc();
    app->byte_input = byte_input_alloc();

    view_dispatcher_add_view(
        app->view_dispatcher, Gen4DumpViewSubmenu, submenu_get_view(app->submenu));
    view_dispatcher_add_view(app->view_dispatcher, Gen4DumpViewPopup, popup_get_view(app->popup));
    view_dispatcher_add_view(
        app->view_dispatcher, Gen4DumpViewTextInput, text_input_get_view(app->text_input));
    view_dispatcher_add_view(
        app->view_dispatcher, Gen4DumpViewByteInput, byte_input_get_view(app->byte_input));
    view_dispatcher_add_view(
        app->view_dispatcher, Gen4DumpViewWidget, widget_get_view(app->widget));

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    return app;
}

static void gen4_dump_app_free(Gen4DumpApp* app) {
    gen4_dump_worker_stop(app);

    notification_message(app->notifications, &sequence_blink_stop);

    view_dispatcher_remove_view(app->view_dispatcher, Gen4DumpViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, Gen4DumpViewPopup);
    view_dispatcher_remove_view(app->view_dispatcher, Gen4DumpViewTextInput);
    view_dispatcher_remove_view(app->view_dispatcher, Gen4DumpViewByteInput);
    view_dispatcher_remove_view(app->view_dispatcher, Gen4DumpViewWidget);

    submenu_free(app->submenu);
    popup_free(app->popup);
    widget_free(app->widget);
    text_input_free(app->text_input);
    byte_input_free(app->byte_input);
    view_dispatcher_free(app->view_dispatcher);

    gen4_dump_free(app->dump);
    nfc_free(app->nfc);

    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);

    free(app);
}

int32_t gen4_dump_app(void* p) {
    UNUSED(p);
    Gen4DumpApp* app = gen4_dump_app_alloc();

    gen4_dump_show_menu(app);
    view_dispatcher_run(app->view_dispatcher);

    gen4_dump_app_free(app);
    return 0;
}
