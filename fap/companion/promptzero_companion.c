/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * promptzero_companion.c — on-device status renderer for the
 * PromptZero agent. Reads a small JSON status file the host writes
 * to SD and paints the current event on the Flipper OLED so the
 * operator sees what the agent is doing at a glance.
 *
 * Wire format (matches host-side internal/flipper/companion):
 *   {"v":1,"t":"busy","label":"subghz_tx","detail":"433.92 MHz",
 *    "risk":"high","ts":1714060801}
 *
 * Optional integration: nothing breaks if the file is absent or
 * the host isn't running — the screen shows "no events yet" until
 * the first push lands.
 *
 * Threading:
 *   The main thread owns ALL storage I/O. The periodic timer just
 *   enqueues an EventTick onto the event queue so the main loop
 *   knows it's time to poll. Doing storage I/O directly in a
 *   timer callback is the textbook cause of MPU faults on Flipper
 *   — the timer service runs on a small dedicated stack that the
 *   storage call chain can blow.
 */

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <stdlib.h>
#include <string.h>

#define COMPANION_STATUS_PATH   "/ext/apps_data/promptzero_companion/status.json"
#define COMPANION_RESPONSE_PATH "/ext/apps_data/promptzero_companion/response.json"
#define COMPANION_SETTINGS_PATH "/ext/apps_data/promptzero_companion/settings.json"
#define COMPANION_RESPONSE_DIR  "/ext/apps_data/promptzero_companion"
#define COMPANION_POLL_MS       250
#define COMPANION_MAX_LABEL     24
#define COMPANION_MAX_DETAIL    33
#define COMPANION_MAX_RISK      10
#define COMPANION_MAX_ID        20
#define COMPANION_READ_BUF      512

/* Wire version this FAP understands. Events with v > this get a warning. */
#define WIRE_VERSION 1

/* Stale threshold: if no fresh event for this many ticks, show "(stale)". */
#define STALE_TICKS furi_ms_to_ticks(5000)

/* Risk badge dimensions at bottom-right of body. */
#define BADGE_X      88
#define BADGE_Y      44
#define BADGE_W      38
#define BADGE_H      11
#define BADGE_MAX_CH  8

/* Marquee scroll: pixels per second at 4 FPS effective = 3px per draw tick. */
#define MARQUEE_PX_PER_TICK 2

/* History ring buffer capacity. */
#define HISTORY_CAP 10

typedef enum {
    EventNone,
    EventIdle,
    EventBusy,
    EventConfirm,
    EventDone,
    /* Internal pseudo-event: host sent a wire version we can't parse. */
    EventVersionMismatch,
} CompanionEventType;

typedef struct {
    CompanionEventType type;
    char label[COMPANION_MAX_LABEL];
    char detail[COMPANION_MAX_DETAIL];
    char risk[COMPANION_MAX_RISK];
    char id[COMPANION_MAX_ID];
    bool ok;       /* meaningful only when type == EventDone */
    int  wire_ver; /* v field; stored so draw can show "host v%d > FAP v%d" */
} CompanionEvent;

/* The two kinds of work that drive the main loop. Inputs come from
 * the GUI's input service; ticks come from a periodic timer. */
typedef enum {
    AppEventInput,
    AppEventTick,
} AppEventType;

typedef struct {
    AppEventType type;
    InputEvent input;
} AppEvent;

/* Active view. */
typedef enum {
    ViewStatus,
    ViewSettings,
    ViewHistory,
} ViewType;

/* Poll-rate options in ms. */
static const uint32_t POLL_RATE_VALUES[] = {250, 500, 1000};
#define POLL_RATE_COUNT 3

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    Storage* storage;
    FuriMessageQueue* events;
    FuriMutex* mutex;
    FuriTimer* poll_timer;

    CompanionEvent ev;
    bool exit;

    /* C2: set after write_response; cleared when a non-confirm event arrives */
    bool waiting_ack;

    /* C3: tick of last poll that returned a fresh (changed) event */
    uint32_t last_fresh_tick;
    bool had_any_event; /* false until the first event ever arrives */

    /* C4: last-seen file size; skip re-read when unchanged */
    uint64_t last_poll_size;

    /* S2: tick when the current busy event arrived */
    uint32_t busy_start_tick;

    /* C5 / S1: runtime toggles, default on */
    bool vibrate_enabled;
    bool sound_enabled;

    /* S3: marquee pixel offset for label / detail */
    int marquee_offset;
    uint32_t last_marquee_tick;

    /* View state */
    ViewType current_view;

    /* Settings view: which row is selected (0=vibrate, 1=sound, 2=poll_rate) */
    int settings_row;

    /* Poll rate index into POLL_RATE_VALUES */
    int poll_rate_idx;

    /* History ring buffer */
    CompanionEvent history[HISTORY_CAP];
    int history_head;   /* next write position */
    int history_count;  /* number of valid entries, 0..HISTORY_CAP */
    int history_scroll; /* top visible row in history view */
} CompanionApp;

/* --- tiny JSON-ish parser ------------------------------------------------ */

static const char* find_field(const char* json, const char* key) {
    char needle[16];
    int n = snprintf(needle, sizeof(needle), "\"%s\":", key);
    if(n < 0 || n >= (int)sizeof(needle)) return NULL;
    return strstr(json, needle);
}

static bool extract_string(const char* json, const char* key, char* out, size_t cap) {
    out[0] = '\0';
    const char* p = find_field(json, key);
    if(!p) return false;
    p += strlen(key) + 3;
    while(*p == ' ') p++;
    if(*p != '"') return false;
    p++;
    size_t i = 0;
    while(*p && *p != '"' && i + 1 < cap) {
        if(*p == '\\' && *(p + 1)) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return true;
}

static bool extract_bool(const char* json, const char* key, bool* out) {
    const char* p = find_field(json, key);
    if(!p) return false;
    p += strlen(key) + 3;
    while(*p == ' ') p++;
    if(strncmp(p, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if(strncmp(p, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

/* Returns the integer value of a numeric JSON field, or -1 if absent. */
static int extract_int(const char* json, const char* key) {
    const char* p = find_field(json, key);
    if(!p) return -1;
    p += strlen(key) + 3;
    while(*p == ' ') p++;
    if(*p < '0' || *p > '9') return -1;
    int val = 0;
    while(*p >= '0' && *p <= '9') val = val * 10 + (*p++ - '0');
    return val;
}

static CompanionEventType parse_type(const char* json) {
    char buf[12];
    if(!extract_string(json, "t", buf, sizeof(buf))) return EventNone;
    if(strcmp(buf, "idle") == 0) return EventIdle;
    if(strcmp(buf, "busy") == 0) return EventBusy;
    if(strcmp(buf, "confirm") == 0) return EventConfirm;
    if(strcmp(buf, "done") == 0) return EventDone;
    return EventNone;
}

/* --- settings persistence ----------------------------------------------- */

static void load_settings(CompanionApp* app) {
    File* f = storage_file_alloc(app->storage);
    if(!storage_file_open(f, COMPANION_SETTINGS_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(f);
        /* Defaults already set in app struct init. */
        return;
    }
    char buf[80];
    uint16_t n = storage_file_read(f, buf, sizeof(buf) - 1);
    storage_file_close(f);
    storage_file_free(f);
    if(n == 0) return;
    buf[n] = '\0';

    bool tmp;
    if(extract_bool(buf, "vibrate", &tmp)) app->vibrate_enabled = tmp;
    if(extract_bool(buf, "sound", &tmp)) app->sound_enabled = tmp;
    int pr = extract_int(buf, "poll_rate");
    if(pr > 0) {
        for(int i = 0; i < POLL_RATE_COUNT; i++) {
            if((int)POLL_RATE_VALUES[i] == pr) {
                app->poll_rate_idx = i;
                break;
            }
        }
    }
}

static void save_settings(CompanionApp* app) {
    storage_simply_mkdir(app->storage, COMPANION_RESPONSE_DIR);
    File* f = storage_file_alloc(app->storage);
    if(!storage_file_open(f, COMPANION_SETTINGS_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(f);
        return;
    }
    char body[80];
    int n = snprintf(
        body,
        sizeof(body),
        "{\"vibrate\":%s,\"sound\":%s,\"poll_rate\":%lu}\n",
        app->vibrate_enabled ? "true" : "false",
        app->sound_enabled ? "true" : "false",
        (unsigned long)POLL_RATE_VALUES[app->poll_rate_idx]);
    if(n > 0 && n < (int)sizeof(body)) {
        storage_file_write(f, body, (uint16_t)n);
    }
    storage_file_close(f);
    storage_file_free(f);
}

/* --- history ring buffer ------------------------------------------------ */

static void history_push(CompanionApp* app, const CompanionEvent* ev) {
    app->history[app->history_head] = *ev;
    app->history_head = (app->history_head + 1) % HISTORY_CAP;
    if(app->history_count < HISTORY_CAP) app->history_count++;
}

/* Read entry at logical index i (0 = oldest, count-1 = newest). */
static const CompanionEvent* history_get(const CompanionApp* app, int i) {
    if(i < 0 || i >= app->history_count) return NULL;
    /* physical index: oldest entry is at (head - count + i) mod CAP */
    int phys = (app->history_head - app->history_count + i + HISTORY_CAP * 2) % HISTORY_CAP;
    return &app->history[phys];
}

/* --- file I/O (main thread only) ---------------------------------------- */

static void poll_status(CompanionApp* app) {
    /* C4: stat the file first; skip the full read if size is unchanged.
     * This halves SD I/O when the host is idle (no new events). */
    FileInfo fi;
    memset(&fi, 0, sizeof(fi));
    if(storage_common_stat(app->storage, COMPANION_STATUS_PATH, &fi) != FSE_OK) {
        return;
    }
    if(fi.size == 0) return;
    if(fi.size == app->last_poll_size) return; /* nothing new */
    app->last_poll_size = fi.size;

    File* f = storage_file_alloc(app->storage);
    if(!storage_file_open(f, COMPANION_STATUS_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(f);
        return;
    }

    /* The host writes one event per file overwrite, but some
     * firmware (notably Momentum's `storage write_chunk`) appends
     * to the existing file instead of truncating. Result: the
     * file may contain a sequence of newline-terminated events
     * and only the last one is current.
     *
     * Seek to the tail so the read window always covers the most
     * recent event regardless of accumulated history. Tolerates
     * unbounded file growth — a session that runs for hours stays
     * cheap to poll. */
    uint64_t fsize = storage_file_size(f);
    char buf[COMPANION_READ_BUF];
    const uint16_t cap = sizeof(buf) - 1;
    if(fsize > (uint64_t)cap) {
        storage_file_seek(f, (uint32_t)(fsize - (uint64_t)cap), true);
    }
    uint16_t n = storage_file_read(f, buf, cap);
    storage_file_close(f);
    storage_file_free(f);
    if(n == 0) return;
    buf[n] = '\0';
    /* Strip trailing newline so the last-line scan doesn't land on an empty suffix. */
    if(n > 0 && buf[n - 1] == '\n') {
        buf[n - 1] = '\0';
        n--;
    }

    /* Locate the start of the last complete event line. */
    const char* last = buf;
    for(size_t i = n; i > 0; i--) {
        if(buf[i - 1] == '\n') {
            last = &buf[i];
            break;
        }
    }

    /* C7: check wire version before attempting to parse the event. */
    int wire_ver = extract_int(last, "v");
    if(wire_ver > WIRE_VERSION) {
        CompanionEvent next;
        memset(&next, 0, sizeof(next));
        next.type = EventVersionMismatch;
        next.wire_ver = wire_ver;
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->ev = next;
        furi_mutex_release(app->mutex);
        view_port_update(app->view_port);
        return;
    }

    CompanionEvent next;
    memset(&next, 0, sizeof(next));
    next.wire_ver = (wire_ver > 0) ? wire_ver : 1;
    next.type = parse_type(last);
    if(next.type == EventNone) return;
    extract_string(last, "label", next.label, sizeof(next.label));
    extract_string(last, "detail", next.detail, sizeof(next.detail));
    extract_string(last, "risk", next.risk, sizeof(next.risk));
    if(next.type == EventConfirm) {
        extract_string(last, "id", next.id, sizeof(next.id));
    }
    if(next.type == EventDone) {
        next.ok = true;
        extract_bool(last, "ok", &next.ok);
    }

    bool changed = false;
    bool confirm_arrived = false;
    bool is_critical = false;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(memcmp(&next, &app->ev, sizeof(next)) != 0) {
        CompanionEventType prev_type = app->ev.type;
        app->ev = next;
        changed = true;

        /* Append to history ring buffer on every fresh (deduped) event. */
        history_push(app, &next);

        /* C3: record when we last saw a fresh event. */
        app->last_fresh_tick = furi_get_tick();
        app->had_any_event = true;

        /* C2: a fresh non-confirm event clears the waiting-ack flag. */
        if(next.type != EventConfirm) {
            app->waiting_ack = false;
        }

        /* S2: track when busy started for elapsed-time display. */
        if(next.type == EventBusy && prev_type != EventBusy) {
            app->busy_start_tick = furi_get_tick();
        }

        /* S3: reset marquee on any content change. */
        app->marquee_offset = 0;
        app->last_marquee_tick = furi_get_tick();

        if(next.type == EventConfirm && prev_type != EventConfirm) {
            confirm_arrived = true;
            is_critical = (strncmp(next.risk, "critical", 8) == 0);
        }
    }
    furi_mutex_release(app->mutex);

    if(changed) view_port_update(app->view_port);

    /* C5 / S1: alert bursts happen outside the mutex — no I/O inside.
     * furi_delay_ms is safe here because we're on the main app thread,
     * not a timer callback. The 250ms poll period is advisory. */
    if(confirm_arrived) {
        if(app->vibrate_enabled) {
            uint32_t ms = is_critical ? 400 : 200;
            furi_hal_vibro_on(true);
            furi_delay_ms(ms);
            furi_hal_vibro_on(false);
        }
        if(app->sound_enabled) {
            /* S1: short 440 Hz beep to attract operator attention. */
            if(furi_hal_speaker_acquire(500)) {
                furi_hal_speaker_start(440.0f, 0.5f);
                furi_delay_ms(100);
                furi_hal_speaker_stop();
                furi_hal_speaker_release();
            }
        }
    }
}

static void write_response(CompanionApp* app, const char* id, const char* decision) {
    if(!id || id[0] == '\0') return;
    storage_simply_mkdir(app->storage, COMPANION_RESPONSE_DIR);
    File* f = storage_file_alloc(app->storage);
    if(!storage_file_open(f, COMPANION_RESPONSE_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(f);
        return;
    }
    char body[96];
    int n = snprintf(body, sizeof(body), "{\"id\":\"%s\",\"decision\":\"%s\"}\n", id, decision);
    if(n > 0 && n < (int)sizeof(body)) {
        storage_file_write(f, body, (uint16_t)n);
    }
    storage_file_close(f);
    storage_file_free(f);
}

/* --- callbacks (post events; do NO work) -------------------------------- */

static void timer_callback(void* ctx) {
    CompanionApp* app = ctx;
    AppEvent ev = {.type = AppEventTick};
    /* Non-blocking put — if the queue is backed up just drop the tick. */
    furi_message_queue_put(app->events, &ev, 0);
}

static void input_callback(InputEvent* input_event, void* ctx) {
    CompanionApp* app = ctx;
    AppEvent ev = {.type = AppEventInput, .input = *input_event};
    furi_message_queue_put(app->events, &ev, FuriWaitForever);
}

/* --- rendering ---------------------------------------------------------- */

static const char* event_header(CompanionEventType t) {
    switch(t) {
    case EventIdle:            return "PromptZero  ready";
    case EventBusy:            return "working";
    case EventConfirm:         return "confirm";
    case EventDone:            return "done";
    case EventVersionMismatch: return "version mismatch";
    default:                   return "PromptZero";
    }
}

static const char* event_footer(CompanionEventType t, bool waiting_ack) {
    if(t == EventConfirm) {
        /* C2: show a different footer while waiting for the host to ack. */
        return waiting_ack ? "sent — waiting…" : "OK=yes  LEFT=no";
    }
    switch(t) {
    case EventBusy: return "BACK to leave";
    default:        return "BACK to exit";
    }
}

/* Draw the risk badge as an inverse-video block (C6).
 * Clips the risk string to BADGE_MAX_CH chars to keep it inside the box. */
static void draw_risk_badge(Canvas* canvas, const char* risk) {
    if(!risk || risk[0] == '\0') return;

    char clipped[BADGE_MAX_CH + 1];
    strncpy(clipped, risk, BADGE_MAX_CH);
    clipped[BADGE_MAX_CH] = '\0';

    /* Filled black rectangle. */
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, BADGE_X, BADGE_Y, BADGE_W, BADGE_H);

    /* White text on top. */
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, BADGE_X + 2, BADGE_Y + 9, clipped);

    /* Restore default drawing color. */
    canvas_set_color(canvas, ColorBlack);
}

/* S3: return a pointer into str offset by marquee_offset characters
 * (wraps around if offset >= strlen). If str fits in max_px, returns str
 * unchanged so short strings never scroll. Approx 6px per char for FontSecondary. */
static const char* marquee_str(const char* str, int offset, int max_px) {
    int len = (int)strlen(str);
    if(len == 0) return str;
    /* Approx char width in FontSecondary is 6px. */
    if(len * 6 <= max_px) return str;
    if(offset <= 0) return str;
    int idx = offset % len;
    return str + idx;
}

/* --- draw_status_view --------------------------------------------------- */

static void draw_status_view(Canvas* canvas, CompanionApp* app) {
    CompanionEvent ev;
    bool waiting_ack;
    bool had_any_event;
    uint32_t last_fresh_tick;
    uint32_t busy_start_tick;
    int marquee_offset;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    ev = app->ev;
    waiting_ack = app->waiting_ack;
    had_any_event = app->had_any_event;
    last_fresh_tick = app->last_fresh_tick;
    busy_start_tick = app->busy_start_tick;
    marquee_offset = app->marquee_offset;
    furi_mutex_release(app->mutex);

    canvas_set_font(canvas, FontPrimary);

    /* C7: version mismatch gets its own simple render. */
    if(ev.type == EventVersionMismatch) {
        canvas_draw_str(canvas, 2, 12, "! version mismatch");
        canvas_draw_line(canvas, 0, 15, 128, 15);
        canvas_set_font(canvas, FontSecondary);
        char line[48];
        snprintf(line, sizeof(line), "host wire v%d > FAP v%d", ev.wire_ver, WIRE_VERSION);
        canvas_draw_str(canvas, 2, 30, line);
        canvas_draw_str(canvas, 2, 42, "please update FAP");
        canvas_draw_str(canvas, 2, 63, "BACK to exit");
        return;
    }

    const char* glyph = "  ";
    switch(ev.type) {
    case EventIdle:    glyph = "o "; break;
    case EventBusy:    glyph = "> "; break;
    case EventConfirm: glyph = "! "; break;
    case EventDone:    glyph = ev.ok ? "v " : "x "; break;
    default:           glyph = "  "; break;
    }

    /* C3: stale suffix when no fresh event for >5s (and we've had at least one). */
    bool stale = had_any_event &&
                 ((furi_get_tick() - last_fresh_tick) > STALE_TICKS);

    /* S2: elapsed time suffix during Busy events. */
    char elapsed_buf[12] = {0};
    if(ev.type == EventBusy) {
        uint32_t elapsed_ms = furi_get_tick() - busy_start_tick; /* ticks == ms on Flipper */
        uint32_t secs = elapsed_ms / 1000;
        if(secs < 60) {
            snprintf(elapsed_buf, sizeof(elapsed_buf), " %lus", (unsigned long)secs);
        } else {
            snprintf(
                elapsed_buf,
                sizeof(elapsed_buf),
                " %lum%lus",
                (unsigned long)(secs / 60),
                (unsigned long)(secs % 60));
        }
    }

    char header[48];
    snprintf(
        header,
        sizeof(header),
        "%s%s%s%s",
        glyph,
        event_header(ev.type),
        elapsed_buf,
        stale ? " (stale)" : "");
    canvas_draw_str(canvas, 2, 12, header);
    canvas_draw_line(canvas, 0, 15, 128, 15);

    canvas_set_font(canvas, FontSecondary);
    if(ev.type == EventNone) {
        canvas_draw_str(canvas, 2, 30, "no events yet");
        canvas_draw_str(canvas, 2, 42, "host: start a session");
    } else {
        /* S3: marquee-scroll strings that are too wide for the display.
         * Available body width is ~126px; badge occupies right ~40px on
         * the detail row — use 84px for scrollable area there. */
        if(ev.label[0]) {
            canvas_draw_str(canvas, 2, 30, marquee_str(ev.label, marquee_offset, 124));
        }
        if(ev.detail[0]) {
            canvas_draw_str(canvas, 2, 42, marquee_str(ev.detail, marquee_offset, 84));
        }
        /* C6: risk badge (inverse-video) replaces the plain "risk: xxx" line. */
        if(ev.risk[0]) {
            draw_risk_badge(canvas, ev.risk);
        }
    }

    /* C1: hint during Confirm that short-press BACK is a no-op. */
    if(ev.type == EventConfirm && !waiting_ack) {
        canvas_draw_str(canvas, 2, 63, "long-press BACK to exit");
    } else {
        canvas_draw_str(canvas, 2, 63, event_footer(ev.type, waiting_ack));
    }
}

/* --- draw_settings_view ------------------------------------------------- */

/* Row definitions for the settings page. */
#define SETTINGS_ROW_VIBRATE   0
#define SETTINGS_ROW_SOUND     1
#define SETTINGS_ROW_POLL_RATE 2
#define SETTINGS_ROW_COUNT     3

/* Vertical layout: header at y=12, rows start at y=26, 12px apart. */
#define SETTINGS_ROW_Y0    26
#define SETTINGS_ROW_STEP  12

static void draw_settings_view(Canvas* canvas, CompanionApp* app) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, "Settings");
    canvas_draw_line(canvas, 0, 15, 128, 15);

    canvas_set_font(canvas, FontSecondary);

    const char* row_labels[SETTINGS_ROW_COUNT] = {"Vibration", "Sound", "Poll rate"};
    char row_vals[SETTINGS_ROW_COUNT][12];

    snprintf(row_vals[SETTINGS_ROW_VIBRATE], sizeof(row_vals[0]),
             "%s", app->vibrate_enabled ? "ON" : "OFF");
    snprintf(row_vals[SETTINGS_ROW_SOUND], sizeof(row_vals[1]),
             "%s", app->sound_enabled ? "ON" : "OFF");
    snprintf(row_vals[SETTINGS_ROW_POLL_RATE], sizeof(row_vals[2]),
             "%lums", (unsigned long)POLL_RATE_VALUES[app->poll_rate_idx]);

    for(int i = 0; i < SETTINGS_ROW_COUNT; i++) {
        int y = SETTINGS_ROW_Y0 + i * SETTINGS_ROW_STEP;
        if(i == app->settings_row) {
            /* Selection highlight: filled box, white text. */
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y - 9, 128, 11);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_set_color(canvas, ColorBlack);
        }
        /* Left: label; right-aligned: value at x=90. */
        canvas_draw_str(canvas, 2, y, row_labels[i]);
        canvas_draw_str(canvas, 90, y, row_vals[i]);
        canvas_set_color(canvas, ColorBlack);
    }

    canvas_draw_str(canvas, 2, 63, "OK=toggle  BACK=exit");
}

/* --- draw_history_view -------------------------------------------------- */

/* Rows visible on screen (below 15px header divider, 10px per row). */
#define HISTORY_VISIBLE 4
#define HISTORY_ROW_Y0  26
#define HISTORY_ROW_STEP 10

static const char* event_glyph(const CompanionEvent* ev) {
    switch(ev->type) {
    case EventIdle:    return "o";
    case EventBusy:    return ">";
    case EventConfirm: return "!";
    case EventDone:    return ev->ok ? "v" : "x";
    case EventVersionMismatch: return "?";
    default:           return " ";
    }
}

static const char* event_short_label(const CompanionEvent* ev) {
    /* Prefer label field; fall back to type name. */
    if(ev->label[0]) return ev->label;
    switch(ev->type) {
    case EventIdle:    return "idle";
    case EventBusy:    return "busy";
    case EventConfirm: return "confirm";
    case EventDone:    return ev->ok ? "done:ok" : "done:fail";
    case EventVersionMismatch: return "ver-mismatch";
    default:           return "—";
    }
}

static void draw_history_view(Canvas* canvas, CompanionApp* app) {
    canvas_set_font(canvas, FontPrimary);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    int count = app->history_count;
    furi_mutex_release(app->mutex);

    char header[32];
    snprintf(header, sizeof(header), "History (%d)", count);
    canvas_draw_str(canvas, 2, 12, header);
    canvas_draw_line(canvas, 0, 15, 128, 15);

    canvas_set_font(canvas, FontSecondary);

    if(count == 0) {
        canvas_draw_str(canvas, 2, 30, "no events yet");
        canvas_draw_str(canvas, 2, 63, "BACK=return");
        return;
    }

    /* Clamp scroll so we never show past the end. */
    int max_scroll = count - HISTORY_VISIBLE;
    if(max_scroll < 0) max_scroll = 0;
    if(app->history_scroll > max_scroll) app->history_scroll = max_scroll;

    for(int i = 0; i < HISTORY_VISIBLE; i++) {
        int idx = app->history_scroll + i;
        if(idx >= count) break;

        /* history_get(0) = oldest; we want to show newest first. */
        const CompanionEvent* ev_entry = history_get(app, count - 1 - idx);
        if(!ev_entry) break;

        int y = HISTORY_ROW_Y0 + i * HISTORY_ROW_STEP;
        char line[32];
        /* Format: "<glyph> <label>" truncated to fit display width ~21 chars. */
        snprintf(line, sizeof(line), "%s %s", event_glyph(ev_entry), event_short_label(ev_entry));
        canvas_draw_str(canvas, 2, y, line);
    }

    /* Scroll indicator: show position if list is longer than visible. */
    if(count > HISTORY_VISIBLE) {
        char pos[24];
        snprintf(pos, sizeof(pos), "%d/%d", app->history_scroll + 1, count);
        canvas_draw_str(canvas, 90, 63, pos);
    }
    canvas_draw_str(canvas, 2, 63, "BACK=return");
}

/* --- top-level draw dispatcher ------------------------------------------ */

static void draw_callback(Canvas* canvas, void* ctx) {
    CompanionApp* app = ctx;
    canvas_clear(canvas);
    switch(app->current_view) {
    case ViewSettings:
        draw_settings_view(canvas, app);
        break;
    case ViewHistory:
        draw_history_view(canvas, app);
        break;
    case ViewStatus:
    default:
        draw_status_view(canvas, app);
        break;
    }
}

/* --- input handlers ----------------------------------------------------- */

static void handle_input_settings(CompanionApp* app, const InputEvent* input) {
    if(input->key == InputKeyBack && input->type == InputTypeLong) {
        app->exit = true;
        return;
    }
    if(input->key == InputKeyBack && input->type == InputTypeShort) {
        app->current_view = ViewStatus;
        view_port_update(app->view_port);
        return;
    }
    if(input->type != InputTypeShort) return;

    if(input->key == InputKeyUp) {
        if(app->settings_row > 0) {
            app->settings_row--;
            view_port_update(app->view_port);
        }
        return;
    }
    if(input->key == InputKeyDown) {
        if(app->settings_row < SETTINGS_ROW_COUNT - 1) {
            app->settings_row++;
            view_port_update(app->view_port);
        }
        return;
    }
    if(input->key == InputKeyOk) {
        switch(app->settings_row) {
        case SETTINGS_ROW_VIBRATE:
            app->vibrate_enabled = !app->vibrate_enabled;
            break;
        case SETTINGS_ROW_SOUND:
            app->sound_enabled = !app->sound_enabled;
            break;
        case SETTINGS_ROW_POLL_RATE:
            app->poll_rate_idx = (app->poll_rate_idx + 1) % POLL_RATE_COUNT;
            /* Re-arm the timer with the new rate. */
            furi_timer_stop(app->poll_timer);
            furi_timer_start(
                app->poll_timer,
                furi_ms_to_ticks(POLL_RATE_VALUES[app->poll_rate_idx]));
            break;
        }
        save_settings(app);
        view_port_update(app->view_port);
        return;
    }
}

static void handle_input_history(CompanionApp* app, const InputEvent* input) {
    if(input->key == InputKeyBack && input->type == InputTypeLong) {
        app->exit = true;
        return;
    }
    if(input->key == InputKeyBack && input->type == InputTypeShort) {
        app->current_view = ViewStatus;
        view_port_update(app->view_port);
        return;
    }
    if(input->type != InputTypeShort) return;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    int count = app->history_count;
    furi_mutex_release(app->mutex);

    if(input->key == InputKeyUp) {
        if(app->history_scroll > 0) {
            app->history_scroll--;
            view_port_update(app->view_port);
        }
        return;
    }
    if(input->key == InputKeyDown) {
        int max_scroll = count - HISTORY_VISIBLE;
        if(max_scroll < 0) max_scroll = 0;
        if(app->history_scroll < max_scroll) {
            app->history_scroll++;
            view_port_update(app->view_port);
        }
        return;
    }
}

static void handle_input_status(CompanionApp* app, const InputEvent* input) {
    /* C1: long-press BACK exits from any state. */
    if(input->key == InputKeyBack && input->type == InputTypeLong) {
        app->exit = true;
        return;
    }

    /* C1: short-press BACK during Confirm is a no-op — the operator
     * must use long-press to avoid an accidental exit that leaves the
     * host hanging on a 5-minute idle timeout. */
    if(input->key == InputKeyBack && input->type == InputTypeShort) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        CompanionEventType t = app->ev.type;
        furi_mutex_release(app->mutex);
        if(t == EventConfirm) {
            /* The footer hint is already visible; nothing else to do. */
            return;
        }
        /* Outside Confirm, short BACK still exits so the app feels responsive. */
        app->exit = true;
        return;
    }

    /* UP long-press: enter Settings view. */
    if(input->key == InputKeyUp && input->type == InputTypeLong) {
        app->settings_row = 0;
        app->current_view = ViewSettings;
        view_port_update(app->view_port);
        return;
    }

    if(input->type != InputTypeShort) return;

    /* DOWN short-press: enter History view. */
    if(input->key == InputKeyDown) {
        app->history_scroll = 0;
        app->current_view = ViewHistory;
        view_port_update(app->view_port);
        return;
    }

    /* C5: UP short toggles vibrate + sound (mirrors) and persists. */
    if(input->key == InputKeyUp) {
        app->vibrate_enabled = !app->vibrate_enabled;
        app->sound_enabled = app->vibrate_enabled;
        save_settings(app);
        view_port_update(app->view_port);
        return;
    }

    /* Snapshot of what's currently on screen so the answer is based on
     * what the operator was looking at when they pressed the button. */
    CompanionEvent ev;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    ev = app->ev;
    furi_mutex_release(app->mutex);

    if(ev.type == EventConfirm && ev.id[0] != '\0') {
        const char* decision = NULL;
        if(input->key == InputKeyOk) {
            decision = "approve";
        } else if(input->key == InputKeyLeft) {
            decision = "deny";
        }
        if(decision) {
            write_response(app, ev.id, decision);
            /* C2: immediately show "sent — waiting…" so the operator
             * knows the press registered without waiting for the host
             * to acknowledge and push a new event. */
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->waiting_ack = true;
            furi_mutex_release(app->mutex);
            view_port_update(app->view_port);
        }
    }
}

/* --- top-level input dispatcher ----------------------------------------- */

static void handle_input(CompanionApp* app, const InputEvent* input) {
    switch(app->current_view) {
    case ViewSettings:
        handle_input_settings(app, input);
        break;
    case ViewHistory:
        handle_input_history(app, input);
        break;
    case ViewStatus:
    default:
        handle_input_status(app, input);
        break;
    }
}

/* --- main loop ---------------------------------------------------------- */

int32_t promptzero_companion_app(void* p) {
    UNUSED(p);

    CompanionApp* app = malloc(sizeof(CompanionApp));
    if(!app) return -1;
    memset(app, 0, sizeof(*app));

    app->vibrate_enabled = true;
    app->sound_enabled = true;
    app->poll_rate_idx = 0; /* default: 250ms */
    app->current_view = ViewStatus;

    app->gui = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->events = furi_message_queue_alloc(16, sizeof(AppEvent));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->view_port = view_port_alloc();
    app->ev.type = EventNone;

    load_settings(app);

    view_port_draw_callback_set(app->view_port, draw_callback, app);
    view_port_input_callback_set(app->view_port, input_callback, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    /* One eager poll so the screen lands on the latest state immediately. */
    poll_status(app);

    app->poll_timer = furi_timer_alloc(timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->poll_timer, furi_ms_to_ticks(POLL_RATE_VALUES[app->poll_rate_idx]));

    AppEvent ev;
    while(!app->exit) {
        if(furi_message_queue_get(app->events, &ev, FuriWaitForever) != FuriStatusOk) continue;
        switch(ev.type) {
        case AppEventTick:
            poll_status(app);
            /* S3: advance marquee offset on each tick (~250ms).
             * Only mutates offset — no I/O, so safe inside the main loop. */
            {
                uint32_t now = furi_get_tick();
                furi_mutex_acquire(app->mutex, FuriWaitForever);
                if((now - app->last_marquee_tick) >= furi_ms_to_ticks(333)) {
                    app->marquee_offset += MARQUEE_PX_PER_TICK;
                    app->last_marquee_tick = now;
                    /* Reset when offset exceeds a reasonable bound to
                     * prevent integer overflow in very long sessions. */
                    if(app->marquee_offset > 10000) app->marquee_offset = 0;
                    view_port_update(app->view_port);
                }
                furi_mutex_release(app->mutex);
            }
            break;
        case AppEventInput:
            handle_input(app, &ev.input);
            break;
        }
    }

    furi_timer_stop(app->poll_timer);
    furi_timer_free(app->poll_timer);

    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);

    furi_message_queue_free(app->events);
    furi_mutex_free(app->mutex);

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_STORAGE);

    free(app);
    return 0;
}
