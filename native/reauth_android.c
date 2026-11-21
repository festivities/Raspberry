#define _GNU_SOURCE

#include "reauth.h"

#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

struct rb_game_image;

uintptr_t rb_game_base(const struct rb_game_image *g);
int rb_game_in_rx(const struct rb_game_image *g, uintptr_t addr, size_t width);
int rb_game_in_bss_tail(const struct rb_game_image *g, uintptr_t addr, size_t width);
int rb_validate_relro_slot(const struct rb_game_image *g, uintptr_t slot_va, void *expect_val);
int rb_patch_relro_slot(const struct rb_game_image *g, uintptr_t slot_va, void *expect_val, void *new_val);
void rb_jni_notify_reset(uint64_t epoch, int reason);

#if defined(__aarch64__)
#define OFF_RESP_REQ            0x08u
#define OFF_RESP_ADI_OR_CURL    0x10u
#define OFF_RESP_EVENT_TYPE     0x14u
#define OFF_RESP_HTTP_STATUS    0x20u

#define OFF_REQ_PROTO           0x90u
#define OFF_REQ_TX_ID           0x98u

#define OFF_PROTO_CTX           0x10u

#define OFF_ERR_FLAGS           0x00u
#define OFF_ERR_HTTP_STATUS     0x0Cu
#define OFF_ERR_JSON            0x28u
#define OFF_ERR_CODE            0x40u
#define OFF_ERR_HANDLED         0x60u

#define OFF_DISP_SB_ID          0x38u
#define OFF_SBMESSAGE_ID        0x08u
#define OFF_SB_LISTENER_ADJ     0x170u

#define VA_VTABLE_ON_EVENT          0x392c240u
#define VA_EXPECT_ON_EVENT          0x1b695ecu
#define VA_VTABLE_COMMON_DISPATCH   0x392ab88u
#define VA_EXPECT_COMMON_DISPATCH   0x1a532fcu
#define VA_VTABLE_AVATAR_DISPATCH   0x392b168u
#define VA_EXPECT_AVATAR_DISPATCH   0x1a52af8u
#define VA_VTABLE_MAIN_LOOP         0x3b72940u
#define VA_EXPECT_MAIN_LOOP         0x2c95ef0u
#define VA_VTABLE_LOGIN_MSGPROC     0x395cef0u
#define VA_EXPECT_LOGIN_MSGPROC     0x1d01058u
#define VA_VTABLE_LOGIN_MSGPROC_THK 0x395cfb8u
#define VA_EXPECT_LOGIN_MSGPROC_THK 0x1d024b8u
#define VA_VTABLE_LOGIN_INIT        0x395cae8u
#define VA_EXPECT_LOGIN_INIT        0x1d17838u
#define VA_VTABLE_LOGIN_DTOR_D2     0x395cac0u
#define VA_EXPECT_LOGIN_DTOR_D2     0x1ca8bc0u
#define VA_VTABLE_LOGIN_DTOR_D0     0x395cac8u
#define VA_EXPECT_LOGIN_DTOR_D0     0x1ca8c70u

#define VA_BSS_SLOT_REQ_GUEST       0x3e8a600u
#define VA_BSS_SLOT_SET_VISIBLE_BTN 0x3e8a608u
#define VA_BSS_SLOT_CREATE_GUEST    0x3e8a610u

#define VA_RESUME_REQ_GUEST         0x384ffdcu
#define VA_RESUME_SET_VISIBLE_BTN   0x384fff0u

#define SYM_LOGIN_MSGPROC_THK "_ZThn368_N12NaLoginLayer7MsgProcEP9SbMessage"

#elif defined(__arm__)
#define OFF_RESP_REQ            0x04u
#define OFF_RESP_ADI_OR_CURL    0x08u
#define OFF_RESP_EVENT_TYPE     0x0Cu
#define OFF_RESP_HTTP_STATUS    0x14u

#define OFF_REQ_PROTO           0x50u
#define OFF_REQ_TX_ID           0x54u

#define OFF_PROTO_CTX           0x08u

#define OFF_ERR_FLAGS           0x00u
#define OFF_ERR_HTTP_STATUS     0x0Cu
#define OFF_ERR_JSON            0x20u
#define OFF_ERR_CODE            0x30u
#define OFF_ERR_HANDLED         0x40u

#define OFF_DISP_SB_ID          0x1Cu
#define OFF_SBMESSAGE_ID        0x04u
#define OFF_SB_LISTENER_ADJ     0x114u

#define VA_VTABLE_ON_EVENT          0x20ef5a0u
#define VA_EXPECT_ON_EVENT          (0x11c4f18u | 1u)
#define VA_VTABLE_COMMON_DISPATCH   0x20ef5f4u
#define VA_EXPECT_COMMON_DISPATCH   (0x116fc54u | 1u)
#define VA_VTABLE_AVATAR_DISPATCH   0x20ef69cu
#define VA_EXPECT_AVATAR_DISPATCH   (0x116fab0u | 1u)
#define VA_VTABLE_MAIN_LOOP         0x221797cu
#define VA_EXPECT_MAIN_LOOP         (0x1a97aecu | 1u)
#define VA_VTABLE_LOGIN_MSGPROC     0x2109434u
#define VA_EXPECT_LOGIN_MSGPROC     (0x1292198u | 1u)
#define VA_VTABLE_LOGIN_MSGPROC_THK 0x2109498u
#define VA_EXPECT_LOGIN_MSGPROC_THK (0x1292e84u | 1u)
#define VA_VTABLE_LOGIN_INIT        0x2109230u
#define VA_EXPECT_LOGIN_INIT        (0x12987f4u | 1u)
#define VA_VTABLE_LOGIN_DTOR_D2     0x210921cu
#define VA_EXPECT_LOGIN_DTOR_D2     (0x1270a5cu | 1u)
#define VA_VTABLE_LOGIN_DTOR_D0     0x2109220u
#define VA_EXPECT_LOGIN_DTOR_D0     (0x1270adcu | 1u)

#define VA_BSS_SLOT_REQ_GUEST       0x24b4400u
#define VA_BSS_SLOT_SET_VISIBLE_BTN 0x24b4404u
#define VA_BSS_SLOT_CREATE_GUEST    0x24b4408u

#define VA_RESUME_REQ_GUEST         (0x20806a0u | 1u)
#define VA_RESUME_SET_VISIBLE_BTN   (0x2080684u | 1u)

#define SYM_LOGIN_MSGPROC_THK "_ZThn276_N12NaLoginLayer7MsgProcEP9SbMessage"

#else
#error raspberry: arm64-v8a or armeabi-v7a only
#endif

typedef void (*on_event_fn)(void *self, void *ev);
typedef void (*dispatch_fn)(void *self, int *op_id, void *resp, void *err, uint8_t is_err);
typedef void (*main_loop_fn)(void *director);
typedef int (*msg_proc_fn)(void *self, void *msg);
typedef uint8_t (*login_init_fn)(void *self);
typedef void *(*login_dtor_fn)(void *self);

typedef void (*req_guest_fn)(void *disp, const char *unique_code);
typedef void (*set_visible_btn_fn)(void *layer, uint8_t visible);

typedef const void *(*json_subscript_fn)(const void *val, const char *key);
typedef uint8_t (*json_as_bool_fn)(const void *val);
typedef void (*hide_indicator_fn)(void *sundries, uint32_t sb_id);
typedef void *(*shared_inst_fn)(void);
typedef uint8_t (*is_gdpr_nation_fn)(void *invoker);
typedef void (*set_gdpr_status_fn)(void *invoker, int status);
typedef void (*void_obj_fn)(void *obj);

enum {
    VT_ON_EVENT = 0,
    VT_COMMON_DISPATCH,
    VT_AVATAR_DISPATCH,
    VT_MAIN_LOOP,
    VT_LOGIN_MSGPROC,
    VT_LOGIN_MSGPROC_THK,
    VT_LOGIN_INIT,
    VT_LOGIN_DTOR_D2,
    VT_LOGIN_DTOR_D0,
    VT_N
};

static struct {
    uint32_t **p_adi_tx;
    json_subscript_fn json_subscript;
    json_as_bool_fn json_as_bool;
    void **p_sundries_inst;
    hide_indicator_fn hide_indicator;
    shared_inst_fn shared_data_invoker;
    is_gdpr_nation_fn is_gdpr_nation;
    set_gdpr_status_fn set_gdpr_status;
    void_obj_fn data_invoker_logout;
    shared_inst_fn cookie_get_instance;
    void_obj_fn cookie_clear;
    void_obj_fn cookie_remove_av_auth;
    shared_inst_fn shared_platform_bridge;
    void_obj_fn clear_member_variable;
    void **p_common_disp_inst;
    void *req_guest_sym;
} g_sym;

static on_event_fn g_orig_on_event;
static dispatch_fn g_orig_common_dispatch;
static dispatch_fn g_orig_avatar_dispatch;
static main_loop_fn g_orig_main_loop;
static msg_proc_fn g_orig_login_msgproc;
static login_init_fn g_orig_login_init;
static login_dtor_fn g_orig_login_dtor_d2;
static login_dtor_fn g_orig_login_dtor_d0;

static req_guest_fn g_resume_req_guest;
static set_visible_btn_fn g_resume_set_visible_btn;

static pthread_mutex_t g_reauth_mu = PTHREAD_MUTEX_INITIALIZER;
static rb_reauth_state g_reauth;
static void *g_active_login_layer;

static void mark_login_layer_alive_locked(void *layer) {
    if (layer) {
        g_active_login_layer = layer;
    }
    rb_reauth_set_login_alive(&g_reauth, 1);
}

static void reauth_log(const char *tag) {
    __android_log_print(ANDROID_LOG_ERROR, "raspberry", "reauth %s", tag);
}

static uint32_t current_tx_id(void) {
    uint32_t *handle;
    if (!g_sym.p_adi_tx) {
        return 0u;
    }
    handle = __atomic_load_n(g_sym.p_adi_tx, __ATOMIC_ACQUIRE);
    if (!handle) {
        return 0u;
    }
    return __atomic_load_n(handle, __ATOMIC_SEQ_CST);
}

static void rb_trigger_guest_request(const char *uuid) {
    void *disp;
    if (!uuid || uuid[0] == '\0' || !g_sym.p_common_disp_inst || !g_resume_req_guest) {
        return;
    }
    disp = __atomic_load_n(g_sym.p_common_disp_inst, __ATOMIC_ACQUIRE);
    if (!disp) {
        return;
    }
    g_resume_req_guest(disp, uuid);
}

static int read_json_result_true(const void *err) {
    const void *json_val;
    const void *res;
    if (!err || !g_sym.json_subscript || !g_sym.json_as_bool) {
        return 0;
    }
    json_val = (const char *)err + OFF_ERR_JSON;
    res = g_sym.json_subscript(json_val, "result");
    if (!res) {
        return 0;
    }
    return g_sym.json_as_bool(res) != 0 ? 1 : 0;
}

static void extract_dispatch_fields(const void *resp,
                                    const void *err,
                                    uint8_t is_err,
                                    int op_id,
                                    int check_json,
                                    int *out_adi_or_curl,
                                    int *out_http_status,
                                    uint32_t *out_err_flags,
                                    int *out_err_code,
                                    int *out_json_true) {
    int adi_or_curl = -1;
    int http_status = 0;
    uint32_t err_flags = 0u;
    int err_code = 0;
    int json_true = 0;

    if (resp) {
        adi_or_curl = *(const int32_t *)((const char *)resp + OFF_RESP_ADI_OR_CURL);
        if (!is_err) {
            long st = *(const long *)((const char *)resp + OFF_RESP_HTTP_STATUS);
            if (st >= 0 && st <= 999) {
                http_status = (int)st;
            }
        }
    }
    if (err) {
        err_flags = *(const uint32_t *)((const char *)err + OFF_ERR_FLAGS);
        err_code = *(const int32_t *)((const char *)err + OFF_ERR_CODE);
        if (is_err) {
            http_status = *(const int32_t *)((const char *)err + OFF_ERR_HTTP_STATUS);
        }
        if (check_json && !is_err && adi_or_curl == 0 && (http_status == 200 || http_status == 201)) {
            (void)op_id;
            json_true = read_json_result_true(err);
        }
    }

    *out_adi_or_curl = adi_or_curl;
    *out_http_status = http_status;
    *out_err_flags = err_flags;
    *out_err_code = err_code;
    *out_json_true = json_true;
}

static void hook_OnEvent(void *self, void *ev) {
    if (ev) {
        int32_t event_type = *(const int32_t *)((const char *)ev + OFF_RESP_EVENT_TYPE);
        if (event_type == 1) {
            void *req = *(void *const *)((const char *)ev + OFF_RESP_REQ);
            if (req) {
                uint32_t tx = *(const uint32_t *)((const char *)req + OFF_REQ_TX_ID);
                int stale;
                pthread_mutex_lock(&g_reauth_mu);
                stale = rb_tx_is_stale(tx, g_reauth.fence_tx_id, g_reauth.fence_active);
                pthread_mutex_unlock(&g_reauth_mu);
                if (stale) {
                    return;
                }
            }
        }
    }
    if (g_orig_on_event) {
        g_orig_on_event(self, ev);
    }
}

static void hook_CommonDispatch(void *self, int *op_id_ptr, void *resp, void *err, uint8_t is_err) {
    int op_id = op_id_ptr ? *op_id_ptr : -1;
    int adi_or_curl = -1;
    int http_status = 0;
    uint32_t err_flags = 0u;
    int err_code = 0;
    int json_true = 0;
    int reason;
    uint64_t epoch = 0u;

    extract_dispatch_fields(resp, err, is_err, op_id, op_id == 14, &adi_or_curl, &http_status,
                            &err_flags, &err_code, &json_true);
    reason = rb_classify_dispatch(0, op_id, is_err ? 1 : 0, adi_or_curl, http_status,
                                  err_flags, err_code, json_true);

    if (reason == RB_RESET_LOGOUT) {
        uint32_t cur_tx = current_tx_id();
        pthread_mutex_lock(&g_reauth_mu);
        (void)rb_reauth_begin_reset(&g_reauth, cur_tx, 0, &epoch);
        pthread_mutex_unlock(&g_reauth_mu);
        if (g_orig_common_dispatch) {
            g_orig_common_dispatch(self, op_id_ptr, resp, err, is_err);
        }
        rb_jni_notify_reset(epoch, RB_RESET_LOGOUT);
        return;
    }

    if (reason == RB_RESET_CHECK_SESSION_404) {
        void *req = resp ? *(void *const *)((const char *)resp + OFF_RESP_REQ) : NULL;
        void *proto = req ? *(void *const *)((const char *)req + OFF_REQ_PROTO) : NULL;
        void *ctx = proto ? *(void *const *)((const char *)proto + OFF_PROTO_CTX) : NULL;
        int mid_session = (ctx != NULL && *((const uint32_t *)ctx + 4) == 1u);
        uint32_t cur_tx = current_tx_id();

        pthread_mutex_lock(&g_reauth_mu);
        (void)rb_reauth_begin_reset(&g_reauth, cur_tx, mid_session ? 0 : 1, &epoch);
        if (!mid_session) {
            mark_login_layer_alive_locked(NULL);
        }
        pthread_mutex_unlock(&g_reauth_mu);

        if (self && g_sym.p_sundries_inst && g_sym.hide_indicator) {
            void *sundries = __atomic_load_n(g_sym.p_sundries_inst, __ATOMIC_ACQUIRE);
            if (sundries) {
                uint32_t sb_id = *(const uint32_t *)((const char *)self + OFF_DISP_SB_ID);
                g_sym.hide_indicator(sundries, sb_id);
            }
        }
        if (g_sym.shared_data_invoker && g_sym.is_gdpr_nation && g_sym.set_gdpr_status) {
            void *invoker = g_sym.shared_data_invoker();
            if (invoker && g_sym.is_gdpr_nation(invoker)) {
                g_sym.set_gdpr_status(invoker, 0);
            }
        }
        if (g_sym.cookie_get_instance && g_sym.cookie_clear && g_sym.cookie_remove_av_auth) {
            void *cm = g_sym.cookie_get_instance();
            if (cm) {
                g_sym.cookie_clear(cm);
                g_sym.cookie_remove_av_auth(cm);
            }
        }
        if (mid_session && g_sym.shared_data_invoker && g_sym.data_invoker_logout) {
            void *invoker = g_sym.shared_data_invoker();
            if (invoker) {
                g_sym.data_invoker_logout(invoker);
            }
        }
        rb_jni_notify_reset(epoch, RB_RESET_CHECK_SESSION_404);
        return;
    }

    if (reason == RB_RESET_GUEST_400) {
        uint32_t cur_tx = current_tx_id();
        pthread_mutex_lock(&g_reauth_mu);
        (void)rb_reauth_begin_reset(&g_reauth, cur_tx, 1, &epoch);
        mark_login_layer_alive_locked(NULL);
        pthread_mutex_unlock(&g_reauth_mu);

        if (self && g_sym.p_sundries_inst && g_sym.hide_indicator) {
            void *sundries = __atomic_load_n(g_sym.p_sundries_inst, __ATOMIC_ACQUIRE);
            if (sundries) {
                uint32_t sb_id = *(const uint32_t *)((const char *)self + OFF_DISP_SB_ID);
                g_sym.hide_indicator(sundries, sb_id);
            }
        }
        if (err) {
            *((uint8_t *)err + OFF_ERR_HANDLED) = 1u;
        }
        rb_jni_notify_reset(epoch, RB_RESET_GUEST_400);
        return;
    }

    if (g_orig_common_dispatch) {
        g_orig_common_dispatch(self, op_id_ptr, resp, err, is_err);
    }
}

static void hook_AvatarDispatch(void *self, int *op_id_ptr, void *resp, void *err, uint8_t is_err) {
    int op_id = op_id_ptr ? *op_id_ptr : -1;
    int adi_or_curl = -1;
    int http_status = 0;
    uint32_t err_flags = 0u;
    int err_code = 0;
    int json_true = 0;
    int reason;
    uint64_t epoch = 0u;

    extract_dispatch_fields(resp, err, is_err, op_id, op_id == 13, &adi_or_curl, &http_status,
                            &err_flags, &err_code, &json_true);
    reason = rb_classify_dispatch(1, op_id, is_err ? 1 : 0, adi_or_curl, http_status,
                                  err_flags, err_code, json_true);

    if (reason == RB_RESET_DELETE_AVATAR) {
        uint32_t cur_tx = current_tx_id();
        pthread_mutex_lock(&g_reauth_mu);
        (void)rb_reauth_begin_reset(&g_reauth, cur_tx, 0, &epoch);
        pthread_mutex_unlock(&g_reauth_mu);

        if (g_orig_avatar_dispatch) {
            g_orig_avatar_dispatch(self, op_id_ptr, resp, err, is_err);
        }
        if (g_sym.shared_platform_bridge && g_sym.clear_member_variable) {
            void *bridge = g_sym.shared_platform_bridge();
            if (bridge) {
                g_sym.clear_member_variable(bridge);
            }
        }
        if (g_sym.cookie_get_instance && g_sym.cookie_clear && g_sym.cookie_remove_av_auth) {
            void *cm = g_sym.cookie_get_instance();
            if (cm) {
                g_sym.cookie_clear(cm);
                g_sym.cookie_remove_av_auth(cm);
            }
        }
        rb_jni_notify_reset(epoch, RB_RESET_DELETE_AVATAR);
        return;
    }

    if (g_orig_avatar_dispatch) {
        g_orig_avatar_dispatch(self, op_id_ptr, resp, err, is_err);
    }
}

static void hook_mainLoop(void *director) {
    char fresh_uuid[RB_UUID_MAX + 1];
    int fire;

    pthread_mutex_lock(&g_reauth_mu);
    fire = rb_reauth_poll_continuation(&g_reauth, fresh_uuid, sizeof fresh_uuid);
    pthread_mutex_unlock(&g_reauth_mu);

    if (fire) {
        rb_trigger_guest_request(fresh_uuid);
    }
    if (g_orig_main_loop) {
        g_orig_main_loop(director);
    }
}

static void hook_createGuestAccount(void *self) {
    char fresh_uuid[RB_UUID_MAX + 1];
    int ready;
    (void)self;

    pthread_mutex_lock(&g_reauth_mu);
    mark_login_layer_alive_locked(NULL);
    ready = rb_reauth_on_consent_ready(&g_reauth, fresh_uuid, sizeof fresh_uuid);
    pthread_mutex_unlock(&g_reauth_mu);

    if (ready) {
        rb_trigger_guest_request(fresh_uuid);
    }
}

static void hook_ReqAccessTokenForGuest(void *self, const char *unique_code) {
    char fresh_uuid[RB_UUID_MAX + 1];
    int ok;
    (void)unique_code;

    pthread_mutex_lock(&g_reauth_mu);
    ok = rb_reauth_get_guest_uuid(&g_reauth, fresh_uuid, sizeof fresh_uuid);
    pthread_mutex_unlock(&g_reauth_mu);

    if (!ok || !g_resume_req_guest) {
        return;
    }
    g_resume_req_guest(self, fresh_uuid);
}

static void hook_SetVisibleLoginBtn(void *self, uint8_t visible) {
    (void)visible;
    pthread_mutex_lock(&g_reauth_mu);
    mark_login_layer_alive_locked(self);
    pthread_mutex_unlock(&g_reauth_mu);
    if (g_resume_set_visible_btn) {
        g_resume_set_visible_btn(self, 0u);
    }
}

static int hook_MsgProc(void *self, void *msg) {
    int32_t msg_id = msg ? *(const int32_t *)((const char *)msg + OFF_SBMESSAGE_ID) : 0;
    int ret;

    if (self) {
        pthread_mutex_lock(&g_reauth_mu);
        mark_login_layer_alive_locked(self);
        pthread_mutex_unlock(&g_reauth_mu);
    }
    if (msg_id == 11981) {
        return 1;
    }
    if (msg_id == 10043) {
        int req;
        pthread_mutex_lock(&g_reauth_mu);
        req = g_reauth.reauth_required;
        pthread_mutex_unlock(&g_reauth_mu);
        if (req) {
            return 1;
        }
    }
    ret = g_orig_login_msgproc ? g_orig_login_msgproc(self, msg) : 0;
    if (msg_id == 10716) {
        hook_createGuestAccount(NULL);
    }
    return ret;
}

static int hook_MsgProc_SbListener(void *sb_listener, void *msg) {
    void *layer = sb_listener ? (void *)((char *)sb_listener - OFF_SB_LISTENER_ADJ) : NULL;
    return hook_MsgProc(layer, msg);
}

static uint8_t hook_LoginInit(void *self) {
    uint8_t ok = g_orig_login_init ? g_orig_login_init(self) : 0u;
    if (ok) {
        pthread_mutex_lock(&g_reauth_mu);
        mark_login_layer_alive_locked(self);
        pthread_mutex_unlock(&g_reauth_mu);
    }
    return ok;
}

static void *hook_LoginDtorD2(void *self) {
    pthread_mutex_lock(&g_reauth_mu);
    if (self == g_active_login_layer || g_active_login_layer == NULL) {
        g_active_login_layer = NULL;
        rb_reauth_set_login_alive(&g_reauth, 0);
    }
    pthread_mutex_unlock(&g_reauth_mu);
    return g_orig_login_dtor_d2 ? g_orig_login_dtor_d2(self) : self;
}

static void *hook_LoginDtorD0(void *self) {
    pthread_mutex_lock(&g_reauth_mu);
    if (self == g_active_login_layer || g_active_login_layer == NULL) {
        g_active_login_layer = NULL;
        rb_reauth_set_login_alive(&g_reauth, 0);
    }
    pthread_mutex_unlock(&g_reauth_mu);
    return g_orig_login_dtor_d0 ? g_orig_login_dtor_d0(self) : NULL;
}

struct vtable_hook_spec {
    uintptr_t slot_va;
    uintptr_t expect_va;
    const char *sym;
    void *hook_fn;
};

static const struct vtable_hook_spec k_vtables[VT_N] = {
    {VA_VTABLE_ON_EVENT, VA_EXPECT_ON_EVENT,
     "_ZN18ADIMultiDispatcher7OnEventEPN3ADI4Impl12ADIEventBaseE", (void *)hook_OnEvent},
    {VA_VTABLE_COMMON_DISPATCH, VA_EXPECT_COMMON_DISPATCH,
     "_ZN17ADIDispatcherBaseI18NaDispatcherCommonE8DispatchERiPN3ADI4Impl11ADIResponseER16ADI_ERROR_RESULTb",
     (void *)hook_CommonDispatch},
    {VA_VTABLE_AVATAR_DISPATCH, VA_EXPECT_AVATAR_DISPATCH,
     "_ZN17ADIDispatcherBaseI18NaDispatcherAvatarE8DispatchERiPN3ADI4Impl11ADIResponseER16ADI_ERROR_RESULTb",
     (void *)hook_AvatarDispatch},
    {VA_VTABLE_MAIN_LOOP, VA_EXPECT_MAIN_LOOP,
     "_ZN7cocos2d21CCDisplayLinkDirector8mainLoopEv", (void *)hook_mainLoop},
    {VA_VTABLE_LOGIN_MSGPROC, VA_EXPECT_LOGIN_MSGPROC,
     "_ZN12NaLoginLayer7MsgProcEP9SbMessage", (void *)hook_MsgProc},
    {VA_VTABLE_LOGIN_MSGPROC_THK, VA_EXPECT_LOGIN_MSGPROC_THK,
     SYM_LOGIN_MSGPROC_THK, (void *)hook_MsgProc_SbListener},
    {VA_VTABLE_LOGIN_INIT, VA_EXPECT_LOGIN_INIT,
     "_ZN12NaLoginLayer4initEv", (void *)hook_LoginInit},
    {VA_VTABLE_LOGIN_DTOR_D2, VA_EXPECT_LOGIN_DTOR_D2,
     "_ZN12NaLoginLayerD2Ev", (void *)hook_LoginDtorD2},
    {VA_VTABLE_LOGIN_DTOR_D0, VA_EXPECT_LOGIN_DTOR_D0,
     "_ZN12NaLoginLayerD0Ev", (void *)hook_LoginDtorD0},
};

static int resolve_all_symbols(void *libgame) {
    struct {
        const char *name;
        void **out;
    } syms[] = {
        {"_ZN3ADI4Impl20TransactionGenerator11TransactionE", (void **)&g_sym.p_adi_tx},
        {"_ZNK4Json5ValueixEPKc", (void **)&g_sym.json_subscript},
        {"_ZNK4Json5Value6asBoolEv", (void **)&g_sym.json_as_bool},
        {"_ZN11SbSingletonI11CNaSundriesE12ms_pInstanceE", (void **)&g_sym.p_sundries_inst},
        {"_ZN11CNaSundries19HideSystemIndicatorEj", (void **)&g_sym.hide_indicator},
        {"_ZN13NaDataInvoker17sharedDataInvokerEv", (void **)&g_sym.shared_data_invoker},
        {"_ZNK13NaDataInvoker12IsGdprNationEv", (void **)&g_sym.is_gdpr_nation},
        {"_ZN13NaDataInvoker13SetGdprStatusE12LPGdprStatus", (void **)&g_sym.set_gdpr_status},
        {"_ZN13NaDataInvoker6LogoutEv", (void **)&g_sym.data_invoker_logout},
        {"_ZN18NaADICookieManager11GetInstanceEv", (void **)&g_sym.cookie_get_instance},
        {"_ZN18NaADICookieManager5ClearEv", (void **)&g_sym.cookie_clear},
        {"_ZN18NaADICookieManager18RemoveAvAuthCookieEv", (void **)&g_sym.cookie_remove_av_auth},
        {"_ZN6ArtsPf17CPfPlatformBridge20sharedPlatformBridgeEv", (void **)&g_sym.shared_platform_bridge},
        {"_ZN6ArtsPf17CPfPlatformBridge19ClearMemberValiableEv", (void **)&g_sym.clear_member_variable},
        {"_ZN11SbSingletonI18NaDispatcherCommonE12ms_pInstanceE", (void **)&g_sym.p_common_disp_inst},
        {"_ZN18NaDispatcherCommon22ReqAccessTokenForGuestEPKc", (void **)&g_sym.req_guest_sym},
    };
    size_t i;
    for (i = 0; i < sizeof syms / sizeof syms[0]; i++) {
        void *p = dlsym(libgame, syms[i].name);
        if (!p) {
            return -1;
        }
        *syms[i].out = p;
    }
    return 0;
}

static void clear_bss_slots(uintptr_t base) {
    __atomic_store_n((void **)(base + VA_BSS_SLOT_REQ_GUEST), NULL, __ATOMIC_RELEASE);
    __atomic_store_n((void **)(base + VA_BSS_SLOT_SET_VISIBLE_BTN), NULL, __ATOMIC_RELEASE);
    __atomic_store_n((void **)(base + VA_BSS_SLOT_CREATE_GUEST), NULL, __ATOMIC_RELEASE);
}

void rb_reauth_rollback(const struct rb_game_image *g) {
    uintptr_t base = rb_game_base(g);
    int i;
    if (!g) {
        return;
    }
    for (i = 0; i < VT_N; i++) {
        uintptr_t expect_addr = base + k_vtables[i].expect_va;
        (void)rb_patch_relro_slot(g, k_vtables[i].slot_va, k_vtables[i].hook_fn, (void *)expect_addr);
    }
    clear_bss_slots(base);
}

int rb_reauth_install(const struct rb_game_image *g) {
    void *libgame;
    uintptr_t base;
    void *vt_orig[VT_N];
    uintptr_t bss_va[3] = {
        VA_BSS_SLOT_REQ_GUEST,
        VA_BSS_SLOT_SET_VISIBLE_BTN,
        VA_BSS_SLOT_CREATE_GUEST,
    };
    void *bss_hook[3] = {
        (void *)hook_ReqAccessTokenForGuest,
        (void *)hook_SetVisibleLoginBtn,
        (void *)hook_createGuestAccount,
    };
    int i;

    if (!g) {
        return -1;
    }
    base = rb_game_base(g);
    libgame = dlopen("libgame.so", RTLD_NOW | RTLD_NOLOAD);
    if (!libgame) {
        reauth_log("dlopen");
        return -1;
    }
    if (resolve_all_symbols(libgame) != 0) {
        reauth_log("dlsym");
        return -1;
    }
    if (!rb_game_in_rx(g, (base + VA_RESUME_REQ_GUEST) & ~(uintptr_t)1u, 4u) ||
        !rb_game_in_rx(g, (base + VA_RESUME_SET_VISIBLE_BTN) & ~(uintptr_t)1u, 4u)) {
        reauth_log("rx");
        return -1;
    }
    for (i = 0; i < VT_N; i++) {
        void *sym = dlsym(libgame, k_vtables[i].sym);
        uintptr_t expect_addr;
        if (k_vtables[i].expect_va > UINTPTR_MAX - base) {
            reauth_log("vtable");
            return -1;
        }
        expect_addr = base + k_vtables[i].expect_va;
        if (!sym || (uintptr_t)sym != expect_addr) {
            reauth_log("vtsym");
            return -1;
        }
        if (rb_validate_relro_slot(g, k_vtables[i].slot_va, (void *)expect_addr) != 0) {
            reauth_log("vtslot");
            return -1;
        }
        vt_orig[i] = sym;
    }
    for (i = 0; i < 3; i++) {
        uintptr_t addr;
        if (bss_va[i] > UINTPTR_MAX - base) {
            reauth_log("bss");
            return -1;
        }
        addr = base + bss_va[i];
        if (!rb_game_in_bss_tail(g, addr, sizeof(void *))) {
            reauth_log("bsstail");
            return -1;
        }
        if (__atomic_load_n((void **)addr, __ATOMIC_ACQUIRE) != NULL) {
            reauth_log("bssval");
            return -1;
        }
    }

    g_orig_on_event = (on_event_fn)vt_orig[VT_ON_EVENT];
    g_orig_common_dispatch = (dispatch_fn)vt_orig[VT_COMMON_DISPATCH];
    g_orig_avatar_dispatch = (dispatch_fn)vt_orig[VT_AVATAR_DISPATCH];
    g_orig_main_loop = (main_loop_fn)vt_orig[VT_MAIN_LOOP];
    g_orig_login_msgproc = (msg_proc_fn)vt_orig[VT_LOGIN_MSGPROC];
    g_orig_login_init = (login_init_fn)vt_orig[VT_LOGIN_INIT];
    g_orig_login_dtor_d2 = (login_dtor_fn)vt_orig[VT_LOGIN_DTOR_D2];
    g_orig_login_dtor_d0 = (login_dtor_fn)vt_orig[VT_LOGIN_DTOR_D0];

    g_resume_req_guest = (req_guest_fn)(base + VA_RESUME_REQ_GUEST);
    g_resume_set_visible_btn = (set_visible_btn_fn)(base + VA_RESUME_SET_VISIBLE_BTN);

    for (i = 0; i < 3; i++) {
        __atomic_store_n((void **)(base + bss_va[i]), bss_hook[i], __ATOMIC_RELEASE);
    }
    for (i = 0; i < VT_N; i++) {
        void *expect_ptr = (void *)(base + k_vtables[i].expect_va);
        if (rb_patch_relro_slot(g, k_vtables[i].slot_va, expect_ptr, k_vtables[i].hook_fn) != 0) {
            int j;
            for (j = i - 1; j >= 0; j--) {
                void *orig_ptr = (void *)(base + k_vtables[j].expect_va);
                (void)rb_patch_relro_slot(g, k_vtables[j].slot_va, k_vtables[j].hook_fn, orig_ptr);
            }
            clear_bss_slots(base);
            reauth_log("vtpatch");
            return -1;
        }
    }
    return 0;
}

int rb_reauth_set_initial_uuid_cstr(const char *uuid) {
    int ok;
    pthread_mutex_lock(&g_reauth_mu);
    ok = rb_reauth_set_initial_uuid(&g_reauth, uuid);
    pthread_mutex_unlock(&g_reauth_mu);
    return ok;
}

int rb_reauth_complete_cstr(uint64_t epoch, const char *uuid) {
    int ok;
    pthread_mutex_lock(&g_reauth_mu);
    ok = rb_reauth_complete(&g_reauth, epoch, uuid);
    pthread_mutex_unlock(&g_reauth_mu);
    return ok;
}
