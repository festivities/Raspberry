#ifndef RASPBERRY_REAUTH_H
#define RASPBERRY_REAUTH_H

#include <stddef.h>
#include <stdint.h>

#define RB_UUID_MAX 128

enum {
    RB_RESET_NONE = 0,
    RB_RESET_LOGOUT = 1,
    RB_RESET_DELETE_AVATAR = 2,
    RB_RESET_CHECK_SESSION_404 = 3,
    RB_RESET_GUEST_400 = 4
};

typedef struct rb_reauth_state {
    uint64_t reset_epoch;
    uint64_t completed_epoch;
    int reauth_required;
    int consent_ready_parked;
    int login_layer_alive;
    int fence_active;
    uint32_t fence_tx_id;
    char uuid[RB_UUID_MAX + 1];
} rb_reauth_state;

/* Zero-initializes a re-auth state machine. */
void rb_reauth_init(rb_reauth_state *st);

/* Returns 1 iff uuid is non-NULL, non-empty, <= RB_UUID_MAX bytes, and ASCII printable. */
int rb_valid_uuid(const char *uuid);

/* Closed 4-trigger classifier matching android-reset-dispatch-spec.md. */
int rb_classify_dispatch(int is_avatar_dispatcher,
                         int op_id,
                         int is_err,
                         int adi_or_curl_err,
                         int http_status,
                         uint32_t err_flags,
                         int err_code,
                         int json_result_true);

/* Wrap-safe transaction watermark predicate: 1 if fence is active and req_tx != 0 <= fence_tx. */
int rb_tx_is_stale(uint32_t req_tx, uint32_t fence_tx, int fence_active);

/* Advances monotonic fence, bumps reset_epoch, latches reauth_required, clears uuid. */
int rb_reauth_begin_reset(rb_reauth_state *st,
                          uint32_t cur_tx_id,
                          int park_consent_ready,
                          uint64_t *out_epoch);

/* Sets startup UUID only before any reset has occurred (!reauth_required && reset_epoch == 0). */
int rb_reauth_set_initial_uuid(rb_reauth_state *st, const char *uuid);

/* Completes an active reset epoch with a validated fresh UUID. */
int rb_reauth_complete(rb_reauth_state *st, uint64_t epoch, const char *uuid);

/* Parks consent_ready if reauth_required or uuid is empty; otherwise returns 1 and copies uuid. */
int rb_reauth_on_consent_ready(rb_reauth_state *st, char *out_uuid, size_t out_cap);

/* One-shot GL-thread poll: returns 1 and clears consent_ready_parked when ready to fire. */
int rb_reauth_poll_continuation(rb_reauth_state *st, char *out_uuid, size_t out_cap);

/* Fail-closed UUID read for ReqAccessTokenForGuest. */
int rb_reauth_get_guest_uuid(const rb_reauth_state *st, char *out_uuid, size_t out_cap);

/* Updates tracked NaLoginLayer liveness. */
void rb_reauth_set_login_alive(rb_reauth_state *st, int alive);

#endif
