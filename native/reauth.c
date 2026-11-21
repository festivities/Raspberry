#include "reauth.h"

#include <string.h>

static int copy_uuid_out(const char *uuid, char *out, size_t cap) {
    size_t len;
    if (!uuid || !out || cap == 0) {
        return 0;
    }
    len = strlen(uuid);
    if (len == 0 || len > RB_UUID_MAX || len + 1 > cap) {
        return 0;
    }
    memcpy(out, uuid, len + 1);
    return 1;
}

void rb_reauth_init(rb_reauth_state *st) {
    if (!st) {
        return;
    }
    memset(st, 0, sizeof *st);
}

int rb_valid_uuid(const char *uuid) {
    size_t i;
    if (!uuid || uuid[0] == '\0') {
        return 0;
    }
    for (i = 0; i <= RB_UUID_MAX; i++) {
        unsigned char c = (unsigned char)uuid[i];
        if (c == '\0') {
            return i > 0 ? 1 : 0;
        }
        if (c < 0x20u || c > 0x7eu) {
            return 0;
        }
    }
    return 0;
}

int rb_classify_dispatch(int is_avatar_dispatcher,
                         int op_id,
                         int is_err,
                         int adi_or_curl_err,
                         int http_status,
                         uint32_t err_flags,
                         int err_code,
                         int json_result_true) {
    if (!is_avatar_dispatcher) {
        if (op_id == 14 && !is_err && adi_or_curl_err == 0 &&
            (http_status == 200 || http_status == 201) && json_result_true) {
            return RB_RESET_LOGOUT;
        }
        if (op_id == 6 && is_err && (err_flags & 0x06u) == 0u &&
            (err_flags & 0x08u) != 0u && http_status == 404) {
            return RB_RESET_CHECK_SESSION_404;
        }
        if (op_id == 41 && is_err && (err_flags & 0x16u) == 0u &&
            (err_flags & 0x08u) != 0u && http_status == 400 && err_code == 400) {
            return RB_RESET_GUEST_400;
        }
        return RB_RESET_NONE;
    }
    if (op_id == 13 && !is_err && adi_or_curl_err == 0 &&
        (http_status == 200 || http_status == 201) && json_result_true) {
        return RB_RESET_DELETE_AVATAR;
    }
    return RB_RESET_NONE;
}

int rb_tx_is_stale(uint32_t req_tx, uint32_t fence_tx, int fence_active) {
    uint32_t diff;
    if (!fence_active || req_tx == 0u) {
        return 0;
    }
    diff = req_tx - fence_tx;
    return (diff == 0u || diff >= 0x80000000u) ? 1 : 0;
}

int rb_reauth_begin_reset(rb_reauth_state *st,
                          uint32_t cur_tx_id,
                          int park_consent_ready,
                          uint64_t *out_epoch) {
    if (!st || st->reset_epoch == UINT64_MAX) {
        return 0;
    }
    if (!st->fence_active) {
        st->fence_tx_id = cur_tx_id;
        st->fence_active = 1;
    } else {
        uint32_t diff = cur_tx_id - st->fence_tx_id;
        if (diff != 0u && diff < 0x80000000u) {
            st->fence_tx_id = cur_tx_id;
        }
    }
    st->reset_epoch++;
    st->reauth_required = 1;
    st->consent_ready_parked = park_consent_ready ? 1 : 0;
    memset(st->uuid, 0, sizeof st->uuid);
    if (out_epoch) {
        *out_epoch = st->reset_epoch;
    }
    return 1;
}

int rb_reauth_set_initial_uuid(rb_reauth_state *st, const char *uuid) {
    size_t len;
    if (!st || st->reauth_required || st->reset_epoch != 0u || !rb_valid_uuid(uuid)) {
        return 0;
    }
    len = strlen(uuid);
    memcpy(st->uuid, uuid, len + 1);
    return 1;
}

int rb_reauth_complete(rb_reauth_state *st, uint64_t epoch, const char *uuid) {
    size_t len;
    if (!st || epoch == 0u || !st->reauth_required || epoch != st->reset_epoch ||
        !rb_valid_uuid(uuid)) {
        return 0;
    }
    len = strlen(uuid);
    memcpy(st->uuid, uuid, len + 1);
    st->completed_epoch = epoch;
    st->reauth_required = 0;
    return 1;
}

int rb_reauth_on_consent_ready(rb_reauth_state *st, char *out_uuid, size_t out_cap) {
    if (!st) {
        return 0;
    }
    if (st->reauth_required || st->uuid[0] == '\0' ||
        (st->reset_epoch != 0u && st->completed_epoch != st->reset_epoch)) {
        st->consent_ready_parked = 1;
        return 0;
    }
    if (!copy_uuid_out(st->uuid, out_uuid, out_cap)) {
        return 0;
    }
    st->consent_ready_parked = 0;
    return 1;
}

int rb_reauth_poll_continuation(rb_reauth_state *st, char *out_uuid, size_t out_cap) {
    if (!st) {
        return 0;
    }
    if (st->reauth_required || !st->consent_ready_parked || !st->login_layer_alive ||
        st->uuid[0] == '\0' ||
        (st->reset_epoch != 0u && st->completed_epoch != st->reset_epoch)) {
        return 0;
    }
    if (!copy_uuid_out(st->uuid, out_uuid, out_cap)) {
        return 0;
    }
    st->consent_ready_parked = 0;
    return 1;
}

int rb_reauth_get_guest_uuid(const rb_reauth_state *st, char *out_uuid, size_t out_cap) {
    if (!st || st->reauth_required || st->uuid[0] == '\0' ||
        (st->reset_epoch != 0u && st->completed_epoch != st->reset_epoch)) {
        return 0;
    }
    return copy_uuid_out(st->uuid, out_uuid, out_cap);
}

void rb_reauth_set_login_alive(rb_reauth_state *st, int alive) {
    if (!st) {
        return;
    }
    st->login_layer_alive = alive ? 1 : 0;
}
