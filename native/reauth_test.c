#include "reauth.c"

#include <stdio.h>
#include <string.h>

static int g_fails;

static void check(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "fail: %s\n", msg);
        g_fails++;
    }
}

static void test_uuid_validation(void) {
    char max_ok[RB_UUID_MAX + 1];
    char too_long[RB_UUID_MAX + 2];
    memset(max_ok, 'a', RB_UUID_MAX);
    max_ok[RB_UUID_MAX] = '\0';
    memset(too_long, 'b', RB_UUID_MAX + 1);
    too_long[RB_UUID_MAX + 1] = '\0';

    check(!rb_valid_uuid(NULL), "null uuid");
    check(!rb_valid_uuid(""), "empty uuid");
    check(rb_valid_uuid("550e8400-e29b-41d4-a716-446655440000"), "standard uuid");
    check(rb_valid_uuid(max_ok), "max length 128 accepted");
    check(!rb_valid_uuid(too_long), "length 129 rejected");
    check(!rb_valid_uuid("abc\ndef"), "newline rejected");
    check(!rb_valid_uuid("abc\x7f"), "del 0x7f rejected");
    check(!rb_valid_uuid("abc\x80"), "non-ascii 0x80 rejected");
    check(!rb_valid_uuid("abc\x1f"), "ctrl 0x1f rejected");
}

static void test_classifier(void) {
    /* Trigger 1: Logout */
    check(rb_classify_dispatch(0, 14, 0, 0, 200, 0, 0, 1) == RB_RESET_LOGOUT, "logout 200 true");
    check(rb_classify_dispatch(0, 14, 0, 0, 201, 0, 0, 1) == RB_RESET_LOGOUT, "logout 201 true");
    check(rb_classify_dispatch(0, 14, 0, 0, 200, 0, 0, 0) == RB_RESET_NONE, "logout result false");
    check(rb_classify_dispatch(0, 14, 1, 0, 200, 0, 0, 1) == RB_RESET_NONE, "logout is_err");
    check(rb_classify_dispatch(0, 14, 0, 1, 200, 0, 0, 1) == RB_RESET_NONE, "logout adi err");
    check(rb_classify_dispatch(0, 14, 0, 0, 500, 0, 0, 1) == RB_RESET_NONE, "logout 500");
    check(rb_classify_dispatch(1, 14, 0, 0, 200, 0, 0, 1) == RB_RESET_NONE, "logout wrong dispatcher");

    /* Trigger 2: DeleteAvatar (op 13) and op 12 exclusion */
    check(rb_classify_dispatch(1, 13, 0, 0, 200, 0, 0, 1) == RB_RESET_DELETE_AVATAR, "delete avatar 200");
    check(rb_classify_dispatch(1, 13, 0, 0, 201, 0, 0, 1) == RB_RESET_DELETE_AVATAR, "delete avatar 201");
    check(rb_classify_dispatch(1, 12, 0, 0, 200, 0, 0, 1) == RB_RESET_NONE, "op 12 MUST NOT trigger");
    check(rb_classify_dispatch(1, 13, 0, 0, 200, 0, 0, 0) == RB_RESET_NONE, "delete avatar result false");
    check(rb_classify_dispatch(1, 13, 1, 0, 200, 0, 0, 1) == RB_RESET_NONE, "delete avatar is_err");
    check(rb_classify_dispatch(1, 13, 0, 7, 200, 0, 0, 1) == RB_RESET_NONE, "delete avatar curl err");
    check(rb_classify_dispatch(1, 13, 0, 0, 404, 0, 0, 1) == RB_RESET_NONE, "delete avatar 404");
    check(rb_classify_dispatch(0, 13, 0, 0, 200, 0, 0, 1) == RB_RESET_NONE, "delete avatar common disp");

    /* Trigger 3: checkSession 404 */
    check(rb_classify_dispatch(0, 6, 1, 0, 404, 0x18u, 0, 0) == RB_RESET_CHECK_SESSION_404,
          "checkSession 404 with 0x18 flags");
    check(rb_classify_dispatch(0, 6, 1, 0, 404, 0x08u, 0, 0) == RB_RESET_CHECK_SESSION_404,
          "checkSession 404 with 0x08 flags");
    check(rb_classify_dispatch(0, 6, 1, 0, 404, 0x0Au, 0, 0) == RB_RESET_NONE,
          "checkSession 404 with ADI flag 0x02 excluded");
    check(rb_classify_dispatch(0, 6, 1, 0, 404, 0x0Cu, 0, 0) == RB_RESET_NONE,
          "checkSession 404 with CURL flag 0x04 excluded");
    check(rb_classify_dispatch(0, 6, 1, 0, 404, 0x00u, 0, 0) == RB_RESET_NONE,
          "checkSession 404 missing HTTP flag 0x08 excluded");
    check(rb_classify_dispatch(0, 6, 1, 0, 500, 0x08u, 0, 0) == RB_RESET_NONE, "checkSession 500");
    check(rb_classify_dispatch(0, 6, 1, 0, 401, 0x08u, 0, 0) == RB_RESET_NONE, "checkSession 401");
    check(rb_classify_dispatch(0, 6, 0, 0, 404, 0x18u, 0, 0) == RB_RESET_NONE, "checkSession !is_err");
    check(rb_classify_dispatch(1, 6, 1, 0, 404, 0x18u, 0, 0) == RB_RESET_NONE, "checkSession avatar disp");

    /* Trigger 4: guest/generate 400 + errorCode 400 */
    check(rb_classify_dispatch(0, 41, 1, 0, 400, 0x08u, 400, 0) == RB_RESET_GUEST_400,
          "guest 400 + err_code 400");
    check(rb_classify_dispatch(0, 41, 1, 0, 400, 0x18u, 400, 0) == RB_RESET_NONE,
          "guest 400 with json parse fail 0x10 excluded");
    check(rb_classify_dispatch(0, 41, 1, 0, 400, 0x0Au, 400, 0) == RB_RESET_NONE,
          "guest 400 with ADI flag 0x02 excluded");
    check(rb_classify_dispatch(0, 41, 1, 0, 400, 0x0Cu, 400, 0) == RB_RESET_NONE,
          "guest 400 with CURL flag 0x04 excluded");
    check(rb_classify_dispatch(0, 41, 1, 0, 400, 0x00u, 400, 0) == RB_RESET_NONE,
          "guest 400 missing HTTP flag 0x08 excluded");
    check(rb_classify_dispatch(0, 41, 1, 0, 400, 0x08u, 2013, 0) == RB_RESET_NONE,
          "guest 400 err_code 2013 excluded");
    check(rb_classify_dispatch(0, 41, 1, 0, 504, 0x08u, 400, 0) == RB_RESET_NONE,
          "guest 504 excluded");
    check(rb_classify_dispatch(0, 41, 0, 0, 400, 0x08u, 400, 0) == RB_RESET_NONE,
          "guest !is_err excluded");
    check(rb_classify_dispatch(1, 41, 1, 0, 400, 0x08u, 400, 0) == RB_RESET_NONE,
          "guest avatar disp excluded");
}

static void test_tx_fence(void) {
    check(!rb_tx_is_stale(10u, 20u, 0), "inactive fence never stale");
    check(!rb_tx_is_stale(0u, 20u, 1), "tx 0 ignored");
    check(rb_tx_is_stale(20u, 20u, 1), "equal to fence is stale");
    check(rb_tx_is_stale(19u, 20u, 1), "below fence is stale");
    check(!rb_tx_is_stale(21u, 20u, 1), "above fence is fresh");

    /* 32-bit wrap-around cases */
    check(rb_tx_is_stale(0xFFFFFFFEu, 2u, 1), "pre-wrap tx stale against post-wrap fence");
    check(rb_tx_is_stale(0xFFFFFFFFu, 1u, 1), "0xFFFFFFFF stale against fence 1");
    check(!rb_tx_is_stale(2u, 0xFFFFFFFEu, 1), "post-wrap tx fresh against pre-wrap fence");
    check(!rb_tx_is_stale(1u, 0xFFFFFFFFu, 1), "tx 1 fresh against fence 0xFFFFFFFF");
}

static void test_state_machine(void) {
    rb_reauth_state st;
    char buf[RB_UUID_MAX + 1];
    uint64_t epoch = 0;

    rb_reauth_init(&st);
    check(st.reset_epoch == 0 && !st.reauth_required && !st.fence_active, "init zeroed");

    /* Fail-closed before initial UUID */
    check(!rb_reauth_get_guest_uuid(&st, buf, sizeof buf), "empty uuid fails closed");
    check(!rb_reauth_on_consent_ready(&st, buf, sizeof buf), "consent before uuid parks");
    check(st.consent_ready_parked == 1, "parked set");

    /* Set initial UUID before any reset */
    check(!rb_reauth_set_initial_uuid(&st, ""), "empty initial uuid rejected");
    check(rb_reauth_set_initial_uuid(&st, "init-uuid-1"), "initial uuid set");
    check(rb_reauth_get_guest_uuid(&st, buf, sizeof buf) && strcmp(buf, "init-uuid-1") == 0,
          "get_guest_uuid returns initial uuid");
    check(!rb_reauth_poll_continuation(&st, buf, sizeof buf),
          "poll requires login_layer_alive");

    rb_reauth_set_login_alive(&st, 1);
    check(rb_reauth_poll_continuation(&st, buf, sizeof buf) && strcmp(buf, "init-uuid-1") == 0,
          "poll succeeds once login_layer_alive and parked");
    check(st.consent_ready_parked == 0, "poll clears consent_ready_parked one-shot");
    check(!rb_reauth_poll_continuation(&st, buf, sizeof buf), "second poll is one-shot no-op");

    /* Consent ready directly proceeds when not in reauth */
    check(rb_reauth_on_consent_ready(&st, buf, sizeof buf) && strcmp(buf, "init-uuid-1") == 0,
          "on_consent_ready proceeds with initial uuid");
    check(st.consent_ready_parked == 0, "not parked");

    /* Begin reset 1 (e.g. Logout, not yet on login scene) */
    check(rb_reauth_begin_reset(&st, 100u, 0, &epoch) && epoch == 1u, "begin reset epoch 1");
    check(st.reauth_required == 1 && st.fence_active == 1 && st.fence_tx_id == 100u, "reset state");
    check(st.uuid[0] == '\0', "uuid cleared on reset");
    check(!rb_reauth_get_guest_uuid(&st, buf, sizeof buf), "guest uuid blocked during reauth");
    check(!rb_reauth_set_initial_uuid(&st, "late-init"), "initial uuid blocked after reset_epoch > 0");

    /* Monotonic fence ignores backwards tx_id */
    check(rb_reauth_begin_reset(&st, 50u, 0, &epoch) && epoch == 2u, "begin reset epoch 2");
    check(st.fence_tx_id == 100u, "fence did not regress from 100 to 50");

    /* Monotonic fence advances across wrap (stepping within 2^31 window) */
    check(rb_reauth_begin_reset(&st, 0x70000100u, 0, &epoch) && epoch == 3u, "epoch 3");
    check(st.fence_tx_id == 0x70000100u, "fence advanced to 0x70000100");
    check(rb_reauth_begin_reset(&st, 0xD0000000u, 0, &epoch) && epoch == 4u, "epoch 4");
    check(st.fence_tx_id == 0xD0000000u, "fence advanced to 0xD0000000");
    check(rb_reauth_begin_reset(&st, 0xFFFFFFFCu, 0, &epoch) && epoch == 5u, "epoch 5");
    check(st.fence_tx_id == 0xFFFFFFFCu, "fence advanced to 0xFFFFFFFC");
    check(rb_reauth_begin_reset(&st, 5u, 0, &epoch) && epoch == 6u, "epoch 6 wrap");
    check(st.fence_tx_id == 5u, "fence advanced across 32-bit wrap");
    check(rb_reauth_begin_reset(&st, 0xFFFFFFFEu, 0, &epoch) && epoch == 7u, "epoch 7");
    check(st.fence_tx_id == 5u, "pre-wrap tx does not regress post-wrap fence");

    /* Consent arrives while reauth_required -> parks */
    check(!rb_reauth_on_consent_ready(&st, buf, sizeof buf), "consent parks during reauth");
    check(st.consent_ready_parked == 1, "parked set during reauth");
    check(!rb_reauth_poll_continuation(&st, buf, sizeof buf), "poll blocked during reauth");

    /* Stale/invalid epoch completions rejected */
    check(!rb_reauth_complete(&st, 0u, "fresh-uuid-7"), "epoch 0 rejected");
    check(!rb_reauth_complete(&st, 6u, "fresh-uuid-7"), "stale epoch 6 rejected");
    check(!rb_reauth_complete(&st, 8u, "fresh-uuid-7"), "future epoch 8 rejected");
    check(!rb_reauth_complete(&st, 7u, ""), "empty uuid rejected");
    check(st.reauth_required == 1, "still requiring reauth after rejected completes");

    /* Valid completion */
    check(rb_reauth_complete(&st, 7u, "fresh-uuid-7"), "matching epoch 7 accepted");
    check(st.reauth_required == 0 && st.completed_epoch == 7u, "completed_epoch recorded");
    check(!rb_reauth_complete(&st, 7u, "fresh-uuid-7-dup"), "duplicate complete rejected");

    /* Poll requires login_layer_alive */
    rb_reauth_set_login_alive(&st, 0);
    check(!rb_reauth_poll_continuation(&st, buf, sizeof buf), "poll blocked while login layer dead");
    check(st.consent_ready_parked == 1, "still parked while login layer dead");

    rb_reauth_set_login_alive(&st, 1);
    check(rb_reauth_poll_continuation(&st, buf, sizeof buf) && strcmp(buf, "fresh-uuid-7") == 0,
          "poll fires once login layer alive");
    check(st.consent_ready_parked == 0, "one-shot cleared");
    check(!rb_reauth_poll_continuation(&st, buf, sizeof buf), "one-shot does not re-fire");

    /* Trigger 3/4 park_consent_ready=1 case */
    check(rb_reauth_begin_reset(&st, 10u, 1, &epoch) && epoch == 8u, "epoch 8 with immediate park");
    check(st.consent_ready_parked == 1, "parked immediately");
    check(rb_reauth_complete(&st, 8u, "fresh-uuid-8"), "epoch 8 complete");
    check(rb_reauth_poll_continuation(&st, buf, sizeof buf) && strcmp(buf, "fresh-uuid-8") == 0,
          "poll fires after trigger 3/4 reauth complete");

    /* Small output buffer fails closed without clearing parked */
    check(rb_reauth_begin_reset(&st, 11u, 1, &epoch) && epoch == 9u, "epoch 9");
    check(rb_reauth_complete(&st, 9u, "fresh-uuid-9"), "epoch 9 complete");
    check(!rb_reauth_poll_continuation(&st, buf, 4), "small buffer fails closed");
    check(st.consent_ready_parked == 1, "parked preserved on buffer error");
    check(!rb_reauth_get_guest_uuid(&st, buf, 4), "get_guest_uuid small buffer fails closed");
}

static void test_same_process_reauth_continuation(void) {
    rb_reauth_state st;
    char buf[RB_UUID_MAX + 1];
    uint64_t epoch = 0;

    rb_reauth_init(&st);
    check(rb_reauth_begin_reset(&st, 42u, 1, &epoch) && epoch == 1u,
          "reentry begin_reset parks consent");
    rb_reauth_set_login_alive(&st, 1);
    check(!rb_reauth_poll_continuation(&st, buf, sizeof buf),
          "reentry poll waits until complete");

    check(rb_reauth_complete(&st, epoch, "fresh-uuid-reentry"),
          "reentry complete accepts fresh uuid");
    check(rb_reauth_poll_continuation(&st, buf, sizeof buf) &&
              strcmp(buf, "fresh-uuid-reentry") == 0,
          "reentry poll fires immediately with fresh uuid");
    check(st.consent_ready_parked == 0, "reentry poll clears parked");
    check(!rb_reauth_poll_continuation(&st, buf, sizeof buf),
          "reentry second poll returns 0 (one-shot)");
}

int main(void) {
    test_uuid_validation();
    test_classifier();
    test_tx_fence();
    test_state_machine();
    test_same_process_reauth_continuation();
    if (g_fails) {
        fprintf(stderr, "%d failed\n", g_fails);
        return 1;
    }
    return 0;
}
