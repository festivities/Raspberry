#include "RBKeyboardGeometry.h"

#include <math.h>
#include <stdio.h>

static int failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__,         \
                    __LINE__, #cond);                                      \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static int same_rect(RBKeyboardRect a, RBKeyboardRect b) {
    return a.x == b.x && a.y == b.y && a.width == b.width &&
        a.height == b.height;
}

static RBKeyboardRect rect(double x, double y, double w, double h) {
    RBKeyboardRect r = {x, y, w, h};
    return r;
}

/* Stock scale factor, reduced to the begin-width dependence that matters. */
static double stock_factor(double frame_width, RBKeyboardRect begin) {
    return frame_width / begin.width;
}

static void test_valid_rects_unchanged(void) {
    RBKeyboardRect begin = rect(0, 932, 430, 336);
    RBKeyboardRect end = rect(0, 596, 430, 336);
    RBKeyboardRect b = rect(-1, -1, -1, -1);
    RBKeyboardRect e = rect(-1, -1, -1, -1);
    CHECK(rb_keyboard_sanitize(begin, end, 430, &b, &e) ==
          RB_KEYBOARD_GEOMETRY_UNCHANGED);
    CHECK(same_rect(b, begin));
    CHECK(same_rect(e, end));
}

static void test_zero_begin_uses_end_width(void) {
    RBKeyboardRect begin = rect(0, 0, 0, 0);
    RBKeyboardRect end = rect(0, 596, 430, 336);
    RBKeyboardRect b, e;
    /* Without the guard the stock factor is inf and 0 * inf is NaN. */
    CHECK(isinf(stock_factor(1290, begin)));
    CHECK(isnan(end.x * stock_factor(1290, begin)));
    CHECK(rb_keyboard_sanitize(begin, end, 390, &b, &e) ==
          RB_KEYBOARD_GEOMETRY_SANITIZED);
    CHECK(b.width == 430);
    CHECK(b.x == 0 && b.y == 0 && b.height == 0);
    CHECK(same_rect(e, end));
    CHECK(isfinite(stock_factor(1290, b)));
    CHECK(isfinite(e.x * stock_factor(1290, b)));
}

static void test_zero_begin_and_end_width_uses_view(void) {
    RBKeyboardRect b, e;
    CHECK(rb_keyboard_sanitize(rect(0, 844, 0, 0), rect(0, 844, 0, 0), 390,
                               &b, &e) == RB_KEYBOARD_GEOMETRY_SANITIZED);
    CHECK(b.width == 390);
    CHECK(b.y == 844);
    CHECK(e.width == 0);
}

static void test_negative_begin_width_replaced(void) {
    RBKeyboardRect b, e;
    CHECK(rb_keyboard_sanitize(rect(0, 0, -430, 336), rect(0, 596, 430, 336),
                               430, &b, &e) == RB_KEYBOARD_GEOMETRY_SANITIZED);
    CHECK(b.width == 430);
}

static void test_non_finite_components(void) {
    RBKeyboardRect b, e;
    CHECK(rb_keyboard_sanitize(rect(NAN, INFINITY, 430, NAN),
                               rect(1, 596, 430, 336), 430, &b, &e) ==
          RB_KEYBOARD_GEOMETRY_SANITIZED);
    CHECK(b.x == 1 && b.y == 596 && b.width == 430 && b.height == 336);
    CHECK(rb_keyboard_sanitize(rect(0, 932, 430, 336),
                               rect(NAN, 596, INFINITY, -INFINITY), 430, &b,
                               &e) == RB_KEYBOARD_GEOMETRY_SANITIZED);
    CHECK(same_rect(b, rect(0, 932, 430, 336)));
    CHECK(e.x == 0 && e.y == 596 && e.width == 0 && e.height == 0);
    CHECK(rb_keyboard_sanitize(rect(NAN, NAN, NAN, NAN),
                               rect(NAN, NAN, NAN, NAN), 390, &b, &e) ==
          RB_KEYBOARD_GEOMETRY_SANITIZED);
    CHECK(rb_keyboard_rect_finite(b) && rb_keyboard_rect_finite(e));
    CHECK(b.width == 390);
}

static void test_unusable(void) {
    RBKeyboardRect b = rect(7, 7, 7, 7);
    RBKeyboardRect e = rect(7, 7, 7, 7);
    CHECK(rb_keyboard_sanitize(rect(0, 0, 0, 0), rect(0, 0, 0, 0), 0, &b,
                               &e) == RB_KEYBOARD_GEOMETRY_UNUSABLE);
    CHECK(rb_keyboard_sanitize(rect(0, 0, 0, 0), rect(0, 0, NAN, 0), NAN, &b,
                               &e) == RB_KEYBOARD_GEOMETRY_UNUSABLE);
    CHECK(rb_keyboard_sanitize(rect(0, 0, 430, 0), rect(0, 0, 430, 0), 430,
                               0, &e) == RB_KEYBOARD_GEOMETRY_UNUSABLE);
    CHECK(rb_keyboard_sanitize(rect(0, 0, 430, 0), rect(0, 0, 430, 0), 430,
                               &b, 0) == RB_KEYBOARD_GEOMETRY_UNUSABLE);
}

static void test_trace_inputs(void) {
    CHECK(rb_keyboard_trace_inputs_finite(10.0f, 20.0f, 300.0f, 40.0f));
    CHECK(rb_keyboard_trace_inputs_finite(-10.0f, 0.0f, 0.0f, 0.0f));
    CHECK(!rb_keyboard_trace_inputs_finite(NAN, 20.0f, 300.0f, 40.0f));
    CHECK(!rb_keyboard_trace_inputs_finite(10.0f, INFINITY, 300.0f, 40.0f));
    CHECK(!rb_keyboard_trace_inputs_finite(10.0f, 20.0f, -INFINITY, 40.0f));
    CHECK(!rb_keyboard_trace_inputs_finite(10.0f, 20.0f, 300.0f, NAN));
}

int main(void) {
    test_valid_rects_unchanged();
    test_zero_begin_uses_end_width();
    test_zero_begin_and_end_width_uses_view();
    test_negative_begin_width_replaced();
    test_non_finite_components();
    test_unusable();
    test_trace_inputs();
    if (failures != 0) {
        fprintf(stderr, "RBKeyboardGeometry_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("RBKeyboardGeometry_test: ok\n");
    return 0;
}
