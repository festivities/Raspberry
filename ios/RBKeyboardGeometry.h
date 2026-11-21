#ifndef RB_KEYBOARD_GEOMETRY_H
#define RB_KEYBOARD_GEOMETRY_H

#include <math.h>
#include <stdbool.h>

/*
 * Keyboard-notification geometry guard for the stock EAGLView handler.
 *
 * The stock -[EAGLView onUIKeyboardNotification:] scales every keyboard rect
 * by frameWidth / (beginFrame.width * contentScale / scaleX). A zero, negative
 * or non-finite begin width turns that factor into inf/NaN, the stored editor
 * rects into NaN, and a later UITextView/UITextField setFrame: into an
 * uncaught CALayer geometry exception.
 *
 * This header only decides on numbers. It never reads text, never touches
 * UIKit and keeps every already-valid component unchanged.
 */

typedef struct {
    double x;
    double y;
    double width;
    double height;
} RBKeyboardRect;

typedef enum {
    RB_KEYBOARD_GEOMETRY_UNCHANGED = 0,
    RB_KEYBOARD_GEOMETRY_SANITIZED = 1,
    RB_KEYBOARD_GEOMETRY_UNUSABLE = 2,
} RBKeyboardGeometryResult;

static inline bool rb_keyboard_width_usable(double width) {
    return isfinite(width) && width > 0.0;
}

static inline bool rb_keyboard_rect_finite(RBKeyboardRect rect) {
    return isfinite(rect.x) && isfinite(rect.y) &&
        isfinite(rect.width) && isfinite(rect.height);
}

static inline double rb_keyboard_finite_or(double value, double fallback) {
    if (isfinite(value)) {
        return value;
    }
    return isfinite(fallback) ? fallback : 0.0;
}

/*
 * Sanitize the begin and end keyboard rects of one notification.
 *
 * begin width: kept when usable, else the end width when usable, else
 * view_width when usable. If no usable width exists the notification is
 * UNUSABLE and must not reach the stock handler.
 * Other begin components: kept when finite, else the end component, else 0.
 * End components: kept when finite, else 0 (a zero-size end rect is finite
 * and the stock handler treats it as a hidden keyboard).
 *
 * Returns UNCHANGED when both rects were already usable (outputs equal
 * inputs), SANITIZED when any component was replaced.
 */
static inline RBKeyboardGeometryResult rb_keyboard_sanitize(
    RBKeyboardRect begin,
    RBKeyboardRect end,
    double view_width,
    RBKeyboardRect *begin_out,
    RBKeyboardRect *end_out) {
    if (begin_out == 0 || end_out == 0) {
        return RB_KEYBOARD_GEOMETRY_UNUSABLE;
    }
    *begin_out = begin;
    *end_out = end;
    if (rb_keyboard_rect_finite(begin) &&
        rb_keyboard_width_usable(begin.width) &&
        rb_keyboard_rect_finite(end)) {
        return RB_KEYBOARD_GEOMETRY_UNCHANGED;
    }

    RBKeyboardRect fixed_end = {
        rb_keyboard_finite_or(end.x, 0.0),
        rb_keyboard_finite_or(end.y, 0.0),
        rb_keyboard_finite_or(end.width, 0.0),
        rb_keyboard_finite_or(end.height, 0.0),
    };

    double width;
    if (rb_keyboard_width_usable(begin.width)) {
        width = begin.width;
    } else if (rb_keyboard_width_usable(end.width)) {
        width = end.width;
    } else if (rb_keyboard_width_usable(view_width)) {
        width = view_width;
    } else {
        return RB_KEYBOARD_GEOMETRY_UNUSABLE;
    }

    RBKeyboardRect fixed_begin = {
        rb_keyboard_finite_or(begin.x, fixed_end.x),
        rb_keyboard_finite_or(begin.y, fixed_end.y),
        width,
        rb_keyboard_finite_or(begin.height, fixed_end.height),
    };
    *begin_out = fixed_begin;
    *end_out = fixed_end;
    return RB_KEYBOARD_GEOMETRY_SANITIZED;
}

/* Editor TracePosition inputs: all four must be finite to reach UIKit. */
static inline bool rb_keyboard_trace_inputs_finite(
    float x, float y, float width, float height) {
    return isfinite(x) && isfinite(y) && isfinite(width) && isfinite(height);
}

#endif
