package dev.raspberry.core;

public final class UuidShape {
    private UuidShape() {}

    /** 8-4-4-4-12 lowercase hex. No other shape is a minted code. */
    public static boolean ok(String s) {
        if (s == null || s.length() != 36) {
            return false;
        }
        for (int i = 0; i < 36; i++) {
            char c = s.charAt(i);
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') {
                    return false;
                }
            } else if (!hex(c)) {
                return false;
            }
        }
        return true;
    }

    private static boolean hex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }
}
