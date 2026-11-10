package dev.raspberry.core;

import java.io.File;

/** Clears only the stock client's persisted session cookie before a fresh authorization. */
public final class SessionCookie {
    private SessionCookie() {}

    public static boolean clear(File filesDir) {
        if (filesDir == null) {
            return false;
        }
        File cookie = new File(filesDir, "avcookie.na");
        try {
            return !cookie.exists() || (cookie.isFile() && cookie.delete());
        } catch (RuntimeException e) {
            return false;
        }
    }
}
