package dev.raspberry.core;

import java.io.IOException;

/** Origin-scoped reset for the notice SDK's list cache. */
public final class NoticeMigration {
    public static final String DATABASE = "linenotice_pref.db";
    public static final String PREFERENCES = "line_notice_pref";
    public static final String ORIGIN_KEY = "raspberry.notice.origin";

    private static final String[] TABLES = {"notification_pref", "notification_image"};
    private static final String[] KEYS = {
            "notice_last_revision",
            "board_request_timestamp_notice",
            "notice_server_timestamp",
            "notice_local_timestamp"
    };

    private NoticeMigration() {}

    public interface Store {
        String origin() throws IOException;
        void clearTables(String database, String[] tables) throws IOException;
        void removePreferences(String preferences, String[] keys) throws IOException;
        void writeOrigin(String origin) throws IOException;
    }

    /** Returns false only for a committed matching origin; retry ignores an in-memory failed marker. */
    public static boolean prepare(String origin, boolean retry, Store store) throws IOException {
        if (origin == null || origin.length() == 0 || store == null) {
            throw new IOException("notice migration unavailable");
        }
        if (!retry && origin.equals(store.origin())) {
            return false;
        }
        store.clearTables(DATABASE, TABLES.clone());
        store.removePreferences(PREFERENCES, KEYS.clone());
        store.writeOrigin(origin);
        return true;
    }
}
