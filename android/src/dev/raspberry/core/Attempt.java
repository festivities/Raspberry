package dev.raspberry.core;

/**
 * One in-memory sign-in attempt. A callback for another generation cannot finish this one.
 * Times are monotonic nanoseconds supplied by the caller.
 */
public final class Attempt {
    public static final long LIMIT_NS = 600_000_000_000L;

    public static final int IGNORE = 0;
    public static final int EXCHANGE = 1;
    public static final int FAIL = 2;

    /** Writes the credential. Runs under the attempt's lock, so it cannot interleave with a cancel. */
    public interface Writer {
        boolean write();
    }

    private static final int IDLE = 0;
    private static final int LIVE = 1;
    private static final int EXCHANGING = 2;
    private static final int DONE = 3;
    private static final int FAILED = 4;

    private int gen;
    private int phase = IDLE;
    private String state;
    private long deadline;

    public synchronized int begin(String state, long now) {
        if (!AuthUrl.state(state)) {
            return 0;
        }
        if (phase == LIVE || phase == EXCHANGING) {
            return 0;
        }
        this.gen++;
        this.phase = LIVE;
        this.state = state;
        this.deadline = now + LIMIT_NS;
        return this.gen;
    }

    public synchronized int onCallback(int gen, Callback cb, long now) {
        if (cb == null || gen != this.gen || phase != LIVE) {
            return IGNORE;
        }
        if (now >= deadline) {
            failLocked();
            return FAIL;
        }
        if (!eq(state, cb.state)) {
            return IGNORE;
        }
        if (cb.error != null) {
            failLocked();
            return FAIL;
        }
        if (cb.ticket == null) {
            return IGNORE;
        }
        phase = EXCHANGING;
        this.state = null;
        return EXCHANGE;
    }

    public synchronized void fail(int gen) {
        if (gen == this.gen && phase != DONE) {
            failLocked();
        }
    }

    /** Drops the live attempt. Does not start another. */
    public synchronized void cancel(int gen) {
        if (gen == this.gen && phase != DONE) {
            failLocked();
            this.gen++;
        }
    }

    /**
     * Usable now: this generation, unfinished, and before the deadline. An attempt that ran
     * past its deadline is failed here, so no live phase outlives it and a retry can begin.
     */
    public synchronized boolean live(int gen, long now) {
        if (gen != this.gen || (phase != LIVE && phase != EXCHANGING)) {
            return false;
        }
        if (now >= deadline) {
            failLocked();
            return false;
        }
        return true;
    }

    /**
     * Stores the credential only while this exact generation is still exchanging and in time.
     * The writer runs under this monitor: a cancel cannot land between the check and the store.
     * A false or throwing writer fails the attempt.
     */
    public synchronized boolean commit(int gen, long now, Writer writer) {
        if (writer == null || gen != this.gen || phase != EXCHANGING) {
            return false;
        }
        if (now >= deadline) {
            failLocked();
            return false;
        }
        boolean ok;
        try {
            ok = writer.write();
        } catch (RuntimeException e) {
            ok = false;
        }
        if (ok) {
            phase = DONE;
            state = null;
        } else {
            failLocked();
        }
        return ok;
    }

    private void failLocked() {
        phase = FAILED;
        state = null;
    }

    static boolean eq(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        int n = Math.max(a.length(), b.length());
        int d = a.length() ^ b.length();
        for (int i = 0; i < n; i++) {
            char ca = i < a.length() ? a.charAt(i) : 0;
            char cb = i < b.length() ? b.charAt(i) : 0;
            d |= ca ^ cb;
        }
        return d == 0;
    }
}
