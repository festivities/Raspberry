package dev.raspberry.core;

/**
 * One in-memory sign-in attempt. A callback for another generation cannot finish this one.
 * Times are monotonic nanoseconds supplied by the caller.
 */
public final class Attempt {
    public static final long LIMIT_NS = 600_000_000_000L;
    public static final long TICKET_LIMIT_NS = 120_000_000_000L;

    public static final int IGNORE = 0;
    public static final int EXCHANGE = 1;
    public static final int FAIL = 2;

    /** Writes the credential. Runs under the attempt's lock, so it cannot interleave with a cancel. */
    public interface Writer {
        boolean write();
    }

    private static final int IDLE = 0;
    private static final int LIVE = 1;
    private static final int PENDING = 2;
    private static final int EXCHANGING = 3;
    private static final int DONE = 4;
    private static final int FAILED = 5;

    private int gen;
    private int phase = IDLE;
    private String state;
    private String ticket;
    private String verifier;
    private long deadline;
    private long ticketDeadline;
    private Exchange activeExchange;

    /** Short-lived in-memory exchange input. Clear it as soon as the request finishes or cancels. */
    public static final class Exchange {
        private String ticket;
        private String verifier;
        private byte[] body;

        private Exchange(String ticket, String verifier) {
            this.ticket = ticket;
            this.verifier = verifier;
        }

        public synchronized byte[] body() {
            if (ticket == null || verifier == null
                    || !AuthUrl.ticket(ticket) || !AuthUrl.verifier(verifier)) {
                return null;
            }
            if (body == null) {
                body = ("{\"ticket\":\"" + ticket + "\",\"verifier\":\"" + verifier + "\"}")
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            }
            return body;
        }

        public synchronized void clear() {
            ticket = null;
            verifier = null;
            if (body != null) {
                java.util.Arrays.fill(body, (byte) 0);
                body = null;
            }
        }
    }

    public synchronized int begin(String state, long now) {
        if (!AuthUrl.state(state)) {
            return 0;
        }
        if (phase == LIVE || phase == PENDING || phase == EXCHANGING) {
            if (now < deadline && (phase != PENDING || now < ticketDeadline)) {
                return 0;
            }
            failLocked();
        }
        this.gen++;
        this.phase = LIVE;
        this.state = state;
        this.ticket = null;
        this.verifier = null;
        this.deadline = now + LIMIT_NS;
        this.ticketDeadline = 0;
        return this.gen;
    }

    public synchronized int onCallback(int gen, Callback cb, String verifier, long now) {
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
        if (!AuthUrl.ticket(cb.ticket) || !AuthUrl.verifier(verifier)) {
            return IGNORE;
        }
        phase = PENDING;
        this.state = null;
        this.ticket = cb.ticket;
        this.verifier = verifier;
        this.ticketDeadline = Math.min(deadline, now + TICKET_LIMIT_NS);
        return EXCHANGE;
    }

    /** Claims a validated ticket once, only while both its ticket and attempt deadlines are live. */
    public synchronized Exchange claimExchange(int gen, long now, boolean ownerForeground) {
        if (gen != this.gen || phase != PENDING) {
            return null;
        }
        if (now >= deadline || now >= ticketDeadline) {
            failLocked();
            return null;
        }
        if (!ownerForeground) {
            return null;
        }
        phase = EXCHANGING;
        Exchange exchange = new Exchange(ticket, verifier);
        activeExchange = exchange;
        ticket = null;
        verifier = null;
        return exchange;
    }

    public synchronized boolean pending(int gen) {
        return gen == this.gen && phase == PENDING;
    }

    public synchronized boolean exchanging(int gen) {
        return gen == this.gen && phase == EXCHANGING;
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
        if (gen != this.gen || (phase != LIVE && phase != PENDING && phase != EXCHANGING)) {
            return false;
        }
        if (now >= deadline || (phase == PENDING && now >= ticketDeadline)) {
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
        if (now >= deadline || now >= ticketDeadline) {
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
            clearExchangeLocked();
        } else {
            failLocked();
        }
        return ok;
    }

    private void failLocked() {
        phase = FAILED;
        state = null;
        ticket = null;
        verifier = null;
        ticketDeadline = 0;
        clearExchangeLocked();
    }

    private void clearExchangeLocked() {
        if (activeExchange != null) {
            activeExchange.clear();
            activeExchange = null;
        }
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
