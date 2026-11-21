package dev.raspberry.core;

/**
 * Process-wide monotonic reset and re-auth coordinator.
 *
 * <p>Native session/auth resets advance {@code resetEpoch} synchronously and latch
 * {@code reauthRequired}. Any OAuth attempt captured under an earlier epoch is fenced
 * before credential storage or native re-auth completion.
 */
public final class ReauthState {
    public static final int REASON_LOGOUT = 1;
    public static final int REASON_DELETE_AVATAR = 2;
    public static final int REASON_CHECK_SESSION_404 = 3;
    public static final int REASON_GUEST_400 = 4;

    /** Narrow credential/cookie cleanup target for re-auth resets. */
    public interface AuthStore {
        boolean clearCookie();

        boolean clearPrefsAndVerify();
    }

    private long resetEpoch;
    private boolean reauthRequired;
    private boolean cleanupVerified;

    public static boolean validReason(int reason) {
        return reason >= REASON_LOGOUT && reason <= REASON_GUEST_400;
    }

    /** Clears only the session cookie and auth preferences; fails closed unless both succeed. */
    public static boolean clearNarrowly(AuthStore store) {
        if (store == null) {
            return false;
        }
        boolean cookieOk = store.clearCookie();
        boolean prefsOk = store.clearPrefsAndVerify();
        return cookieOk && prefsOk;
    }

    public synchronized long currentEpoch() {
        return resetEpoch;
    }

    public synchronized boolean isRequired() {
        return reauthRequired;
    }

    public synchronized boolean isCleanupVerified() {
        return cleanupVerified;
    }

    /**
     * Latches a new monotonic reset epoch for a closed reason code.
     * Invalid or stale epochs are ignored.
     */
    public synchronized boolean beginReset(long epoch, int reason) {
        if (epoch <= 0 || !validReason(reason) || epoch <= resetEpoch) {
            return false;
        }
        resetEpoch = epoch;
        reauthRequired = true;
        cleanupVerified = false;
        return true;
    }

    /** Records storage cleanup verification for the active reset epoch only. */
    public synchronized boolean markCleanupResult(long epoch, boolean ok) {
        if (!reauthRequired || epoch <= 0 || epoch != resetEpoch) {
            return false;
        }
        cleanupVerified = ok;
        return true;
    }

    public synchronized boolean canStartAuth() {
        return !reauthRequired || cleanupVerified;
    }

    public synchronized boolean canCommit(long expectedEpoch) {
        return expectedEpoch == resetEpoch;
    }

    public synchronized boolean canComplete(long expectedEpoch) {
        return reauthRequired && cleanupVerified && expectedEpoch == resetEpoch;
    }

    /** Clears {@code reauthRequired} only if cleanup is verified and the epoch still matches. */
    public synchronized boolean completeReauth(long expectedEpoch) {
        if (!canComplete(expectedEpoch)) {
            return false;
        }
        reauthRequired = false;
        return true;
    }
}
