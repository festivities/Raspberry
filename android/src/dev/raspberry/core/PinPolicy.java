package dev.raspberry.core;

/**
 * Optional pin is an extra check. It never replaces platform trust or hostname verification.
 */
public final class PinPolicy {
    private PinPolicy() {}

    /**
     * Accept only when platform trust and platform hostname verification both passed
     * and the leaf DER SHA-256 equals the pin. A local hostname guess is not a substitute.
     */
    public static boolean accept(boolean platformTrusted, boolean platformHostname, byte[] leafSha256, byte[] pin) {
        if (!platformTrusted || !platformHostname) {
            return false;
        }
        return HexPin.eq(leafSha256, pin);
    }
}
