package dev.raspberry.core;

/** Optional asset devPinSha256: 64 hex chars, SHA-256 of the endpoint leaf DER. Blank means absent. */
public final class HexPin {
    private HexPin() {}

    public static byte[] parse(String text) {
        if (text == null) {
            return null;
        }
        String s = text.trim();
        if (s.length() == 0) {
            return null;
        }
        if (s.length() != 64) {
            throw new IllegalArgumentException("pin");
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            int h = Json.hex(s.charAt(i * 2));
            int l = Json.hex(s.charAt(i * 2 + 1));
            if (h < 0 || l < 0) {
                throw new IllegalArgumentException("pin");
            }
            out[i] = (byte) ((h << 4) | l);
        }
        return out;
    }

    public static boolean eq(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int d = 0;
        for (int i = 0; i < a.length; i++) {
            d |= (a[i] ^ b[i]) & 255;
        }
        return d == 0;
    }
}
