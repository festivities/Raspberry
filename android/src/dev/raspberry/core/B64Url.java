package dev.raspberry.core;

final class B64Url {
    private static final char[] T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();

    private B64Url() {}

    static String enc(byte[] in) {
        char[] out = new char[(in.length * 4 + 2) / 3];
        int i = 0;
        int o = 0;
        while (i + 3 <= in.length) {
            int n = ((in[i] & 255) << 16) | ((in[i + 1] & 255) << 8) | (in[i + 2] & 255);
            out[o++] = T[(n >>> 18) & 63];
            out[o++] = T[(n >>> 12) & 63];
            out[o++] = T[(n >>> 6) & 63];
            out[o++] = T[n & 63];
            i += 3;
        }
        if (i < in.length) {
            int n = (in[i] & 255) << 16;
            if (i + 1 < in.length) {
                n |= (in[i + 1] & 255) << 8;
            }
            out[o++] = T[(n >>> 18) & 63];
            out[o++] = T[(n >>> 12) & 63];
            if (i + 1 < in.length) {
                out[o++] = T[(n >>> 6) & 63];
            }
        }
        return new String(out, 0, o);
    }

    static byte[] dec(String s) {
        if (s == null || s.length() == 0 || (s.length() & 3) == 1) {
            return null;
        }
        int pad = (4 - (s.length() & 3)) & 3;
        int outLen = ((s.length() + pad) / 4) * 3 - pad;
        byte[] out = new byte[outLen];
        int o = 0;
        int buf = 0;
        int bits = 0;
        for (int i = 0; i < s.length(); i++) {
            int v = val(s.charAt(i));
            if (v < 0) {
                return null;
            }
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = (byte) ((buf >>> bits) & 255);
            }
        }
        if (o != outLen) {
            return null;
        }
        return out;
    }

    private static int val(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '-') {
            return 62;
        }
        if (c == '_') {
            return 63;
        }
        return -1;
    }
}
