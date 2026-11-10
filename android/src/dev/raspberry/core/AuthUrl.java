package dev.raspberry.core;

public final class AuthUrl {
    private AuthUrl() {}

    /** Loopback return. Null when the port is outside 1024..65535. */
    public static String loopback(int port) {
        if (port < 1024 || port > 65535) {
            return null;
        }
        String s = "http://127.0.0.1:" + port + "/raspberry/cb";
        if (s.length() > 64) {
            return null;
        }
        return s;
    }

    public static String start(Descriptor d, String challenge, String ret, String state) {
        if (d == null || !challenge(challenge) || ret == null || !state(state)) {
            return null;
        }
        if (ret.length() > 64 || ret.indexOf('\r') >= 0 || ret.indexOf('\n') >= 0) {
            return null;
        }
        String c = enc(challenge);
        String r = enc(ret);
        String st = enc(state);
        if (c == null || r == null || st == null) {
            return null;
        }
        return "https://" + d.httpsAuthority() + "/auth/v1/discord/start?challenge="
                + c + "&return=" + r + "&state=" + st;
    }

    public static String exchange(Descriptor d) {
        if (d == null) {
            return null;
        }
        return "https://" + d.httpsAuthority() + "/auth/v1/exchange";
    }

    /** PKCE challenge, verifier, and ticket: base64url of 32 bytes, no padding. */
    public static boolean challenge(String s) {
        return token(s, 43, 43);
    }

    public static boolean verifier(String s) {
        return challenge(s);
    }

    public static boolean ticket(String s) {
        return challenge(s);
    }

    /** Client state. Server rejects outside 16..64. */
    public static boolean state(String s) {
        return token(s, 16, 64);
    }

    /** Safe to embed in a JSON string we build ourselves. Length is the field rule. */
    public static boolean token(String s, int min, int max) {
        if (s == null || s.length() < min || s.length() > max) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    static String enc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean raw = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~';
            if (raw) {
                b.append(c);
            } else {
                if (c > 127) {
                    return null;
                }
                b.append('%');
                b.append(hex(c >>> 4));
                b.append(hex(c & 15));
            }
        }
        return b.toString();
    }

    private static char hex(int n) {
        return "0123456789ABCDEF".charAt(n);
    }
}
