package dev.raspberry.core;

import java.util.Locale;
import java.util.Map;

/**
 * v1 endpoint descriptor. Unknown top-level keys are ignored and never copied
 * into errors. Duplicate keys are rejected (JSONObject would keep the last).
 */
public final class Descriptor {
    public static final int MAX_CHARS = 64 * 1024;

    private final String host;
    private final int p80;
    private final int p443;
    private final int p10000;
    private final int p10123;

    private Descriptor(String host, int p80, int p443, int p10000, int p10123) {
        this.host = host;
        this.p80 = p80;
        this.p443 = p443;
        this.p10000 = p10000;
        this.p10123 = p10123;
    }

    public String host() {
        return host;
    }

    public int port(int original) {
        if (original == 80) {
            return p80;
        }
        if (original == 443) {
            return p443;
        }
        if (original == 10000) {
            return p10000;
        }
        if (original == 10123) {
            return p10123;
        }
        return original;
    }

    /** Mapped ports in JNI order: 80, 443, 10000, 10123. */
    public int[] nativePorts() {
        return new int[] {p80, p443, p10000, p10123};
    }

    /** Host, plus :port when the mapped 443 is not 443. */
    public String httpsAuthority() {
        if (p443 == 443) {
            return host;
        }
        return host + ":" + p443;
    }

    public static Descriptor parse(String text) {
        if (text == null || text.length() == 0 || text.length() > MAX_CHARS) {
            throw desc("empty");
        }
        Object top;
        try {
            top = Json.parse(text);
        } catch (IllegalArgumentException e) {
            throw desc("not json");
        }
        if (!(top instanceof Map)) {
            throw desc("not json");
        }
        Map<?, ?> map = (Map<?, ?>) top;
        Object v = map.get("v");
        if (!(v instanceof Long) || ((Long) v).longValue() != 1L) {
            throw desc("v must be 1");
        }
        Object rawHost = map.get("host");
        if (!(rawHost instanceof String)) {
            throw desc("host invalid");
        }
        String canon = canonicalHost((String) rawHost);
        if (canon == null) {
            throw desc("host invalid");
        }
        int p80 = 80;
        int p443 = 443;
        int p10000 = 10000;
        int p10123 = 10123;
        if (map.containsKey("ports")) {
            Object rawPorts = map.get("ports");
            if (!(rawPorts instanceof Map)) {
                throw desc("ports invalid");
            }
            for (Map.Entry<?, ?> e : ((Map<?, ?>) rawPorts).entrySet()) {
                if (!(e.getKey() instanceof String)) {
                    throw desc("port key not allowed");
                }
                int orig = originalKey((String) e.getKey());
                if (orig == 0) {
                    throw desc("port key not allowed");
                }
                int pv = portValue(e.getValue());
                if (pv == 0) {
                    throw desc("port out of range");
                }
                if (orig == 80) {
                    p80 = pv;
                } else if (orig == 443) {
                    p443 = pv;
                } else if (orig == 10000) {
                    p10000 = pv;
                } else {
                    p10123 = pv;
                }
            }
        }
        return new Descriptor(canon, p80, p443, p10000, p10123);
    }

    private static int originalKey(String k) {
        if (k.equals("80")) {
            return 80;
        }
        if (k.equals("443")) {
            return 443;
        }
        if (k.equals("10000")) {
            return 10000;
        }
        if (k.equals("10123")) {
            return 10123;
        }
        return 0;
    }

    private static int portValue(Object v) {
        if (!(v instanceof Long)) {
            return 0;
        }
        long n = ((Long) v).longValue();
        if (n < 1 || n > 65535) {
            return 0;
        }
        return (int) n;
    }

    static String canonicalHost(String s) {
        if (s == null || s.length() == 0 || s.length() > 253) {
            return null;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > 127 || c < 0x21) {
                return null;
            }
        }
        if (containsAny(s, ":/\\@?#")) {
            return null;
        }
        if (numericAddress(s)) {
            return canonicalIPv4(s);
        }
        if (!validDns(s)) {
            return null;
        }
        return s.toLowerCase(Locale.ROOT);
    }

    private static boolean numericAddress(String s) {
        int start = 0;
        int dots = 0;
        for (int i = 0; i <= s.length(); i++) {
            if (i == s.length() || s.charAt(i) == '.') {
                if (i == start || !numericToken(s.substring(start, i))) {
                    return false;
                }
                if (i != s.length()) {
                    dots++;
                }
                start = i + 1;
            }
        }
        return dots >= 0 && start > 0;
    }

    private static boolean numericToken(String s) {
        if (s.length() >= 2 && s.charAt(0) == '0' && (s.charAt(1) == 'x' || s.charAt(1) == 'X')) {
            if (s.length() == 2) {
                return false;
            }
            for (int i = 2; i < s.length(); i++) {
                if (Json.hex(s.charAt(i)) < 0) {
                    return false;
                }
            }
            return true;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    private static String canonicalIPv4(String s) {
        int parts = 0;
        int n = 0;
        int len = 0;
        int[] b = new int[4];
        for (int i = 0; i <= s.length(); i++) {
            if (i == s.length() || s.charAt(i) == '.') {
                if (parts >= 4 || len == 0 || len > 3 || (len > 1 && s.charAt(i - len) == '0')) {
                    return null;
                }
                if (n > 255) {
                    return null;
                }
                b[parts++] = n;
                n = 0;
                len = 0;
                continue;
            }
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
            n = n * 10 + (c - '0');
            len++;
        }
        if (parts != 4) {
            return null;
        }
        if (b[0] == 198 && b[1] == 18 && b[2] == 0 && b[3] == 1) {
            return null; // reserved by the native routing marker
        }
        return b[0] + "." + b[1] + "." + b[2] + "." + b[3];
    }

    private static boolean validDns(String s) {
        if (s.charAt(0) == '.' || s.charAt(s.length() - 1) == '.') {
            return false;
        }
        int start = 0;
        for (int i = 0; i <= s.length(); i++) {
            if (i != s.length() && s.charAt(i) != '.') {
                continue;
            }
            int len = i - start;
            if (len < 1 || len > 63) {
                return false;
            }
            if (s.charAt(start) == '-' || s.charAt(i - 1) == '-') {
                return false;
            }
            for (int j = start; j < i; j++) {
                char c = s.charAt(j);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok) {
                    return false;
                }
            }
            start = i + 1;
        }
        return true;
    }

    private static boolean containsAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static IllegalArgumentException desc(String msg) {
        return new IllegalArgumentException("descriptor: " + msg);
    }
}
