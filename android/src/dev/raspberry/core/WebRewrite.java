package dev.raspberry.core;

import java.util.Locale;

/**
 * Authority-only rewrite. Path, query and fragment are the original raw slices.
 * java.net.URI rebuilds those components and double-escapes percent sequences.
 */
public final class WebRewrite {
    private WebRewrite() {}

    public static String rewrite(String raw, Descriptor endpoint) {
        if (raw == null || endpoint == null) {
            return raw;
        }
        int scheme = schemeLen(raw);
        if (scheme < 0) {
            return raw;
        }
        int authStart = scheme + 3;
        if (authStart >= raw.length()) {
            return raw;
        }
        int authEnd = authStart;
        while (authEnd < raw.length()) {
            char c = raw.charAt(authEnd);
            if (c == '/' || c == '?' || c == '#') {
                break;
            }
            authEnd++;
        }
        String authority = raw.substring(authStart, authEnd);
        if (authority.length() == 0 || authority.indexOf('@') >= 0 || authority.indexOf('\\') >= 0 || authority.indexOf('%') >= 0) {
            return raw;
        }
        if (authority.charAt(0) == '[') {
            return raw;
        }
        String host = authority;
        int colon = authority.lastIndexOf(':');
        if (colon >= 0) {
            host = authority.substring(0, colon);
            if (!portOk(authority.substring(colon + 1))) {
                return raw;
            }
        }
        if (!allowed(host)) {
            return raw;
        }
        return "https://" + endpoint.httpsAuthority() + raw.substring(authEnd);
    }

    static boolean allowed(String host) {
        if (host == null || host.length() == 0 || host.indexOf('%') >= 0) {
            return false;
        }
        String h = trimDot(host.toLowerCase(Locale.ROOT));
        if (h == null) {
            return false;
        }
        if (h.equals("terms.play.naver.jp") || h.equals("event.play.naver.jp")) {
            return true;
        }
        if (eventPhase(h) || notice(h)) {
            return true;
        }
        return false;
    }

    private static String trimDot(String h) {
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.length() == 0 || h.indexOf('%') >= 0) {
            return null;
        }
        return h;
    }

    /** event-&lt;phase&gt;.play.naver.jp. phase has no dot, so a longer suffix cannot match. */
    private static boolean eventPhase(String h) {
        String prefix = "event-";
        String suffix = ".play.naver.jp";
        if (!h.startsWith(prefix) || !h.endsWith(suffix)) {
            return false;
        }
        if (h.length() <= prefix.length() + suffix.length()) {
            return false;
        }
        return phase(h.substring(prefix.length(), h.length() - suffix.length()));
    }

    private static boolean phase(String s) {
        if (s.length() < 1 || s.length() > 16) {
            return false;
        }
        if (s.charAt(0) == '-' || s.charAt(s.length() - 1) == '-') {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
                continue;
            }
            return false;
        }
        return true;
    }

    /**
     * Exact Java notice/help hosts and the alpha/beta/cn/sandbox twins from the
     * client constants. Not a suffix rule.
     */
    private static boolean notice(String h) {
        return h.equals("help.line.me")
                || h.equals("help.line-alpha.me")
                || h.equals("help.line-beta.me")
                || h.equals("help2.line.me")
                || h.equals("help2.line-alpha.me")
                || h.equals("help2.line-beta.me")
                || h.equals("lan.line.me")
                || h.equals("lan.line-alpha.me")
                || h.equals("lan.line-beta.me")
                || h.equals("lan3rd.line.me")
                || h.equals("lan3rd.line-alpha.me")
                || h.equals("lan3rd.line-beta.me")
                || h.equals("notice.line.me")
                || h.equals("notice.line-alpha.me")
                || h.equals("notice.line-beta.me")
                || h.equals("notice2.line.me")
                || h.equals("notice2.line-alpha.me")
                || h.equals("notice2.line-beta.me")
                || h.equals("terms.line.me")
                || h.equals("terms.line-alpha.me")
                || h.equals("terms.line-beta.me")
                || h.equals("terms2.line.me")
                || h.equals("terms2.line-alpha.me")
                || h.equals("terms2.line-beta.me")
                || h.equals("help2-cn.b612.net")
                || h.equals("help2-cn-beta.b612.net")
                || h.equals("lan3rd-cn.b612.net")
                || h.equals("lan3rd-cn-beta.b612.net")
                || h.equals("notice2-cn.b612.net")
                || h.equals("notice2-cn-beta.b612.net")
                || h.equals("terms2-cn.b612.net")
                || h.equals("terms2-cn-beta.b612.net")
                || h.equals("sdbx-lan3rd.line-apps.com")
                || h.equals("sdbx-terms3rd.line-apps.com");
    }

    private static int schemeLen(String raw) {
        int c = raw.indexOf(':');
        if (c != 4 && c != 5) {
            return -1;
        }
        String sch = raw.substring(0, c);
        if (!sch.equalsIgnoreCase("http") && !sch.equalsIgnoreCase("https")) {
            return -1;
        }
        if (!raw.startsWith("://", c)) {
            return -1;
        }
        return c;
    }

    /** Numeric only, value 1..65535. 0 and 65536 are not rewritten. */
    private static boolean portOk(String s) {
        if (s.length() == 0 || s.length() > 5) {
            return false;
        }
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
            n = n * 10 + (c - '0');
            if (n > 65535) {
                return false;
            }
        }
        return n >= 1;
    }
}
