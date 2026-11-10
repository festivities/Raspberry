package dev.raspberry.core;

/**
 * One loopback GET /raspberry/cb. Malformed input is null and must not finish an attempt.
 * A parsed error is not a ticket.
 */
public final class Callback {
    public static final int MAX_LINE = 2048;
    public static final int MAX_QUERY = 512;

    public final String ticket;
    public final String state;
    public final String error;

    private Callback(String ticket, String state, String error) {
        this.ticket = ticket;
        this.state = state;
        this.error = error;
    }

    public static Callback parseLine(String line) {
        if (line == null) {
            return null;
        }
        if (line.endsWith("\r")) {
            line = line.substring(0, line.length() - 1);
        }
        if (line.length() == 0 || line.length() > MAX_LINE || !line.startsWith("GET ")) {
            return null;
        }
        int sp = line.indexOf(' ', 4);
        if (sp < 0) {
            return null;
        }
        String ver = line.substring(sp + 1);
        if (!ver.equals("HTTP/1.1") && !ver.equals("HTTP/1.0")) {
            return null;
        }
        return parseTarget(line.substring(4, sp));
    }

    public static Callback parseTarget(String target) {
        if (target == null || target.length() == 0 || target.length() > MAX_LINE) {
            return null;
        }
        if (target.indexOf('#') >= 0 || target.indexOf(' ') >= 0 || target.indexOf('\\') >= 0) {
            return null;
        }
        int q = target.indexOf('?');
        String path = q < 0 ? target : target.substring(0, q);
        if (!path.equals("/raspberry/cb")) {
            return null;
        }
        if (q < 0 || q == target.length() - 1) {
            return null;
        }
        String query = target.substring(q + 1);
        if (query.length() > MAX_QUERY) {
            return null;
        }
        return parseQuery(query);
    }

    static Callback parseQuery(String query) {
        boolean sawTicket = false;
        boolean sawState = false;
        boolean sawError = false;
        String ticket = null;
        String state = null;
        String error = null;
        int start = 0;
        for (int i = 0; i <= query.length(); i++) {
            if (i != query.length() && query.charAt(i) != '&') {
                continue;
            }
            String pair = query.substring(start, i);
            start = i + 1;
            if (pair.length() == 0) {
                return null;
            }
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                return null;
            }
            String key = pct(pair.substring(0, eq));
            String val = pct(pair.substring(eq + 1));
            if (key == null || val == null || val.length() == 0) {
                return null;
            }
            if (key.equals("ticket")) {
                if (sawTicket || !AuthUrl.ticket(val)) {
                    return null;
                }
                sawTicket = true;
                ticket = val;
            } else if (key.equals("state")) {
                if (sawState || !AuthUrl.state(val)) {
                    return null;
                }
                sawState = true;
                state = val;
            } else if (key.equals("error")) {
                if (sawError || val.length() > 64) {
                    return null;
                }
                sawError = true;
                error = val;
            } else {
                return null;
            }
        }
        if (!sawState || sawTicket == sawError) {
            return null;
        }
        return new Callback(ticket, state, error);
    }

    static String pct(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '+' || c == '%' && i + 2 >= s.length()) {
                return null;
            }
            if (c == '%') {
                int h = Json.hex(s.charAt(i + 1));
                int l = Json.hex(s.charAt(i + 2));
                if (h < 0 || l < 0) {
                    return null;
                }
                int v = (h << 4) | l;
                if (v < 0x21 || v > 0x7e) {
                    return null;
                }
                b.append((char) v);
                i += 2;
            } else if (c < 0x21 || c > 0x7e) {
                return null;
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }
}
