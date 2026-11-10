package dev.raspberry.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON reader. Rejects duplicate keys; org.json.JSONObject cannot. */
public final class Json {
    private final String s;
    private final int n;
    private int i;

    private Json(String s) {
        this.s = s;
        this.n = s.length();
    }

    static Object parse(String text) {
        if (text == null) {
            throw err();
        }
        Json p = new Json(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.n) {
            throw err();
        }
        return v;
    }

    /** uniqueCode from an exchange body, or null. Other keys are ignored. */
    public static String uniqueCode(String text) {
        Object v;
        try {
            v = parse(text);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!(v instanceof Map)) {
            return null;
        }
        Object code = ((Map<?, ?>) v).get("uniqueCode");
        if (!(code instanceof String) || !UuidShape.ok((String) code)) {
            return null;
        }
        return (String) code;
    }

    private Object value() {
        if (i >= n) {
            throw err();
        }
        char c = s.charAt(i);
        if (c == '{') {
            return object();
        }
        if (c == '[') {
            return array();
        }
        if (c == '"') {
            return string();
        }
        if (c == 't') {
            return literal("true", Boolean.TRUE);
        }
        if (c == 'f') {
            return literal("false", Boolean.FALSE);
        }
        if (c == 'n') {
            return literal("null", null);
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            return number();
        }
        throw err();
    }

    private Map<String, Object> object() {
        i++;
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        ws();
        if (peek('}')) {
            i++;
            return map;
        }
        while (true) {
            ws();
            if (i >= n || s.charAt(i) != '"') {
                throw err();
            }
            String key = string();
            if (map.containsKey(key)) {
                throw err();
            }
            ws();
            if (!peek(':')) {
                throw err();
            }
            i++;
            ws();
            map.put(key, value());
            ws();
            if (peek('}')) {
                i++;
                return map;
            }
            if (!peek(',')) {
                throw err();
            }
            i++;
        }
    }

    private List<Object> array() {
        i++;
        List<Object> list = new ArrayList<Object>();
        ws();
        if (peek(']')) {
            i++;
            return list;
        }
        while (true) {
            ws();
            list.add(value());
            ws();
            if (peek(']')) {
                i++;
                return list;
            }
            if (!peek(',')) {
                throw err();
            }
            i++;
        }
    }

    private String string() {
        i++;
        StringBuilder b = new StringBuilder();
        while (i < n) {
            char c = s.charAt(i++);
            if (c == '"') {
                return b.toString();
            }
            if (c == '\\') {
                if (i >= n) {
                    throw err();
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"':
                    case '\\':
                    case '/':
                        b.append(e);
                        break;
                    case 'b':
                        b.append('\b');
                        break;
                    case 'f':
                        b.append('\f');
                        break;
                    case 'n':
                        b.append('\n');
                        break;
                    case 'r':
                        b.append('\r');
                        break;
                    case 't':
                        b.append('\t');
                        break;
                    case 'u':
                        if (i + 4 > n) {
                            throw err();
                        }
                        int cp = 0;
                        for (int k = 0; k < 4; k++) {
                            int h = hex(s.charAt(i++));
                            if (h < 0) {
                                throw err();
                            }
                            cp = (cp << 4) | h;
                        }
                        b.append((char) cp);
                        break;
                    default:
                        throw err();
                }
                continue;
            }
            if (c < 0x20) {
                throw err();
            }
            b.append(c);
        }
        throw err();
    }

    private Long number() {
        int start = i;
        if (peek('-')) {
            i++;
        }
        if (i >= n || s.charAt(i) < '0' || s.charAt(i) > '9') {
            throw err();
        }
        if (s.charAt(i) == '0') {
            i++;
        } else {
            while (i < n && s.charAt(i) >= '0' && s.charAt(i) <= '9') {
                i++;
            }
        }
        if (i < n && (s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
            throw err();
        }
        String raw = s.substring(start, i);
        if (raw.charAt(0) == '-') {
            throw err();
        }
        if (raw.length() > 1 && raw.charAt(0) == '0') {
            throw err();
        }
        if (raw.length() > 10) {
            throw err();
        }
        long v = 0;
        for (int k = 0; k < raw.length(); k++) {
            v = v * 10 + (raw.charAt(k) - '0');
        }
        return Long.valueOf(v);
    }

    private Object literal(String word, Object value) {
        if (!s.startsWith(word, i)) {
            throw err();
        }
        i += word.length();
        return value;
    }

    private void ws() {
        while (i < n) {
            char c = s.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            i++;
        }
    }

    private boolean peek(char c) {
        return i < n && s.charAt(i) == c;
    }

    static int hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    private static IllegalArgumentException err() {
        return new IllegalArgumentException("json");
    }
}
