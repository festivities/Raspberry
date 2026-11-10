package dev.raspberry.core;

public final class CoreTest {
    private static int fails;

    public static void main(String[] args) {
        pkce();
        callback();
        attempt();
        rewrite();
        descriptor();
        pin();
        exchangeBody();
        if (fails != 0) {
            System.err.println("FAILED " + fails);
            System.exit(1);
        }
        System.out.println("ok");
    }

    private static void pkce() {
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        check(Pkce.challenge(verifier).equals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), "rfc7636");
        byte[] raw = B64Url.dec(verifier);
        check(raw != null && raw.length == 32, "verifier-len");
        Pkce p = Pkce.of(raw);
        check(p.verifier.equals(verifier), "verifier-roundtrip");
        check(p.challenge.equals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), "challenge-of");
        check(B64Url.enc(new byte[32]).equals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "b64-zeros");
        boolean threw = false;
        try {
            Pkce.of(new byte[31]);
        } catch (IllegalArgumentException e) {
            threw = "pkce".equals(e.getMessage());
        }
        check(threw, "pkce-len");
    }

    private static void callback() {
        String ticket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        String state = "abcdefghij123456";
        Callback ok = Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=" + state + " HTTP/1.1");
        check(ok != null && ticket.equals(ok.ticket) && state.equals(ok.state) && ok.error == null, "cb-ok");
        check(Callback.parseLine("GET /raspberry/cb?state=" + state + "&ticket=" + ticket + " HTTP/1.0") != null, "cb-order");
        check(Callback.parseLine("POST /raspberry/cb?ticket=" + ticket + "&state=" + state + " HTTP/1.1") == null, "cb-post");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=" + state + "&ticket=" + ticket + " HTTP/1.1") == null, "cb-dup");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=" + state + "&state=" + state + " HTTP/1.1") == null, "cb-dup-state");
        check(Callback.parseLine("GET /raspberry/cb?state=" + state + " HTTP/1.1") == null, "cb-missing-ticket");
        check(Callback.parseLine("GET /favicon.ico HTTP/1.1") == null, "cb-path");
        check(Callback.parseLine("GET /raspberry/cb/extra?ticket=" + ticket + "&state=" + state + " HTTP/1.1") == null, "cb-path-extra");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=" + state + "&error=x HTTP/1.1") == null, "cb-both");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=" + state + "&x=1 HTTP/1.1") == null, "cb-extra");
        String big = "GET /raspberry/cb?ticket=" + ticket + "&state=" + state + "&error=" + repeat('a', 65) + " HTTP/1.1";
        check(Callback.parseLine(big) == null, "cb-oversize-error");
        Callback err = Callback.parseLine("GET /raspberry/cb?error=access_denied&state=" + pct(state) + " HTTP/1.1");
        check(err != null && err.ticket == null && "access_denied".equals(err.error) && state.equals(err.state), "cb-error-encoded");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=%2 HTTP/1.1") == null, "cb-bad-pct");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=%00aaaa HTTP/1.1") == null, "cb-nul");
        check(Callback.parseTarget("/raspberry/cb?ticket=" + ticket + "&state=" + state + "#x") == null, "cb-fragment");
        String q = "ticket=" + ticket + "&state=" + state;
        check(Callback.parseLine("GET /raspberry/cb?" + q + "&" + q + " HTTP/1.1") == null, "cb-replay-query");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + repeat('A', 44) + "&state=" + state + " HTTP/1.1") == null, "cb-ticket-long");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=" + repeat('a', 15) + " HTTP/1.1") == null, "cb-state-short");
        check(Callback.parseLine("GET /raspberry/cb?ticket=" + ticket + "&state=" + repeat('a', 65) + " HTTP/1.1") == null, "cb-state-long");
    }

    private static void attempt() {
        Attempt a = new Attempt();
        String state = "abcdefghij123456";
        String other = "zzzzzzzzzzzzzzzz";
        String ticket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        long t0 = 1_000L;
        int gen = a.begin(state, t0);
        check(gen != 0, "begin");
        check(new Attempt().begin(repeat('a', 65), t0) == 0, "begin-overlong");
        check(new Attempt().begin(repeat('a', 15), t0) == 0, "begin-short");
        check(a.begin(other, t0) == 0, "one-live");
        Callback wrong = Callback.parseTarget("/raspberry/cb?ticket=" + ticket + "&state=" + other);
        check(a.onCallback(gen, wrong, t0) == Attempt.IGNORE, "wrong-state");
        check(a.live(gen), "still-live");
        check(a.onCallback(gen + 1, callback(ticket, state), t0) == Attempt.IGNORE, "other-gen");
        check(a.live(gen), "gen-isolated");
        check(a.onCallback(gen, callback(ticket, state), t0 + Attempt.LIMIT_NS) == Attempt.FAIL, "expiry");
        check(!a.live(gen), "expired-dead");
        int gen2 = a.begin(state, t0);
        check(a.onCallback(gen, callback(ticket, state), t0) == Attempt.IGNORE, "old-gen-after-restart");
        check(a.onCallback(gen2, callback(ticket, state), t0) == Attempt.EXCHANGE, "exchange");
        check(a.onCallback(gen2, callback(ticket, state), t0) == Attempt.IGNORE, "replay");
        a.done(gen2);
        check(a.onCallback(gen2, callback(ticket, state), t0) == Attempt.IGNORE, "replay-done");
        int gen3 = a.begin(state, t0);
        Callback denied = Callback.parseTarget("/raspberry/cb?error=access_denied&state=" + state);
        check(a.onCallback(gen3, denied, t0) == Attempt.FAIL, "error-fails");
        check(a.onCallback(gen3, callback(ticket, state), t0) == Attempt.IGNORE, "no-auto-exchange");
        int gen4 = a.begin(other, t0);
        a.cancel(gen4);
        check(a.onCallback(gen4, Callback.parseTarget("/raspberry/cb?ticket=" + ticket + "&state=" + other), t0) == Attempt.IGNORE, "cancel-ignores");
        check(a.begin(state, t0) != 0, "retry-after-cancel");
    }

    private static void rewrite() {
        Descriptor d = Descriptor.parse("{\"v\":1,\"host\":\"Ep.Example\",\"ports\":{\"443\":443}}");
        String raw = "https://event.play.naver.jp/web/a%2Fb?q=1%20#f%2F";
        check(WebRewrite.rewrite(raw, d).equals("https://ep.example/web/a%2Fb?q=1%20#f%2F"), "raw-parts");
        check(WebRewrite.rewrite("http://help2.line.me/x", d).equals("https://ep.example/x"), "http-to-https");
        check(WebRewrite.rewrite("https://event-alpha.play.naver.jp/x", d).equals("https://ep.example/x"), "event-alpha");
        check(WebRewrite.rewrite("https://event-rc.play.naver.jp/x", d).equals("https://ep.example/x"), "event-rc");
        check(WebRewrite.rewrite("https://EVENT.play.naver.jp/Ab", d).equals("https://ep.example/Ab"), "host-case");
        check(same("https://notevent.play.naver.jp/x", d), "not-event");
        check(same("https://event.play.naver.jp.evil.com/x", d), "suffix-trap");
        check(same("https://evil.com/event.play.naver.jp", d), "path-trap");
        check(same("https://user:pw@event.play.naver.jp/x", d), "userinfo");
        check(same("//event.play.naver.jp/x", d), "schemeless");
        check(same("ftp://event.play.naver.jp/x", d), "ftp");
        check(same("https://docs.google.com/viewer?url=https://event.play.naver.jp/a.pdf", d), "google");
        check(same("https://fapi.play.naver.jp/v4", d), "fapi");
        check(same("https://access.line.me/", d), "line-sdk");
        check(WebRewrite.rewrite("https://terms.play.naver.jp/a?b=c#d", d).equals("https://ep.example/a?b=c#d"), "terms");
        check(same("https://help2.line.me.evil.com/", d), "help-suffix");
        check(same("https://prefixhelp2.line.me/", d), "help-prefix");
        check(WebRewrite.rewrite("https://event.play.naver.jp", d).equals("https://ep.example"), "no-added-slash");
        check(WebRewrite.rewrite("https://event.play.naver.jp?x=%2F", d).equals("https://ep.example?x=%2F"), "query-only");
        check(WebRewrite.rewrite("https://lan3rd.line.me/v", d).equals("https://ep.example/v"), "lan3rd");
        check(WebRewrite.rewrite("https://notice2.line-beta.me/n", d).equals("https://ep.example/n"), "notice-beta");
        check(same("https://event.play.naver.jp%2eevil.com/", d), "encoded-dot");
        check(WebRewrite.rewrite(raw, null) == raw, "null-endpoint");
        Descriptor mapped = Descriptor.parse("{\"v\":1,\"host\":\"10.0.2.2\",\"ports\":{\"443\":8443}}");
        check(WebRewrite.rewrite("http://help2.line.me/a", mapped).equals("https://10.0.2.2:8443/a"), "mapped-port");
        String start = AuthUrl.start(d, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "http://127.0.0.1:12345/raspberry/cb", "abcdefghij123456");
        check(start != null && start.startsWith("https://ep.example/auth/v1/discord/start?"), "start-host");
        check(start.indexOf(":443") < 0, "omit-443");
        check(start.indexOf("verifier") < 0, "no-verifier");
        check(start.indexOf("return=http%3A%2F%2F127.0.0.1%3A12345%2Fraspberry%2Fcb") > 0, "return-encoded");
        check(AuthUrl.loopback(1023) == null && AuthUrl.loopback(1024) != null, "port-floor");
        check(AuthUrl.loopback(65535).length() <= 64, "return-cap");
        check(AuthUrl.exchange(mapped).equals("https://10.0.2.2:8443/auth/v1/exchange"), "exchange-url");
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        String ret = "http://127.0.0.1:12345/raspberry/cb";
        check(AuthUrl.start(d, challenge + "A", ret, "abcdefghij123456") == null, "start-challenge-long");
        check(AuthUrl.start(d, challenge.substring(1), ret, "abcdefghij123456") == null, "start-challenge-short");
        check(AuthUrl.start(d, challenge, ret, repeat('a', 15)) == null, "start-state-short");
        check(AuthUrl.start(d, challenge, ret, repeat('a', 65)) == null, "start-state-long");
        check(AuthUrl.start(d, challenge, ret, repeat('a', 64)) != null, "start-state-64");
        check(same("https://event.play.naver.jp:0/a%2F?q=1#f", d), "port-0");
        check(same("https://event.play.naver.jp:65536/a%2F?q=1#f", d), "port-65536");
        check(WebRewrite.rewrite("https://event.play.naver.jp:65535/a%2F?q=1%20#f", d).equals("https://ep.example/a%2F?q=1%20#f"), "port-65535");
    }

    private static void descriptor() {
        Descriptor d = Descriptor.parse("{\"v\":1,\"host\":\"Cherry.Example\",\"note\":\"supersecretvalue\"}");
        check(d.host().equals("cherry.example"), "host-lower");
        check(d.port(80) == 80 && d.port(443) == 443 && d.port(10000) == 10000 && d.port(10123) == 10123, "identity");
        check(!d.toString().contains("supersecretvalue"), "no-secret-tostring");
        int[] ports = d.nativePorts();
        check(ports.length == 4 && ports[0] == 80 && ports[1] == 443 && ports[2] == 10000 && ports[3] == 10123, "jni-order");
        Descriptor one = Descriptor.parse("{\"v\":1,\"host\":\"10.0.2.2\",\"ports\":{\"80\":8080}}");
        check(one.port(80) == 8080 && one.port(443) == 443, "partial-ports");
        bad("{\"v\":1,\"host\":\"h.example\",\"token\":\"supersecretvalue\",\"v\":1}", "dup");
        bad("{\"v\":2,\"token\":\"supersecretvalue\"}", "v");
        bad("{\"v\":1,\"host\":\"192.168.001.1\"}", "leading-zero");
        bad("{\"v\":1,\"host\":\"0x7f.0.0.1\"}", "hex-ip");
        bad("{\"v\":1,\"host\":\"127.1\"}", "short-ip");
        bad("{\"v\":1,\"host\":\"198.18.0.1\"}", "reserved-marker");
        bad("{\"v\":1,\"host\":\"h.example\"} trailing", "trailing");
        bad("{\"v\":1,\"host\":\"h.example\",\"ports\":{\"443\":0}}", "port0");
        bad("{\"v\":1,\"host\":\"h.example\",\"ports\":{\"443\":65536}}", "port-hi");
        bad("{\"v\":1,\"host\":\"h.example\",\"ports\":{\"22\":22}}", "port-key");
        bad("{\"v\":1}", "missing-host");
        bad("", "empty");
        bad("{\"v\":1,\"host\":\"user@h.example\"}", "host-userinfo");
        check(message("{\"v\":2,\"token\":\"supersecretvalue\"}").indexOf("supersecretvalue") < 0, "error-leak");
    }

    private static void pin() {
        String hex = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef";
        byte[] a = HexPin.parse(hex);
        byte[] b = HexPin.parse("  " + hex.toLowerCase() + "\n");
        check(a != null && a.length == 32 && HexPin.eq(a, b), "pin-eq");
        check(HexPin.parse("   ") == null, "pin-blank");
        boolean threw = false;
        try {
            HexPin.parse("supersecretvalue");
        } catch (IllegalArgumentException e) {
            threw = "pin".equals(e.getMessage()) && e.getMessage().indexOf("supersecret") < 0;
        }
        check(threw, "pin-invalid");
        check(PinPolicy.accept(true, true, a, b), "pin-policy");
        check(!PinPolicy.accept(false, true, a, b), "pin-policy-trust");
        check(!PinPolicy.accept(true, false, a, b), "pin-policy-host");
        check(!PinPolicy.accept(true, true, a, new byte[32]), "pin-policy-mismatch");
        check(!PinPolicy.accept(true, true, a, null), "pin-policy-null");
    }

    private static void exchangeBody() {
        String uuid = "550e8400-e29b-41d4-a716-446655440000";
        check(uuid.equals(Json.uniqueCode("{\"uniqueCode\":\"" + uuid + "\",\"aid\":\"0\",\"new\":true}")), "code");
        check(Json.uniqueCode("{\"uniqueCode\":\"" + uuid + "\",\"uniqueCode\":\"" + uuid + "\"}") == null, "code-dup");
        check(Json.uniqueCode("{\"uniqueCode\":\"NOT-A-UUID\"}") == null, "code-shape");
        check(Json.uniqueCode("{\"error\":\"invalid_ticket\"}") == null, "code-error");
        check(UuidShape.ok(uuid) && !UuidShape.ok(uuid.toUpperCase()) && !UuidShape.ok(""), "uuid-shape");
    }

    private static Callback callback(String ticket, String state) {
        return Callback.parseTarget("/raspberry/cb?ticket=" + ticket + "&state=" + state);
    }

    private static boolean same(String raw, Descriptor d) {
        return WebRewrite.rewrite(raw, d) == raw;
    }

    private static void bad(String json, String name) {
        boolean threw = false;
        try {
            Descriptor.parse(json);
        } catch (IllegalArgumentException e) {
            threw = e.getMessage() != null && e.getMessage().startsWith("descriptor:");
        }
        check(threw, "bad-" + name);
    }

    private static String message(String json) {
        try {
            Descriptor.parse(json);
            return "";
        } catch (IllegalArgumentException e) {
            return e.toString();
        }
    }

    private static String pct(String s) {
        return s.substring(0, 4) + "%65" + s.substring(5);
    }

    private static String repeat(char c, int n) {
        char[] a = new char[n];
        for (int i = 0; i < n; i++) {
            a[i] = c;
        }
        return new String(a);
    }

    private static void check(boolean ok, String name) {
        if (!ok) {
            fails++;
            System.err.println("FAIL " + name);
        }
    }
}
