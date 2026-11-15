package dev.raspberry.core;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class CoreTest {
    private static int fails;

    private static final Attempt.Writer OK = new Attempt.Writer() {
        public boolean write() {
            return true;
        }
    };
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    public static void main(String[] args) {
        pkce();
        callback();
        attempt();
        attemptCompletion();
        pendingExchange();
        rewrite();
        noticeRewrite();
        noticeMigration();
        descriptor();
        turkishLocale();
        pin();
        exchangeBody();
        sessionCookie();
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
        check(onCallback(a, gen, wrong, t0) == Attempt.IGNORE, "wrong-state");
        check(a.live(gen, t0), "still-live");
        check(onCallback(a, gen + 1, callback(ticket, state), t0) == Attempt.IGNORE, "other-gen");
        check(a.live(gen, t0), "gen-isolated");
        check(onCallback(a, gen, callback(ticket, state), t0 + Attempt.LIMIT_NS) == Attempt.FAIL, "expiry");
        check(!a.live(gen, t0), "expired-dead");
        int gen2 = a.begin(state, t0);
        check(onCallback(a, gen, callback(ticket, state), t0) == Attempt.IGNORE, "old-gen-after-restart");
        check(onCallback(a, gen2, callback(ticket, state), t0) == Attempt.EXCHANGE, "exchange");
        Attempt.Exchange exchange = a.claimExchange(gen2, t0, true);
        check(exchange != null, "exchange-claimed");
        check(onCallback(a, gen2, callback(ticket, state), t0) == Attempt.IGNORE, "replay");
        check(a.commit(gen2, t0, OK), "commit");
        exchange.clear();
        check(onCallback(a, gen2, callback(ticket, state), t0) == Attempt.IGNORE, "replay-done");
        int gen3 = a.begin(state, t0);
        Callback denied = Callback.parseTarget("/raspberry/cb?error=access_denied&state=" + state);
        check(onCallback(a, gen3, denied, t0) == Attempt.FAIL, "error-fails");
        check(onCallback(a, gen3, callback(ticket, state), t0) == Attempt.IGNORE, "no-auto-exchange");
        int gen4 = a.begin(other, t0);
        a.cancel(gen4);
        check(onCallback(a, gen4, Callback.parseTarget("/raspberry/cb?ticket=" + ticket + "&state=" + other), t0) == Attempt.IGNORE, "cancel-ignores");
        check(a.begin(state, t0) != 0, "retry-after-cancel");
    }

    /**
     * Stale-completion cases: a cancelled or superseded generation must never write, a new one
     * must be unaffected, and a write that lands after the deadline must be refused.
     */
    private static void attemptCompletion() {
        String state = "abcdefghij123456";
        String ticket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        long t0 = 1_000L;
        int[] writes = {0};
        Attempt.Writer count = new Attempt.Writer() {
            public boolean write() {
                writes[0]++;
                return true;
            }
        };

        // Cancelled between HTTP completion and the store: the store must not run.
        Attempt a = new Attempt();
        int g1 = a.begin(state, t0);
        check(!a.commit(g1, t0, count) && writes[0] == 0, "c-no-exchange-no-write");
        check(onCallback(a, g1, callback(ticket, state), t0) == Attempt.EXCHANGE, "c-exchange");
        check(!a.commit(g1, t0, count) && writes[0] == 0, "c-before-claim-no-write");
        a.cancel(g1);
        check(!a.commit(g1, t0, count) && writes[0] == 0, "c-cancel-no-write");
        check(a.claimExchange(g1, t0, true) == null, "c-cancel-no-claim");
        check(!a.live(g1, t0), "c-cancel-dead");

        // A newer generation owns the store: the old completion writes nothing and does not
        // clear or consume the new attempt.
        int g2 = a.begin(state, t0);
        check(g2 != 0 && g2 != g1, "c-next-gen");
        check(onCallback(a, g2, callback(ticket, state), t0) == Attempt.EXCHANGE, "c-next-exchange");
        Attempt.Exchange g2Exchange = a.claimExchange(g2, t0, true);
        check(g2Exchange != null, "c-next-claim");
        check(!a.commit(g1, t0, count) && writes[0] == 0, "c-old-gen-no-write");
        check(a.commit(g2, t0, count) && writes[0] == 1, "c-new-gen-write");
        check(!a.commit(g2, t0, count) && writes[0] == 1, "c-done-no-rewrite");
        g2Exchange.clear();

        // Accepted in time, stored after the deadline: refused.
        Attempt b = new Attempt();
        int g3 = b.begin(state, t0);
        check(onCallback(b, g3, callback(ticket, state), t0 + Attempt.LIMIT_NS - 1) == Attempt.EXCHANGE, "x-exchange");
        Attempt.Exchange g3Exchange = b.claimExchange(g3, t0 + Attempt.LIMIT_NS - 1, true);
        check(g3Exchange != null, "x-claim");
        check(!b.commit(g3, t0 + Attempt.LIMIT_NS, count) && writes[0] == 1, "x-expired-no-write");
        check(!b.live(g3, t0 + Attempt.LIMIT_NS), "x-expired-dead");
        g3Exchange.clear();

        // live() enforces the deadline itself.
        Attempt c = new Attempt();
        int g4 = c.begin(state, t0);
        check(c.live(g4, t0 + Attempt.LIMIT_NS - 1), "l-before-deadline");
        check(!c.live(g4, t0 + Attempt.LIMIT_NS), "l-at-deadline");
        check(c.begin(state, t0) != 0, "l-retry-after-expiry");

        // A throwing writer fails the attempt instead of reporting success.
        Attempt d = new Attempt();
        int g5 = d.begin(state, t0);
        check(onCallback(d, g5, callback(ticket, state), t0) == Attempt.EXCHANGE, "t-exchange");
        Attempt.Exchange g5Exchange = d.claimExchange(g5, t0, true);
        check(g5Exchange != null, "t-claim");
        boolean failedClosed = !d.commit(g5, t0, new Attempt.Writer() {
            public boolean write() {
                throw new IllegalStateException("write");
            }
        });
        check(failedClosed && !d.live(g5, t0), "t-throwing-fails");
        g5Exchange.clear();
    }

    private static void pendingExchange() {
        String state = "abcdefghij123456";
        String ticket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        long t0 = 5_000L;

        // Callback arrives while backgrounded; retain it until the foreground gate claims it.
        Attempt a = new Attempt();
        int g1 = a.begin(state, t0);
        long received = t0 + 10;
        Callback cb = callback(ticket, state);
        Callback duplicate = callback(repeat('B', 43), state);
        check(onCallback(a, g1, cb, received) == Attempt.EXCHANGE, "p-stage");
        check(a.pending(g1), "p-pending");
        check(onCallback(a, g1, duplicate, received) == Attempt.IGNORE, "p-duplicate-pending");
        check(a.live(g1, received + 60_000_000_000L), "p-live-in-background");
        check(a.claimExchange(g1, received + 60_000_000_000L, false) == null, "p-background-no-claim");
        check(a.pending(g1), "p-background-retains");
        Attempt.Exchange queued = a.claimExchange(g1, received + 60_000_000_000L, true);
        check(queued != null, "p-foreground-claim");
        Attempt.Exchange once = a.claimExchange(g1, received + 60_000_000_000L, true);
        check(once == null, "p-only-one-claim");
        check(onCallback(a, g1, duplicate, received + 60_000_000_000L) == Attempt.IGNORE, "p-duplicate-after-claim");
        check(a.exchanging(g1), "p-exchanging");
        if (queued != null) {
            byte[] body = queued.body();
            check(body != null && new String(body).contains(ticket) && new String(body).contains(VERIFIER), "p-exchange-body");
            queued.clear();
            check(queued.body() == null, "p-clear");
            check(allZero(body), "p-body-erased");
        }

        // Simulates the activity already being resumed when the callback is accepted.
        Attempt b = new Attempt();
        int g2 = b.begin(state, t0);
        check(onCallback(b, g2, cb, received) == Attempt.EXCHANGE, "f-stage");
        Attempt.Exchange immediate = b.claimExchange(g2, received, true);
        check(immediate != null && b.claimExchange(g2, received, true) == null, "f-one-exchange");
        if (immediate != null) {
            immediate.clear();
        }

        // Ticket TTL starts at callback receipt and is capped by the original attempt deadline.
        Attempt expired = new Attempt();
        int g3 = expired.begin(state, t0);
        check(onCallback(expired, g3, cb, received) == Attempt.EXCHANGE, "e-stage");
        check(expired.claimExchange(g3, received + Attempt.TICKET_LIMIT_NS, false) == null, "e-ticket-expired");
        check(!expired.live(g3, received + Attempt.TICKET_LIMIT_NS), "e-dead");
        check(expired.begin(state, received + Attempt.TICKET_LIMIT_NS) != 0, "e-retry");

        Attempt capped = new Attempt();
        int g4 = capped.begin(state, t0);
        long nearAttemptDeadline = t0 + Attempt.LIMIT_NS - 1;
        check(onCallback(capped, g4, cb, nearAttemptDeadline) == Attempt.EXCHANGE, "e-attempt-stage");
        check(capped.claimExchange(g4, t0 + Attempt.LIMIT_NS, true) == null, "e-attempt-caps-ticket");

        // Cancellation/retry and stale generations erase queued data and cannot claim or commit.
        Attempt stale = new Attempt();
        int g5 = stale.begin(state, t0);
        check(onCallback(stale, g5, cb, received) == Attempt.EXCHANGE, "s-stage");
        stale.cancel(g5);
        int g6 = stale.begin(state, received);
        check(stale.claimExchange(g5, received, true) == null, "s-cancel-clears-ticket");
        check(onCallback(stale, g5, cb, received) == Attempt.IGNORE, "s-old-callback");
        check(onCallback(stale, g6, cb, received) == Attempt.EXCHANGE, "s-new-stage");
        Attempt.Exchange current = stale.claimExchange(g6, received, true);
        check(current != null, "s-new-claim");
        byte[] currentBody = current == null ? null : current.body();
        stale.cancel(g6);
        check(current != null && current.body() == null && allZero(currentBody), "s-cancel-erases-active");
        int[] writes = {0};
        check(!stale.commit(g6, received, new Attempt.Writer() {
            public boolean write() {
                writes[0]++;
                return true;
            }
        }) && writes[0] == 0, "s-cancel-no-store");
        check(!stale.commit(g5, received, new Attempt.Writer() {
            public boolean write() {
                writes[0]++;
                return true;
            }
        }) && writes[0] == 0, "s-stale-no-store");
        if (current != null) {
            current.clear();
        }

        // The callback TTL still applies after claim; an expired exchange cannot write.
        Attempt inFlight = new Attempt();
        int g7 = inFlight.begin(state, t0);
        long inFlightReceived = t0 + 1;
        check(onCallback(inFlight, g7, cb, inFlightReceived) == Attempt.EXCHANGE, "x-inflight-stage");
        Attempt.Exchange inFlightExchange = inFlight.claimExchange(g7, inFlightReceived, true);
        check(inFlightExchange != null, "x-inflight-claim");
        byte[] inFlightBody = inFlightExchange == null ? null : inFlightExchange.body();
        int[] expiredWrites = {0};
        check(!inFlight.commit(g7, inFlightReceived + Attempt.TICKET_LIMIT_NS, new Attempt.Writer() {
            public boolean write() {
                expiredWrites[0]++;
                return true;
            }
        }) && expiredWrites[0] == 0, "x-inflight-ticket-expired-no-write");
        check(inFlightExchange != null && inFlightExchange.body() == null && allZero(inFlightBody), "x-inflight-ticket-erased");
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

    private static void noticeRewrite() {
        Descriptor endpoint = Descriptor.parse("{\"v\":1,\"host\":\"Ep.Example\",\"ports\":{\"80\":8080,\"443\":8443}}");
        String raw = "https://lan3rd.line.me:443/v1/lineplay/android/a%2Fb?q=1%20#f%2F";
        NoticeRewrite.Route route = NoticeRewrite.route(raw, endpoint);
        check(route.routed(), "notice-api-target");
        check(route.url().equals("https://ep.example:8443/v1/lineplay/android/a%2Fb?q=1%20#f%2F"), "notice-raw-parts");
        check(!route.followsRedirects(), "notice-no-redirect");

        route = NoticeRewrite.route("http://play-static.line-scdn.net/img/read/notice/a%2Fb?q=%2F", endpoint);
        check(route.routed() && route.url().equals("http://ep.example:8080/img/read/notice/a%2Fb?q=%2F"), "notice-http-port");
        route = NoticeRewrite.route("https://fapi.play.naver.jp:443/v4/a", endpoint);
        check(route.routed() && route.url().equals("https://ep.example:8443/v4/a"), "notice-suffix-default-port");
        check(NoticeRewrite.route("https://fapi.play.naver.net/v4/a", endpoint).routed(), "notice-naver-net-family");
        check(NoticeRewrite.route("https://asset.line-apps.com/a", endpoint).routed(), "notice-line-apps-family");
        check(NoticeRewrite.route("https://sdk.line.naver.jp/a", endpoint).routed(), "notice-line-naver-family");
        String[] apexHosts = {
                "play.naver.jp", "play.naver.net", "line-scdn.net", "line-apps.com", "line.naver.jp"
        };
        for (String host : apexHosts) {
            route = NoticeRewrite.route("https://" + host + "/v1", endpoint);
            check(route.routed() && route.url().equals("https://ep.example:8443/v1"), "notice-apex-" + host);
            check(!NoticeRewrite.route("https://x" + host + "/v1", endpoint).routed(), "notice-prefix-trap-" + host);
            check(!NoticeRewrite.route("https://" + host + ".evil.example/v1", endpoint).routed(),
                    "notice-suffix-trap-" + host);
        }
        route = NoticeRewrite.route("https://LAN3RD.LINE.ME./v1", endpoint);
        check(route.routed() && route.url().equals("https://ep.example:8443/v1"), "notice-case-trailing-dot");
        route = NoticeRewrite.route("https://terms.line.me/v1", endpoint);
        check(route.routed(), "notice-exact-contract-host");
        route = NoticeRewrite.route("https://sdbx-terms3rd.line-apps.com/v1", endpoint);
        check(route.routed(), "notice-sdk-sandbox-host");

        route = NoticeRewrite.route("https://unrelated.example/a%2Fb?q=1%20#f%2F", null);
        check(!route.routed() && route.followsRedirects(), "notice-unrelated-no-config");
        check(route.url().equals("https://unrelated.example/a%2Fb?q=1%20#f%2F"), "notice-unrelated-raw");
        check(!NoticeRewrite.route("https://evil.line.me/v1", endpoint).routed(), "notice-no-line-me-suffix");
        check(!NoticeRewrite.route("https://fapi.play.naver.jp.evil.com/v1", endpoint).routed(), "notice-suffix-trap");
        check(!NoticeRewrite.route("http://127.0.0.1:8080/v1", endpoint).routed(), "notice-ip-unrelated");
        String ipv6 = "http://[2001:db8::1]:8080/a%2Fb?q=%2F";
        route = NoticeRewrite.route(ipv6, endpoint);
        check(!route.routed() && route.url().equals(ipv6), "notice-ipv6-unrelated-raw");

        route = NoticeRewrite.route("https://lan3rd.line.me/v1", Descriptor.parse("{\"v\":1,\"host\":\"lan3rd.line.me\"}"));
        check(route.routed() && route.url().equals("https://lan3rd.line.me/v1") && !route.followsRedirects(), "notice-same-authority-still-no-redirect");
        badNotice("https://lan3rd.line.me/v1", null, "notice-missing-config");
        badNotice("https://lan3rd.line.me:444/v1", endpoint, "notice-nondefault-port");
        badNotice("http://lan3rd.line.me:81/v1", endpoint, "notice-http-nondefault-port");
        badNotice("https://lan3rd.line.me:0/v1", endpoint, "notice-port-zero");
        badNotice("https://lan3rd.line.me:65536/v1", endpoint, "notice-port-overflow");
        badNotice("https://lan3rd.line.me:/v1", endpoint, "notice-port-empty");
        badNotice("https://lan3rd.line.me:bad/v1", endpoint, "notice-port-malformed");
        badNotice("https://user@lan3rd.line.me/v1", endpoint, "notice-userinfo");
        badNotice("https://lan3rd.line%2Eme/v1", endpoint, "notice-percent-host");
        badNotice("https://lan3rd.line.me/v1?bad=%2", endpoint, "notice-malformed-url");
        badNotice("https://lan3rd.line.me.evil.com:bad/v1", endpoint, "notice-malformed-unrelated");
        check(sameNotice("https://lan3rd.line.me:443/v1", null), "notice-target-fails-closed");
    }

    private static void noticeMigration() {
        String origin = "https://endpoint.example:8443";
        NoticeStore matching = new NoticeStore();
        matching.origin = origin;
        check(!migrate(origin, false, matching), "migration-match-skip");
        check(matching.calls.size() == 1 && matching.calls.get(0).equals("origin"), "migration-match-no-reset");
        check(matching.rows.containsKey("notification_pref") && matching.prefs.containsKey("notice_last_revision"),
                "migration-match-preserves-cache");

        NoticeStore first = new NoticeStore();
        first.origin = "https://old.example";
        check(migrate(origin, false, first), "migration-first-reset");
        check(first.calls.equals(Arrays.asList("origin", "db", "prefs", "marker")), "migration-marker-last");
        check(!first.rows.containsKey("notification_pref") && !first.rows.containsKey("notification_image"),
                "migration-clears-notice-tables");
        check("preserve".equals(first.rows.get("game_state")), "migration-preserves-other-table");
        check(!first.prefs.containsKey("notice_last_revision")
                        && !first.prefs.containsKey("board_request_timestamp_notice")
                        && !first.prefs.containsKey("notice_server_timestamp")
                        && !first.prefs.containsKey("notice_local_timestamp"),
                "migration-clears-exact-keys");
        check("preserve".equals(first.prefs.get("white_list"))
                        && "preserve".equals(first.prefs.get("other_pref")),
                "migration-preserves-other-preferences");
        check(origin.equals(first.origin), "migration-origin-written");

        NoticeStore prefFailure = new NoticeStore();
        prefFailure.origin = null;
        prefFailure.failPreferences = true;
        check(migrationFails(origin, false, prefFailure), "migration-pref-failure");
        check(prefFailure.origin == null && !prefFailure.calls.contains("marker"), "migration-no-marker-on-failure");
        prefFailure.failPreferences = false;
        check(migrate(origin, false, prefFailure), "migration-retries-without-marker");
        check(origin.equals(prefFailure.origin), "migration-retry-marker");

        NoticeStore databaseFailure = new NoticeStore();
        databaseFailure.origin = "https://old.example";
        Map<String, String> originalPreferences = new HashMap<>(databaseFailure.prefs);
        databaseFailure.failDatabase = true;
        check(migrationFails(origin, false, databaseFailure), "migration-db-failure");
        check(databaseFailure.prefs.equals(originalPreferences)
                        && "https://old.example".equals(databaseFailure.origin),
                "migration-db-failure-preserves-preferences-and-marker");
        check(databaseFailure.calls.equals(Arrays.asList("origin", "db")),
                "migration-db-failure-stops-before-preferences");

        NoticeStore markerFailure = new NoticeStore();
        markerFailure.origin = "https://old.example";
        markerFailure.failMarker = true;
        check(migrationFails(origin, false, markerFailure), "migration-marker-failure");
        check(origin.equals(markerFailure.origin), "migration-marker-failure-memory-value");
        markerFailure.failMarker = false;
        check(migrate(origin, true, markerFailure), "migration-force-retry-after-marker-failure");
        check(markerFailure.calls.get(markerFailure.calls.size() - 3).equals("db")
                        && markerFailure.calls.get(markerFailure.calls.size() - 2).equals("prefs")
                        && markerFailure.calls.get(markerFailure.calls.size() - 1).equals("marker"),
                "migration-forced-reset-order");
    }

    private static boolean migrate(String origin, boolean retry, NoticeStore store) {
        try {
            return NoticeMigration.prepare(origin, retry, store);
        } catch (IOException e) {
            check(false, "migration-unexpected-failure");
            return false;
        }
    }

    private static boolean migrationFails(String origin, boolean retry, NoticeStore store) {
        try {
            NoticeMigration.prepare(origin, retry, store);
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    private static final class NoticeStore implements NoticeMigration.Store {
        String origin;
        boolean failPreferences;
        boolean failDatabase;
        boolean failMarker;
        final ArrayList<String> calls = new ArrayList<>();
        final Map<String, String> rows = new HashMap<>();
        final Map<String, String> prefs = new HashMap<>();

        NoticeStore() {
            rows.put("notification_pref", "cached notice");
            rows.put("notification_image", "cached banner");
            rows.put("game_state", "preserve");
            prefs.put("notice_last_revision", "old");
            prefs.put("board_request_timestamp_notice", "old");
            prefs.put("notice_server_timestamp", "old");
            prefs.put("notice_local_timestamp", "old");
            prefs.put("white_list", "preserve");
            prefs.put("other_pref", "preserve");
        }

        public String origin() {
            calls.add("origin");
            return origin;
        }

        public void clearTables(String database, String[] tables) throws IOException {
            calls.add("db");
            if (!NoticeMigration.DATABASE.equals(database)
                    || !Arrays.equals(tables, new String[] {"notification_pref", "notification_image"})) {
                throw new IOException("wrong table scope");
            }
            if (failDatabase) {
                throw new IOException("database reset failed");
            }
            for (String table : tables) {
                rows.remove(table);
            }
        }

        public void removePreferences(String preferences, String[] keys) throws IOException {
            calls.add("prefs");
            if (!NoticeMigration.PREFERENCES.equals(preferences)
                    || !Arrays.equals(keys, new String[] {
                            "notice_last_revision", "board_request_timestamp_notice",
                            "notice_server_timestamp", "notice_local_timestamp"})) {
                throw new IOException("wrong preference scope");
            }
            for (String key : keys) {
                prefs.remove(key);
            }
            if (failPreferences) {
                throw new IOException("preference commit failed");
            }
        }

        public void writeOrigin(String value) throws IOException {
            calls.add("marker");
            origin = value;
            if (failMarker) {
                throw new IOException("marker commit failed");
            }
        }
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

    private static void turkishLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("tr", "TR"));
            Descriptor d = Descriptor.parse("{\"v\":1,\"host\":\"ASCII.EXAMPLE\"}");
            check(d.host().equals("ascii.example"), "host-turkish");
            check(WebRewrite.rewrite("https://NOTICE2.LINE.ME/Ab%2F?q=I%20#f%2F", d).equals("https://ascii.example/Ab%2F?q=I%20#f%2F"), "rewrite-turkish");
            NoticeRewrite.Route route = NoticeRewrite.route("HTTPS://PLAY.NAVER.JP./v1", d);
            check(route.routed() && route.url().equals("HTTPS://ascii.example/v1"), "notice-turkish");
        } finally {
            Locale.setDefault(original);
        }
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

    private static void sessionCookie() {
        File dir = null;
        File cookie = null;
        File nested = null;
        File sibling = null;
        try {
            dir = Files.createTempDirectory("raspberry-session-cookie-").toFile();
            cookie = new File(dir, "avcookie.na");
            sibling = new File(dir, "unrelated.pref");
            writeFile(sibling);
            check(SessionCookie.clear(dir), "cookie-missing");
            check(sibling.isFile(), "cookie-missing-preserves-sibling");

            writeFile(cookie);
            check(SessionCookie.clear(dir) && !cookie.exists(), "cookie-file-removed");
            check(sibling.isFile(), "cookie-removal-preserves-sibling");

            check(cookie.mkdir(), "cookie-directory-create");
            nested = new File(cookie, "keep");
            writeFile(nested);
            check(!SessionCookie.clear(dir), "cookie-directory-refused");
            check(cookie.isDirectory() && nested.isFile() && sibling.isFile(), "cookie-directory-untouched");
        } catch (Exception e) {
            check(false, "cookie-test-io");
        } finally {
            if (nested != null) {
                nested.delete();
            }
            if (cookie != null) {
                cookie.delete();
            }
            if (sibling != null) {
                sibling.delete();
            }
            if (dir != null) {
                dir.delete();
            }
        }
    }

    private static void writeFile(File file) throws IOException {
        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(1);
        } finally {
            out.close();
        }
    }

    private static Callback callback(String ticket, String state) {
        return Callback.parseTarget("/raspberry/cb?ticket=" + ticket + "&state=" + state);
    }

    private static int onCallback(Attempt attempt, int gen, Callback callback, long now) {
        return attempt.onCallback(gen, callback, VERIFIER, now);
    }

    private static boolean allZero(byte[] bytes) {
        if (bytes == null) {
            return false;
        }
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean same(String raw, Descriptor d) {
        return WebRewrite.rewrite(raw, d) == raw;
    }

    private static boolean sameNotice(String raw, Descriptor d) {
        try {
            NoticeRewrite.route(raw, d);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static void badNotice(String raw, Descriptor d, String name) {
        boolean threw = false;
        try {
            NoticeRewrite.route(raw, d);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check(threw, name);
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
