#include "endpoint.c"

#include <stdio.h>
#include <string.h>

static int g_fails;

static void check(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "fail: %s\n", msg);
        g_fails++;
    }
}

static void test_redirect(void) {
    char long_name[300];
    memset(long_name, 'a', sizeof long_name);
    long_name[sizeof long_name - 1] = '\0';
    check(!rb_redirect(NULL), "null");
    check(!rb_redirect(""), "empty");
    check(!rb_redirect("example.com"), "unrelated");
    check(!rb_redirect("play.google.com"), "play.google.com");
    check(!rb_redirect("line.me"), "bare line.me");
    check(!rb_redirect("naver.jp"), "bare naver.jp");
    check(!rb_redirect("evilplay.naver.jp"), "suffix trap prefix");
    check(!rb_redirect("play.naver.jp.evil.example"), "suffix trap parent");
    check(!rb_redirect("notline-apps.com"), "suffix trap hyphen");
    check(!rb_redirect("fortune.line.me"), "fortune not exact");
    check(!rb_redirect("foo.lan3rd.line.me"), "exact is not a suffix");
    check(!rb_redirect("xhelp2.line.me"), "exact prefix trap");
    check(!rb_redirect("help2.line.me.extra"), "exact child");
    check(!rb_redirect("198.18.0.1"), "marker literal");
    check(!rb_redirect("203.0.113.10"), "ip literal");
    check(!rb_redirect("127.1"), "short inet_aton");
    check(!rb_redirect("0x7f000001"), "hex inet_aton");
    check(!rb_redirect(long_name), "unbounded");
    check(!rb_redirect("fapi.play.naver.jp.."), "two trailing dots");
    check(rb_redirect("fapi.play.naver.jp"), "child suffix");
    check(rb_redirect("play.naver.jp"), "suffix itself");
    check(rb_redirect("Fapi.Play.Naver.JP."), "case and one dot");
    check(rb_redirect("foo.bar.play.naver.net"), "naver.net");
    check(rb_redirect("obs.line-scdn.net"), "scdn");
    check(rb_redirect("a.line-apps.com"), "apps");
    check(rb_redirect("channel-apis.line.naver.jp"), "line.naver.jp suffix");
    check(rb_redirect("ads.play.naver.jp"), "exact ads");
    check(rb_redirect("ADS.PLAY.NAVER.JP"), "ads case");
    check(rb_redirect("lan3rd.line.me"), "exact lan3rd");
    check(rb_redirect("Lan3rd.Line.Me."), "lan3rd dot");
    check(rb_redirect("terms.line.me"), "terms");
    check(rb_redirect("notice2.line.me"), "notice2");
    check(rb_redirect("help2.line.me"), "help2");
    check(rb_redirect("HELP2.LINE.ME."), "help2 case dot");
}

static void test_install_publish(void) {
    int publish = 1;
    check(rb_install_finish(0, &publish) == 0 && publish == 0, "failed install stays unpublished and retryable");
    publish = 1;
    check(rb_install_finish(0, &publish) == 0 && publish == 0, "stale publish cleared");
    publish = 0;
    check(rb_install_finish(1, &publish) == 2 && publish == 1, "publish only after slots restored");
    check(rb_install_finish(1, NULL) == 2, "finish without publish out");
}

static void test_marker_reserved(void) {
    /* 198.18.0.1 stays reserved. Go canonicalIPv4 and Java canonicalIPv4 must reject the same bytes. */
    rb_config cfg;
    int id[4] = {80, 443, 10000, 10123};
    const uint8_t *m = rb_marker();
    uint8_t out[4];
    uint16_t mapped[4] = {80, 443, 10000, 10123};
    uint16_t port = 9;
    char lit[16];
    int n = snprintf(lit, sizeof lit, "%u.%u.%u.%u", m[0], m[1], m[2], m[3]);
    check(n > 0 && n < (int)sizeof lit, "marker literal fits");
    check(m[0] == 198 && m[1] == 18 && m[2] == 0 && m[3] == 1, "marker bytes are 198.18.0.1");
    check(strcmp(lit, "198.18.0.1") == 0, "marker text");
    memset(&cfg, 0x5a, sizeof cfg);
    check(!rb_validate(lit, id, &cfg) && cfg.host[0] == '\0' && !cfg.is_ipv4, "operator endpoint rejects marker");
    check(rb_rewrite(m, 443, m, mapped, out, &port) == -1 && port == 9, "rewrite does not use marker endpoint");
}

static void test_config(void) {
    rb_config cfg;
    int id[4] = {80, 443, 10000, 10123};
    int remap[4] = {8080, 8443, 10000, 10123};
    int bad_port[4] = {0, 443, 10000, 10123};
    int neg[4] = {-1, 443, 10000, 10123};
    int big[4] = {80, 65536, 10000, 10123};
    int edges[4] = {1, 65535, 10000, 10123};
    memset(&cfg, 0x5a, sizeof cfg);
    check(rb_validate("Cherry.Example.ORG", id, &cfg), "dns config");
    check(strcmp(cfg.host, "cherry.example.org") == 0 && !cfg.is_ipv4, "canonical dns");
    check(cfg.ports[0] == 80 && cfg.ports[1] == 443 && cfg.ports[2] == 10000 && cfg.ports[3] == 10123,
          "identity ports");
    check(rb_validate("203.0.113.10", remap, &cfg), "ipv4 config");
    check(cfg.is_ipv4 && cfg.ip[0] == 203 && cfg.ip[1] == 0 && cfg.ip[2] == 113 && cfg.ip[3] == 10,
          "ipv4 bytes");
    check(cfg.ports[0] == 8080 && cfg.ports[1] == 8443, "remapped ports stored");
    check(rb_validate("localhost", edges, &cfg) && cfg.ports[0] == 1 && cfg.ports[1] == 65535, "port edges");
    check(!rb_validate("198.18.0.1", id, &cfg) && cfg.host[0] == '\0', "marker endpoint");
    check(!rb_validate("127.1", id, &cfg) && cfg.host[0] == '\0', "short form");
    check(!rb_validate("0177.0.0.1", id, &cfg), "octal");
    check(!rb_validate("0x7f.0.0.1", id, &cfg), "hex octets");
    check(!rb_validate("0x7f000001", id, &cfg), "hex word");
    check(!rb_validate("1.2.3.256", id, &cfg), "octet 256");
    check(!rb_validate("18446744073709551616.2.3.4", id, &cfg), "long octet");
    check(!rb_validate("01.2.3.4", id, &cfg), "leading zero");
    check(!rb_validate("cherry.example.org.", id, &cfg), "config trailing dot");
    check(!rb_validate("http://cherry.example.org", id, &cfg), "url");
    check(!rb_validate("", id, &cfg), "empty host");
    check(!rb_validate(NULL, id, &cfg), "null host");
    check(!rb_validate("cherry.example.org", bad_port, &cfg) && cfg.host[0] == '\0', "port 0");
    check(!rb_validate("cherry.example.org", neg, &cfg), "port negative");
    check(!rb_validate("cherry.example.org", big, &cfg), "port 65536");
    check(rb_validate("cherry.example.org", id, &cfg), "restore after reject");
    check(!rb_validate("bad host", id, &cfg) && cfg.host[0] == '\0', "reject clears");
}

static void test_rewrite(void) {
    const uint8_t *marker = rb_marker();
    uint8_t ep[4] = {203, 0, 113, 10};
    uint8_t other[4] = {198, 51, 100, 7};
    uint8_t dst[4];
    uint8_t out[4];
    uint16_t mapped[4] = {8080, 8443, 11000, 11123};
    uint16_t oport = 1;
    memcpy(dst, ep, 4);
    check(rb_rewrite(dst, 443, ep, mapped, out, &oport) == 0, "endpoint ip not remapped");
    check(dst[0] == 203 && dst[3] == 10, "input unchanged");
    check(rb_rewrite(other, 80, ep, mapped, out, &oport) == 0, "other address untouched");
    check(rb_rewrite(marker, 443, NULL, mapped, out, &oport) == -1, "marker without endpoint");
    check(rb_rewrite(marker, 443, marker, mapped, out, &oport) == -1, "marker endpoint rejected");
    check(rb_rewrite(marker, 443, ep, mapped, out, &oport) == 1, "marker rewritten");
    check(out[0] == 203 && out[1] == 0 && out[2] == 113 && out[3] == 10 && oport == 8443, "443 map");
    check(marker[0] == 198 && marker[3] == 1, "marker constant intact");
    check(rb_rewrite(marker, 80, ep, mapped, out, &oport) == 1 && oport == 8080, "80 map");
    check(rb_rewrite(marker, 10000, ep, mapped, out, &oport) == 1 && oport == 11000, "10000 map");
    check(rb_rewrite(marker, 10123, ep, mapped, out, &oport) == 1 && oport == 11123, "10123 map");
    check(rb_rewrite(marker, 9, ep, mapped, out, &oport) == 1 && oport == 9 && out[0] == 203,
          "unmapped port keeps ip rewrite");
}

static void test_span(void) {
    check(rb_span_inside(0x1000, 0x2000, 0x1000, 8), "span start");
    check(rb_span_inside(0x1000, 0x2000, 0x1ff8, 8), "span last bytes");
    check(!rb_span_inside(0x1000, 0x2000, 0x1ff9, 8), "span crosses end");
    check(!rb_span_inside(0x1000, 0x2000, 0x2000, 8), "span at hi");
    check(!rb_span_inside(0x1000, 0x2000, 0x3000, 8), "span beyond");
    check(!rb_span_inside(0x1000, 0x1100, ~(uintptr_t)0, 8), "span above hi no wrap");
    check(!rb_span_inside(0x1000, 0x2000, 0x0fff, 8), "span before");
    check(!rb_span_inside(0x2000, 0x1000, 0x1800, 8), "span inverted");
    check(!rb_span_inside(0x1000, 0x2000, 0x1000, 0), "span zero width");
}

static void test_ai_plan(void) {
    char canon[64];
    int action = -1;
    memset(canon, 'E', sizeof canon);
    check(rb_prepare_ai("fapi.play.naver.jp", "cherry.example.org", 1, 1, 1, canon, sizeof canon, &action) == 0,
          "numeric returns");
    check(action == RB_AI_NONAME && canon[0] == 'E', "numeric no resolve no canon");
    check(rb_prepare_ai("fapi.play.naver.jp", "cherry.example.org", 0, 1, 1, canon, sizeof canon, &action) == 0,
          "family returns");
    check(action == RB_AI_FAMILY, "family before numeric");
    check(rb_prepare_ai("fapi.play.naver.jp", "cherry.example.org", 1, 0, 1, canon, sizeof canon, &action) == 1,
          "canon filled");
    check(action == RB_AI_RESOLVE && strcmp(canon, "fapi.play.naver.jp") == 0, "canon is original name");
    check(strcmp(canon, "cherry.example.org") != 0, "canon is not endpoint");
    check(rb_prepare_ai("fapi.play.naver.jp", "cherry.example.org", 1, 0, 0, canon, sizeof canon, &action) == 0 &&
              action == RB_AI_RESOLVE,
          "resolve without canon");
}

static void test_cache(void) {
    check(rb_cache_fresh(100, 100, 1), "fresh zero");
    check(rb_cache_fresh(129, 100, 1), "fresh 29");
    check(!rb_cache_fresh(130, 100, 1), "ttl 30 expired");
    check(!rb_cache_fresh(100, 100, 0), "invalid");
    check(!rb_cache_fresh(99, 100, 1), "clock back");
}

static int contains(char rules[][64], int n, const char *s) {
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(rules[i], s) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_hosts_file(void) {
    FILE *f = fopen("patches/hosts.txt", "r");
    char line[256];
    char suffix[16][64];
    char exact[16][64];
    int ns = 0;
    int ne = 0;
    size_t n = 0;
    size_t i;
    const char *const *table;
    if (!f) {
        check(0, "patches/hosts.txt missing from repo root");
        return;
    }
    while (fgets(line, sizeof line, f)) {
        char kind[16];
        char name[64];
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n') {
            check(0, "hosts.txt line too long");
            fclose(f);
            return;
        }
        {
            char *s = line;
            while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
                s++;
            }
            if (*s == '#' || *s == '\0') {
                continue;
            }
        }
        if (sscanf(line, "%15s %63s", kind, name) != 2) {
            check(0, "hosts.txt rule");
            fclose(f);
            return;
        }
        if (strcmp(kind, "suffix") == 0) {
            if (ns >= 16) {
                check(0, "too many suffixes");
                fclose(f);
                return;
            }
            memcpy(suffix[ns], name, strlen(name) + 1);
            ns++;
        } else if (strcmp(kind, "exact") == 0) {
            if (ne >= 16) {
                check(0, "too many exacts");
                fclose(f);
                return;
            }
            memcpy(exact[ne], name, strlen(name) + 1);
            ne++;
        } else {
            check(0, "unknown rule kind");
            fclose(f);
            return;
        }
    }
    fclose(f);
    table = rb_suffixes(&n);
    check(n == (size_t)ns, "suffix count");
    for (i = 0; i < n; i++) {
        check(contains(suffix, ns, table[i]), "suffix in hosts.txt");
    }
    table = rb_exacts(&n);
    check(n == (size_t)ne, "exact count");
    for (i = 0; i < n; i++) {
        check(contains(exact, ne, table[i]), "exact in hosts.txt");
    }
    check(contains(exact, ne, "terms.line.me") && contains(exact, ne, "notice2.line.me") &&
              contains(exact, ne, "help2.line.me") && contains(exact, ne, "lan3rd.line.me"),
          "native exacts present");
}

int main(void) {
    test_redirect();
    test_install_publish();
    test_marker_reserved();
    test_config();
    test_rewrite();
    test_span();
    test_ai_plan();
    test_cache();
    test_hosts_file();
    if (g_fails) {
        fprintf(stderr, "%d failed\n", g_fails);
        return 1;
    }
    return 0;
}
