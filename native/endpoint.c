#include "endpoint.h"

#include <string.h>

static const char *const k_suffixes[] = {
    "play.naver.jp",
    "play.naver.net",
    "line-scdn.net",
    "line-apps.com",
    "line.naver.jp",
};

static const char *const k_exacts[] = {
    "ads.play.naver.jp",
    "lan3rd.line.me",
    "terms.line.me",
    "notice2.line.me",
    "help2.line.me",
};

static const uint16_t k_orig_port[RB_PORT_N] = {80, 443, 10000, 10123};
/* 198.18.0.1 is the in-process routing marker (benchmarking range), not an operator endpoint.
   Go canonicalIPv4 and Java canonicalIPv4 must reject these bytes too; native is not the only gate. */
static const uint8_t k_marker[4] = {198, 18, 0, 1};

const char *const *rb_suffixes(size_t *n) {
    *n = sizeof k_suffixes / sizeof k_suffixes[0];
    return k_suffixes;
}

const char *const *rb_exacts(size_t *n) {
    *n = sizeof k_exacts / sizeof k_exacts[0];
    return k_exacts;
}

const uint8_t *rb_marker(void) {
    return k_marker;
}

int rb_span_inside(uintptr_t lo, uintptr_t hi, uintptr_t addr, uintptr_t width) {
    if (width == 0 || hi <= lo || addr < lo || addr >= hi) {
        return 0;
    }
    return width <= hi - addr;
}

int rb_install_finish(int slots_restored, int *publish) {
    if (publish) {
        *publish = 0;
    }
    if (!slots_restored) {
        return 0;
    }
    if (publish) {
        *publish = 1;
    }
    return 2;
}

int rb_prepare_ai(const char *original, const char *endpoint, int family_ok, int numeric_host, int want_canon,
                  char *canon, size_t cap, int *action) {
    size_t n = 0;
    (void)endpoint;
    if (!action) {
        return -1;
    }
    if (!family_ok) {
        *action = RB_AI_FAMILY;
        return 0;
    }
    if (numeric_host) {
        *action = RB_AI_NONAME;
        return 0;
    }
    *action = RB_AI_RESOLVE;
    if (!want_canon) {
        return 0;
    }
    if (!original || !canon) {
        return -1;
    }
    while (original[n] != '\0' && n < cap) {
        n++;
    }
    if (original[n] != '\0' || n + 1 > cap) {
        return -1;
    }
    memcpy(canon, original, n + 1);
    return 1;
}

int rb_cache_fresh(int64_t now, int64_t at, int valid) {
    if (!valid || now < at) {
        return 0;
    }
    return (now - at) < RB_CACHE_TTL;
}

static int numeric_token(const char *s, size_t n) {
    size_t i;
    if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        if (n == 2) {
            return 0;
        }
        for (i = 2; i < n; i++) {
            char c = s[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return 0;
            }
        }
        return 1;
    }
    if (n == 0) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
    }
    return 1;
}

static int all_numeric(const char *s, size_t n) {
    size_t i = 0;
    if (n == 0) {
        return 0;
    }
    while (i < n) {
        size_t start = i;
        while (i < n && s[i] != '.') {
            i++;
        }
        if (!numeric_token(s + start, i - start)) {
            return 0;
        }
        if (i == n) {
            return 1;
        }
        i++;
        if (i == n) {
            return 0;
        }
    }
    return 0;
}

static int parse_octet(const char *s, size_t n, int *out) {
    size_t i;
    int v = 0;
    if (n == 0 || n > 3 || (n > 1 && s[0] == '0')) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
        v = v * 10 + (s[i] - '0');
    }
    if (v > 255) {
        return 0;
    }
    *out = v;
    return 1;
}

static int strict_ipv4(const char *s, size_t n, uint8_t ip[4]) {
    size_t i = 0;
    int part;
    if (!all_numeric(s, n)) {
        return 0;
    }
    for (part = 0; part < 4; part++) {
        size_t start = i;
        int oct;
        while (i < n && s[i] != '.') {
            i++;
        }
        if (!parse_octet(s + start, i - start, &oct)) {
            return 0;
        }
        ip[part] = (uint8_t)oct;
        if (part < 3) {
            if (i >= n || s[i] != '.') {
                return 0;
            }
            i++;
        }
    }
    return i == n;
}

static int dns_name(const char *s, size_t n) {
    size_t i = 0;
    int labels = 0;
    if (n == 0 || n > RB_HOST_MAX) {
        return 0;
    }
    while (i < n) {
        size_t start = i;
        size_t len;
        size_t j;
        while (i < n && s[i] != '.') {
            i++;
        }
        len = i - start;
        if (len < 1 || len > 63 || s[start] == '-' || s[start + len - 1] == '-') {
            return 0;
        }
        for (j = start; j < i; j++) {
            char c = s[j];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
                return 0;
            }
        }
        labels++;
        if (i == n) {
            break;
        }
        i++;
        if (i == n) {
            return 0;
        }
    }
    return labels > 0;
}

static int bounded_copy(const char *s, size_t cap, char *buf, size_t *out_n) {
    size_t n = 0;
    if (!s) {
        return 0;
    }
    while (n <= cap && s[n] != '\0') {
        n++;
    }
    if (n > cap || s[n] != '\0') {
        return 0;
    }
    memcpy(buf, s, n);
    buf[n] = '\0';
    *out_n = n;
    return 1;
}

static void lower_copy(char *s, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] = (char)(s[i] + 32);
        }
    }
}

static int is_marker(const uint8_t ip[4]) {
    return memcmp(ip, k_marker, 4) == 0;
}

int rb_validate(const char *host, const int ports[RB_PORT_N], rb_config *out) {
    char buf[RB_HOST_MAX + 1];
    size_t n = 0;
    int i;
    uint8_t ip[4];
    if (!out) {
        return 0;
    }
    memset(out, 0, sizeof *out);
    if (!host || !ports || !bounded_copy(host, RB_HOST_MAX, buf, &n)) {
        return 0;
    }
    lower_copy(buf, n);
    for (i = 0; i < RB_PORT_N; i++) {
        if (ports[i] < 1 || ports[i] > 65535) {
            return 0;
        }
    }
    if (all_numeric(buf, n)) {
        if (!strict_ipv4(buf, n, ip) || is_marker(ip)) {
            return 0;
        }
        memcpy(out->host, buf, n + 1);
        memcpy(out->ip, ip, 4);
        out->is_ipv4 = 1;
    } else if (!dns_name(buf, n)) {
        return 0;
    } else {
        memcpy(out->host, buf, n + 1);
    }
    for (i = 0; i < RB_PORT_N; i++) {
        out->ports[i] = (uint16_t)ports[i];
    }
    return 1;
}

int rb_redirect(const char *name) {
    char buf[RB_HOST_MAX + 2];
    size_t n = 0;
    size_t i;
    uint8_t ip[4];
    if (!bounded_copy(name, RB_HOST_MAX + 1, buf, &n)) {
        return 0;
    }
    if (n > 0 && buf[n - 1] == '.') {
        n--;
        buf[n] = '\0';
        if (n == 0 || buf[n - 1] == '.') {
            return 0;
        }
    }
    if (n > RB_HOST_MAX) {
        return 0;
    }
    lower_copy(buf, n);
    if (all_numeric(buf, n) || strict_ipv4(buf, n, ip) || !dns_name(buf, n)) {
        return 0;
    }
    for (i = 0; i < sizeof k_exacts / sizeof k_exacts[0]; i++) {
        if (strcmp(buf, k_exacts[i]) == 0) {
            return 1;
        }
    }
    for (i = 0; i < sizeof k_suffixes / sizeof k_suffixes[0]; i++) {
        size_t ls = strlen(k_suffixes[i]);
        if (strcmp(buf, k_suffixes[i]) == 0) {
            return 1;
        }
        if (n > ls && buf[n - ls - 1] == '.' && strcmp(buf + (n - ls), k_suffixes[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int rb_rewrite(const uint8_t dst[4], uint16_t port, const uint8_t *endpoint,
               const uint16_t mapped[RB_PORT_N], uint8_t out_ip[4], uint16_t *out_port) {
    int i;
    if (!dst || memcmp(dst, k_marker, 4) != 0) {
        return 0;
    }
    if (!endpoint || !mapped || !out_ip || !out_port || is_marker(endpoint)) {
        return -1;
    }
    memcpy(out_ip, endpoint, 4);
    *out_port = port;
    for (i = 0; i < RB_PORT_N; i++) {
        if (port == k_orig_port[i]) {
            *out_port = mapped[i];
            break;
        }
    }
    return 1;
}
