#include "RBSocketRouter.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int g_fails;

static void check_cond(int cond, const char *msg, int line) {
    if (!cond) {
        fprintf(stderr, "FAIL (line %d): %s\n", line, msg);
        g_fails++;
    }
}

#define CHECK(cond, msg) check_cond((cond) ? 1 : 0, (msg), __LINE__)

struct fake_env {
    pthread_mutex_t mu;
    int64_t now_sec;
    int getaddrinfo_calls;
    int freeaddrinfo_calls;
    int gethostbyname_calls;
    int connect_calls;
    char last_gai_node[256];
    char last_gai_service[64];
    char last_ghbn_name[256];
    int fail_endpoint_dns;
    int endpoint_dns_rc;
    int endpoint_ipv6_only;
    uint8_t endpoint_ip[4];
    uint8_t passthrough_ip[4];
    int last_connect_fd;
    struct sockaddr_in last_connect_sin;
    socklen_t last_connect_len;
    struct hostent passthrough_ent;
    char passthrough_name[256];
    char *passthrough_aliases[1];
    char *passthrough_addrs[2];
    uint8_t passthrough_addr_bytes[4];
};

static struct fake_env g_fake;

static void fake_reset(void) {
    memset(&g_fake, 0, sizeof g_fake);
    pthread_mutex_init(&g_fake.mu, NULL);
    g_fake.now_sec = 1000;
    g_fake.endpoint_ip[0] = 203;
    g_fake.endpoint_ip[1] = 0;
    g_fake.endpoint_ip[2] = 113;
    g_fake.endpoint_ip[3] = 10;
    g_fake.passthrough_ip[0] = 198;
    g_fake.passthrough_ip[1] = 51;
    g_fake.passthrough_ip[2] = 100;
    g_fake.passthrough_ip[3] = 77;
}

static void fake_destroy(void) {
    pthread_mutex_destroy(&g_fake.mu);
}

static int64_t fake_now_sec(void) {
    int64_t t;
    pthread_mutex_lock(&g_fake.mu);
    t = g_fake.now_sec;
    pthread_mutex_unlock(&g_fake.mu);
    return t;
}

static struct addrinfo *alloc_fake_ai_v4(const uint8_t ip[4], uint16_t port, int socktype, int protocol) {
    struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof *ai);
    struct sockaddr_in *sin = (struct sockaddr_in *)calloc(1, sizeof *sin);
    if (!ai || !sin) {
        free(sin);
        free(ai);
        return NULL;
    }
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    memcpy(&sin->sin_addr, ip, 4);
    ai->ai_family = AF_INET;
    ai->ai_socktype = socktype;
    ai->ai_protocol = protocol;
    ai->ai_addrlen = (socklen_t)sizeof *sin;
    ai->ai_addr = (struct sockaddr *)sin;
    return ai;
}

static struct addrinfo *alloc_fake_ai_v6(void) {
    struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof *ai);
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)calloc(1, sizeof *sin6);
    if (!ai || !sin6) {
        free(sin6);
        free(ai);
        return NULL;
    }
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr.s6_addr[15] = 1;
    ai->ai_family = AF_INET6;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen = (socklen_t)sizeof *sin6;
    ai->ai_addr = (struct sockaddr *)sin6;
    return ai;
}

static int fake_getaddrinfo(const char *node, const char *service,
                            const struct addrinfo *hints, struct addrinfo **res) {
    uint8_t ip[4];
    int fail_ep;
    int ep_rc;
    int ep_v6_only;

    pthread_mutex_lock(&g_fake.mu);
    g_fake.getaddrinfo_calls++;
    if (node) {
        snprintf(g_fake.last_gai_node, sizeof g_fake.last_gai_node, "%s", node);
    } else {
        g_fake.last_gai_node[0] = '\0';
    }
    if (service) {
        snprintf(g_fake.last_gai_service, sizeof g_fake.last_gai_service, "%s", service);
    } else {
        g_fake.last_gai_service[0] = '\0';
    }
    fail_ep = g_fake.fail_endpoint_dns;
    ep_rc = g_fake.endpoint_dns_rc ? g_fake.endpoint_dns_rc : EAI_NONAME;
    ep_v6_only = g_fake.endpoint_ipv6_only;
    memcpy(ip, g_fake.endpoint_ip, 4);
    pthread_mutex_unlock(&g_fake.mu);

    if (!res) {
        return EAI_FAIL;
    }
    *res = NULL;

    if (node && strcmp(node, "cherry.example.org") == 0) {
        if (fail_ep) {
            return ep_rc;
        }
        if (ep_v6_only) {
            *res = alloc_fake_ai_v6();
            return *res ? 0 : EAI_MEMORY;
        }
        *res = alloc_fake_ai_v4(ip, 0,
                                hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM,
                                hints && hints->ai_protocol ? hints->ai_protocol : IPPROTO_TCP);
        return *res ? 0 : EAI_MEMORY;
    }

    if (node && strcmp(node, "198.18.0.1") == 0) {
        *res = alloc_fake_ai_v4(rb_marker(), 443, SOCK_STREAM, IPPROTO_TCP);
        return *res ? 0 : EAI_MEMORY;
    }

    pthread_mutex_lock(&g_fake.mu);
    memcpy(ip, g_fake.passthrough_ip, 4);
    pthread_mutex_unlock(&g_fake.mu);

    *res = alloc_fake_ai_v4(ip, 443,
                            hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM,
                            hints && hints->ai_protocol ? hints->ai_protocol : IPPROTO_TCP);
    return *res ? 0 : EAI_MEMORY;
}

static void fake_freeaddrinfo(struct addrinfo *res) {
    pthread_mutex_lock(&g_fake.mu);
    g_fake.freeaddrinfo_calls++;
    pthread_mutex_unlock(&g_fake.mu);
    while (res != NULL) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_canonname);
        free(res->ai_addr);
        free(res);
        res = next;
    }
}

static struct hostent *fake_gethostbyname(const char *name) {
    pthread_mutex_lock(&g_fake.mu);
    g_fake.gethostbyname_calls++;
    if (name) {
        snprintf(g_fake.last_ghbn_name, sizeof g_fake.last_ghbn_name, "%s", name);
    } else {
        g_fake.last_ghbn_name[0] = '\0';
    }
    if (!name) {
        pthread_mutex_unlock(&g_fake.mu);
        h_errno = HOST_NOT_FOUND;
        return NULL;
    }
    snprintf(g_fake.passthrough_name, sizeof g_fake.passthrough_name, "%s", name);
    memcpy(g_fake.passthrough_addr_bytes, g_fake.passthrough_ip, 4);
    g_fake.passthrough_aliases[0] = NULL;
    g_fake.passthrough_addrs[0] = (char *)g_fake.passthrough_addr_bytes;
    g_fake.passthrough_addrs[1] = NULL;
    memset(&g_fake.passthrough_ent, 0, sizeof g_fake.passthrough_ent);
    g_fake.passthrough_ent.h_name = g_fake.passthrough_name;
    g_fake.passthrough_ent.h_aliases = g_fake.passthrough_aliases;
    g_fake.passthrough_ent.h_addrtype = AF_INET;
    g_fake.passthrough_ent.h_length = 4;
    g_fake.passthrough_ent.h_addr_list = g_fake.passthrough_addrs;
    pthread_mutex_unlock(&g_fake.mu);
    return &g_fake.passthrough_ent;
}

static int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    pthread_mutex_lock(&g_fake.mu);
    g_fake.connect_calls++;
    g_fake.last_connect_fd = sockfd;
    g_fake.last_connect_len = addrlen;
    memset(&g_fake.last_connect_sin, 0, sizeof g_fake.last_connect_sin);
    if (addr && addrlen >= (socklen_t)sizeof(struct sockaddr_in) && addr->sa_family == AF_INET) {
        memcpy(&g_fake.last_connect_sin, addr, sizeof(struct sockaddr_in));
    } else if (addr) {
        g_fake.last_connect_sin.sin_family = addr->sa_family;
    }
    pthread_mutex_unlock(&g_fake.mu);
    return 0;
}

static rb_socket_ops make_fake_ops(void) {
    rb_socket_ops ops = {
        .real_getaddrinfo = fake_getaddrinfo,
        .real_freeaddrinfo = fake_freeaddrinfo,
        .real_gethostbyname = fake_gethostbyname,
        .real_connect = fake_connect,
        .now_monotonic_sec = fake_now_sec,
    };
    return ops;
}

static rb_config make_dns_cfg(void) {
    rb_config cfg;
    int ports[RB_PORT_N] = {8080, 8443, 11000, 11123};
    int ok = rb_validate("Cherry.Example.ORG", ports, &cfg);
    CHECK(ok == 1, "rb_validate dns config");
    return cfg;
}

static rb_config make_ipv4_cfg(void) {
    rb_config cfg;
    int ports[RB_PORT_N] = {8081, 8444, 12000, 12123};
    int ok = rb_validate("192.0.2.50", ports, &cfg);
    CHECK(ok == 1, "rb_validate ipv4 config");
    return cfg;
}

static int addrinfo_has_marker(const struct addrinfo *ai, uint16_t expected_port) {
    const struct sockaddr_in *sin;
    if (!ai || ai->ai_family != AF_INET || !ai->ai_addr ||
        ai->ai_addrlen < (socklen_t)sizeof(struct sockaddr_in)) {
        return 0;
    }
    sin = (const struct sockaddr_in *)ai->ai_addr;
    return memcmp(&sin->sin_addr, rb_marker(), 4) == 0 &&
           ntohs(sin->sin_port) == expected_port;
}

static void test_redirected_getaddrinfo_and_connect(void) {
    static const char *const redirected_hosts[] = {
        "fapi.play.naver.jp",
        "gws.play.naver.jp",
        "session.play.naver.jp",
        "play-static.line-scdn.net",
        "terms.line.me",
    };
    static const uint16_t orig_ports[] = {443, 80, 10123, 10000};
    static const uint16_t mapped_ports[] = {8443, 8080, 11123, 11000};
    RBSocketRouter router;
    rb_socket_ops ops = make_fake_ops();
    rb_config cfg = make_dns_cfg();
    size_t i;

    fake_reset();
    CHECK(rb_router_init(&router, &ops, &cfg) == 0, "init router");

    for (i = 0; i < sizeof redirected_hosts / sizeof redirected_hosts[0]; i++) {
        struct addrinfo hints;
        struct addrinfo *res = NULL;
        int rc;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = (i % 2 == 0) ? AF_UNSPEC : AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = (i == 0) ? AI_CANONNAME : 0;

        rc = rb_router_getaddrinfo(&router, redirected_hosts[i], "443", &hints, &res);
        CHECK(rc == 0 && res != NULL, "redirected getaddrinfo succeeds");
        CHECK(addrinfo_has_marker(res, 443), "synthesized addrinfo carries marker + port 443");
        CHECK(res->ai_socktype == SOCK_STREAM && res->ai_protocol == IPPROTO_TCP, "socktype/proto honored");
        CHECK(res->ai_next == NULL, "single addrinfo synthesized");
        if (i == 0) {
            CHECK(res->ai_canonname != NULL && strcmp(res->ai_canonname, redirected_hosts[i]) == 0,
                  "canonname preserves original LINE host");
        } else {
            CHECK(res->ai_canonname == NULL, "canonname null when not requested");
        }
        CHECK(strcmp(g_fake.last_gai_node, "cherry.example.org") == 0,
              "real_getaddrinfo called only with endpoint host, never LINE host");

        rb_router_freeaddrinfo(&router, res);
        CHECK(g_fake.freeaddrinfo_calls == 1, "freeaddrinfo only called for internal endpoint resolution");
    }

    CHECK(g_fake.getaddrinfo_calls == 1, "cache reused across all 5 redirected hosts within TTL");

    /* Service name and port mapping tests */
    {
        struct addrinfo *res = NULL;
        CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "https", NULL, &res) == 0 &&
                  addrinfo_has_marker(res, 443),
              "service 'https' -> 443");
        rb_router_freeaddrinfo(&router, res);

        res = NULL;
        CHECK(rb_router_getaddrinfo(&router, "terms.line.me", "http", NULL, &res) == 0 &&
                  addrinfo_has_marker(res, 80),
              "service 'http' -> 80");
        rb_router_freeaddrinfo(&router, res);

        res = NULL;
        CHECK(rb_router_getaddrinfo(&router, "gws.play.naver.jp", NULL, NULL, &res) == 0 &&
                  addrinfo_has_marker(res, 0),
              "NULL service -> port 0");
        rb_router_freeaddrinfo(&router, res);

        /* Hints honoring SOCK_DGRAM / AF_INET6 / AI_NUMERICHOST / AI_NUMERICSERV */
        {
            struct addrinfo hints;
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            res = NULL;
            CHECK(rb_router_getaddrinfo(&router, "session.play.naver.jp", "10123", &hints, &res) == 0 &&
                      addrinfo_has_marker(res, 10123) &&
                      res->ai_socktype == SOCK_DGRAM && res->ai_protocol == IPPROTO_UDP,
                  "SOCK_DGRAM honored");
            rb_router_freeaddrinfo(&router, res);

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET6;
            res = NULL;
            CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", &hints, &res) == EAI_NONAME &&
                      res == NULL,
                  "AF_INET6-only rejected with EAI_NONAME");

            memset(&hints, 0, sizeof hints);
            hints.ai_flags = AI_NUMERICHOST;
            res = NULL;
            CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", &hints, &res) == EAI_NONAME &&
                      res == NULL,
                  "AI_NUMERICHOST on DNS host returns EAI_NONAME");

            memset(&hints, 0, sizeof hints);
            hints.ai_flags = AI_NUMERICSERV;
            res = NULL;
            CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "https", &hints, &res) == EAI_NONAME &&
                      res == NULL,
                  "AI_NUMERICSERV rejects non-numeric service");

            res = NULL;
            CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "70000", NULL, &res) == EAI_SERVICE &&
                      res == NULL,
                  "out-of-range service port rejected");
        }
    }

    /* Marker connect maps 443, 80, 10123, 10000 and keeps unmapped port */
    for (i = 0; i < 4; i++) {
        struct sockaddr_in target;
        memset(&target, 0, sizeof target);
        target.sin_family = AF_INET;
        target.sin_port = htons(orig_ports[i]);
        memcpy(&target.sin_addr, rb_marker(), 4);

        CHECK(rb_router_connect(&router, 10 + (int)i, (const struct sockaddr *)&target, sizeof target) == 0,
              "marker connect succeeds");
        CHECK(memcmp(&g_fake.last_connect_sin.sin_addr, g_fake.endpoint_ip, 4) == 0,
              "connect rewrites marker IP to resolved endpoint IP");
        CHECK(ntohs(g_fake.last_connect_sin.sin_port) == mapped_ports[i],
              "connect maps port to configured port");
    }

    {
        struct sockaddr_in target;
        memset(&target, 0, sizeof target);
        target.sin_family = AF_INET;
        target.sin_port = htons(9001);
        memcpy(&target.sin_addr, rb_marker(), 4);
        CHECK(rb_router_connect(&router, 20, (const struct sockaddr *)&target, sizeof target) == 0,
              "marker connect unmapped port succeeds");
        CHECK(memcmp(&g_fake.last_connect_sin.sin_addr, g_fake.endpoint_ip, 4) == 0 &&
                  ntohs(g_fake.last_connect_sin.sin_port) == 9001,
              "unmapped port keeps original port while rewriting marker IP");
    }

    rb_router_destroy(&router);
    fake_destroy();
}

static void test_gethostbyname_redirect_and_passthrough(void) {
    RBSocketRouter router;
    rb_socket_ops ops = make_fake_ops();
    rb_config cfg = make_dns_cfg();
    struct hostent *ent;
    struct in_addr addr;

    fake_reset();
    CHECK(rb_router_init(&router, &ops, &cfg) == 0, "init router");

    ent = rb_router_gethostbyname(&router, "session.play.naver.jp");
    CHECK(ent != NULL, "gethostbyname session.play.naver.jp succeeds");
    CHECK(ent->h_addrtype == AF_INET && ent->h_length == 4, "hostent AF_INET length 4");
    CHECK(ent->h_addr_list != NULL && ent->h_addr_list[0] != NULL && ent->h_addr_list[1] == NULL,
          "hostent single address");
    memcpy(&addr, ent->h_addr_list[0], 4);
    CHECK(memcmp(&addr, rb_marker(), 4) == 0, "hostent contains marker IP");
    CHECK(strcmp(inet_ntoa(addr), "198.18.0.1") == 0, "inet_ntoa yields marker literal");
    CHECK(g_fake.gethostbyname_calls == 0, "real_gethostbyname never called for redirected host");
    CHECK(g_fake.getaddrinfo_calls == 1 && strcmp(g_fake.last_gai_node, "cherry.example.org") == 0,
          "endpoint resolved via real_getaddrinfo");

    ent = rb_router_gethostbyname(&router, "gws.play.naver.jp");
    CHECK(ent != NULL && memcmp(ent->h_addr_list[0], rb_marker(), 4) == 0,
          "gethostbyname gws.play.naver.jp returns marker");
    CHECK(g_fake.gethostbyname_calls == 0, "real_gethostbyname still not called");
    CHECK(g_fake.getaddrinfo_calls == 1, "cache reused for gws.play.naver.jp");

    /* Unrelated host passes through to real_gethostbyname */
    ent = rb_router_gethostbyname(&router, "example.com");
    CHECK(ent != NULL && memcmp(ent->h_addr_list[0], g_fake.passthrough_ip, 4) == 0,
          "unrelated gethostbyname passes through");
    CHECK(g_fake.gethostbyname_calls == 1 && strcmp(g_fake.last_ghbn_name, "example.com") == 0,
          "real_gethostbyname called with unrelated host");

    rb_router_destroy(&router);
    fake_destroy();
}

static void test_passthrough_and_marker_only_connect(void) {
    static const char *const unrelated[] = {"example.com", "google.com", "1.2.3.4"};
    RBSocketRouter router;
    rb_socket_ops ops = make_fake_ops();
    rb_config cfg = make_dns_cfg();
    size_t i;

    fake_reset();
    CHECK(rb_router_init(&router, &ops, &cfg) == 0, "init router");

    for (i = 0; i < sizeof unrelated / sizeof unrelated[0]; i++) {
        struct addrinfo *res = NULL;
        int prev_free = g_fake.freeaddrinfo_calls;
        CHECK(rb_router_getaddrinfo(&router, unrelated[i], "443", NULL, &res) == 0 && res != NULL,
              "unrelated getaddrinfo passes through");
        CHECK(strcmp(g_fake.last_gai_node, unrelated[i]) == 0, "real_getaddrinfo saw unrelated host");
        CHECK(memcmp(&((struct sockaddr_in *)res->ai_addr)->sin_addr, g_fake.passthrough_ip, 4) == 0,
              "unrelated result is untouched passthrough IP");
        rb_router_freeaddrinfo(&router, res);
        CHECK(g_fake.freeaddrinfo_calls == prev_free + 1,
              "non-marker addrinfo forwarded to real_freeaddrinfo");
    }

    /* Literal 198.18.0.1 passed to getaddrinfo is NOT redirected and is freed via real_freeaddrinfo */
    {
        struct addrinfo *res = NULL;
        int prev_free = g_fake.freeaddrinfo_calls;
        CHECK(rb_router_getaddrinfo(&router, "198.18.0.1", "443", NULL, &res) == 0 && res != NULL,
              "literal marker getaddrinfo passes through");
        CHECK(strcmp(g_fake.last_gai_node, "198.18.0.1") == 0, "literal marker passed to real_getaddrinfo");
        rb_router_freeaddrinfo(&router, res);
        CHECK(g_fake.freeaddrinfo_calls == prev_free + 1,
              "real addrinfo with marker bytes still forwarded to real_freeaddrinfo");
    }

    /* connect to non-marker IP (EVEN if equal to endpoint IP!) passes through with original port untouched */
    {
        struct sockaddr_in direct_ep;
        memset(&direct_ep, 0, sizeof direct_ep);
        direct_ep.sin_family = AF_INET;
        direct_ep.sin_port = htons(443);
        memcpy(&direct_ep.sin_addr, g_fake.endpoint_ip, 4);

        CHECK(rb_router_connect(&router, 33, (const struct sockaddr *)&direct_ep, sizeof direct_ep) == 0,
              "direct connect to endpoint IP passes through");
        CHECK(memcmp(&g_fake.last_connect_sin.sin_addr, g_fake.endpoint_ip, 4) == 0 &&
                  ntohs(g_fake.last_connect_sin.sin_port) == 443,
              "endpoint-IP equality does NOT remap port 443 -> 8443");
    }

    /* Non-AF_INET connect passes through untouched */
    {
        struct sockaddr_in6 v6;
        memset(&v6, 0, sizeof v6);
        v6.sin6_family = AF_INET6;
        CHECK(rb_router_connect(&router, 34, (const struct sockaddr *)&v6, sizeof v6) == 0 &&
                  g_fake.last_connect_sin.sin_family == AF_INET6,
              "AF_INET6 connect passes through untouched");
    }

    rb_router_destroy(&router);
    fake_destroy();
}

static void test_fail_closed_when_endpoint_dns_fails(void) {
    RBSocketRouter router;
    rb_socket_ops ops = make_fake_ops();
    rb_config cfg = make_dns_cfg();
    struct addrinfo *res = (struct addrinfo *)(uintptr_t)0x1;
    struct hostent *ent;
    struct sockaddr_in marker_sin;

    fake_reset();
    g_fake.fail_endpoint_dns = 1;
    g_fake.endpoint_dns_rc = EAI_NONAME;
    CHECK(rb_router_init(&router, &ops, &cfg) == 0, "init router");

    CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", NULL, &res) == EAI_NONAME &&
              res == NULL,
          "getaddrinfo fails closed when endpoint DNS fails");
    CHECK(g_fake.getaddrinfo_calls == 1 && strcmp(g_fake.last_gai_node, "cherry.example.org") == 0,
          "never falls back to real LINE host in getaddrinfo");

    h_errno = 0;
    ent = rb_router_gethostbyname(&router, "session.play.naver.jp");
    CHECK(ent == NULL && h_errno == HOST_NOT_FOUND, "gethostbyname fails closed on endpoint DNS failure");
    CHECK(g_fake.gethostbyname_calls == 0, "never falls back to real_gethostbyname");

    memset(&marker_sin, 0, sizeof marker_sin);
    marker_sin.sin_family = AF_INET;
    marker_sin.sin_port = htons(443);
    memcpy(&marker_sin.sin_addr, rb_marker(), 4);
    errno = 0;
    CHECK(rb_router_connect(&router, 5, (const struct sockaddr *)&marker_sin, sizeof marker_sin) == -1 &&
              errno == EHOSTUNREACH,
          "connect fails closed with EHOSTUNREACH when endpoint unresolvable");
    CHECK(g_fake.connect_calls == 0, "real_connect never called with marker IP");

    /* Also fail closed if endpoint resolves to IPv6-only or to the marker IP itself */
    g_fake.fail_endpoint_dns = 0;
    g_fake.endpoint_ipv6_only = 1;
    res = NULL;
    CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", NULL, &res) == EAI_NONAME &&
              res == NULL,
          "endpoint resolving to IPv6-only fails closed");

    g_fake.endpoint_ipv6_only = 0;
    memcpy(g_fake.endpoint_ip, rb_marker(), 4);
    res = NULL;
    CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", NULL, &res) == EAI_FAIL &&
              res == NULL,
          "endpoint resolving to marker IP fails closed");

    rb_router_destroy(&router);
    fake_destroy();
}

static void test_cache_ttl_and_ipv4_literal_cfg(void) {
    RBSocketRouter router;
    rb_socket_ops ops = make_fake_ops();
    rb_config dns_cfg = make_dns_cfg();
    rb_config ip_cfg = make_ipv4_cfg();
    struct addrinfo *res = NULL;
    struct sockaddr_in marker_sin;

    fake_reset();
    CHECK(rb_router_init(&router, &ops, &dns_cfg) == 0, "init dns router");

    g_fake.now_sec = 2000;
    CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", NULL, &res) == 0,
          "initial lookup populates cache");
    rb_router_freeaddrinfo(&router, res);
    CHECK(g_fake.getaddrinfo_calls == 1, "1 DNS lookup");

    /* Mutate endpoint_ip in fake DNS; within TTL cache must still return old IP */
    g_fake.endpoint_ip[3] = 99;
    g_fake.now_sec = 2000 + RB_CACHE_TTL - 1;
    memset(&marker_sin, 0, sizeof marker_sin);
    marker_sin.sin_family = AF_INET;
    marker_sin.sin_port = htons(80);
    memcpy(&marker_sin.sin_addr, rb_marker(), 4);

    CHECK(rb_router_connect(&router, 40, (const struct sockaddr *)&marker_sin, sizeof marker_sin) == 0,
          "connect within TTL succeeds");
    CHECK(g_fake.getaddrinfo_calls == 1, "no new DNS lookup before TTL");
    CHECK(g_fake.last_connect_sin.sin_addr.s_addr != 0 &&
              ((const uint8_t *)&g_fake.last_connect_sin.sin_addr)[3] == 10,
          "connect used cached IP (.10)");

    /* At exact TTL boundary, cache expires and refreshes to .99 */
    g_fake.now_sec = 2000 + RB_CACHE_TTL;
    CHECK(rb_router_connect(&router, 41, (const struct sockaddr *)&marker_sin, sizeof marker_sin) == 0,
          "connect after TTL expiry succeeds");
    CHECK(g_fake.getaddrinfo_calls == 2, "DNS refreshed after TTL expiry");
    CHECK(((const uint8_t *)&g_fake.last_connect_sin.sin_addr)[3] == 99 &&
              ntohs(g_fake.last_connect_sin.sin_port) == 8080,
          "connect uses refreshed IP (.99) and mapped port 8080");

    /* Reconfigure with IPv4 literal: never calls real_getaddrinfo */
    CHECK(rb_router_configure(&router, &ip_cfg) == 0, "reconfigure with IPv4 literal");
    res = NULL;
    CHECK(rb_router_getaddrinfo(&router, "terms.line.me", "443", NULL, &res) == 0 &&
              addrinfo_has_marker(res, 443),
          "ipv4 config getaddrinfo returns marker");
    rb_router_freeaddrinfo(&router, res);
    CHECK(g_fake.getaddrinfo_calls == 2, "ipv4 config makes zero DNS queries");

    CHECK(rb_router_connect(&router, 42, (const struct sockaddr *)&marker_sin, sizeof marker_sin) == 0,
          "ipv4 config connect succeeds");
    CHECK(((const uint8_t *)&g_fake.last_connect_sin.sin_addr)[0] == 192 &&
              ((const uint8_t *)&g_fake.last_connect_sin.sin_addr)[3] == 50 &&
              ntohs(g_fake.last_connect_sin.sin_port) == 8081,
          "ipv4 config rewrites to literal IP and port 8081");

    rb_router_destroy(&router);
    fake_destroy();
}

static void test_disabled_and_freeaddrinfo_ownership(void) {
    RBSocketRouter router;
    rb_socket_ops ops = make_fake_ops();
    rb_config cfg = make_dns_cfg();
    struct addrinfo *synth = NULL;
    struct addrinfo *real_ai = NULL;
    struct sockaddr_in marker_sin;

    fake_reset();
    /* Unconfigured init passes everything through */
    CHECK(rb_router_init(&router, &ops, NULL) == 0, "init unconfigured router");
    CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", NULL, &real_ai) == 0,
          "disabled getaddrinfo passes LINE host through");
    CHECK(strcmp(g_fake.last_gai_node, "fapi.play.naver.jp") == 0,
          "disabled router passed original LINE host");
    rb_router_freeaddrinfo(&router, real_ai);
    CHECK(g_fake.freeaddrinfo_calls == 1, "disabled passthrough freed via real_freeaddrinfo");

    /* Enable, synthesize, then disable before freeing */
    CHECK(rb_router_configure(&router, &cfg) == 0, "enable router");
    CHECK(rb_router_getaddrinfo(&router, "fapi.play.naver.jp", "443", NULL, &synth) == 0 &&
              addrinfo_has_marker(synth, 443),
          "enabled router synthesizes marker");

    CHECK(rb_router_configure(&router, NULL) == 0, "disable router");
    rb_router_freeaddrinfo(&router, synth);
    CHECK(g_fake.freeaddrinfo_calls == 2,
          "synthesized addrinfo still freed cleanly without calling real_freeaddrinfo after disable");
    rb_router_freeaddrinfo(&router, NULL);
    CHECK(g_fake.freeaddrinfo_calls == 2, "freeaddrinfo(NULL) is a no-op");

    /* Disabled connect passes marker IP through untouched */
    memset(&marker_sin, 0, sizeof marker_sin);
    marker_sin.sin_family = AF_INET;
    marker_sin.sin_port = htons(443);
    memcpy(&marker_sin.sin_addr, rb_marker(), 4);
    CHECK(rb_router_connect(&router, 50, (const struct sockaddr *)&marker_sin, sizeof marker_sin) == 0 &&
              memcmp(&g_fake.last_connect_sin.sin_addr, rb_marker(), 4) == 0,
          "disabled connect passes through untouched");

    /* Reject invalid configs */
    {
        rb_config bad;
        memset(&bad, 0, sizeof bad);
        CHECK(rb_router_configure(&router, &bad) == -1, "empty config rejected");
    }

    rb_router_destroy(&router);
    fake_destroy();
}

static void *worker_thread(void *arg) {
    RBSocketRouter *router = (RBSocketRouter *)arg;
    int i;
    for (i = 0; i < 40; i++) {
        struct addrinfo *res = NULL;
        struct hostent *ent;
        struct sockaddr_in sin;

        if (rb_router_getaddrinfo(router, "fapi.play.naver.jp", "443", NULL, &res) != 0 ||
            !addrinfo_has_marker(res, 443)) {
            return (void *)(uintptr_t)1;
        }
        rb_router_freeaddrinfo(router, res);

        ent = rb_router_gethostbyname(router, "session.play.naver.jp");
        if (!ent || !ent->h_addr_list || !ent->h_addr_list[0] ||
            memcmp(ent->h_addr_list[0], rb_marker(), 4) != 0) {
            return (void *)(uintptr_t)1;
        }

        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(10123);
        memcpy(&sin.sin_addr, rb_marker(), 4);
        if (rb_router_connect(router, 1, (const struct sockaddr *)&sin, sizeof sin) != 0) {
            return (void *)(uintptr_t)1;
        }
    }
    return NULL;
}

static void test_concurrent_routing(void) {
    RBSocketRouter router;
    rb_socket_ops ops = make_fake_ops();
    rb_config cfg = make_dns_cfg();
    pthread_t th[4];
    int i;

    fake_reset();
    CHECK(rb_router_init(&router, &ops, &cfg) == 0, "init concurrent router");
    for (i = 0; i < 4; i++) {
        CHECK(pthread_create(&th[i], NULL, worker_thread, &router) == 0, "pthread_create");
    }
    for (i = 0; i < 4; i++) {
        void *ret = NULL;
        CHECK(pthread_join(th[i], &ret) == 0 && ret == NULL, "worker thread succeeded");
    }
    CHECK(g_fake.getaddrinfo_calls >= 1 && g_fake.getaddrinfo_calls <= 4 &&
              g_fake.freeaddrinfo_calls == g_fake.getaddrinfo_calls,
          "only initial endpoint DNS resolutions called real_freeaddrinfo");
    rb_router_destroy(&router);
    fake_destroy();
}

int main(void) {
    test_redirected_getaddrinfo_and_connect();
    test_gethostbyname_redirect_and_passthrough();
    test_passthrough_and_marker_only_connect();
    test_fail_closed_when_endpoint_dns_fails();
    test_cache_ttl_and_ipv4_literal_cfg();
    test_disabled_and_freeaddrinfo_ownership();
    test_concurrent_routing();

    if (g_fails != 0) {
        fprintf(stderr, "socket_router_test: %d failure(s)\n", g_fails);
        return 1;
    }
    printf("socket_router_test: all tests passed\n");
    return 0;
}
