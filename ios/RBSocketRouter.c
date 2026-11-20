#include "RBSocketRouter.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static _Thread_local struct hostent g_tls_ent;
static _Thread_local char g_tls_name[RB_HOST_MAX + 2];
static _Thread_local char *g_tls_aliases[1];
static _Thread_local char *g_tls_addrs[2];
static _Thread_local uint8_t g_tls_addr[4];

static int validate_cfg(const rb_config *cfg, rb_config *out) {
    int ports[RB_PORT_N];
    int i;
    if (!cfg || !out) {
        return 0;
    }
    for (i = 0; i < RB_PORT_N; i++) {
        ports[i] = (int)cfg->ports[i];
    }
    if (!rb_validate(cfg->host, ports, out)) {
        return 0;
    }
    if (cfg->is_ipv4) {
        if (!out->is_ipv4 || memcmp(out->ip, cfg->ip, 4) != 0) {
            memset(out, 0, sizeof *out);
            return 0;
        }
    }
    return 1;
}

static int snapshot_cfg(RBSocketRouter *router, rb_config *out_cfg, uint64_t *out_gen) {
    int enabled;
    pthread_mutex_lock(&router->mu);
    enabled = atomic_load_explicit(&router->configured, memory_order_acquire) &&
              router->cfg.host[0] != '\0';
    if (enabled) {
        *out_cfg = router->cfg;
        *out_gen = router->cfg_gen;
    }
    pthread_mutex_unlock(&router->mu);
    return enabled;
}

static int monotonic_now(const RBSocketRouter *router, int64_t *out_sec) {
    struct timespec ts;
    if (router->ops.now_monotonic_sec != NULL) {
        *out_sec = router->ops.now_monotonic_sec();
        return 1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    *out_sec = (int64_t)ts.tv_sec;
    return 1;
}

static void map_eai_to_h_errno(int rc) {
    if (rc == EAI_AGAIN) {
        h_errno = TRY_AGAIN;
    } else if (rc == EAI_NONAME || rc == EAI_FAIL) {
        h_errno = HOST_NOT_FOUND;
    } else if (rc == EAI_MEMORY) {
        h_errno = NETDB_INTERNAL;
        errno = ENOMEM;
    } else {
        h_errno = NO_RECOVERY;
    }
}

static int ascii_strcasecmp(const char *a, const char *b) {
    size_t i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (unsigned char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return (int)ca - (int)cb;
        }
        i++;
    }
    return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
}

static int parse_service_port(const char *service, const struct addrinfo *hints, uint16_t *out_port) {
    size_t i;
    uint32_t val = 0;
    int numeric_only = hints != NULL && (hints->ai_flags & AI_NUMERICSERV) != 0;

    if (service == NULL) {
        *out_port = 0;
        return 0;
    }
    if (service[0] == '\0') {
        return EAI_SERVICE;
    }

    for (i = 0; service[i] != '\0'; i++) {
        unsigned char c = (unsigned char)service[i];
        if (c < '0' || c > '9') {
            break;
        }
        val = val * 10u + (uint32_t)(c - '0');
        if (val > 65535u) {
            return EAI_SERVICE;
        }
    }
    if (service[i] == '\0') {
        *out_port = (uint16_t)val;
        return 0;
    }

    if (numeric_only) {
        return EAI_NONAME;
    }
    if (ascii_strcasecmp(service, "http") == 0) {
        *out_port = 80;
        return 0;
    }
    if (ascii_strcasecmp(service, "https") == 0) {
        *out_port = 443;
        return 0;
    }
    return EAI_SERVICE;
}

static char *dup_cstr(const char *s) {
    size_t n = strlen(s);
    char *copy = (char *)malloc(n + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, s, n + 1);
    return copy;
}

static int resolve_endpoint_ip(RBSocketRouter *router, const rb_config *cfg, uint64_t snap_gen,
                               uint8_t out_ip[4]) {
    struct addrinfo v4_hints;
    struct addrinfo *ep_res = NULL;
    struct addrinfo *ai;
    int64_t now = 0;
    int rc;
    int found = 0;
    const uint8_t *marker = rb_marker();

    if (cfg->is_ipv4) {
        if (memcmp(cfg->ip, marker, 4) == 0) {
            return EAI_FAIL;
        }
        memcpy(out_ip, cfg->ip, 4);
        return 0;
    }

    if (monotonic_now(router, &now)) {
        pthread_mutex_lock(&router->mu);
        if (atomic_load_explicit(&router->configured, memory_order_acquire) &&
            router->cfg_gen == snap_gen &&
            rb_cache_fresh(now, router->cache_at, router->cache_valid) &&
            memcmp(router->cache_ip, marker, 4) != 0) {
            memcpy(out_ip, router->cache_ip, 4);
            pthread_mutex_unlock(&router->mu);
            return 0;
        }
        pthread_mutex_unlock(&router->mu);
    }

    memset(&v4_hints, 0, sizeof v4_hints);
    v4_hints.ai_family = AF_INET;
    v4_hints.ai_socktype = SOCK_STREAM;

    /* Fail closed: resolve cfg->host only, never the intercepted LINE hostname. */
    rc = router->ops.real_getaddrinfo(cfg->host, NULL, &v4_hints, &ep_res);
    if (rc != 0) {
        return rc;
    }

    for (ai = ep_res; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addr != NULL &&
            ai->ai_addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)ai->ai_addr;
            memcpy(out_ip, &sin->sin_addr, 4);
            found = 1;
            break;
        }
    }
    router->ops.real_freeaddrinfo(ep_res);

    if (!found) {
        return EAI_NONAME;
    }
    if (memcmp(out_ip, marker, 4) == 0) {
        return EAI_FAIL;
    }

    if (monotonic_now(router, &now)) {
        pthread_mutex_lock(&router->mu);
        if (atomic_load_explicit(&router->configured, memory_order_acquire) &&
            router->cfg_gen == snap_gen) {
            memcpy(router->cache_ip, out_ip, 4);
            router->cache_at = now;
            router->cache_valid = 1;
        }
        pthread_mutex_unlock(&router->mu);
    }
    return 0;
}

static int track_synth_ptr(RBSocketRouter *router, struct addrinfo *ai) {
    int ok = 0;
    pthread_mutex_lock(&router->mu);
    if (router->synth_count == router->synth_cap) {
        size_t next_cap = router->synth_cap == 0 ? 16 : router->synth_cap * 2;
        if (next_cap > router->synth_cap && next_cap <= SIZE_MAX / sizeof(struct addrinfo *)) {
            struct addrinfo **grown = (struct addrinfo **)realloc(
                router->synth_ptrs, next_cap * sizeof(struct addrinfo *));
            if (grown != NULL) {
                router->synth_ptrs = grown;
                router->synth_cap = next_cap;
            }
        }
    }
    if (router->synth_count < router->synth_cap) {
        router->synth_ptrs[router->synth_count++] = ai;
        ok = 1;
    }
    pthread_mutex_unlock(&router->mu);
    return ok;
}

static int untrack_synth_ptr(RBSocketRouter *router, struct addrinfo *ai) {
    size_t i;
    int found = 0;
    pthread_mutex_lock(&router->mu);
    for (i = 0; i < router->synth_count; i++) {
        if (router->synth_ptrs[i] == ai) {
            router->synth_ptrs[i] = router->synth_ptrs[router->synth_count - 1];
            router->synth_count--;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&router->mu);
    return found;
}

static void free_synth_chain(struct addrinfo *res) {
    while (res != NULL) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_canonname);
        free(res->ai_addr);
        free(res);
        res = next;
    }
}

int rb_router_init(RBSocketRouter *router, const rb_socket_ops *ops, const rb_config *cfg) {
    rb_config validated;
    if (!router || !ops ||
        !ops->real_getaddrinfo || !ops->real_freeaddrinfo ||
        !ops->real_gethostbyname || !ops->real_connect) {
        return -1;
    }
    if (cfg != NULL && !validate_cfg(cfg, &validated)) {
        return -1;
    }
    memset(router, 0, sizeof *router);
    if (pthread_mutex_init(&router->mu, NULL) != 0) {
        return -1;
    }
    router->ops = *ops;
    atomic_init(&router->initialized, 1);
    if (cfg != NULL) {
        router->cfg = validated;
        router->cfg_gen = 1;
        atomic_init(&router->configured, 1);
    } else {
        atomic_init(&router->configured, 0);
    }
    return 0;
}

int rb_router_configure(RBSocketRouter *router, const rb_config *cfg) {
    rb_config validated;
    if (!router || !atomic_load_explicit(&router->initialized, memory_order_acquire)) {
        return -1;
    }
    if (cfg != NULL && !validate_cfg(cfg, &validated)) {
        return -1;
    }
    pthread_mutex_lock(&router->mu);
    memset(&router->cache_ip, 0, sizeof router->cache_ip);
    router->cache_at = 0;
    router->cache_valid = 0;
    router->cfg_gen++;
    if (cfg != NULL) {
        router->cfg = validated;
        atomic_store_explicit(&router->configured, 1, memory_order_release);
    } else {
        memset(&router->cfg, 0, sizeof router->cfg);
        atomic_store_explicit(&router->configured, 0, memory_order_release);
    }
    pthread_mutex_unlock(&router->mu);
    return 0;
}

void rb_router_destroy(RBSocketRouter *router) {
    if (!router) {
        return;
    }
    if (atomic_exchange_explicit(&router->initialized, 0, memory_order_acq_rel) != 1) {
        return;
    }
    atomic_store_explicit(&router->configured, 0, memory_order_release);
    pthread_mutex_lock(&router->mu);
    free(router->synth_ptrs);
    router->synth_ptrs = NULL;
    router->synth_count = 0;
    router->synth_cap = 0;
    pthread_mutex_unlock(&router->mu);
    pthread_mutex_destroy(&router->mu);
    memset(router, 0, sizeof *router);
}

int rb_router_getaddrinfo(RBSocketRouter *router, const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res) {
    rb_config cfg;
    uint64_t snap_gen = 0;
    uint8_t ep_ip[4];
    uint16_t port = 0;
    char canon[RB_HOST_MAX + 2];
    int family_ok;
    int numeric_host;
    int want_canon;
    int action = RB_AI_FAMILY;
    int prepared;
    int socktype;
    int protocol;
    int rc;
    struct addrinfo *ai;
    struct sockaddr_in *sin;
    char *cname = NULL;

    if (!router || !atomic_load_explicit(&router->initialized, memory_order_acquire) ||
        !router->ops.real_getaddrinfo) {
        return EAI_FAIL;
    }
    if (!atomic_load_explicit(&router->configured, memory_order_acquire) ||
        node == NULL || !rb_redirect(node)) {
        return router->ops.real_getaddrinfo(node, service, hints, res);
    }
    if (!snapshot_cfg(router, &cfg, &snap_gen)) {
        return router->ops.real_getaddrinfo(node, service, hints, res);
    }
    if (!res) {
        return EAI_FAIL;
    }
    *res = NULL;

    family_ok = !hints || hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET;
    numeric_host = hints && (hints->ai_flags & AI_NUMERICHOST) != 0;
    want_canon = hints && (hints->ai_flags & AI_CANONNAME) != 0;
    prepared = rb_prepare_ai(node, cfg.host, family_ok, numeric_host, want_canon,
                             canon, sizeof canon, &action);
    if (prepared < 0) {
        return EAI_FAIL;
    }
    if (action == RB_AI_FAMILY) {
        return (hints && hints->ai_family == AF_INET6) ? EAI_NONAME : EAI_FAMILY;
    }
    if (action == RB_AI_NONAME) {
        return EAI_NONAME;
    }

    rc = parse_service_port(service, hints, &port);
    if (rc != 0) {
        return rc;
    }

    rc = resolve_endpoint_ip(router, &cfg, snap_gen, ep_ip);
    if (rc != 0) {
        return rc;
    }

    protocol = hints ? hints->ai_protocol : 0;
    socktype = hints ? hints->ai_socktype : 0;
    if (socktype == 0) {
        socktype = (protocol == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    }
    if (protocol == 0) {
        if (socktype == SOCK_STREAM) {
            protocol = IPPROTO_TCP;
        } else if (socktype == SOCK_DGRAM) {
            protocol = IPPROTO_UDP;
        }
    }

    ai = (struct addrinfo *)calloc(1, sizeof *ai);
    sin = (struct sockaddr_in *)calloc(1, sizeof *sin);
    if (prepared == 1) {
        cname = dup_cstr(canon);
    }
    if (!ai || !sin || (prepared == 1 && !cname)) {
        free(cname);
        free(sin);
        free(ai);
        return EAI_MEMORY;
    }

#if defined(__APPLE__)
    sin->sin_len = (uint8_t)sizeof(*sin);
#endif
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    memcpy(&sin->sin_addr, rb_marker(), 4);

    ai->ai_flags = 0;
    ai->ai_family = AF_INET;
    ai->ai_socktype = socktype;
    ai->ai_protocol = protocol;
    ai->ai_addrlen = (socklen_t)sizeof(*sin);
    ai->ai_addr = (struct sockaddr *)sin;
    ai->ai_canonname = cname;
    ai->ai_next = NULL;

    if (!track_synth_ptr(router, ai)) {
        free_synth_chain(ai);
        return EAI_MEMORY;
    }

    *res = ai;
    return 0;
}

void rb_router_freeaddrinfo(RBSocketRouter *router, struct addrinfo *res) {
    if (res == NULL) {
        return;
    }
    if (!router || !atomic_load_explicit(&router->initialized, memory_order_acquire)) {
        return;
    }
    if (untrack_synth_ptr(router, res)) {
        free_synth_chain(res);
        return;
    }
    if (router->ops.real_freeaddrinfo != NULL) {
        router->ops.real_freeaddrinfo(res);
    }
}

struct hostent *rb_router_gethostbyname(RBSocketRouter *router, const char *name) {
    rb_config cfg;
    uint64_t snap_gen = 0;
    uint8_t ep_ip[4];
    int rc;
    size_t i;

    if (!router || !atomic_load_explicit(&router->initialized, memory_order_acquire) ||
        !router->ops.real_gethostbyname) {
        h_errno = NO_RECOVERY;
        return NULL;
    }
    if (!atomic_load_explicit(&router->configured, memory_order_acquire) ||
        name == NULL || !rb_redirect(name)) {
        return router->ops.real_gethostbyname(name);
    }
    if (!snapshot_cfg(router, &cfg, &snap_gen)) {
        return router->ops.real_gethostbyname(name);
    }

    rc = resolve_endpoint_ip(router, &cfg, snap_gen, ep_ip);
    if (rc != 0) {
        map_eai_to_h_errno(rc);
        return NULL;
    }

    i = 0;
    while (i < sizeof g_tls_name - 1 && name[i] != '\0') {
        g_tls_name[i] = name[i];
        i++;
    }
    g_tls_name[i] = '\0';

    memcpy(g_tls_addr, rb_marker(), 4);
    g_tls_aliases[0] = NULL;
    g_tls_addrs[0] = (char *)g_tls_addr;
    g_tls_addrs[1] = NULL;

    memset(&g_tls_ent, 0, sizeof g_tls_ent);
    g_tls_ent.h_name = g_tls_name;
    g_tls_ent.h_aliases = g_tls_aliases;
    g_tls_ent.h_addrtype = AF_INET;
    g_tls_ent.h_length = 4;
    g_tls_ent.h_addr_list = g_tls_addrs;
    return &g_tls_ent;
}

int rb_router_connect(RBSocketRouter *router, int sockfd,
                      const struct sockaddr *addr, socklen_t addrlen) {
    rb_config cfg;
    uint64_t snap_gen = 0;
    struct sockaddr_in in;
    struct sockaddr_in rewritten;
    uint8_t dst_ip[4];
    uint8_t ep_ip[4];
    uint8_t out_ip[4];
    uint16_t out_port = 0;
    int plan;

    if (!router || !atomic_load_explicit(&router->initialized, memory_order_acquire) ||
        !router->ops.real_connect) {
        errno = EHOSTUNREACH;
        return -1;
    }
    if (!atomic_load_explicit(&router->configured, memory_order_acquire) ||
        addr == NULL || addrlen < (socklen_t)sizeof(struct sockaddr_in) ||
        addr->sa_family != AF_INET) {
        return router->ops.real_connect(sockfd, addr, addrlen);
    }

    memcpy(&in, addr, sizeof in);
    memcpy(dst_ip, &in.sin_addr, 4);
    if (memcmp(dst_ip, rb_marker(), 4) != 0) {
        return router->ops.real_connect(sockfd, addr, addrlen);
    }
    if (!snapshot_cfg(router, &cfg, &snap_gen)) {
        return router->ops.real_connect(sockfd, addr, addrlen);
    }

    if (resolve_endpoint_ip(router, &cfg, snap_gen, ep_ip) != 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    plan = rb_rewrite(dst_ip, ntohs(in.sin_port), ep_ip, cfg.ports, out_ip, &out_port);
    if (plan != 1) {
        errno = EHOSTUNREACH;
        return -1;
    }

    rewritten = in;
    memcpy(&rewritten.sin_addr, out_ip, 4);
    rewritten.sin_port = htons(out_port);
    return router->ops.real_connect(sockfd, (const struct sockaddr *)&rewritten,
                                    (socklen_t)sizeof rewritten);
}
