#define _GNU_SOURCE

#include "endpoint.h"

#include <android/log.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

enum { SLOT_GETADDRINFO, SLOT_GETHOSTBYNAME, SLOT_CONNECT, SLOT_SENDTO, SLOT_N };

#if defined(__aarch64__)
/* Locked baseline VAs (arm64 LOAD delta 0). Not a relocation walk. */
static const uintptr_t k_va[SLOT_N] = {0x3b93a18, 0x3b93c90, 0x3b93920, 0x3b93a58};
#elif defined(__arm__)
/* Locked baseline VAs. armv7 file off is VA - 0x1000; dlpi_addr adds to the VA. */
static const uintptr_t k_va[SLOT_N] = {0x2237bf8, 0x2237cdc, 0x2237bd8, 0x2237cf8};
#else
#error raspberry: arm64-v8a or armeabi-v7a only
#endif

static const char *const k_sym[SLOT_N] = {
    "getaddrinfo", "gethostbyname", "connect", "sendto",
};

typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef struct hostent *(*gethostbyname_fn)(const char *);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

static void *g_real[SLOT_N];
static rb_config g_cfg;
static int g_ready;
static int g_state;
static void *g_libc;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static struct {
    int valid;
    int64_t at;
    uint8_t ip[4];
} g_cache;

static _Thread_local struct hostent tls_ent;
static _Thread_local char tls_name[RB_HOST_MAX + 2];
static _Thread_local char *tls_aliases[1];
static _Thread_local char *tls_addrs[2];
static _Thread_local uint8_t tls_addr[4];

static int ready(void) {
    return __atomic_load_n(&g_ready, __ATOMIC_ACQUIRE) && g_cfg.host[0] != '\0';
}

static int cache_get(uint8_t out[4]) {
    struct timespec ts;
    int ok;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    pthread_mutex_lock(&g_mu);
    ok = rb_cache_fresh((int64_t)ts.tv_sec, g_cache.at, g_cache.valid);
    if (ok) {
        memcpy(out, g_cache.ip, 4);
    }
    pthread_mutex_unlock(&g_mu);
    return ok;
}

static void cache_put(const uint8_t ip[4]) {
    struct timespec ts;
    if (memcmp(ip, rb_marker(), 4) == 0 || clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return;
    }
    pthread_mutex_lock(&g_mu);
    memcpy(g_cache.ip, ip, 4);
    g_cache.at = (int64_t)ts.tv_sec;
    g_cache.valid = 1;
    pthread_mutex_unlock(&g_mu);
}

static void cache_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(&g_cache, 0, sizeof g_cache);
    pthread_mutex_unlock(&g_mu);
}

static void *real_slot(int slot) {
    return __atomic_load_n(&g_real[slot], __ATOMIC_ACQUIRE);
}

static int resolve_ip(uint8_t out[4]) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    int rc;
    if (!ready()) {
        return EAI_FAIL;
    }
    if (cache_get(out)) {
        return 0;
    }
    if (g_cfg.is_ipv4) {
        if (memcmp(g_cfg.ip, rb_marker(), 4) == 0) {
            return EAI_FAIL;
        }
        cache_put(g_cfg.ip);
        memcpy(out, g_cfg.ip, 4);
        return 0;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = ((getaddrinfo_fn)real_slot(SLOT_GETADDRINFO))(g_cfg.host, NULL, &hints, &res);
    if (rc != 0) {
        return rc;
    }
    rc = EAI_FAIL;
    for (ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addr && ai->ai_addrlen >= sizeof(struct sockaddr_in)) {
            memcpy(out, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
            if (memcmp(out, rb_marker(), 4) != 0) {
                rc = 0;
            }
            break;
        }
    }
    freeaddrinfo(res);
    if (rc == 0) {
        cache_put(out);
    }
    return rc;
}

static void herr(int rc) {
    if (rc == EAI_AGAIN) {
        h_errno = TRY_AGAIN;
    } else if (rc == EAI_NONAME || rc == EAI_FAIL || rc == EAI_NODATA) {
        h_errno = HOST_NOT_FOUND;
    } else if (rc == EAI_MEMORY) {
        h_errno = NETDB_INTERNAL;
        errno = ENOMEM;
    } else {
        h_errno = NO_RECOVERY;
    }
}

static int paint_marker(struct addrinfo *res) {
    struct addrinfo *ai;
    int n = 0;
    for (ai = res; ai; ai = ai->ai_next) {
        struct sockaddr_in *in;
        if (ai->ai_canonname) {
            free(ai->ai_canonname);
            ai->ai_canonname = NULL;
        }
        if (ai->ai_family != AF_INET || !ai->ai_addr || ai->ai_addrlen < sizeof(struct sockaddr_in)) {
            return -1;
        }
        in = (struct sockaddr_in *)ai->ai_addr;
        memcpy(&in->sin_addr, rb_marker(), 4);
        n++;
    }
    return n > 0 ? 0 : -1;
}

static int hook_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                            struct addrinfo **res) {
    getaddrinfo_fn real = real_slot(SLOT_GETADDRINFO);
    struct addrinfo h;
    struct addrinfo *got = NULL;
    const char *query;
    char lit[16];
    char canon[RB_HOST_MAX + 2];
    uint8_t ip[4];
    int rc;
    int hit;
    int prepared = 0;
    if (!real) {
        return EAI_FAIL;
    }
    if (!node || !rb_redirect(node)) {
        return real(node, service, hints, res);
    }
    if (!res || !ready()) {
        return EAI_FAIL;
    }
    *res = NULL;
    {
        int family_ok = !hints || hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET;
        int numeric = hints && (hints->ai_flags & AI_NUMERICHOST);
        int want_canon = hints && (hints->ai_flags & AI_CANONNAME);
        int action = RB_AI_FAMILY;
        prepared = rb_prepare_ai(node, g_cfg.host, family_ok, numeric, want_canon, canon, sizeof canon, &action);
        if (prepared < 0) {
            return EAI_FAIL;
        }
        if (action == RB_AI_FAMILY) {
            return EAI_FAMILY;
        }
        /* Numeric-only allowlisted name: no original DNS and no endpoint resolve. */
        if (action == RB_AI_NONAME) {
            return EAI_NONAME;
        }
    }
    memset(&h, 0, sizeof h);
    if (hints) {
        h = *hints;
    }
    h.ai_family = AF_INET;
    h.ai_flags &= ~AI_CANONNAME;
    hit = cache_get(ip);
    if (!hit && g_cfg.is_ipv4) {
        memcpy(ip, g_cfg.ip, 4);
        hit = 1;
    }
    if (hit) {
        if (memcmp(ip, rb_marker(), 4) == 0) {
            return EAI_FAIL;
        }
        rc = snprintf(lit, sizeof lit, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        if (rc < 0 || rc >= (int)sizeof lit) {
            return EAI_FAIL;
        }
        query = lit;
        h.ai_flags |= AI_NUMERICHOST;
    } else {
        query = g_cfg.host;
    }
    /* Endpoint only. node is the original URI and is not resolved. */
    rc = real(query, service, &h, &got);
    if (rc != 0) {
        return rc;
    }
    if (!hit) {
        struct addrinfo *ai;
        int found = 0;
        for (ai = got; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET && ai->ai_addr && ai->ai_addrlen >= sizeof(struct sockaddr_in)) {
                memcpy(ip, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
                found = 1;
                break;
            }
        }
        if (!found || memcmp(ip, rb_marker(), 4) == 0) {
            freeaddrinfo(got);
            return EAI_FAIL;
        }
        cache_put(ip);
    }
    if (paint_marker(got) != 0) {
        freeaddrinfo(got);
        return EAI_FAIL;
    }
    if (prepared == 1) {
        /* Head only. Bionic freeaddrinfo frees this. Device probe: that free, and this numeric-flag path. */
        char *owned = strdup(canon);
        if (!owned) {
            freeaddrinfo(got);
            return EAI_MEMORY;
        }
        got->ai_canonname = owned;
    }
    *res = got;
    return 0;
}

static struct hostent *hook_gethostbyname(const char *name) {
    gethostbyname_fn real = real_slot(SLOT_GETHOSTBYNAME);
    uint8_t ip[4];
    size_t i;
    int rc;
    if (!real) {
        h_errno = NO_RECOVERY;
        return NULL;
    }
    if (!name || !rb_redirect(name)) {
        return real(name);
    }
    rc = resolve_ip(ip);
    if (rc != 0) {
        herr(rc);
        return NULL;
    }
    (void)ip;
    i = 0;
    while (i < sizeof tls_name - 1 && name[i] != '\0') {
        tls_name[i] = name[i];
        i++;
    }
    tls_name[i] = '\0';
    memcpy(tls_addr, rb_marker(), 4);
    tls_aliases[0] = NULL;
    tls_addrs[0] = (char *)tls_addr;
    tls_addrs[1] = NULL;
    memset(&tls_ent, 0, sizeof tls_ent);
    tls_ent.h_name = tls_name;
    tls_ent.h_aliases = tls_aliases;
    tls_ent.h_addrtype = AF_INET;
    tls_ent.h_length = 4;
    tls_ent.h_addr_list = tls_addrs;
    return &tls_ent;
}

static int take_dest(const struct sockaddr *addr, socklen_t len, struct sockaddr_in *local, int *fail) {
    struct sockaddr_in in;
    uint8_t ip[4];
    uint8_t ep[4];
    uint8_t out_ip[4];
    uint16_t port;
    uint16_t out_port;
    int plan;
    *fail = 0;
    if (!addr || len < (socklen_t)sizeof in) {
        return 0;
    }
    memcpy(&in, addr, sizeof in);
    if (in.sin_family != AF_INET) {
        return 0;
    }
    memcpy(ip, &in.sin_addr, 4);
    if (memcmp(ip, rb_marker(), 4) != 0) {
        return 0;
    }
    port = ntohs(in.sin_port);
    if (resolve_ip(ep) != 0) {
        *fail = 1;
        return 0;
    }
    plan = rb_rewrite(ip, port, ep, g_cfg.ports, out_ip, &out_port);
    if (plan != 1) {
        *fail = 1;
        return 0;
    }
    memcpy(local, &in, sizeof *local);
    memcpy(&local->sin_addr, out_ip, 4);
    local->sin_port = htons(out_port);
    return 1;
}

static int hook_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    connect_fn real = real_slot(SLOT_CONNECT);
    struct sockaddr_in local;
    int fail = 0;
    if (!real) {
        errno = EHOSTUNREACH;
        return -1;
    }
    if (!take_dest(addr, len, &local, &fail)) {
        if (fail) {
            errno = EHOSTUNREACH;
            return -1;
        }
        return real(fd, addr, len);
    }
    return real(fd, (struct sockaddr *)&local, (socklen_t)sizeof local);
}

static ssize_t hook_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr,
                           socklen_t len) {
    sendto_fn real = real_slot(SLOT_SENDTO);
    struct sockaddr_in local;
    int fail = 0;
    /* recvfrom source vs marker is unproven; not hooked. */
    if (!real) {
        errno = EHOSTUNREACH;
        return -1;
    }
    if (!addr || !take_dest(addr, len, &local, &fail)) {
        if (fail) {
            errno = EHOSTUNREACH;
            return -1;
        }
        return real(fd, buf, n, flags, addr, len);
    }
    return real(fd, buf, n, flags, (struct sockaddr *)&local, (socklen_t)sizeof local);
}

static const char *basename_of(const char *path) {
    const char *s = path;
    const char *p;
    if (!path) {
        return "";
    }
    for (p = path; *p; p++) {
        if (*p == '/') {
            s = p + 1;
        }
    }
    return s;
}

struct game_image {
    int count;
    uintptr_t base;
    ElfW(Phdr) phdr[32];
    ElfW(Half) phnum;
};

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    struct game_image *g = data;
    const char *base;
    (void)size;
    if (!info || !info->dlpi_name) {
        return 0;
    }
    base = basename_of(info->dlpi_name);
    if (strcmp(base, "libgame.so") != 0) {
        return 0;
    }
    g->count++;
    if (g->count != 1 || info->dlpi_phnum == 0 || info->dlpi_phnum > 32) {
        g->count = -1;
        return 1;
    }
    g->base = (uintptr_t)info->dlpi_addr;
    g->phnum = info->dlpi_phnum;
    memcpy(g->phdr, info->dlpi_phdr, info->dlpi_phnum * sizeof(ElfW(Phdr)));
    return 0;
}

static int in_load(const struct game_image *g, uintptr_t slot) {
    ElfW(Half) i;
    for (i = 0; i < g->phnum; i++) {
        uintptr_t lo;
        uintptr_t hi;
        if (g->phdr[i].p_type != PT_LOAD) {
            continue;
        }
        if ((uintptr_t)g->phdr[i].p_vaddr > UINTPTR_MAX - g->base) {
            continue;
        }
        lo = g->base + (uintptr_t)g->phdr[i].p_vaddr;
        if ((uintptr_t)g->phdr[i].p_memsz > UINTPTR_MAX - lo) {
            continue;
        }
        hi = lo + (uintptr_t)g->phdr[i].p_memsz;
        if (rb_span_inside(lo, hi, slot, sizeof(void *))) {
            return 1;
        }
    }
    return 0;
}

static int hex_nibble(char c) {
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

static int parse_addr(const char **pp, uintptr_t *out) {
    const char *p = *pp;
    uintptr_t v = 0;
    int n = 0;
    int d;
    while ((d = hex_nibble(*p)) >= 0) {
        if (n >= (int)(sizeof(uintptr_t) * 2)) {
            return 0;
        }
        v = (v << 4) | (uintptr_t)d;
        p++;
        n++;
    }
    if (n == 0) {
        return 0;
    }
    *pp = p;
    *out = v;
    return 1;
}

static int prot_at(uintptr_t addr, int *prot) {
    FILE *f = fopen("/proc/self/maps", "re");
    char line[1024];
    if (!f) {
        f = fopen("/proc/self/maps", "r");
    }
    if (!f) {
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        const char *p = line;
        uintptr_t start;
        uintptr_t end;
        int bits = 0;
        if (!parse_addr(&p, &start) || *p != '-' || (++p, !parse_addr(&p, &end)) || *p != ' ') {
            continue;
        }
        p++;
        if (p[0] == '\0' || p[1] == '\0' || p[2] == '\0') {
            continue;
        }
        if (addr < start || addr >= end) {
            continue;
        }
        if (p[0] == 'r') {
            bits |= PROT_READ;
        }
        if (p[1] == 'w') {
            bits |= PROT_WRITE;
        }
        if (p[2] == 'x') {
            bits |= PROT_EXEC;
        }
        *prot = bits;
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

static void rb_stage(const char *id) {
    __android_log_print(ANDROID_LOG_ERROR, "raspberry", "install %s", id);
}

static int page_set(uintptr_t page, long ps, int prot) {
    return mprotect((void *)page, (size_t)ps, prot);
}

static int install_slots(const struct game_image *g) {
    void *hook[SLOT_N];
    void *expect[SLOT_N];
    uintptr_t slot[SLOT_N];
    uintptr_t page;
    uintptr_t page_end;
    int old = 0;
    int write_prot;
    long ps;
    int i;
    ps = sysconf(_SC_PAGESIZE);
    if (ps < 4096 || (ps & (ps - 1)) != 0) {
        rb_stage("got");
        return -1;
    }
    hook[SLOT_GETADDRINFO] = (void *)hook_getaddrinfo;
    hook[SLOT_GETHOSTBYNAME] = (void *)hook_gethostbyname;
    hook[SLOT_CONNECT] = (void *)hook_connect;
    hook[SLOT_SENDTO] = (void *)hook_sendto;
    if (!g_libc) {
        g_libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
        if (!g_libc) {
            g_libc = dlopen("libc.so", RTLD_NOW);
        }
    }
    if (!g_libc) {
        rb_stage("got");
        return -1;
    }
    for (i = 0; i < SLOT_N; i++) {
        uintptr_t addr;
        void *cur;
        expect[i] = dlsym(g_libc, k_sym[i]);
        if (!expect[i] || k_va[i] > UINTPTR_MAX - g->base) {
            rb_stage("got");
            return -1;
        }
        addr = g->base + k_va[i];
        if ((addr % sizeof(void *)) != 0 || !in_load(g, addr)) {
            rb_stage("got");
            return -1;
        }
        /* Lazy PLT stubs are not the libc symbol; fail closed instead of guessing. */
        cur = __atomic_load_n((void **)addr, __ATOMIC_ACQUIRE);
        if (cur != expect[i]) {
            rb_stage("got");
            return -1;
        }
        slot[i] = addr;
    }
    page = slot[0] & ~((uintptr_t)ps - 1);
    if ((uintptr_t)ps > UINTPTR_MAX - page) {
        rb_stage("got");
        return -1;
    }
    page_end = page + (uintptr_t)ps;
    for (i = 0; i < SLOT_N; i++) {
        if (!rb_span_inside(page, page_end, slot[i], sizeof(void *))) {
            rb_stage("got");
            return -1;
        }
    }
    if (prot_at(slot[0], &old) != 0 || (old & PROT_READ) == 0 || (old & PROT_EXEC) != 0) {
        rb_stage("got");
        return -1;
    }
    write_prot = old | PROT_WRITE;
    if (page_set(page, ps, write_prot) != 0) {
        rb_stage("mprotect");
        return -1;
    }
    for (i = 0; i < SLOT_N; i++) {
        void *cur = __atomic_load_n((void **)slot[i], __ATOMIC_ACQUIRE);
        if (cur != expect[i]) {
            if (page_set(page, ps, old) != 0) {
                rb_stage("restore");
                return -1;
            }
            rb_stage("got");
            return -1;
        }
    }
    for (i = 0; i < SLOT_N; i++) {
        __atomic_store_n(&g_real[i], expect[i], __ATOMIC_RELEASE);
        __atomic_store_n((void **)slot[i], hook[i], __ATOMIC_RELEASE);
    }
    if (page_set(page, ps, old) != 0) {
        /* Failed mprotect leaves this page writable. Put libc pointers back before any other prot change. */
        rb_stage("restore");
        for (i = 0; i < SLOT_N; i++) {
            __atomic_store_n((void **)slot[i], expect[i], __ATOMIC_RELEASE);
        }
        if (page_set(page, ps, old) != 0) {
            rb_stage("restore");
        }
        return -1;
    }
    return 0;
}

int rb_install(const rb_config *cfg) {
    struct game_image image;
    int zero = 0;
    int rc;
    int publish = 0;
    int next;
    if (!cfg || cfg->host[0] == '\0') {
        return -1;
    }
    if (__atomic_load_n(&g_state, __ATOMIC_ACQUIRE) == 2) {
        return memcmp(&g_cfg, cfg, sizeof g_cfg) == 0 ? 0 : -1;
    }
    if (!__atomic_compare_exchange_n(&g_state, &zero, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return -1;
    }
    memset(&image, 0, sizeof image);
    dl_iterate_phdr(phdr_cb, &image);
    if (image.count != 1) {
        rb_stage("module");
        rc = -1;
    } else {
        rc = install_slots(&image);
    }
    next = rb_install_finish(rc == 0, &publish);
    if (!publish) {
        __atomic_store_n(&g_ready, 0, __ATOMIC_RELEASE);
        memset(&g_cfg, 0, sizeof g_cfg);
        cache_clear();
        __atomic_store_n(&g_state, next, __ATOMIC_RELEASE);
        return -1;
    }
    /* Slots are installed and page prot restored. Publish only now. */
    g_cfg = *cfg;
    if (cfg->is_ipv4) {
        cache_put(cfg->ip);
    }
    __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&g_state, next, __ATOMIC_RELEASE);
    return 0;
}
