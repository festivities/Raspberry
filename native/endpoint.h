#ifndef RASPBERRY_ENDPOINT_H
#define RASPBERRY_ENDPOINT_H

#include <stddef.h>
#include <stdint.h>

#define RB_HOST_MAX 253
#define RB_PORT_N 4
#define RB_CACHE_TTL 30

/* ports[0..3] are the endpoint ports for client ports 80, 443, 10000, 10123. */
typedef struct rb_config {
    char host[RB_HOST_MAX + 1];
    uint8_t ip[4];
    int is_ipv4;
    uint16_t ports[RB_PORT_N];
} rb_config;

enum {
    RB_AI_RESOLVE = 0,
    RB_AI_NONAME = 1,
    RB_AI_FAMILY = 2
};

/* 1 if [addr, addr+width) is inside [lo, hi). Rejects an empty span, an inverted range, and a slot past hi (no unsigned wrap). */
int rb_span_inside(uintptr_t lo, uintptr_t hi, uintptr_t addr, uintptr_t width);

/* Done (2) and *publish=1 only after slots are installed and page prot restored.
   Otherwise idle (0), *publish=0: redirects stay inactive and install stays retryable. */
int rb_install_finish(int slots_restored, int *publish);

/* Allowlisted getaddrinfo policy. Copies original into canon when want_canon; never reads endpoint into the result. */
int rb_prepare_ai(const char *original, const char *endpoint, int family_ok, int numeric_host, int want_canon,
                  char *canon, size_t cap, int *action);

int rb_validate(const char *host, const int ports[RB_PORT_N], rb_config *out);
int rb_redirect(const char *name);
int rb_cache_fresh(int64_t now, int64_t at, int valid);

/* 0 pass through, 1 rewrite into out_*, -1 marker but no usable endpoint.
   Does not write dst. endpoint NULL means the endpoint IP is unknown. */
int rb_rewrite(const uint8_t dst[4], uint16_t port, const uint8_t *endpoint,
               const uint16_t mapped[RB_PORT_N], uint8_t out_ip[4], uint16_t *out_port);

const char *const *rb_suffixes(size_t *n);
const char *const *rb_exacts(size_t *n);
const uint8_t *rb_marker(void);

#endif
