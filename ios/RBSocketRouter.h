#ifndef RASPBERRY_RB_SOCKET_ROUTER_H
#define RASPBERRY_RB_SOCKET_ROUTER_H

#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "../native/endpoint.h"

/*
 * Pure C11/POSIX marker-based socket router core for iOS.
 *
 * All real libc socket/DNS entry points are injected through rb_socket_ops so
 * routing, caching, fail-closed resolution, and synthesized addrinfo lifetime
 * are deterministic under host fakes and safe for Mach-O interposition.
 */
typedef struct rb_socket_ops {
    int (*real_getaddrinfo)(const char *node, const char *service,
                            const struct addrinfo *hints, struct addrinfo **res);
    void (*real_freeaddrinfo)(struct addrinfo *res);
    struct hostent *(*real_gethostbyname)(const char *name);
    int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int64_t (*now_monotonic_sec)(void);
} rb_socket_ops;

typedef struct RBSocketRouter {
    pthread_mutex_t mu;
    atomic_int initialized;
    atomic_int configured;
    rb_socket_ops ops;
    rb_config cfg;
    uint64_t cfg_gen;
    int cache_valid;
    int64_t cache_at;
    uint8_t cache_ip[4];
    struct addrinfo **synth_ptrs;
    size_t synth_count;
    size_t synth_cap;
} RBSocketRouter;

/*
 * Initializes router with required libc ops (real_getaddrinfo,
 * real_freeaddrinfo, real_gethostbyname, real_connect; now_monotonic_sec is
 * optional and defaults to CLOCK_MONOTONIC).
 * If cfg is non-NULL, validates and enables routing; if cfg is NULL, leaves
 * routing disabled (passthrough) until rb_router_configure is called.
 * Returns 0 on success, -1 on invalid arguments or initialization failure.
 */
int rb_router_init(RBSocketRouter *router, const rb_socket_ops *ops, const rb_config *cfg);

/*
 * Atomically updates routing configuration or disables routing (cfg == NULL)
 * and clears any cached endpoint IPv4 resolution.
 * Returns 0 on success, -1 if router is uninitialized or cfg is invalid.
 */
int rb_router_configure(RBSocketRouter *router, const rb_config *cfg);

/*
 * Destroys router synchronization primitives and internal tracking storage.
 * Callers must free any outstanding addrinfo results before destroying.
 */
void rb_router_destroy(RBSocketRouter *router);

int rb_router_getaddrinfo(RBSocketRouter *router, const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res);

void rb_router_freeaddrinfo(RBSocketRouter *router, struct addrinfo *res);

struct hostent *rb_router_gethostbyname(RBSocketRouter *router, const char *name);

int rb_router_connect(RBSocketRouter *router, int sockfd,
                      const struct sockaddr *addr, socklen_t addrlen);

#endif
