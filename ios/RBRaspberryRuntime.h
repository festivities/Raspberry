#ifndef RB_RASPBERRY_RUNTIME_H
#define RB_RASPBERRY_RUNTIME_H

#import <Foundation/Foundation.h>

#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

NS_ASSUME_NONNULL_BEGIN

/// Exact resolver-to-stub ABI. Returns an unretained/+0 id.
/// On arm64 the first four arguments occupy x0-x3 and callerLR occupies x4.
__attribute__((visibility("default"), used, ns_returns_not_retained))
id rb_ios_notice_404_diagnostic_entry(
    id __unsafe_unretained receiver,
    SEL selector,
    id __unsafe_unretained URL,
    id __unsafe_unretained name,
    uintptr_t callerLR);

__attribute__((visibility("default"), used))
int rb_ios_getaddrinfo(
    const char * _Nullable node,
    const char * _Nullable service,
    const struct addrinfo * _Nullable hints,
    struct addrinfo * _Nullable * _Nullable res);

__attribute__((visibility("default"), used))
void rb_ios_freeaddrinfo(struct addrinfo * _Nullable res);

__attribute__((visibility("default"), used))
struct hostent * _Nullable rb_ios_gethostbyname(const char * _Nullable name);

__attribute__((visibility("default"), used))
int rb_ios_connect(
    int sockfd,
    const struct sockaddr * _Nullable addr,
    socklen_t addrlen);

__attribute__((visibility("default"), used))
const char * _Nullable rb_ios_guest_unique_code(
    void * _Nullable invoker,
    const char * _Nullable stockUniqueCode);

NS_ASSUME_NONNULL_END

#endif
