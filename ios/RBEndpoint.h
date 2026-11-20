#ifndef RB_ENDPOINT_H
#define RB_ENDPOINT_H

#import <Foundation/Foundation.h>

#include "../native/endpoint.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const RBEndpointErrorDomain;

typedef NS_ENUM(NSInteger, RBEndpointErrorCode) {
    RBEndpointErrorEmpty = 1,
    RBEndpointErrorTooLarge,
    RBEndpointErrorNotJSON,
    RBEndpointErrorVersion,
    RBEndpointErrorHostRequired,
    RBEndpointErrorHostInvalid,
    RBEndpointErrorPortsInvalid,
    RBEndpointErrorPortKeyNotAllowed,
    RBEndpointErrorPortOutOfRange,
    RBEndpointErrorUnreadable,
};

/// Immutable, side-effect-free representation of the v1 endpoint descriptor.
@interface RBEndpoint : NSObject <NSCopying>

@property(nonatomic, copy, readonly) NSString *host;
/// HTTPS origin uses the mapped 443 port when it is not the default 443.
@property(nonatomic, copy, readonly) NSString *httpsOrigin;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

+ (nullable instancetype)endpointWithJSONData:(nullable NSData *)data
                                      error:(NSError * _Nullable * _Nullable)error;
+ (nullable instancetype)endpointFromFileURL:(nullable NSURL *)fileURL
                                       error:(NSError * _Nullable * _Nullable)error;

/// Returns the mapped port for a supported original client port, or the input
/// unchanged for other ports.
- (uint16_t)mappedPortForOriginalClientPort:(uint16_t)originalPort;

/// Uses the shared native redirect allowlist; does not add suffix matching.
- (BOOL)redirectsHost:(NSString *)hostname;

/// Returns an independent copy of the C configuration for a future installer.
- (rb_config)copyOutRBConfig;

@end

NS_ASSUME_NONNULL_END

#endif
