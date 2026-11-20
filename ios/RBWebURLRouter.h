#ifndef RB_WEB_URL_ROUTER_H
#define RB_WEB_URL_ROUTER_H

#import <Foundation/Foundation.h>

#import "RBEndpoint.h"

NS_ASSUME_NONNULL_BEGIN

/// Rewrites allowlisted LINE PLAY HTTP(S) URLs for in-app WebViews and external
/// browser launches while preserving HTTP headers, method, body, and request
/// options. Fails closed (`blocked = YES`, returns `nil`) on malformed LINE
/// URLs or missing endpoints for LINE targets; never falls back to the original
/// URL when blocked.
@interface RBWebURLRouter : NSObject

+ (nullable NSURLRequest *)rewrittenRequest:(nullable NSURLRequest *)request
                                   endpoint:(nullable RBEndpoint *)endpoint
                                 didRewrite:(BOOL * _Nullable)didRewrite
                                    blocked:(BOOL * _Nullable)blocked;

+ (nullable NSURL *)rewrittenExternalURL:(nullable NSURL *)url
                                endpoint:(nullable RBEndpoint *)endpoint
                              didRewrite:(BOOL * _Nullable)didRewrite
                                 blocked:(BOOL * _Nullable)blocked;

+ (instancetype)new NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END

#endif
