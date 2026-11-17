#ifndef RB_URL_REWRITE_H
#define RB_URL_REWRITE_H

#import <Foundation/Foundation.h>

#import "RBEndpoint.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const RBURLRewriteErrorDomain;

typedef NS_ENUM(NSInteger, RBURLRewriteErrorCode) {
    RBURLRewriteErrorInvalidInput = 1,
    RBURLRewriteErrorMalformedTarget,
    RBURLRewriteErrorEndpointRequired,
};

/// Rewrites only the raw authority of a recognized HTTP(S) target. A nontarget
/// input is returned as an immutable copy. A malformed recognized target or a
/// missing endpoint returns nil with a fixed error; callers must not fall back
/// to the original URL on error. This helper does not enforce redirect policy
/// or perform cache migration.
@interface RBURLRewrite : NSObject

+ (nullable NSString *)rewriteURLString:(nullable NSString *)URLString
                               endpoint:(nullable RBEndpoint *)endpoint
                             didRewrite:(BOOL * _Nullable)didRewrite
                                  error:(NSError * _Nullable * _Nullable)error;

+ (instancetype)new NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END

#endif
