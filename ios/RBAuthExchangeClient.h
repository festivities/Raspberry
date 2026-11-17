#ifndef RB_AUTH_EXCHANGE_CLIENT_H
#define RB_AUTH_EXCHANGE_CLIENT_H

#import <Foundation/Foundation.h>

#import "RBAuthAttempt.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, RBAuthExchangeClientError) {
    RBAuthExchangeClientErrorNone = 0,
    RBAuthExchangeClientErrorInvalidRequest,
    RBAuthExchangeClientErrorTransport,
    RBAuthExchangeClientErrorRedirectRefused,
    RBAuthExchangeClientErrorHTTPStatus,
    RBAuthExchangeClientErrorResponseTooLarge,
    RBAuthExchangeClientErrorInvalidResponse,
    RBAuthExchangeClientErrorCancelled,
};

typedef void (^RBAuthExchangeCompletion)(NSString *_Nullable uniqueCode,
                                         RBAuthExchangeClientError error);

/// One-shot HTTPS exchange transport for an already-claimed auth request.
/// It returns only a validated uniqueCode or a fixed error enum; it does not
/// commit credentials or authorize the owning RBAuthAttempt.
@interface RBAuthExchangeClient : NSObject

- (instancetype)initWithExchangeRequest:(RBAuthExchangeRequest *)request NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

/// Starts one NSURLSession task (no client retry loop). Returns NO without
/// invoking completion if already started or cancelled. For an accepted start,
/// completion is invoked exactly once asynchronously on a global concurrent
/// queue (never on the main queue), outside internal locks. NSURLSession may
/// perform internal transport retries; this API does not promise wire-level
/// exactly-once delivery. Keep this client alive until completion and weakly
/// capture owners in the block.
- (BOOL)startWithCompletion:(RBAuthExchangeCompletion)completion;

/// Idempotent. The owner must cancel the RBAuthAttempt and this transport
/// together; late transport completion never bypasses attempt commit checks.
/// Success alone is not authorization: the owner must gate it through
/// RBAuthAttempt's commitWithWriter:.
- (void)cancel;

@end

NS_ASSUME_NONNULL_END

#endif
