#ifndef RB_NOTICE_ROUTE_CLIENT_H
#define RB_NOTICE_ROUTE_CLIENT_H

#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

#import "RBEndpoint.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, RBNoticeRouteResult) {
    RBNoticeRouteResultSuccess = 0,
    RBNoticeRouteResultNoNotice,
    RBNoticeRouteResultInvalidRequest,
    RBNoticeRouteResultTransportFailure,
    RBNoticeRouteResultTimedOut,
    RBNoticeRouteResultRedirectRefused,
    RBNoticeRouteResultUnexpectedStatus,
    RBNoticeRouteResultResponseTooLarge,
    RBNoticeRouteResultInvalidResponse,
    RBNoticeRouteResultCancelled,
};

typedef void (^RBNoticeRouteCompletion)(NSData *_Nullable responseBody,
                                        RBNoticeRouteResult result);

/// Standalone fetch for the stock iOS unified-notice route only, configured
/// from an operator-supplied RBEndpoint (no hardcoded server, host, or port).
/// Success returns opaque in-memory response bytes; a 404 returns NoNotice.
/// This class has no stock-client binding, cache migration, parser, or UI.
@interface RBNoticeRouteClient : NSObject

/// Initializes a one-shot unified-notice route client. Optional userAgent, if
/// non-nil, must be 1..512 printable ASCII characters (0x20..0x7E) and is
/// otherwise rejected fail-closed as InvalidRequest before any task starts.
- (instancetype)initWithStockURLString:(nullable NSString *)URLString
                              endpoint:(nullable RBEndpoint *)endpoint
                             userAgent:(nullable NSString *)userAgent
    NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithStockURLString:(nullable NSString *)URLString
                              endpoint:(nullable RBEndpoint *)endpoint;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

/// Starts at most one GET. Accepted starts complete exactly once asynchronously
/// off-main. Keep the client alive until completion. NSURLSession may perform
/// internal transport retries; this class has no application retry loop.
- (BOOL)startWithCompletion:(RBNoticeRouteCompletion)completion;

/// Idempotent. Cancels the task and completes an accepted start as Cancelled.
- (void)cancel;

/// True only while executing on this client's private NSURLSession delegate
/// operation queue. Used by synchronous error-adapter facades to refuse
/// deadlocking calls before they wait.
- (BOOL)isExecutingOnSessionCallbackQueue;

#if defined(RB_NOTICE_ROUTE_TESTING)
- (instancetype)initWithStockURLString:(nullable NSString *)URLString
                              endpoint:(nullable RBEndpoint *)endpoint
                       protocolClasses:(NSArray<Class> *)protocolClasses
                      deadlineInterval:(NSTimeInterval)deadlineInterval;
- (instancetype)initWithStockURLString:(nullable NSString *)URLString
                              endpoint:(nullable RBEndpoint *)endpoint
                             userAgent:(nullable NSString *)userAgent
                       protocolClasses:(NSArray<Class> *)protocolClasses
                      deadlineInterval:(NSTimeInterval)deadlineInterval;
- (nullable NSURLSessionConfiguration *)testEffectiveSessionConfiguration;
- (BOOL)testPerformBlockOnSessionCallbackQueue:(dispatch_block_t)block;
#endif

@end

NS_ASSUME_NONNULL_END

#endif
