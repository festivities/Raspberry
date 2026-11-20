#ifndef RB_NOTICE_ROUTE_ERROR_ADAPTER_H
#define RB_NOTICE_ROUTE_ERROR_ADAPTER_H

#import <Foundation/Foundation.h>

#import "RBNoticeRouteClient.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, RBNoticeRouteErrorKind) {
    RBNoticeRouteErrorKindHTTP404 = 1,
    RBNoticeRouteErrorKindRedirectRefused,
    RBNoticeRouteErrorKindTransport,
    RBNoticeRouteErrorKindTimeout,
    RBNoticeRouteErrorKindUnexpectedStatus,
    RBNoticeRouteErrorKindFixtureSuccessRefused,
    RBNoticeRouteErrorKindResponseTooLarge,
    RBNoticeRouteErrorKindInvalidResponse,
    RBNoticeRouteErrorKindInvalidRequest,
    RBNoticeRouteErrorKindCancelled,
    RBNoticeRouteErrorKindWrongExecutionQueue,
    RBNoticeRouteErrorKindAlreadyUsed,
    RBNoticeRouteErrorKindStartRefused,
    RBNoticeRouteErrorKindFactoryFailure,
};

/// Test-only, immediate stand-in factory. It receives only a fixed kind, never
/// an NSError, URL, status detail, header, or response body.
typedef id _Nullable (^RBNoticeRouteFakeErrorObjectFactory)(
    RBNoticeRouteErrorKind kind);

/// Synchronous facade for one exclusively owned RBNoticeRouteClient. It returns
/// only an injected fake error object; a 200 is always refused, so bytes can
/// never reach a stock parser or cache through this API. Configured indirectly
/// via the owned client's RBEndpoint (no hardcoded server, host, or port); this
/// class has no stock-client binding, cache migration, or UI.
@interface RBNoticeRouteErrorAdapter : NSObject

- (nullable instancetype)initWithOwnedClient:(RBNoticeRouteClient *)client
                           fakeErrorFactory:
                               (RBNoticeRouteFakeErrorObjectFactory)factory
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

/// Background-only, finite synchronous wait. Main-thread and the client's
/// NSURLSession callback queue are refused without waiting or starting a task.
/// The caller must transfer exclusive operational ownership of the client and
/// must not hold an external lock needed by completion.
- (nullable id)performSynchronouslyWithErrorKind:
    (RBNoticeRouteErrorKind * _Nullable)errorKind;

#if defined(RB_NOTICE_ROUTE_TESTING)
- (nullable instancetype)initWithOwnedClient:(RBNoticeRouteClient *)client
                           fakeErrorFactory:
                               (RBNoticeRouteFakeErrorObjectFactory)factory
                            deadlineInterval:(NSTimeInterval)deadlineInterval;
#endif

@end

NS_ASSUME_NONNULL_END

#endif
