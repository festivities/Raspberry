#ifndef RB_AUTH_UIKIT_LIFECYCLE_BINDING_H
#define RB_AUTH_UIKIT_LIFECYCLE_BINDING_H

#import <UIKit/UIKit.h>

#import "RBAuthFlowCoordinator.h"

NS_ASSUME_NONNULL_BEGIN

/// Explicit UIKit lifecycle adapter for one coordinator attempt. It creates
/// the coordinator with UIApplication.sharedApplication, the shared UIKit
/// liveness check, and UIApplicationDidBecomeActiveNotification. It never
/// discovers or substitutes a controller, endpoint, or application.
///
/// Start and stop are main-thread-only. The caller must supply a previously
/// configured RBEndpoint and the existing, live presentation controller.
/// Resigning active for a system-browser sheet is intentionally not observed
/// as cancellation. The main-thread owner must retain this binding and call
/// stop before releasing it or its presentation owner. Deallocation is only a
/// nonblocking fallback, not the normal teardown path.
@interface RBAuthUIKitLifecycleBinding : NSObject

@property(nonatomic, readonly) RBAuthFlowStatus status;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

- (nullable instancetype)initWithBrowserDriver:
                            (id<RBAuthBrowserSessionDriver>)browserDriver
                                 exchangeFactory:
                                     (RBAuthFlowExchangeFactory)exchangeFactory
                                          scheduler:
                                              (nullable id<RBAuthFlowScheduler>)scheduler
                                       attemptClock:
                                           (nullable id<RBAuthAttemptClock>)attemptClock;

/// Main-thread-only. The owner is checked without forcing view loading. An
/// observer for the exact shared application is installed before forwarding
/// the explicit start to RBAuthFlowCoordinator.
- (RBAuthFlowStatus)startWithEndpoint:(nullable RBEndpoint *)endpoint
                      foregroundOwner:(nullable UIViewController *)foregroundOwner
                         statusHandler:(nullable RBAuthFlowStatusHandler)statusHandler;

/// Main-thread-only, idempotent teardown: unregisters the exact app observer
/// and cancels the coordinator's current attempt. Returns NO off the main
/// thread without queueing work. Call this before releasing the binding or its
/// presentation owner.
- (BOOL)stop;

@end

NS_ASSUME_NONNULL_END

#endif
