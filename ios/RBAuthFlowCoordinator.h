#ifndef RB_AUTH_FLOW_COORDINATOR_H
#define RB_AUTH_FLOW_COORDINATOR_H

#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

#import "RBAuthAttempt.h"
#import "RBAuthBrowserSession.h"
#import "RBAuthExchangeClient.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, RBAuthFlowStatus) {
    RBAuthFlowStatusIdle = 0,
    RBAuthFlowStatusMainThreadRequired,
    RBAuthFlowStatusInvalidRequest,
    RBAuthFlowStatusBrowserStarting,
    RBAuthFlowStatusBrowserPresented,
    RBAuthFlowStatusWaitingForOwningApplicationForeground,
    RBAuthFlowStatusExchangeInProgress,
    RBAuthFlowStatusForegroundLost,
    // Diagnostic only: response validated, code discarded, not signed in.
    RBAuthFlowStatusExchangeValidatedNotCommitted,
    RBAuthFlowStatusExchangeTimedOut,
    RBAuthFlowStatusFailed,
    RBAuthFlowStatusCancelled,
    RBAuthFlowStatusExpired,
};

typedef void (^RBAuthFlowStatusHandler)(RBAuthFlowStatus status);

/// Structural seam implemented by RBAuthExchangeClient and host fakes.
@protocol RBAuthFlowExchangeClient <NSObject>
- (BOOL)startWithCompletion:(RBAuthExchangeCompletion)completion;
- (void)cancel;
@end

typedef id<RBAuthFlowExchangeClient> _Nullable (^RBAuthFlowExchangeFactory)(
    RBAuthExchangeRequest *request);

/// Scheduled blocks are delivered on the main thread. A scheduler must not
/// invoke a block inline from scheduleAfter:block:.
@protocol RBAuthFlowScheduledTask <NSObject>
- (void)cancel;
@end

@protocol RBAuthFlowScheduler <NSObject>
- (nullable id<RBAuthFlowScheduledTask>)scheduleAfter:(NSTimeInterval)delay
                                                block:(dispatch_block_t)block;
@end

/// Synchronous main-thread liveness probe. The two object arguments are
/// borrowed identities owned by the coordinator; implementations must not
/// retain them, dispatch asynchronously, call back into the coordinator, or
/// treat a prior foreground notification as proof of current liveness.
@protocol RBAuthFlowOwnerLiveness <NSObject>
- (BOOL)isForegroundOwner:(id)foregroundOwner
       inOwningApplication:(id)owningApplication;
@end

/// Main-thread-owned composition of one in-memory attempt, its browser callback
/// owner, and a single foreground-claimed exchange. It never commits or exposes
/// an exchange credential; callers receive only fixed status values. A
/// successful exchange is diagnostic-only, not authorization: real app-scoped
/// credential continuation is intentionally missing and must not be replaced
/// with a fallback identity or account setting.
@interface RBAuthFlowCoordinator : NSObject

@property(nonatomic, readonly) RBAuthFlowStatus status;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

/// owningApplication is the exact object used as the notification center's
/// object filter. Pass UIApplication.sharedApplication and
/// UIApplicationDidBecomeActiveNotification in production. The caller must
/// observe that notification on the main queue and forward it here.
/// ownerLiveness is mandatory; initialization fails if it is absent. Its
/// synchronous answer must verify the current active app and exact foreground
/// presentation owner, not merely remember an earlier notification.
- (nullable instancetype)initWithBrowserDriver:(id<RBAuthBrowserSessionDriver>)browserDriver
                              owningApplication:(id)owningApplication
            applicationDidBecomeActiveNotificationName:(NSString *)notificationName
                                    ownerLiveness:(nullable id<RBAuthFlowOwnerLiveness>)ownerLiveness
                                   exchangeFactory:(nullable RBAuthFlowExchangeFactory)exchangeFactory
                                        scheduler:(nullable id<RBAuthFlowScheduler>)scheduler
                                     attemptClock:(nullable id<RBAuthAttemptClock>)attemptClock;

/// Main-thread-only. Every call is an explicit new attempt and supersedes any
/// earlier one before starting. foregroundOwner is the existing live
/// presentation UIViewController expected by the UIKit browser driver.
- (RBAuthFlowStatus)startWithEndpoint:(nullable RBEndpoint *)endpoint
                     foregroundOwner:(id _Nullable)foregroundOwner
                        statusHandler:(nullable RBAuthFlowStatusHandler)statusHandler;

/// Main-thread-only. Claims the exchange only when notification name and
/// notification.object both exactly match the configured app foreground event.
- (RBAuthFlowStatus)applicationDidBecomeActive:(NSNotification *)notification;

/// Main-thread-only. Cancels browser and exchange work and fences all late
/// results. Off-main calls are refused synchronously and are never queued.
- (RBAuthFlowStatus)cancelCurrentAttempt;

@end

NS_ASSUME_NONNULL_END

#endif
