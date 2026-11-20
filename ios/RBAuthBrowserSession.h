#ifndef RB_AUTH_BROWSER_SESSION_H
#define RB_AUTH_BROWSER_SESSION_H

#import <Foundation/Foundation.h>

#import "RBAuthAttempt.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const RBAuthBrowserCallbackScheme;

typedef NS_ENUM(NSInteger, RBAuthBrowserOutcome) {
    RBAuthBrowserOutcomeStarted = 0,
    RBAuthBrowserOutcomeInvalidRequest,
    RBAuthBrowserOutcomeAttemptInactive,
    RBAuthBrowserOutcomeAlreadyActive,
    RBAuthBrowserOutcomeMainThreadRequired,
    RBAuthBrowserOutcomeOwnerNotForeground,
    RBAuthBrowserOutcomeStartFailed,
    RBAuthBrowserOutcomeTicketAccepted,
    RBAuthBrowserOutcomeServerRejected,
    RBAuthBrowserOutcomeCallbackRejected,
    RBAuthBrowserOutcomeBrowserCancelled,
    RBAuthBrowserOutcomeBrowserFailed,
};

typedef NS_OPTIONS(uint32_t, RBAuthBrowserOwnerConditions) {
    RBAuthBrowserOwnerConditionMainThread = 1U << 0,
    RBAuthBrowserOwnerConditionViewController = 1U << 1,
    RBAuthBrowserOwnerConditionAttachedWindow = 1U << 2,
    RBAuthBrowserOwnerConditionKeyWindow = 1U << 3,
    RBAuthBrowserOwnerConditionForegroundScene = 1U << 4,
    RBAuthBrowserOwnerConditionActiveApplication = 1U << 5,
};

/// UIKit-independent facts for the exact borrowed owner/application snapshot.
/// ownerViewAndWindowVisible includes visible owner/ancestor/window alpha and
/// hidden state; ownerViewAttachedToWindow requires the supplied owner's
/// already-loaded view to belong to its window. Scene facts refer only to that
/// window's scene and the supplied owning application.
typedef struct {
    BOOL onMainThread;
    BOOL exactOwningApplication;
    BOOL foregroundOwnerIsViewController;
    BOOL ownerViewLoaded;
    BOOL ownerViewAttachedToWindow;
    BOOL ownerViewAndWindowVisible;
    BOOL windowIsKey;
    BOOL sceneConnectedToOwningApplication;
    BOOL sceneIsForegroundActive;
    BOOL applicationIsActive;
} RBAuthBrowserOwnerFacts;

/// Builds the tracked condition mask from a fact snapshot. A mismatched app
/// identity produces no conditions.
FOUNDATION_EXPORT RBAuthBrowserOwnerConditions
RBAuthBrowserOwnerConditionsFromFacts(RBAuthBrowserOwnerFacts facts);

FOUNDATION_EXPORT BOOL RBAuthBrowserOwnerConditionsAllowPresentation(
    RBAuthBrowserOwnerConditions conditions);

/// Runs synchronously only on main; off-main returns NO without queueing.
FOUNDATION_EXPORT BOOL RBAuthBrowserPerformDriverCancellationOnMainThread(
    void (^operation)(void));

typedef NS_ENUM(NSInteger, RBAuthBrowserDriverStartResult) {
    RBAuthBrowserDriverStartResultStarted = 0,
    RBAuthBrowserDriverStartResultOwnerNotForeground,
    RBAuthBrowserDriverStartResultFailed,
};

typedef NS_ENUM(NSInteger, RBAuthBrowserDriverCompletionKind) {
    RBAuthBrowserDriverCompletionKindCompleted = 0,
    RBAuthBrowserDriverCompletionKindCancelled,
    RBAuthBrowserDriverCompletionKindFailed,
};

typedef void (^RBAuthBrowserDriverCompletion)(
    RBAuthBrowserDriverCompletionKind kind,
    NSURL * _Nullable callbackURL);

@protocol RBAuthBrowserSessionDriver <NSObject>

/*
 * Start/cancel are called only from the main thread. A failed start leaves no
 * live session. Drivers must not complete inline; the coordinator still queues
 * completions defensively. A reentrant coordinator cancellation during start
 * is terminal and makes start return BrowserCancelled, never Started. The
 * callback URL remains private to the coordinator.
 */
- (RBAuthBrowserDriverStartResult)startAuthorizationURL:(NSURL *)authorizationURL
                                          callbackScheme:(NSString *)callbackScheme
                                prefersEphemeralSession:(BOOL)prefersEphemeralSession
                                        foregroundOwner:(id)foregroundOwner
                                             completion:(RBAuthBrowserDriverCompletion)completion;
- (void)cancelCurrentSession;

@end

typedef void (^RBAuthBrowserOutcomeHandler)(RBAuthBrowserOutcome outcome);

/*
 * Foundation-only callback owner. The caller supplies the existing attempt
 * and an explicit foreground owner. The only completion exposed to the caller
 * is a fixed enum; callback URLs are delivered only to that attempt.
 */
@interface RBAuthBrowserSession : NSObject

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

- (nullable instancetype)initWithDriver:(nullable id<RBAuthBrowserSessionDriver>)driver;

- (RBAuthBrowserOutcome)startForForegroundOwner:(id _Nullable)owner
                                        attempt:(RBAuthAttempt * _Nullable)attempt
                                 outcomeHandler:(nullable RBAuthBrowserOutcomeHandler)outcomeHandler;

/// Main-thread-only. Returns BrowserCancelled once, then AttemptInactive.
- (RBAuthBrowserOutcome)cancelCurrentSession;

@end

NS_ASSUME_NONNULL_END

#endif
