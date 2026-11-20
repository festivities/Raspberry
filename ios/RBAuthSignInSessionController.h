#ifndef RB_AUTH_SIGNIN_SESSION_CONTROLLER_H
#define RB_AUTH_SIGNIN_SESSION_CONTROLLER_H

#import <Foundation/Foundation.h>

#import "RBAuthFlowCoordinator.h"
#import "RBAuthGuestCredentialGate.h"
#import "RBEndpoint.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, RBAuthSignInGateState) {
    RBAuthSignInGateStateSignInRequired = 0,
    RBAuthSignInGateStateAttemptInProgress,
    RBAuthSignInGateStateRetryRequired,
    RBAuthSignInGateStateAuthorized,
};

/// Structural seam implemented by RBAuthUIKitLifecycleBinding and host fakes.
@protocol RBAuthSignInAttemptBinding <NSObject>
- (RBAuthFlowStatus)startWithEndpoint:(nullable RBEndpoint *)endpoint
                      foregroundOwner:(nullable id)foregroundOwner
                         statusHandler:(nullable RBAuthFlowStatusHandler)statusHandler;
- (BOOL)stop;
@end

typedef id<RBAuthSignInAttemptBinding> _Nullable (^RBAuthSignInBindingFactory)(
    id<RBAuthFlowCommitter> committer);

/// Main-thread-owned sign-in gate state machine coupling RBEndpoint,
/// RBAuthGuestCredentialGate, and one-shot attempt bindings across retries and
/// session invalidation.
@interface RBAuthSignInSessionController : NSObject

@property(nonatomic, readonly) RBAuthSignInGateState state;
@property(nonatomic, readonly) RBAuthFlowStatus lastFlowStatus;
@property(nonatomic, readonly) BOOL requiresSignInOverlay;
@property(nonatomic, readonly) BOOL canStartSignIn;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

- (nullable instancetype)initWithEndpoint:(nullable RBEndpoint *)endpoint
                           credentialGate:(nullable RBAuthGuestCredentialGate *)credentialGate
                           bindingFactory:(nullable RBAuthSignInBindingFactory)bindingFactory
    NS_DESIGNATED_INITIALIZER;

/// Main-thread-only. Reloads existing authorization from RBAuthStore via the
/// credential gate and updates state accordingly.
- (RBAuthSignInGateState)refreshAuthorizationFromStore;

/// Main-thread-only. Starts a fresh sign-in attempt if not already authorized
/// and no attempt is currently in progress.
- (RBAuthFlowStatus)startSignInWithForegroundOwner:(nullable id)foregroundOwner
                                     statusHandler:(nullable RBAuthFlowStatusHandler)statusHandler;

/// Main-thread-only. Cancels any active attempt and returns to RetryRequired
/// (or stays Authorized if already authorized).
- (BOOL)cancelActiveAttempt;

/// Main-thread-only. Stops any active attempt, clears in-memory (and optionally
/// persisted) authorization, and transitions back to SignInRequired.
- (BOOL)invalidateAuthorizationAndClearStore:(BOOL)clearStore;

@end

NS_ASSUME_NONNULL_END

#endif
