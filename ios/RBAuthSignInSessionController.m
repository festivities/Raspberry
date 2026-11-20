#import "RBAuthSignInSessionController.h"

static BOOL RBAuthFlowStatusIsInProgress(RBAuthFlowStatus status) {
    switch (status) {
        case RBAuthFlowStatusBrowserStarting:
        case RBAuthFlowStatusBrowserPresented:
        case RBAuthFlowStatusWaitingForOwningApplicationForeground:
        case RBAuthFlowStatusExchangeInProgress:
            return YES;
        default:
            return NO;
    }
}

@interface RBAuthSignInSessionController () {
    RBEndpoint *_endpoint;
    RBAuthGuestCredentialGate *_credentialGate;
    RBAuthSignInBindingFactory _bindingFactory;
    id<RBAuthSignInAttemptBinding> _activeBinding;
    uint64_t _activeRoundID;
    RBAuthSignInGateState _state;
    RBAuthFlowStatus _lastFlowStatus;
}
- (void)handleFlowStatus:(RBAuthFlowStatus)status
                 roundID:(uint64_t)roundID
           callerHandler:(nullable RBAuthFlowStatusHandler)callerHandler;
@end

@implementation RBAuthSignInSessionController

- (nullable instancetype)initWithEndpoint:(nullable RBEndpoint *)endpoint
                           credentialGate:(nullable RBAuthGuestCredentialGate *)credentialGate
                           bindingFactory:(nullable RBAuthSignInBindingFactory)bindingFactory {
    if (![NSThread isMainThread] ||
        ![endpoint isKindOfClass:[RBEndpoint class]] ||
        ![credentialGate isKindOfClass:[RBAuthGuestCredentialGate class]] ||
        bindingFactory == nil) {
        return nil;
    }

    self = [super init];
    if (self != nil) {
        _endpoint = [endpoint copy];
        _credentialGate = credentialGate;
        _bindingFactory = [bindingFactory copy];
        _activeRoundID = 0;
        _lastFlowStatus = RBAuthFlowStatusIdle;
        if ([_credentialGate isAuthorized] ||
            [_credentialGate reloadFromStoreError:NULL]) {
            _state = RBAuthSignInGateStateAuthorized;
            _lastFlowStatus = RBAuthFlowStatusAuthorized;
        } else {
            _state = RBAuthSignInGateStateSignInRequired;
        }
    }
    return self;
}

- (RBAuthSignInGateState)state {
    return _state;
}

- (RBAuthFlowStatus)lastFlowStatus {
    return _lastFlowStatus;
}

- (BOOL)requiresSignInOverlay {
    return _state != RBAuthSignInGateStateAuthorized && ![_credentialGate isAuthorized];
}

- (BOOL)canStartSignIn {
    return [NSThread isMainThread] &&
           self.requiresSignInOverlay &&
           _state != RBAuthSignInGateStateAttemptInProgress &&
           _activeBinding == nil;
}

- (RBAuthSignInGateState)refreshAuthorizationFromStore {
    if (![NSThread isMainThread]) {
        return _state;
    }
    if (_activeBinding != nil || _state == RBAuthSignInGateStateAttemptInProgress) {
        return _state;
    }
    if ([_credentialGate reloadFromStoreError:NULL] && [_credentialGate isAuthorized]) {
        _state = RBAuthSignInGateStateAuthorized;
        _lastFlowStatus = RBAuthFlowStatusAuthorized;
    } else if (_state == RBAuthSignInGateStateAuthorized) {
        _state = RBAuthSignInGateStateSignInRequired;
        _lastFlowStatus = RBAuthFlowStatusIdle;
    }
    return _state;
}

- (RBAuthFlowStatus)startSignInWithForegroundOwner:(nullable id)foregroundOwner
                                     statusHandler:(nullable RBAuthFlowStatusHandler)statusHandler {
    if (![NSThread isMainThread]) {
        return RBAuthFlowStatusMainThreadRequired;
    }
    if ([_credentialGate isAuthorized] || _state == RBAuthSignInGateStateAuthorized) {
        _state = RBAuthSignInGateStateAuthorized;
        _lastFlowStatus = RBAuthFlowStatusAuthorized;
        if (statusHandler != nil) {
            statusHandler(RBAuthFlowStatusAuthorized);
        }
        return RBAuthFlowStatusAuthorized;
    }
    if (_activeBinding != nil || _state == RBAuthSignInGateStateAttemptInProgress ||
        foregroundOwner == nil) {
        return RBAuthFlowStatusInvalidRequest;
    }

    id<RBAuthSignInAttemptBinding> binding = _bindingFactory(_credentialGate);
    if (binding == nil) {
        _state = RBAuthSignInGateStateRetryRequired;
        _lastFlowStatus = RBAuthFlowStatusFailed;
        if (statusHandler != nil) {
            statusHandler(RBAuthFlowStatusFailed);
        }
        return RBAuthFlowStatusFailed;
    }

    _activeRoundID += 1;
    uint64_t roundID = _activeRoundID;
    _activeBinding = binding;
    _state = RBAuthSignInGateStateAttemptInProgress;
    _lastFlowStatus = RBAuthFlowStatusBrowserStarting;

    RBAuthFlowStatusHandler copiedHandler = [statusHandler copy];
    __weak typeof(self) weakSelf = self;
    RBAuthFlowStatus startStatus =
        [binding startWithEndpoint:_endpoint
                   foregroundOwner:foregroundOwner
                     statusHandler:^(RBAuthFlowStatus status) {
                         RBAuthSignInSessionController *strongSelf = weakSelf;
                         if (strongSelf != nil) {
                             [strongSelf handleFlowStatus:status
                                                  roundID:roundID
                                            callerHandler:copiedHandler];
                         }
                     }];

    if (_activeRoundID == roundID && !RBAuthFlowStatusIsInProgress(startStatus)) {
        [self handleFlowStatus:startStatus roundID:roundID callerHandler:nil];
    }
    return startStatus;
}

- (void)handleFlowStatus:(RBAuthFlowStatus)status
                 roundID:(uint64_t)roundID
           callerHandler:(nullable RBAuthFlowStatusHandler)callerHandler {
    if (![NSThread isMainThread] || roundID != _activeRoundID) {
        return;
    }

    _lastFlowStatus = status;
    if (RBAuthFlowStatusIsInProgress(status)) {
        _state = RBAuthSignInGateStateAttemptInProgress;
        if (callerHandler != nil) {
            callerHandler(status);
        }
        return;
    }

    // Fence this round before notifying caller so reentrant start/cancel sees clean state.
    _activeRoundID += 1;
    id<RBAuthSignInAttemptBinding> finishedBinding = _activeBinding;
    _activeBinding = nil;
    (void)finishedBinding;

    if (status == RBAuthFlowStatusAuthorized && [_credentialGate isAuthorized]) {
        _state = RBAuthSignInGateStateAuthorized;
    } else {
        _state = RBAuthSignInGateStateRetryRequired;
        if (status == RBAuthFlowStatusAuthorized) {
            _lastFlowStatus = RBAuthFlowStatusCommitFailed;
            status = RBAuthFlowStatusCommitFailed;
        }
    }

    if (callerHandler != nil) {
        callerHandler(status);
    }
}

- (BOOL)cancelActiveAttempt {
    if (![NSThread isMainThread]) {
        return NO;
    }
    if (_activeBinding == nil) {
        return YES;
    }
    _activeRoundID += 1;
    id<RBAuthSignInAttemptBinding> binding = _activeBinding;
    _activeBinding = nil;
    BOOL stopped = [binding stop];
    if ([_credentialGate isAuthorized]) {
        _state = RBAuthSignInGateStateAuthorized;
        _lastFlowStatus = RBAuthFlowStatusAuthorized;
    } else {
        _state = RBAuthSignInGateStateRetryRequired;
        _lastFlowStatus = RBAuthFlowStatusCancelled;
    }
    return stopped;
}

- (BOOL)invalidateAuthorizationAndClearStore:(BOOL)clearStore {
    if (![NSThread isMainThread]) {
        return NO;
    }
    if (_activeBinding != nil) {
        _activeRoundID += 1;
        id<RBAuthSignInAttemptBinding> binding = _activeBinding;
        _activeBinding = nil;
        (void)[binding stop];
    }
    BOOL cleared = [_credentialGate invalidateInMemoryAndClearStore:clearStore error:NULL];
    _state = RBAuthSignInGateStateSignInRequired;
    _lastFlowStatus = RBAuthFlowStatusIdle;
    return cleared;
}

@end
