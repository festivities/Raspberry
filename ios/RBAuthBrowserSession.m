#import "RBAuthBrowserSession.h"

#import <dispatch/dispatch.h>

NSString *const RBAuthBrowserCallbackScheme = @"raspberry";

RBAuthBrowserOwnerConditions
RBAuthBrowserOwnerConditionsFromFacts(RBAuthBrowserOwnerFacts facts) {
    if (!facts.exactOwningApplication) {
        return 0;
    }

    RBAuthBrowserOwnerConditions conditions = 0;
    if (facts.onMainThread) {
        conditions |= RBAuthBrowserOwnerConditionMainThread;
    }
    if (facts.foregroundOwnerIsViewController) {
        conditions |= RBAuthBrowserOwnerConditionViewController;
    }
    if (facts.ownerViewLoaded &&
        facts.ownerViewAttachedToWindow &&
        facts.ownerViewAndWindowVisible) {
        conditions |= RBAuthBrowserOwnerConditionAttachedWindow;
    }
    if (facts.windowIsKey && facts.ownerViewAndWindowVisible) {
        conditions |= RBAuthBrowserOwnerConditionKeyWindow;
    }
    if (facts.sceneConnectedToOwningApplication &&
        facts.sceneIsForegroundActive) {
        conditions |= RBAuthBrowserOwnerConditionForegroundScene;
    }
    if (facts.applicationIsActive) {
        conditions |= RBAuthBrowserOwnerConditionActiveApplication;
    }
    return conditions;
}

BOOL RBAuthBrowserOwnerConditionsAllowPresentation(
    RBAuthBrowserOwnerConditions conditions) {
    const uint32_t required =
        RBAuthBrowserOwnerConditionMainThread |
        RBAuthBrowserOwnerConditionViewController |
        RBAuthBrowserOwnerConditionAttachedWindow |
        RBAuthBrowserOwnerConditionKeyWindow |
        RBAuthBrowserOwnerConditionForegroundScene |
        RBAuthBrowserOwnerConditionActiveApplication;
    return ((uint32_t)conditions & required) == required &&
        ((uint32_t)conditions & ~required) == 0;
}

BOOL RBAuthBrowserPerformDriverCancellationOnMainThread(
    void (^operation)(void)) {
    if (![NSThread isMainThread]) {
        return NO;
    }
    operation();
    return YES;
}

@interface RBAuthBrowserRound : NSObject
@property(nonatomic, strong) RBAuthAttempt *attempt;
@property(nonatomic, copy, nullable) RBAuthBrowserOutcomeHandler outcomeHandler;
@property(nonatomic) uint64_t identifier;
@property(nonatomic) BOOL finished;
@end

@implementation RBAuthBrowserRound
@end

@interface RBAuthBrowserSession () {
    id<RBAuthBrowserSessionDriver> _driver;
    RBAuthBrowserRound *_currentRound;
    uint64_t _nextIdentifier;
}

- (void)completeRound:(RBAuthBrowserRound *)round
                 kind:(RBAuthBrowserDriverCompletionKind)kind
          callbackURL:(NSURL * _Nullable)callbackURL;
- (void)finishFailedStart:(RBAuthBrowserRound *)round;

@end

@implementation RBAuthBrowserSession

- (nullable instancetype)initWithDriver:(id<RBAuthBrowserSessionDriver>)driver {
    if (driver == nil) {
        return nil;
    }
    self = [super init];
    if (self != nil) {
        _driver = driver;
    }
    return self;
}

- (RBAuthBrowserOutcome)startForForegroundOwner:(id)owner
                                        attempt:(RBAuthAttempt *)attempt
                                 outcomeHandler:(RBAuthBrowserOutcomeHandler)outcomeHandler {
    if (![NSThread isMainThread]) {
        return RBAuthBrowserOutcomeMainThreadRequired;
    }
    if (owner == nil || attempt == nil) {
        return RBAuthBrowserOutcomeInvalidRequest;
    }

    RBAuthBrowserRound *round = [[RBAuthBrowserRound alloc] init];
    round.attempt = attempt;
    round.outcomeHandler = outcomeHandler;
    @synchronized(self) {
        if (_currentRound != nil) {
            return RBAuthBrowserOutcomeAlreadyActive;
        }
        if (attempt.stage != RBAuthAttemptStageAwaitingCallback) {
            return RBAuthBrowserOutcomeAttemptInactive;
        }
        _nextIdentifier++;
        if (_nextIdentifier == 0) {
            _nextIdentifier++;
        }
        round.identifier = _nextIdentifier;
        _currentRound = round;
    }

    __weak typeof(self) weakSelf = self;
    RBAuthBrowserDriverStartResult startResult =
        [_driver startAuthorizationURL:attempt.authorizationURL
                         callbackScheme:RBAuthBrowserCallbackScheme
               prefersEphemeralSession:YES
                       foregroundOwner:owner
        completion:^(RBAuthBrowserDriverCompletionKind kind,
                      NSURL * _Nullable callbackURL) {
            dispatch_async(dispatch_get_main_queue(), ^{
                RBAuthBrowserSession *strongSelf = weakSelf;
                if (strongSelf != nil) {
                    [strongSelf completeRound:round
                                         kind:kind
                                  callbackURL:callbackURL];
                }
            });
        }];

    switch (startResult) {
        case RBAuthBrowserDriverStartResultStarted:
            @synchronized(self) {
                if (_currentRound == round && !round.finished) {
                    return RBAuthBrowserOutcomeStarted;
                }
                return round.finished
                    ? RBAuthBrowserOutcomeBrowserCancelled
                    : RBAuthBrowserOutcomeAttemptInactive;
            }
        case RBAuthBrowserDriverStartResultOwnerNotForeground:
            [self finishFailedStart:round];
            return RBAuthBrowserOutcomeOwnerNotForeground;
        case RBAuthBrowserDriverStartResultFailed:
        default:
            [self finishFailedStart:round];
            return RBAuthBrowserOutcomeStartFailed;
    }
}

- (RBAuthBrowserOutcome)cancelCurrentSession {
    if (![NSThread isMainThread]) {
        return RBAuthBrowserOutcomeMainThreadRequired;
    }
    RBAuthBrowserRound *round = nil;
    @synchronized(self) {
        if (_currentRound == nil || _currentRound.finished) {
            return RBAuthBrowserOutcomeAttemptInactive;
        }
        round = _currentRound;
        round.finished = YES;
        _currentRound = nil;
        [round.attempt cancel];
    }

    [_driver cancelCurrentSession];
    RBAuthBrowserOutcomeHandler handler = round.outcomeHandler;
    if (handler != nil) {
        handler(RBAuthBrowserOutcomeBrowserCancelled);
    }
    return RBAuthBrowserOutcomeBrowserCancelled;
}

- (void)finishFailedStart:(RBAuthBrowserRound *)round {
    @synchronized(self) {
        if (_currentRound == round && !round.finished) {
            round.finished = YES;
            _currentRound = nil;
            [round.attempt cancel];
        }
    }
}

- (void)completeRound:(RBAuthBrowserRound *)round
                 kind:(RBAuthBrowserDriverCompletionKind)kind
          callbackURL:(NSURL *)callbackURL {
    RBAuthBrowserOutcome outcome = RBAuthBrowserOutcomeBrowserFailed;
    RBAuthBrowserOutcomeHandler handler = nil;
    @synchronized(self) {
        if (_currentRound != round || round.finished ||
            round.identifier != _nextIdentifier) {
            return;
        }
        round.finished = YES;
        _currentRound = nil;

        if (kind == RBAuthBrowserDriverCompletionKindCancelled) {
            [round.attempt cancel];
            outcome = RBAuthBrowserOutcomeBrowserCancelled;
        } else if (kind == RBAuthBrowserDriverCompletionKindFailed) {
            [round.attempt cancel];
            outcome = RBAuthBrowserOutcomeBrowserFailed;
        } else if (kind == RBAuthBrowserDriverCompletionKindCompleted &&
                   callbackURL != nil) {
            RBAuthCallbackResult callbackResult =
                [round.attempt acceptCallbackURL:callbackURL];
            switch (callbackResult) {
                case RBAuthCallbackTicketAccepted:
                    outcome = RBAuthBrowserOutcomeTicketAccepted;
                    break;
                case RBAuthCallbackServerRejected:
                    outcome = RBAuthBrowserOutcomeServerRejected;
                    break;
                case RBAuthCallbackRejected:
                default:
                    [round.attempt cancel];
                    outcome = RBAuthBrowserOutcomeCallbackRejected;
                    break;
            }
        } else {
            [round.attempt cancel];
            outcome = RBAuthBrowserOutcomeCallbackRejected;
        }
        handler = round.outcomeHandler;
    }

    if (handler != nil) {
        handler(outcome);
    }
}

@end
