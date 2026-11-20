#import "RBAuthFlowCoordinator.h"

#import "RBAuthExchangeClient.h"
#import "RBEndpoint.h"

#import <dispatch/dispatch.h>
#import <math.h>
#import <stdint.h>

static const NSTimeInterval RBAuthFlowAttemptTimeout = 600.0;
static const NSTimeInterval RBAuthFlowTicketTimeout = 120.0;
static const NSTimeInterval RBAuthFlowExchangeTimeout = 30.0;

typedef NS_ENUM(NSInteger, RBAuthFlowTimerKind) {
    RBAuthFlowTimerKindAttempt = 0,
    RBAuthFlowTimerKindTicket,
    RBAuthFlowTimerKindExchange,
};

typedef NS_ENUM(NSInteger, RBAuthFlowAttemptTermination) {
    RBAuthFlowAttemptTerminationNone = 0,
    RBAuthFlowAttemptTerminationCancel,
    RBAuthFlowAttemptTerminationFailExchange,
};

@interface RBAuthFlowDispatchScheduledTask : NSObject <RBAuthFlowScheduledTask>
- (nullable instancetype)initWithDelay:(NSTimeInterval)delay block:(dispatch_block_t)block;
@end

@interface RBAuthFlowDispatchScheduler : NSObject <RBAuthFlowScheduler>
@end

@interface RBAuthFlowRound : NSObject
@property(nonatomic, strong) RBAuthAttempt *attempt;
@property(nonatomic, strong) id foregroundOwner;
@property(nonatomic, strong) id<RBAuthFlowExchangeClient> exchangeClient;
@property(nonatomic, strong) id<RBAuthFlowScheduledTask> attemptTimer;
@property(nonatomic, strong) id<RBAuthFlowScheduledTask> ticketTimer;
@property(nonatomic, strong) id<RBAuthFlowScheduledTask> exchangeTimer;
@property(nonatomic, copy) RBAuthFlowStatusHandler statusHandler;
@property(nonatomic) RBAuthFlowStatus status;
@property(nonatomic) BOOL exchangeClaimed;
@property(nonatomic) BOOL owningForegroundObserved;
@end

@implementation RBAuthFlowRound
@end

@interface RBAuthFlowCoordinator () {
    RBAuthBrowserSession *_browserSession;
    id _owningApplication;
    NSString *_foregroundNotificationName;
    id<RBAuthFlowOwnerLiveness> _ownerLiveness;
    RBAuthFlowExchangeFactory _exchangeFactory;
    id<RBAuthFlowScheduler> _scheduler;
    id<RBAuthAttemptClock> _attemptClock;
    RBAuthFlowRound *_currentRound;
    RBAuthFlowStatus _status;
}

- (void)handleBrowserOutcome:(RBAuthBrowserOutcome)outcome
                       round:(RBAuthFlowRound *)round;
- (void)handleExchangeResult:(BOOL)hasValidatedCode
                       error:(RBAuthExchangeClientError)error
                       round:(RBAuthFlowRound *)round;
- (void)claimExchangeForRound:(RBAuthFlowRound *)round;
- (void)timeoutRound:(RBAuthFlowRound *)round kind:(RBAuthFlowTimerKind)kind;

@end

@implementation RBAuthFlowDispatchScheduledTask {
    dispatch_source_t _source;
    dispatch_block_t _block;
    BOOL _cancelled;
}

- (nullable instancetype)initWithDelay:(NSTimeInterval)delay block:(dispatch_block_t)block {
    if (block == nil || !isfinite(delay) || delay <= 0 ||
        delay > (NSTimeInterval)INT64_MAX / (NSTimeInterval)NSEC_PER_SEC) {
        return nil;
    }
    self = [super init];
    if (self == nil) {
        return nil;
    }
    _source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                    dispatch_get_main_queue());
    if (_source == nil) {
        return nil;
    }
    _block = [block copy];
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_source, ^{
        RBAuthFlowDispatchScheduledTask *strongSelf = weakSelf;
        [strongSelf fire];
    });
    int64_t nanoseconds = (int64_t)(delay * (NSTimeInterval)NSEC_PER_SEC);
    dispatch_source_set_timer(_source, dispatch_time(DISPATCH_TIME_NOW, nanoseconds),
                              DISPATCH_TIME_FOREVER, 0);
    dispatch_resume(_source);
    return self;
}

- (void)fire {
    dispatch_block_t block = nil;
    dispatch_source_t source = nil;
    @synchronized(self) {
        if (_cancelled) {
            return;
        }
        _cancelled = YES;
        block = _block;
        _block = nil;
        source = _source;
        _source = nil;
    }
    if (source != nil) {
        dispatch_source_set_event_handler(source, ^{});
        dispatch_source_cancel(source);
    }
    if (block != nil) {
        block();
    }
}

- (void)cancel {
    dispatch_source_t source = nil;
    @synchronized(self) {
        if (_cancelled) {
            return;
        }
        _cancelled = YES;
        _block = nil;
        source = _source;
        _source = nil;
    }
    if (source != nil) {
        dispatch_source_set_event_handler(source, ^{});
        dispatch_source_cancel(source);
    }
}

- (void)dealloc {
    [self cancel];
}

@end

@implementation RBAuthFlowDispatchScheduler

- (nullable id<RBAuthFlowScheduledTask>)scheduleAfter:(NSTimeInterval)delay
                                                block:(dispatch_block_t)block {
    return [[RBAuthFlowDispatchScheduledTask alloc] initWithDelay:delay block:block];
}

@end

@implementation RBAuthFlowCoordinator

- (nullable instancetype)initWithBrowserDriver:(id<RBAuthBrowserSessionDriver>)browserDriver
                              owningApplication:(id)owningApplication
            applicationDidBecomeActiveNotificationName:(NSString *)notificationName
                                    ownerLiveness:(id<RBAuthFlowOwnerLiveness>)ownerLiveness
                                     exchangeFactory:(RBAuthFlowExchangeFactory)exchangeFactory
                                          scheduler:(id<RBAuthFlowScheduler>)scheduler
                                       attemptClock:(id<RBAuthAttemptClock>)attemptClock {
    if (browserDriver == nil || owningApplication == nil ||
        notificationName.length == 0 || ownerLiveness == nil) {
        return nil;
    }
    self = [super init];
    if (self == nil) {
        return nil;
    }
    _browserSession = [[RBAuthBrowserSession alloc] initWithDriver:browserDriver];
    if (_browserSession == nil) {
        return nil;
    }
    _owningApplication = owningApplication;
    _foregroundNotificationName = [notificationName copy];
    _ownerLiveness = ownerLiveness;
    if (exchangeFactory != nil) {
        _exchangeFactory = [exchangeFactory copy];
    } else {
        _exchangeFactory = ^id<RBAuthFlowExchangeClient>(RBAuthExchangeRequest *request) {
            return (id<RBAuthFlowExchangeClient>)
                [[RBAuthExchangeClient alloc] initWithExchangeRequest:request];
        };
    }
    _scheduler = scheduler ?: [[RBAuthFlowDispatchScheduler alloc] init];
    _attemptClock = attemptClock;
    _status = RBAuthFlowStatusIdle;
    return self;
}

- (RBAuthFlowStatus)status {
    return _status;
}

- (NSString *)description {
    return @"<RBAuthFlowCoordinator>";
}

- (RBAuthFlowStatus)startWithEndpoint:(RBEndpoint *)endpoint
                     foregroundOwner:(id)foregroundOwner
                        statusHandler:(RBAuthFlowStatusHandler)statusHandler {
    if (![NSThread isMainThread]) {
        return RBAuthFlowStatusMainThreadRequired;
    }

    [self supersedeCurrentRound];
    if (endpoint == nil || foregroundOwner == nil) {
        [self publishStatus:RBAuthFlowStatusInvalidRequest handler:statusHandler];
        return _status;
    }

    NSError *attemptError = nil;
    RBAuthAttempt *attempt = _attemptClock == nil
        ? [RBAuthAttempt attemptWithEndpoint:endpoint error:&attemptError]
        : [RBAuthAttempt attemptWithEndpoint:endpoint
                                       clock:_attemptClock
                                       error:&attemptError];
    if (attempt == nil) {
        [self publishStatus:RBAuthFlowStatusFailed handler:statusHandler];
        return _status;
    }

    RBAuthFlowRound *round = [[RBAuthFlowRound alloc] init];
    round.attempt = attempt;
    round.foregroundOwner = foregroundOwner;
    round.statusHandler = statusHandler;
    round.status = RBAuthFlowStatusBrowserStarting;
    _currentRound = round;

    round.attemptTimer = [self scheduleTimerForRound:round
                                               kind:RBAuthFlowTimerKindAttempt
                                              delay:RBAuthFlowAttemptTimeout];
    if (round.attemptTimer == nil) {
        [self finishRound:round
                   status:RBAuthFlowStatusFailed
            cancelBrowser:NO
           cancelExchange:NO
        attemptTermination:RBAuthFlowAttemptTerminationCancel];
        return _status;
    }

    [self publishRoundStatus:RBAuthFlowStatusBrowserStarting round:round];
    if (![self isCurrentRound:round]) {
        return _status;
    }

    __weak typeof(self) weakSelf = self;
    __weak RBAuthFlowRound *weakRound = round;
    RBAuthBrowserOutcome outcome =
        [_browserSession startForForegroundOwner:round.foregroundOwner
                                         attempt:attempt
                                  outcomeHandler:^(RBAuthBrowserOutcome browserOutcome) {
            RBAuthFlowCoordinator *strongSelf = weakSelf;
            RBAuthFlowRound *strongRound = weakRound;
            if (strongSelf != nil && strongRound != nil) {
                [strongSelf handleBrowserOutcome:browserOutcome round:strongRound];
            }
        }];
    if (![self isCurrentRound:round]) {
        return _status;
    }
    if (outcome == RBAuthBrowserOutcomeStarted) {
        round.status = RBAuthFlowStatusBrowserPresented;
        [self publishRoundStatus:round.status round:round];
    } else {
        [self finishRound:round
                   status:outcome == RBAuthBrowserOutcomeBrowserCancelled
                       ? RBAuthFlowStatusCancelled
                       : RBAuthFlowStatusFailed
            cancelBrowser:NO
           cancelExchange:NO
        attemptTermination:RBAuthFlowAttemptTerminationCancel];
    }
    return _status;
}

- (RBAuthFlowStatus)applicationDidBecomeActive:(NSNotification *)notification {
    if (![NSThread isMainThread]) {
        return RBAuthFlowStatusMainThreadRequired;
    }
    RBAuthFlowRound *round = _currentRound;
    if (round == nil ||
        notification == nil ||
        ![notification.name isEqualToString:_foregroundNotificationName] ||
        notification.object != _owningApplication ||
        round.exchangeClaimed) {
        return _status;
    }
    BOOL ownerIsForeground =
        [_ownerLiveness isForegroundOwner:round.foregroundOwner
                     inOwningApplication:_owningApplication];
    if (![self isCurrentRound:round] || !ownerIsForeground) {
        return _status;
    }
    if (round.status == RBAuthFlowStatusBrowserPresented) {
        // The app-active notification can precede ASWebAuthenticationSession's
        // callback delivery. Latch only an exact event for this live browser
        // round; the later validated ticket still gates exchange creation.
        round.owningForegroundObserved = YES;
        return _status;
    }
    if (round.status != RBAuthFlowStatusWaitingForOwningApplicationForeground) {
        return _status;
    }
    round.owningForegroundObserved = YES;
    [self claimExchangeForRound:round];
    return _status;
}

- (void)claimExchangeForRound:(RBAuthFlowRound *)round {
    if (![NSThread isMainThread] || ![self isCurrentRound:round] ||
        round.status != RBAuthFlowStatusWaitingForOwningApplicationForeground ||
        !round.owningForegroundObserved || round.exchangeClaimed) {
        return;
    }
    BOOL ownerIsForeground =
        [_ownerLiveness isForegroundOwner:round.foregroundOwner
                     inOwningApplication:_owningApplication];
    if (![self isCurrentRound:round]) {
        return;
    }
    if (!ownerIsForeground) {
        [self finishRound:round
                   status:RBAuthFlowStatusForegroundLost
            cancelBrowser:NO
           cancelExchange:NO
        attemptTermination:RBAuthFlowAttemptTerminationCancel];
        return;
    }
    [round.ticketTimer cancel];
    round.ticketTimer = nil;
    round.exchangeClaimed = YES;

    RBAuthExchangeRequest *request =
        [round.attempt claimExchangeWithOwnerForeground:YES];
    if (request == nil) {
        RBAuthFlowStatus failedStatus =
            round.attempt.stage == RBAuthAttemptStageExpired
                ? RBAuthFlowStatusExpired
                : RBAuthFlowStatusFailed;
        [self finishRound:round
                   status:failedStatus
            cancelBrowser:NO
           cancelExchange:NO
        attemptTermination:RBAuthFlowAttemptTerminationCancel];
        return;
    }

    id<RBAuthFlowExchangeClient> client = _exchangeFactory(request);
    if (![self isCurrentRound:round]) {
        [client cancel];
        return;
    }
    if (client == nil) {
        [self finishRound:round
                   status:RBAuthFlowStatusFailed
            cancelBrowser:NO
           cancelExchange:NO
        attemptTermination:RBAuthFlowAttemptTerminationFailExchange];
        return;
    }
    round.exchangeClient = client;
    round.exchangeTimer = [self scheduleTimerForRound:round
                                                kind:RBAuthFlowTimerKindExchange
                                               delay:RBAuthFlowExchangeTimeout];
    if (round.exchangeTimer == nil) {
        [self finishRound:round
                   status:RBAuthFlowStatusFailed
            cancelBrowser:NO
           cancelExchange:YES
        attemptTermination:RBAuthFlowAttemptTerminationCancel];
        return;
    }

    round.status = RBAuthFlowStatusExchangeInProgress;
    [self publishRoundStatus:round.status round:round];
    if (![self isCurrentRound:round]) {
        return;
    }
    BOOL ownerStillForeground =
        [_ownerLiveness isForegroundOwner:round.foregroundOwner
                     inOwningApplication:_owningApplication];
    if (![self isCurrentRound:round]) {
        return;
    }
    if (!ownerStillForeground) {
        [self finishRound:round
                   status:RBAuthFlowStatusForegroundLost
            cancelBrowser:NO
           cancelExchange:YES
        attemptTermination:RBAuthFlowAttemptTerminationCancel];
        return;
    }

    __weak typeof(self) weakSelf = self;
    __weak RBAuthFlowRound *weakRound = round;
    BOOL started = [client startWithCompletion:^(NSString *uniqueCode,
                                                  RBAuthExchangeClientError error) {
        // The response value is deliberately reduced to a boolean in this
        // stack frame; only the fixed result and error enum cross to main.
        BOOL hasValidatedCode = uniqueCode != nil &&
                                error == RBAuthExchangeClientErrorNone;
        RBAuthFlowCoordinator *strongSelf = weakSelf;
        RBAuthFlowRound *strongRound = weakRound;
        if (strongSelf == nil || strongRound == nil) {
            return;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            RBAuthFlowCoordinator *mainSelf = weakSelf;
            RBAuthFlowRound *mainRound = weakRound;
            if (mainSelf != nil && mainRound != nil) {
                [mainSelf handleExchangeResult:hasValidatedCode
                                         error:error
                                         round:mainRound];
            }
        });
    }];
    if (!started && [self isCurrentRound:round]) {
        [self finishRound:round
                   status:RBAuthFlowStatusFailed
            cancelBrowser:NO
           cancelExchange:YES
        attemptTermination:RBAuthFlowAttemptTerminationFailExchange];
    }
}

- (RBAuthFlowStatus)cancelCurrentAttempt {
    if (![NSThread isMainThread]) {
        return RBAuthFlowStatusMainThreadRequired;
    }
    RBAuthFlowRound *round = _currentRound;
    if (round != nil) {
        [self finishRound:round
                   status:RBAuthFlowStatusCancelled
            cancelBrowser:YES
           cancelExchange:YES
        attemptTermination:RBAuthFlowAttemptTerminationCancel];
    }
    return _status;
}

- (void)handleBrowserOutcome:(RBAuthBrowserOutcome)outcome
                       round:(RBAuthFlowRound *)round {
    if (![NSThread isMainThread]) {
        __weak typeof(self) weakSelf = self;
        __weak RBAuthFlowRound *weakRound = round;
        dispatch_async(dispatch_get_main_queue(), ^{
            RBAuthFlowCoordinator *strongSelf = weakSelf;
            RBAuthFlowRound *strongRound = weakRound;
            if (strongSelf != nil && strongRound != nil) {
                [strongSelf handleBrowserOutcome:outcome round:strongRound];
            }
        });
        return;
    }
    if (![self isCurrentRound:round] ||
        round.status != RBAuthFlowStatusBrowserPresented) {
        return;
    }

    switch (outcome) {
        case RBAuthBrowserOutcomeTicketAccepted:
            if (round.attempt.stage != RBAuthAttemptStageTicketPending) {
                [self finishRound:round
                           status:round.attempt.stage == RBAuthAttemptStageExpired
                                     ? RBAuthFlowStatusExpired
                                     : RBAuthFlowStatusFailed
                    cancelBrowser:NO
                   cancelExchange:NO
                attemptTermination:RBAuthFlowAttemptTerminationCancel];
                return;
            }
            round.ticketTimer = [self scheduleTimerForRound:round
                                                       kind:RBAuthFlowTimerKindTicket
                                                      delay:RBAuthFlowTicketTimeout];
            if (round.ticketTimer == nil) {
                [self finishRound:round
                           status:RBAuthFlowStatusFailed
                    cancelBrowser:NO
                   cancelExchange:NO
                attemptTermination:RBAuthFlowAttemptTerminationCancel];
                return;
            }
            round.status = RBAuthFlowStatusWaitingForOwningApplicationForeground;
            [self publishRoundStatus:round.status round:round];
            if ([self isCurrentRound:round] && round.owningForegroundObserved) {
                [self claimExchangeForRound:round];
            }
            return;

        case RBAuthBrowserOutcomeServerRejected:
            [self finishRound:round
                       status:RBAuthFlowStatusFailed
                cancelBrowser:NO
               cancelExchange:NO
            attemptTermination:RBAuthFlowAttemptTerminationNone];
            return;

        case RBAuthBrowserOutcomeBrowserCancelled:
            [self finishRound:round
                       status:RBAuthFlowStatusCancelled
                cancelBrowser:NO
               cancelExchange:NO
            attemptTermination:RBAuthFlowAttemptTerminationNone];
            return;

        case RBAuthBrowserOutcomeStarted:
        case RBAuthBrowserOutcomeInvalidRequest:
        case RBAuthBrowserOutcomeAttemptInactive:
        case RBAuthBrowserOutcomeAlreadyActive:
        case RBAuthBrowserOutcomeMainThreadRequired:
        case RBAuthBrowserOutcomeOwnerNotForeground:
        case RBAuthBrowserOutcomeStartFailed:
        case RBAuthBrowserOutcomeCallbackRejected:
        case RBAuthBrowserOutcomeBrowserFailed:
        default:
            [self finishRound:round
                       status:RBAuthFlowStatusFailed
                cancelBrowser:NO
               cancelExchange:NO
            attemptTermination:RBAuthFlowAttemptTerminationCancel];
            return;
    }
}

- (void)handleExchangeResult:(BOOL)hasValidatedCode
                       error:(RBAuthExchangeClientError)error
                       round:(RBAuthFlowRound *)round {
    if (![NSThread isMainThread]) {
        __weak typeof(self) weakSelf = self;
        __weak RBAuthFlowRound *weakRound = round;
        dispatch_async(dispatch_get_main_queue(), ^{
            RBAuthFlowCoordinator *strongSelf = weakSelf;
            RBAuthFlowRound *strongRound = weakRound;
            if (strongSelf != nil && strongRound != nil) {
                [strongSelf handleExchangeResult:hasValidatedCode
                                            error:error
                                            round:strongRound];
            }
        });
        return;
    }
    if (![self isCurrentRound:round] ||
        round.status != RBAuthFlowStatusExchangeInProgress) {
        return;
    }
    [round.exchangeTimer cancel];
    round.exchangeTimer = nil;
    round.exchangeClient = nil;

    if (round.attempt.stage == RBAuthAttemptStageExpired) {
        [self finishRound:round
                   status:RBAuthFlowStatusExpired
            cancelBrowser:NO
           cancelExchange:NO
        attemptTermination:RBAuthFlowAttemptTerminationNone];
        return;
    }
    if (error == RBAuthExchangeClientErrorNone && hasValidatedCode) {
        // This is a diagnostic boundary, not sign-in. Discard the validated
        // code and clear the attempt; a real app-scoped continuation is absent.
        [self finishRound:round
                   status:RBAuthFlowStatusExchangeValidatedNotCommitted
            cancelBrowser:NO
           cancelExchange:NO
        attemptTermination:RBAuthFlowAttemptTerminationFailExchange];
        return;
    }
    [self finishRound:round
               status:RBAuthFlowStatusFailed
        cancelBrowser:NO
       cancelExchange:NO
    attemptTermination:RBAuthFlowAttemptTerminationFailExchange];
}

- (void)timeoutRound:(RBAuthFlowRound *)round kind:(RBAuthFlowTimerKind)kind {
    if (![NSThread isMainThread]) {
        __weak typeof(self) weakSelf = self;
        __weak RBAuthFlowRound *weakRound = round;
        dispatch_async(dispatch_get_main_queue(), ^{
            RBAuthFlowCoordinator *strongSelf = weakSelf;
            RBAuthFlowRound *strongRound = weakRound;
            if (strongSelf != nil && strongRound != nil) {
                [strongSelf timeoutRound:strongRound kind:kind];
            }
        });
        return;
    }
    if (![self isCurrentRound:round]) {
        return;
    }
    if (kind == RBAuthFlowTimerKindTicket &&
        round.status != RBAuthFlowStatusWaitingForOwningApplicationForeground) {
        return;
    }
    if (kind == RBAuthFlowTimerKindExchange &&
        round.status != RBAuthFlowStatusExchangeInProgress) {
        return;
    }

    BOOL attemptExpired = round.attempt.stage == RBAuthAttemptStageExpired;
    RBAuthFlowStatus timeoutStatus =
        attemptExpired ? RBAuthFlowStatusExpired :
        kind == RBAuthFlowTimerKindExchange ? RBAuthFlowStatusExchangeTimedOut
                                            : RBAuthFlowStatusExpired;
    [self finishRound:round
               status:timeoutStatus
        cancelBrowser:kind == RBAuthFlowTimerKindAttempt
       cancelExchange:kind == RBAuthFlowTimerKindExchange ||
                      kind == RBAuthFlowTimerKindAttempt
    attemptTermination:RBAuthFlowAttemptTerminationCancel];
}

- (nullable id<RBAuthFlowScheduledTask>)scheduleTimerForRound:(RBAuthFlowRound *)round
                                                         kind:(RBAuthFlowTimerKind)kind
                                                        delay:(NSTimeInterval)delay {
    __weak typeof(self) weakSelf = self;
    __weak RBAuthFlowRound *weakRound = round;
    return [_scheduler scheduleAfter:delay block:^{
        RBAuthFlowCoordinator *strongSelf = weakSelf;
        RBAuthFlowRound *strongRound = weakRound;
        if (strongSelf != nil && strongRound != nil) {
            [strongSelf timeoutRound:strongRound kind:kind];
        }
    }];
}

- (BOOL)isCurrentRound:(RBAuthFlowRound *)round {
    return round != nil && _currentRound == round;
}

- (void)publishRoundStatus:(RBAuthFlowStatus)status round:(RBAuthFlowRound *)round {
    if (![self isCurrentRound:round]) {
        return;
    }
    _status = status;
    round.status = status;
    RBAuthFlowStatusHandler handler = round.statusHandler;
    if (handler != nil) {
        handler(status);
    }
}

- (void)publishStatus:(RBAuthFlowStatus)status
              handler:(RBAuthFlowStatusHandler)handler {
    _status = status;
    if (handler != nil) {
        handler(status);
    }
}

- (void)finishRound:(RBAuthFlowRound *)round
             status:(RBAuthFlowStatus)status
      cancelBrowser:(BOOL)cancelBrowser
     cancelExchange:(BOOL)cancelExchange
  attemptTermination:(RBAuthFlowAttemptTermination)attemptTermination {
    if (![self isCurrentRound:round]) {
        return;
    }

    _currentRound = nil;
    [round.attemptTimer cancel];
    [round.ticketTimer cancel];
    [round.exchangeTimer cancel];
    round.attemptTimer = nil;
    round.ticketTimer = nil;
    round.exchangeTimer = nil;

    if (attemptTermination == RBAuthFlowAttemptTerminationCancel) {
        [round.attempt cancel];
    } else if (attemptTermination == RBAuthFlowAttemptTerminationFailExchange) {
        [round.attempt failExchange];
    }
    if (cancelExchange) {
        [round.exchangeClient cancel];
    }
    round.exchangeClient = nil;
    if (cancelBrowser) {
        (void)[_browserSession cancelCurrentSession];
    }

    _status = status;
    RBAuthFlowStatusHandler handler = round.statusHandler;
    round.statusHandler = nil;
    round.foregroundOwner = nil;
    if (handler != nil) {
        handler(status);
    }
}

- (void)supersedeCurrentRound {
    RBAuthFlowRound *round = _currentRound;
    if (round == nil) {
        return;
    }
    _currentRound = nil;
    [round.attemptTimer cancel];
    [round.ticketTimer cancel];
    [round.exchangeTimer cancel];
    round.attemptTimer = nil;
    round.ticketTimer = nil;
    round.exchangeTimer = nil;
    [round.attempt cancel];
    [round.exchangeClient cancel];
    round.exchangeClient = nil;
    round.statusHandler = nil;
    round.foregroundOwner = nil;
    (void)[_browserSession cancelCurrentSession];
}

@end
