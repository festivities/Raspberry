#import "RBAuthUIKitLifecycleBinding.h"

#import "RBEndpoint.h"
#import "RBAuthUIKitOwnerConditions.h"
#import "RBAuthUIKitLifecycleStatusGate.h"

@interface RBAuthUIKitLifecycleBinding ()
@property(nonatomic, strong) UIApplication *application;
@property(nonatomic, strong) NSNotificationCenter *notificationCenter;
@property(nonatomic, strong) RBAuthFlowCoordinator *coordinator;
@property(nonatomic, strong) RBAuthUIKitLifecycleStatusGate *statusGate;
@property(nonatomic, copy, nullable) RBAuthFlowStatusHandler statusHandler;
@property(nonatomic, strong, nullable) id activeObserver;
@property(nonatomic) BOOL startedOnce;
@property(nonatomic) BOOL attemptStarted;
@property(nonatomic) BOOL stopped;
- (void)removeActiveObserver;
- (void)finishAfterTerminalStatus;
- (void)forwardStatus:(RBAuthFlowStatus)status;
@end

@implementation RBAuthUIKitLifecycleBinding

- (nullable instancetype)initWithBrowserDriver:
                            (id<RBAuthBrowserSessionDriver>)browserDriver
                                 exchangeFactory:
                                     (RBAuthFlowExchangeFactory)exchangeFactory
                                          scheduler:
                                              (id<RBAuthFlowScheduler>)scheduler
                                       attemptClock:
                                           (id<RBAuthAttemptClock>)attemptClock {
    return [self initWithBrowserDriver:browserDriver
                       exchangeFactory:exchangeFactory
                             scheduler:scheduler
                          attemptClock:attemptClock
                             committer:nil];
}

- (nullable instancetype)initWithBrowserDriver:
                            (id<RBAuthBrowserSessionDriver>)browserDriver
                                 exchangeFactory:
                                     (RBAuthFlowExchangeFactory)exchangeFactory
                                          scheduler:
                                              (id<RBAuthFlowScheduler>)scheduler
                                       attemptClock:
                                           (id<RBAuthAttemptClock>)attemptClock
                                          committer:
                                              (id<RBAuthFlowCommitter>)committer {
    if (![NSThread isMainThread] || browserDriver == nil ||
        exchangeFactory == nil) {
        return nil;
    }

    UIApplication *application = UIApplication.sharedApplication;
    if (application == nil) {
        return nil;
    }

    self = [super init];
    if (self == nil) {
        return nil;
    }
    _application = application;
    _notificationCenter = NSNotificationCenter.defaultCenter;
    _statusGate = [[RBAuthUIKitLifecycleStatusGate alloc] init];

    RBAuthUIKitOwnerLiveness *ownerLiveness =
        [[RBAuthUIKitOwnerLiveness alloc] init];
    _coordinator =
        [[RBAuthFlowCoordinator alloc] initWithBrowserDriver:browserDriver
                                          owningApplication:application
                applicationDidBecomeActiveNotificationName:
                    UIApplicationDidBecomeActiveNotification
                                              ownerLiveness:ownerLiveness
                                             exchangeFactory:exchangeFactory
                                                    scheduler:scheduler
                                                 attemptClock:attemptClock
                                                    committer:committer];
    if (_coordinator == nil) {
        return nil;
    }
    return self;
}

- (RBAuthFlowStatus)status {
    return _coordinator.status;
}

- (RBAuthFlowStatus)startWithEndpoint:(RBEndpoint *)endpoint
                      foregroundOwner:(id)foregroundOwner
                         statusHandler:(RBAuthFlowStatusHandler)statusHandler {
    if (![NSThread isMainThread]) {
        return RBAuthFlowStatusMainThreadRequired;
    }
    if (_stopped || _startedOnce) {
        return RBAuthFlowStatusInvalidRequest;
    }
    if (![endpoint isKindOfClass:[RBEndpoint class]] ||
        ![foregroundOwner isKindOfClass:[UIViewController class]] ||
        !RBAuthUIKitOwnerIsForeground(foregroundOwner, _application, NULL)) {
        return RBAuthFlowStatusInvalidRequest;
    }

    __weak typeof(self) weakSelf = self;
    UIApplication *exactApplication = _application;
    id observer = [_notificationCenter
        addObserverForName:UIApplicationDidBecomeActiveNotification
                    object:exactApplication
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(NSNotification *notification) {
                    RBAuthUIKitLifecycleBinding *strongSelf = weakSelf;
                    if (strongSelf == nil || strongSelf->_stopped ||
                        ![NSThread isMainThread] ||
                        ![notification.name
                            isEqualToString:
                                UIApplicationDidBecomeActiveNotification] ||
                        notification.object != exactApplication) {
                        return;
                    }
                    [strongSelf->_coordinator
                        applicationDidBecomeActive:notification];
                }];
    if (observer == nil) {
        return RBAuthFlowStatusFailed;
    }

    _activeObserver = observer;
    _startedOnce = YES;
    _attemptStarted = YES;
    _statusHandler = [statusHandler copy];
    __weak typeof(self) statusWeakSelf = self;
    RBAuthFlowStatusHandler coordinatorStatusHandler =
        ^(RBAuthFlowStatus status) {
            RBAuthUIKitLifecycleBinding *strongSelf = statusWeakSelf;
            if (strongSelf != nil) {
                [strongSelf forwardStatus:status];
            }
        };
    RBAuthFlowStatus status =
        [_coordinator startWithEndpoint:endpoint
                        foregroundOwner:foregroundOwner
                           statusHandler:coordinatorStatusHandler];

    if (!_stopped && status != RBAuthFlowStatusBrowserStarting &&
        status != RBAuthFlowStatusBrowserPresented &&
        status != RBAuthFlowStatusWaitingForOwningApplicationForeground &&
        status != RBAuthFlowStatusExchangeInProgress) {
        [self stop];
    }
    return status;
}

- (BOOL)stop {
    if (![NSThread isMainThread]) {
        return NO;
    }
    if (_stopped) {
        return YES;
    }
    _stopped = YES;
    [self removeActiveObserver];
    if (_attemptStarted) {
        _attemptStarted = NO;
        [_coordinator cancelCurrentAttempt];
    }
    return YES;
}

- (void)removeActiveObserver {
    id observer = _activeObserver;
    _activeObserver = nil;
    if (observer != nil) {
        [_notificationCenter removeObserver:observer];
    }
}

- (void)forwardStatus:(RBAuthFlowStatus)status {
    __weak typeof(self) weakSelf = self;
    [_statusGate forwardStatus:status
               terminalCleanup:^{
                   RBAuthUIKitLifecycleBinding *strongSelf = weakSelf;
                   [strongSelf finishAfterTerminalStatus];
               }
                 statusHandler:_statusHandler];
}

- (void)finishAfterTerminalStatus {
    // The coordinator has already completed this round. Do not call cancel
    // here: caller notification can reenter stop, and that must not resurrect
    // or cancel a later round.
    _stopped = YES;
    _attemptStarted = NO;
    [self removeActiveObserver];
    _statusHandler = nil;
}

- (void)dealloc {
    [self removeActiveObserver];
    if (!_attemptStarted || _stopped) {
        return;
    }

    // Normal ownership requires stop on main before release. This fallback is
    // deliberately nonblocking off-main and captures only this binding's
    // private, one-attempt coordinator, never self or a process-global target.
    RBAuthFlowCoordinator *orphanedCoordinator = _coordinator;
    dispatch_async(dispatch_get_main_queue(), ^{
        [orphanedCoordinator cancelCurrentAttempt];
    });
}

@end
