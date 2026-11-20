#import "RBAuthBrowserSession.h"

#import "RBEndpoint.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dispatch/dispatch.h>

#include <stdio.h>

static int failures = 0;

#define CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", label); \
        failures++; \
    } \
} while (0)

@interface RBSyntheticClock : NSObject <RBAuthAttemptClock>
@property(nonatomic) NSTimeInterval now;
@end

@implementation RBSyntheticClock
- (NSTimeInterval)monotonicTime {
    return self.now;
}
@end

@interface RBFakeCompletion : NSObject
@property(nonatomic, copy) RBAuthBrowserDriverCompletion block;
@end

@implementation RBFakeCompletion
@end

@interface RBFakeBrowserDriver : NSObject <RBAuthBrowserSessionDriver>
@property(nonatomic) RBAuthBrowserDriverStartResult configuredStartResult;
@property(nonatomic, strong) NSMutableArray<RBFakeCompletion *> *completions;
@property(nonatomic, strong, nullable) NSObject *retainedSessionToken;
@property(nonatomic, strong, nullable) id retainedPresentationAnchor;
@property(nonatomic, strong, nullable) id retainedOwner;
@property(nonatomic, strong, nullable) NSURL *lastAuthorizationURL;
@property(nonatomic, copy, nullable) NSString *lastCallbackScheme;
@property(nonatomic) BOOL lastPrefersEphemeral;
@property(nonatomic) NSUInteger activeCompletionIndex;
@property(nonatomic) NSUInteger startCalls;
@property(nonatomic) NSUInteger cancelCalls;
@property(nonatomic) BOOL completeSynchronouslyDuringStart;
@property(nonatomic, strong, nullable) NSURL *synchronousStartCallbackURL;
@property(nonatomic) RBAuthBrowserDriverCompletionKind synchronousStartKind;
@property(nonatomic, copy, nullable) dispatch_block_t startReentrancyHandler;
@end

@implementation RBFakeBrowserDriver

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _completions = [[NSMutableArray alloc] init];
        _activeCompletionIndex = NSNotFound;
    }
    return self;
}

- (RBAuthBrowserDriverStartResult)startAuthorizationURL:(NSURL *)authorizationURL
                                          callbackScheme:(NSString *)callbackScheme
                                prefersEphemeralSession:(BOOL)prefersEphemeralSession
                                        foregroundOwner:(id)foregroundOwner
                                             completion:(RBAuthBrowserDriverCompletion)completion {
    self.startCalls++;
    self.lastAuthorizationURL = authorizationURL;
    self.lastCallbackScheme = callbackScheme;
    self.lastPrefersEphemeral = prefersEphemeralSession;
    BOOL willStart =
        self.configuredStartResult == RBAuthBrowserDriverStartResultStarted;
    if (!willStart && !self.completeSynchronouslyDuringStart) {
        return self.configuredStartResult;
    }

    RBFakeCompletion *record = [[RBFakeCompletion alloc] init];
    record.block = completion;
    NSUInteger recordIndex = self.completions.count;
    [self.completions addObject:record];
    if (willStart) {
        self.activeCompletionIndex = recordIndex;
        self.retainedSessionToken = [[NSObject alloc] init];
        self.retainedPresentationAnchor = foregroundOwner;
        self.retainedOwner = foregroundOwner;
    }
    if (self.completeSynchronouslyDuringStart) {
        /*
         * The failed-start case deliberately violates the driver contract to
         * verify the coordinator still fences an already-queued completion.
         */
        completion(self.synchronousStartKind, self.synchronousStartCallbackURL);
    }
    if (self.startReentrancyHandler != nil) {
        self.startReentrancyHandler();
    }
    return self.configuredStartResult;
}

- (void)cancelCurrentSession {
    self.cancelCalls++;
    self.activeCompletionIndex = NSNotFound;
    self.retainedSessionToken = nil;
    self.retainedPresentationAnchor = nil;
    self.retainedOwner = nil;
}

- (void)completeAtIndex:(NSUInteger)index
                   kind:(RBAuthBrowserDriverCompletionKind)kind
            callbackURL:(NSURL * _Nullable)callbackURL {
    RBAuthBrowserDriverCompletion block = nil;
    @synchronized(self) {
        if (index >= self.completions.count) {
            return;
        }
        if (self.activeCompletionIndex == index) {
            self.activeCompletionIndex = NSNotFound;
            self.retainedSessionToken = nil;
            self.retainedPresentationAnchor = nil;
            self.retainedOwner = nil;
        }
        block = self.completions[index].block;
    }
    if (block != nil) {
        block(kind, callbackURL);
    }
}

@end

@interface RBOutcomeRecorder : NSObject
@property(nonatomic, strong) NSMutableArray<NSNumber *> *outcomes;
@property(nonatomic) BOOL callbacksStayedOnMainThread;
@end

@implementation RBOutcomeRecorder
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _outcomes = [[NSMutableArray alloc] init];
        _callbacksStayedOnMainThread = YES;
    }
    return self;
}
@end

static RBAuthAttempt *NewSyntheticAttempt(void) {
    NSError *error = nil;
    NSData *endpointJSON =
        [@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"443\":8443}}"
            dataUsingEncoding:NSUTF8StringEncoding];
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:endpointJSON error:&error];
    if (endpoint == nil) {
        CHECK(NO, "synthetic endpoint created");
        return nil;
    }

    RBSyntheticClock *clock = [[RBSyntheticClock alloc] init];
    clock.now = 10.0;
    RBAuthAttempt *attempt =
        [RBAuthAttempt attemptWithEndpoint:endpoint clock:clock error:&error];
    CHECK(attempt != nil, "synthetic auth attempt created");
    return attempt;
}

static NSString *StateFromSyntheticAttempt(RBAuthAttempt *attempt) {
    NSURLComponents *components =
        [NSURLComponents componentsWithURL:attempt.authorizationURL
                   resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"state"]) {
            return item.value;
        }
    }
    CHECK(NO, "state found in synthetic authorization request");
    return nil;
}

static NSURL *SyntheticDeniedCallbackForState(NSString *state) {
    NSString *callback =
        [NSString stringWithFormat:@"raspberry://auth?error=denied&state=%@", state];
    return [NSURL URLWithString:callback];
}

static void RecordOutcome(RBOutcomeRecorder *recorder,
    RBAuthBrowserOutcome outcome) {
    if (![NSThread isMainThread]) {
        recorder.callbacksStayedOnMainThread = NO;
    }
    [recorder.outcomes addObject:@(outcome)];
}

static void PumpMainQueue(NSUInteger iterations) {
    for (NSUInteger i = 0; i < iterations; i++) {
        (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, true);
    }
}

static void WaitForOutcomeCount(RBOutcomeRecorder *recorder,
    NSUInteger expectedCount, const char *label) {
    for (NSUInteger i = 0; i < 200 && recorder.outcomes.count < expectedCount; i++) {
        (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, true);
    }
    CHECK(recorder.outcomes.count >= expectedCount, label);
}

static BOOL RunOnWorkerThread(dispatch_block_t block) {
    dispatch_semaphore_t finished = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        block();
        dispatch_semaphore_signal(finished);
    });
    return dispatch_semaphore_wait(
        finished, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0;
}

static void TestForegroundOwnerEligibilitySeam(void) {
    RBAuthBrowserOwnerConditions allConditions =
        RBAuthBrowserOwnerConditionMainThread |
        RBAuthBrowserOwnerConditionViewController |
        RBAuthBrowserOwnerConditionAttachedWindow |
        RBAuthBrowserOwnerConditionKeyWindow |
        RBAuthBrowserOwnerConditionForegroundScene |
        RBAuthBrowserOwnerConditionActiveApplication;
    RBAuthBrowserOwnerConditions required[] = {
        RBAuthBrowserOwnerConditionMainThread,
        RBAuthBrowserOwnerConditionViewController,
        RBAuthBrowserOwnerConditionAttachedWindow,
        RBAuthBrowserOwnerConditionKeyWindow,
        RBAuthBrowserOwnerConditionForegroundScene,
        RBAuthBrowserOwnerConditionActiveApplication
    };
    CHECK(RBAuthBrowserOwnerConditionsAllowPresentation(allConditions),
          "actual UIKit owner-state seam accepts fully foreground owner");
    for (NSUInteger i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        CHECK(!RBAuthBrowserOwnerConditionsAllowPresentation(
                  allConditions & ~required[i]),
              "actual UIKit owner-state seam rejects every missing condition");
    }
    CHECK(!RBAuthBrowserOwnerConditionsAllowPresentation(
              allConditions | (RBAuthBrowserOwnerConditions)(1U << 20)),
          "actual UIKit owner-state seam rejects unknown state bits");
}

static RBAuthBrowserOwnerFacts AllForegroundOwnerFacts(void) {
    return (RBAuthBrowserOwnerFacts){
        .onMainThread = YES,
        .exactOwningApplication = YES,
        .foregroundOwnerIsViewController = YES,
        .ownerViewLoaded = YES,
        .ownerViewAttachedToWindow = YES,
        .ownerViewAndWindowVisible = YES,
        .windowIsKey = YES,
        .sceneConnectedToOwningApplication = YES,
        .sceneIsForegroundActive = YES,
        .applicationIsActive = YES,
    };
}

static void TestForegroundOwnerFactsFailClosed(void) {
    RBAuthBrowserOwnerFacts facts = AllForegroundOwnerFacts();
    RBAuthBrowserOwnerConditions allConditions =
        RBAuthBrowserOwnerConditionsFromFacts(facts);
    CHECK(RBAuthBrowserOwnerConditionsAllowPresentation(allConditions),
          "complete exact-owner/app scene snapshot passes shared gate");

    facts = AllForegroundOwnerFacts();
    facts.exactOwningApplication = NO;
    CHECK(RBAuthBrowserOwnerConditionsFromFacts(facts) == 0,
          "wrong application identity produces no owner conditions");

#define CHECK_MISSING_OWNER_FACT(field, label) do { \
    RBAuthBrowserOwnerFacts missingFacts = AllForegroundOwnerFacts(); \
    missingFacts.field = NO; \
    CHECK(!RBAuthBrowserOwnerConditionsAllowPresentation( \
              RBAuthBrowserOwnerConditionsFromFacts(missingFacts)), label); \
} while (0)
    CHECK_MISSING_OWNER_FACT(onMainThread,
                             "off-main owner snapshot fails closed");
    CHECK_MISSING_OWNER_FACT(foregroundOwnerIsViewController,
                             "wrong or non-controller owner fails closed");
    CHECK_MISSING_OWNER_FACT(ownerViewLoaded,
                             "unloaded owner view fails without loading it");
    CHECK_MISSING_OWNER_FACT(ownerViewAttachedToWindow,
                             "detached owner view fails closed");
    CHECK_MISSING_OWNER_FACT(ownerViewAndWindowVisible,
                             "hidden owner/window ancestry fails closed");
    CHECK_MISSING_OWNER_FACT(windowIsKey,
                             "non-key owner window fails closed");
    CHECK_MISSING_OWNER_FACT(sceneConnectedToOwningApplication,
                             "disconnected scene fails closed");
    CHECK_MISSING_OWNER_FACT(sceneIsForegroundActive,
                             "background or nil scene fails closed");
    CHECK_MISSING_OWNER_FACT(applicationIsActive,
                             "inactive application fails closed");
#undef CHECK_MISSING_OWNER_FACT

    facts = AllForegroundOwnerFacts();
    facts.sceneConnectedToOwningApplication = NO;
    facts.sceneIsForegroundActive = NO;
    CHECK(!RBAuthBrowserOwnerConditionsAllowPresentation(
              RBAuthBrowserOwnerConditionsFromFacts(facts)),
          "nil scene fails closed");

    RBAuthBrowserOwnerConditions withUnknownBit =
        allConditions | (RBAuthBrowserOwnerConditions)(1U << 20);
    CHECK(!RBAuthBrowserOwnerConditionsAllowPresentation(withUnknownBit),
          "shared gate continues to reject unknown condition bits");
}

static void TestExplicitForegroundOwnerAndCurrentAttemptCallback(void) {
    RBFakeBrowserDriver *driver = [[RBFakeBrowserDriver alloc] init];
    RBAuthBrowserSession *session =
        [[RBAuthBrowserSession alloc] initWithDriver:driver];
    RBAuthAttempt *attempt = NewSyntheticAttempt();
    RBOutcomeRecorder *recorder = [[RBOutcomeRecorder alloc] init];
    NSObject *owner = [[NSObject alloc] init];
    __weak NSObject *weakOwner = owner;

    CHECK([session startForForegroundOwner:nil
                                   attempt:attempt
                            outcomeHandler:nil] ==
              RBAuthBrowserOutcomeInvalidRequest,
          "ownerless start rejected");
    CHECK(driver.startCalls == 0, "ownerless start never reaches driver");

    CHECK([session startForForegroundOwner:owner
                                   attempt:attempt
                            outcomeHandler:^(RBAuthBrowserOutcome outcome) {
        RecordOutcome(recorder, outcome);
    }] == RBAuthBrowserOutcomeStarted, "explicit owner starts fake browser session");
    owner = nil;

    CHECK(weakOwner != nil && driver.retainedOwner == weakOwner &&
              driver.retainedPresentationAnchor == weakOwner,
          "driver retains owner/presentation stand-in while active");
    CHECK(driver.retainedSessionToken != nil, "driver retains active-session stand-in");
    CHECK([driver.lastCallbackScheme isEqualToString:@"raspberry"],
          "fixed callback scheme passed to driver");
    CHECK(driver.lastPrefersEphemeral, "ephemeral browser preference enabled");
    CHECK(driver.lastAuthorizationURL == attempt.authorizationURL,
          "existing attempt authorization URL passed without rewriting");
    CHECK(recorder.outcomes.count == 0, "start reports no URL or callback payload");

    NSString *state = StateFromSyntheticAttempt(attempt);
    NSURL *callback = SyntheticDeniedCallbackForState(state);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [driver completeAtIndex:0
                           kind:RBAuthBrowserDriverCompletionKindCompleted
                    callbackURL:callback];
    });
    WaitForOutcomeCount(recorder, 1, "off-main callback delivered to main");
    CHECK(attempt.stage == RBAuthAttemptStageFailed,
          "only current attempt consumes its matching synthetic callback");
    CHECK(recorder.outcomes.count == 1 &&
              recorder.outcomes[0].integerValue ==
                  RBAuthBrowserOutcomeServerRejected,
          "caller receives only fixed server-rejected outcome");
    CHECK(recorder.callbacksStayedOnMainThread,
          "app outcome callback is marshalled to main thread");
    CHECK(driver.retainedSessionToken == nil &&
              driver.retainedPresentationAnchor == nil,
          "driver releases retained session and anchor at completion");

    [driver completeAtIndex:0
                       kind:RBAuthBrowserDriverCompletionKindCompleted
                callbackURL:callback];
    PumpMainQueue(5);
    CHECK(recorder.outcomes.count == 1, "duplicate completion is one-shot");
    CHECK([session cancelCurrentSession] == RBAuthBrowserOutcomeAttemptInactive,
          "completed round cannot be cancelled again");
    CHECK(driver.cancelCalls == 0, "completion does not invoke driver cancellation");
}

static void TestForegroundAndStartFailures(void) {
    RBAuthAttempt *notForegroundAttempt = NewSyntheticAttempt();
    RBFakeBrowserDriver *notForeground = [[RBFakeBrowserDriver alloc] init];
    notForeground.configuredStartResult =
        RBAuthBrowserDriverStartResultOwnerNotForeground;
    RBAuthBrowserSession *notForegroundSession =
        [[RBAuthBrowserSession alloc] initWithDriver:notForeground];

    CHECK([notForegroundSession startForForegroundOwner:[[NSObject alloc] init]
                                                attempt:notForegroundAttempt
                                         outcomeHandler:nil] ==
              RBAuthBrowserOutcomeOwnerNotForeground,
          "driver foreground rejection returned as fixed outcome");
    CHECK(notForegroundAttempt.stage == RBAuthAttemptStageCancelled,
          "foreground rejection cancels the still-current attempt");
    CHECK(notForeground.retainedSessionToken == nil &&
              notForeground.cancelCalls == 0,
          "failed foreground start leaves no live fake session");

    RBAuthAttempt *failedAttempt = NewSyntheticAttempt();
    RBFakeBrowserDriver *failedDriver = [[RBFakeBrowserDriver alloc] init];
    failedDriver.configuredStartResult = RBAuthBrowserDriverStartResultFailed;
    RBAuthBrowserSession *failedSession =
        [[RBAuthBrowserSession alloc] initWithDriver:failedDriver];
    CHECK([failedSession startForForegroundOwner:[[NSObject alloc] init]
                                         attempt:failedAttempt
                                  outcomeHandler:nil] ==
              RBAuthBrowserOutcomeStartFailed,
          "driver start failure returned as fixed outcome");
    CHECK(failedAttempt.stage == RBAuthAttemptStageCancelled,
          "failed start cancels attempt state");
    CHECK(failedDriver.completions.count == 0 &&
              failedDriver.cancelCalls == 0,
          "failed start has no callback or retained session");
}

static void TestSynchronousCallbackDuringStartIsDeferredAndFenced(void) {
    RBAuthAttempt *successfulAttempt = NewSyntheticAttempt();
    RBFakeBrowserDriver *successfulDriver = [[RBFakeBrowserDriver alloc] init];
    successfulDriver.completeSynchronouslyDuringStart = YES;
    successfulDriver.synchronousStartKind =
        RBAuthBrowserDriverCompletionKindCompleted;
    successfulDriver.synchronousStartCallbackURL =
        SyntheticDeniedCallbackForState(StateFromSyntheticAttempt(successfulAttempt));
    RBAuthBrowserSession *successfulSession =
        [[RBAuthBrowserSession alloc] initWithDriver:successfulDriver];
    RBOutcomeRecorder *successfulRecorder = [[RBOutcomeRecorder alloc] init];

    CHECK([successfulSession startForForegroundOwner:[[NSObject alloc] init]
                                              attempt:successfulAttempt
                                       outcomeHandler:^(RBAuthBrowserOutcome outcome) {
        RecordOutcome(successfulRecorder, outcome);
    }] == RBAuthBrowserOutcomeStarted,
          "synchronous successful driver start returns started");
    CHECK(successfulAttempt.stage == RBAuthAttemptStageAwaitingCallback &&
              successfulRecorder.outcomes.count == 0,
          "synchronous fake callback cannot reenter start");
    WaitForOutcomeCount(successfulRecorder, 1,
                        "queued synchronous callback completes after start");
    CHECK(successfulAttempt.stage == RBAuthAttemptStageFailed &&
              successfulRecorder.outcomes[0].integerValue ==
                  RBAuthBrowserOutcomeServerRejected,
          "deferred synchronous callback reaches its attempt");

    RBAuthAttempt *failedAttempt = NewSyntheticAttempt();
    RBFakeBrowserDriver *failedDriver = [[RBFakeBrowserDriver alloc] init];
    failedDriver.configuredStartResult = RBAuthBrowserDriverStartResultFailed;
    failedDriver.completeSynchronouslyDuringStart = YES;
    failedDriver.synchronousStartKind =
        RBAuthBrowserDriverCompletionKindCompleted;
    failedDriver.synchronousStartCallbackURL =
        SyntheticDeniedCallbackForState(StateFromSyntheticAttempt(failedAttempt));
    RBAuthBrowserSession *failedSession =
        [[RBAuthBrowserSession alloc] initWithDriver:failedDriver];
    RBOutcomeRecorder *failedRecorder = [[RBOutcomeRecorder alloc] init];

    CHECK([failedSession startForForegroundOwner:[[NSObject alloc] init]
                                         attempt:failedAttempt
                                  outcomeHandler:^(RBAuthBrowserOutcome outcome) {
        RecordOutcome(failedRecorder, outcome);
    }] == RBAuthBrowserOutcomeStartFailed,
          "failed synchronous start returns fixed failure");
    CHECK(failedAttempt.stage == RBAuthAttemptStageCancelled &&
              failedRecorder.outcomes.count == 0,
          "failed start cancels before queued completion can run");
    PumpMainQueue(5);
    CHECK(failedRecorder.outcomes.count == 0,
          "failed start cannot emit an outcome from synchronous callback");
}

static void TestStartCancelAreMainThreadSerialized(void) {
    RBFakeBrowserDriver *driver = [[RBFakeBrowserDriver alloc] init];
    RBAuthBrowserSession *session =
        [[RBAuthBrowserSession alloc] initWithDriver:driver];
    RBAuthAttempt *attempt = NewSyntheticAttempt();
    NSObject *owner = [[NSObject alloc] init];
    __block RBAuthBrowserOutcome offMainStart =
        RBAuthBrowserOutcomeInvalidRequest;
    CHECK(RunOnWorkerThread(^{
        offMainStart = [session startForForegroundOwner:owner
                                                attempt:attempt
                                         outcomeHandler:nil];
    }), "background start test worker finished");
    CHECK(offMainStart == RBAuthBrowserOutcomeMainThreadRequired &&
              driver.startCalls == 0 &&
              attempt.stage == RBAuthAttemptStageAwaitingCallback,
          "background start is rejected without changing attempt");

    CHECK([session startForForegroundOwner:owner
                                   attempt:attempt
                            outcomeHandler:nil] == RBAuthBrowserOutcomeStarted,
          "main-thread owner starts round");
    __block RBAuthBrowserOutcome offMainCancel =
        RBAuthBrowserOutcomeInvalidRequest;
    CHECK(RunOnWorkerThread(^{
        offMainCancel = [session cancelCurrentSession];
    }), "background cancellation test worker finished");
    CHECK(offMainCancel == RBAuthBrowserOutcomeMainThreadRequired &&
              driver.cancelCalls == 0 &&
              attempt.stage == RBAuthAttemptStageAwaitingCallback,
          "background cancellation is rejected without racing driver");
    CHECK([session cancelCurrentSession] ==
              RBAuthBrowserOutcomeBrowserCancelled &&
              driver.cancelCalls == 1 &&
              attempt.stage == RBAuthAttemptStageCancelled,
          "main-thread cancellation serially consumes active round");
}

static void TestUIKitDriverCancellationGateRefusesOffMainWithoutQueueing(void) {
    __block NSUInteger currentSessionGeneration = 1;
    __block NSUInteger cancelledSessionGeneration = 0;
    __block BOOL workerCancellationAccepted = YES;

    CHECK(RunOnWorkerThread(^{
        workerCancellationAccepted =
            RBAuthBrowserPerformDriverCancellationOnMainThread(^{
                cancelledSessionGeneration = currentSessionGeneration;
            });
    }), "direct-driver cancellation test worker finished");
    currentSessionGeneration = 2;
    PumpMainQueue(5);

    CHECK(!workerCancellationAccepted && cancelledSessionGeneration == 0,
          "off-main driver cancellation is refused and never queued to cancel a newer session");
    CHECK(RBAuthBrowserPerformDriverCancellationOnMainThread(^{
              cancelledSessionGeneration = currentSessionGeneration;
          }) && cancelledSessionGeneration == 2,
          "main-thread driver cancellation executes synchronously");
}

static void TestReentrantCancellationDoesNotReportStartSuccess(void) {
    RBFakeBrowserDriver *driver = [[RBFakeBrowserDriver alloc] init];
    RBAuthBrowserSession *session =
        [[RBAuthBrowserSession alloc] initWithDriver:driver];
    RBAuthAttempt *attempt = NewSyntheticAttempt();
    RBOutcomeRecorder *recorder = [[RBOutcomeRecorder alloc] init];
    __block RBAuthBrowserOutcome reentrantCancel =
        RBAuthBrowserOutcomeInvalidRequest;
    driver.startReentrancyHandler = ^{
        reentrantCancel = [session cancelCurrentSession];
    };

    RBAuthBrowserOutcome startOutcome =
        [session startForForegroundOwner:[[NSObject alloc] init]
                                  attempt:attempt
                           outcomeHandler:^(RBAuthBrowserOutcome outcome) {
            RecordOutcome(recorder, outcome);
        }];

    CHECK(reentrantCancel == RBAuthBrowserOutcomeBrowserCancelled &&
              startOutcome == RBAuthBrowserOutcomeBrowserCancelled,
          "reentrant cancellation remains terminal instead of start success");
    CHECK(attempt.stage == RBAuthAttemptStageCancelled &&
              driver.cancelCalls == 1 &&
              recorder.outcomes.count == 1 &&
              recorder.outcomes[0].integerValue ==
                  RBAuthBrowserOutcomeBrowserCancelled,
          "reentrant cancellation emits exactly one cancellation outcome");
}

static void TestCancellationOneShotAndStaleRoundFence(void) {
    RBFakeBrowserDriver *driver = [[RBFakeBrowserDriver alloc] init];
    RBAuthBrowserSession *session =
        [[RBAuthBrowserSession alloc] initWithDriver:driver];
    RBAuthAttempt *attemptA = NewSyntheticAttempt();
    RBAuthAttempt *attemptB = NewSyntheticAttempt();
    RBOutcomeRecorder *recorderA = [[RBOutcomeRecorder alloc] init];
    RBOutcomeRecorder *recorderB = [[RBOutcomeRecorder alloc] init];
    NSObject *owner = [[NSObject alloc] init];

    CHECK([session startForForegroundOwner:owner
                                   attempt:attemptA
                            outcomeHandler:^(RBAuthBrowserOutcome outcome) {
        RecordOutcome(recorderA, outcome);
    }] == RBAuthBrowserOutcomeStarted, "round A starts");
    NSURL *callbackA =
        SyntheticDeniedCallbackForState(StateFromSyntheticAttempt(attemptA));

    CHECK([session cancelCurrentSession] ==
              RBAuthBrowserOutcomeBrowserCancelled,
          "first cancellation consumes round A");
    CHECK([session cancelCurrentSession] ==
              RBAuthBrowserOutcomeAttemptInactive,
          "second cancellation is inert");
    CHECK(attemptA.stage == RBAuthAttemptStageCancelled &&
              driver.cancelCalls == 1,
          "cancellation reaches attempt and driver once");
    CHECK(recorderA.outcomes.count == 1 &&
              recorderA.outcomes[0].integerValue ==
                  RBAuthBrowserOutcomeBrowserCancelled,
          "cancellation reports one fixed enum");

    CHECK([session startForForegroundOwner:owner
                                   attempt:attemptB
                            outcomeHandler:^(RBAuthBrowserOutcome outcome) {
        RecordOutcome(recorderB, outcome);
    }] == RBAuthBrowserOutcomeStarted, "round B starts after cancellation");
    NSURL *callbackB =
        SyntheticDeniedCallbackForState(StateFromSyntheticAttempt(attemptB));

    [driver completeAtIndex:0
                       kind:RBAuthBrowserDriverCompletionKindCompleted
                callbackURL:callbackA];
    PumpMainQueue(5);
    CHECK(attemptB.stage == RBAuthAttemptStageAwaitingCallback &&
              recorderB.outcomes.count == 0,
          "stale round A callback cannot reach current attempt B");

    [driver completeAtIndex:1
                       kind:RBAuthBrowserDriverCompletionKindCompleted
                callbackURL:callbackB];
    WaitForOutcomeCount(recorderB, 1,
                        "current round callback delivered after main hop");
    CHECK(attemptB.stage == RBAuthAttemptStageFailed,
          "round B callback reaches only attempt B");
    CHECK(recorderB.outcomes.count == 1 &&
              recorderB.outcomes[0].integerValue ==
                  RBAuthBrowserOutcomeServerRejected,
          "round B completion exposes fixed outcome only");
    CHECK(recorderA.outcomes.count == 1 &&
              recorderB.outcomes.count == 1,
          "stale and current callback paths remain one-shot");
}

static void TestBusyRoundAndMismatchedCallback(void) {
    RBFakeBrowserDriver *driver = [[RBFakeBrowserDriver alloc] init];
    RBAuthBrowserSession *session =
        [[RBAuthBrowserSession alloc] initWithDriver:driver];
    RBAuthAttempt *attemptA = NewSyntheticAttempt();
    RBAuthAttempt *attemptB = NewSyntheticAttempt();
    RBOutcomeRecorder *recorder = [[RBOutcomeRecorder alloc] init];
    NSObject *owner = [[NSObject alloc] init];

    CHECK([session startForForegroundOwner:owner
                                   attempt:attemptA
                            outcomeHandler:^(RBAuthBrowserOutcome outcome) {
        RecordOutcome(recorder, outcome);
    }] == RBAuthBrowserOutcomeStarted, "busy-test first round starts");
    CHECK([session startForForegroundOwner:owner
                                   attempt:attemptB
                            outcomeHandler:nil] ==
              RBAuthBrowserOutcomeAlreadyActive,
          "second simultaneous round rejected");
    CHECK(driver.startCalls == 1 &&
              attemptB.stage == RBAuthAttemptStageAwaitingCallback,
          "busy rejection does not launch or consume other attempt");

    NSURL *wrongCallback =
        SyntheticDeniedCallbackForState(StateFromSyntheticAttempt(attemptB));
    [driver completeAtIndex:0
                       kind:RBAuthBrowserDriverCompletionKindCompleted
                callbackURL:wrongCallback];
    WaitForOutcomeCount(recorder, 1, "mismatched callback processed");
    CHECK(attemptA.stage == RBAuthAttemptStageCancelled,
          "mismatched callback rejects and closes current attempt");
    CHECK(attemptB.stage == RBAuthAttemptStageAwaitingCallback,
          "callback state is not forwarded to unrelated attempt");
    CHECK(recorder.outcomes.count == 1 &&
              recorder.outcomes[0].integerValue ==
                  RBAuthBrowserOutcomeCallbackRejected,
          "mismatched callback reports fixed rejection only");
}

static void TestBrowserCancellationCompletion(void) {
    RBFakeBrowserDriver *driver = [[RBFakeBrowserDriver alloc] init];
    RBAuthBrowserSession *session =
        [[RBAuthBrowserSession alloc] initWithDriver:driver];
    RBAuthAttempt *attempt = NewSyntheticAttempt();
    RBOutcomeRecorder *recorder = [[RBOutcomeRecorder alloc] init];

    CHECK([session startForForegroundOwner:[[NSObject alloc] init]
                                   attempt:attempt
                            outcomeHandler:^(RBAuthBrowserOutcome outcome) {
        RecordOutcome(recorder, outcome);
    }] == RBAuthBrowserOutcomeStarted, "browser-cancel test starts");
    [driver completeAtIndex:0
                       kind:RBAuthBrowserDriverCompletionKindCancelled
                callbackURL:nil];
    WaitForOutcomeCount(recorder, 1, "browser cancellation processed");
    CHECK(attempt.stage == RBAuthAttemptStageCancelled,
          "browser cancellation cancels current attempt");
    CHECK(recorder.outcomes.count == 1 &&
              recorder.outcomes[0].integerValue ==
                  RBAuthBrowserOutcomeBrowserCancelled,
          "browser cancellation exposes fixed outcome only");
    CHECK([session cancelCurrentSession] ==
              RBAuthBrowserOutcomeAttemptInactive &&
              driver.cancelCalls == 0,
          "completed browser cancellation cannot be repeated");
}

int main(void) {
    @autoreleasepool {
        TestExplicitForegroundOwnerAndCurrentAttemptCallback();
        TestForegroundOwnerEligibilitySeam();
        TestForegroundOwnerFactsFailClosed();
        TestForegroundAndStartFailures();
        TestSynchronousCallbackDuringStartIsDeferredAndFenced();
        TestStartCancelAreMainThreadSerialized();
        TestUIKitDriverCancellationGateRefusesOffMainWithoutQueueing();
        TestReentrantCancellationDoesNotReportStartSuccess();
        TestCancellationOneShotAndStaleRoundFence();
        TestBusyRoundAndMismatchedCallback();
        TestBrowserCancellationCompletion();
    }
    if (failures != 0) {
        fprintf(stderr, "%d browser-session test(s) failed\n", failures);
        return 1;
    }
    puts("browser_session_test: fake-driver ownership/state cases passed");
    return 0;
}
