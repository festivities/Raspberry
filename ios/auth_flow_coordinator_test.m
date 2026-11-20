#import "RBAuthFlowCoordinator.h"

#import "RBAuthStore.h"
#import "RBEndpoint.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dispatch/dispatch.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", label); \
        failures++; \
    } \
} while (0)

static NSString *const TestForegroundNotificationName =
    @"org.raspberry.test.application-did-become-active";

static void PumpMainQueue(NSUInteger iterations);

@interface RBFakeClock : NSObject <RBAuthAttemptClock>
@property(nonatomic) NSTimeInterval now;
@end

@implementation RBFakeClock
- (NSTimeInterval)monotonicTime {
    return self.now;
}
@end

@interface RBFakeOwnerLiveness : NSObject <RBAuthFlowOwnerLiveness>
@property(nonatomic, strong) id expectedApplication;
@property(nonatomic, strong) id expectedOwner;
@property(nonatomic) BOOL active;
@property(nonatomic) NSUInteger checkCalls;
@property(nonatomic, copy, nullable) dispatch_block_t checkHook;
@end

@implementation RBFakeOwnerLiveness
- (BOOL)isForegroundOwner:(id)foregroundOwner
       inOwningApplication:(id)owningApplication {
    self.checkCalls++;
    if (self.checkHook != nil) {
        self.checkHook();
    }
    return [NSThread isMainThread] && self.active &&
           foregroundOwner == self.expectedOwner &&
           owningApplication == self.expectedApplication;
}
@end

@interface RBFakeScheduledTask : NSObject <RBAuthFlowScheduledTask>
@property(nonatomic, copy) dispatch_block_t block;
@property(nonatomic) BOOL cancelled;
@property(nonatomic) BOOL fired;
- (void)fire;
@end

@implementation RBFakeScheduledTask
- (void)cancel {
    self.cancelled = YES;
    self.block = nil;
}

- (void)fire {
    if (self.cancelled || self.fired) {
        return;
    }
    self.fired = YES;
    dispatch_block_t block = self.block;
    self.block = nil;
    if (block != nil) {
        block();
    }
}
@end

@interface RBFakeScheduler : NSObject <RBAuthFlowScheduler>
@property(nonatomic, strong) NSMutableArray<RBFakeScheduledTask *> *tasks;
- (void)fireTaskAtIndex:(NSUInteger)index;
@end

@implementation RBFakeScheduler
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _tasks = [[NSMutableArray alloc] init];
    }
    return self;
}

- (nullable id<RBAuthFlowScheduledTask>)scheduleAfter:(NSTimeInterval)delay
                                                block:(dispatch_block_t)block {
    if (delay <= 0 || block == nil) {
        return nil;
    }
    RBFakeScheduledTask *task = [[RBFakeScheduledTask alloc] init];
    task.block = block;
    [self.tasks addObject:task];
    return task;
}

- (void)fireTaskAtIndex:(NSUInteger)index {
    if (index < self.tasks.count) {
        [self.tasks[index] fire];
    } else {
        CHECK(NO, "requested fake timer exists");
    }
}
@end

@interface RBFakeBrowserCompletion : NSObject
@property(nonatomic, copy) RBAuthBrowserDriverCompletion block;
@end

@implementation RBFakeBrowserCompletion
@end

@interface RBFakeBrowserDriver : NSObject <RBAuthBrowserSessionDriver>
@property(nonatomic, strong) NSMutableArray<RBFakeBrowserCompletion *> *completions;
@property(nonatomic, strong, nullable) id activeOwner;
@property(nonatomic, strong, nullable) NSURL *lastAuthorizationURL;
@property(nonatomic) NSUInteger activeIndex;
@property(nonatomic) NSUInteger startCalls;
@property(nonatomic) NSUInteger cancelCalls;
- (void)completeAtIndex:(NSUInteger)index
                   kind:(RBAuthBrowserDriverCompletionKind)kind
            callbackURL:(NSURL * _Nullable)callbackURL;
- (void)completeActiveWithCallbackURL:(NSURL *)callbackURL;
@end

@implementation RBFakeBrowserDriver
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _completions = [[NSMutableArray alloc] init];
        _activeIndex = NSNotFound;
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
    if (![callbackScheme isEqualToString:@"raspberry"] || !prefersEphemeralSession ||
        foregroundOwner == nil || completion == nil) {
        return RBAuthBrowserDriverStartResultFailed;
    }
    RBFakeBrowserCompletion *entry = [[RBFakeBrowserCompletion alloc] init];
    entry.block = completion;
    self.activeIndex = self.completions.count;
    self.activeOwner = foregroundOwner;
    [self.completions addObject:entry];
    return RBAuthBrowserDriverStartResultStarted;
}

- (void)cancelCurrentSession {
    self.cancelCalls++;
    self.activeIndex = NSNotFound;
    self.activeOwner = nil;
}

- (void)completeAtIndex:(NSUInteger)index
                   kind:(RBAuthBrowserDriverCompletionKind)kind
            callbackURL:(NSURL * _Nullable)callbackURL {
    if (index >= self.completions.count) {
        CHECK(NO, "fake browser completion exists");
        return;
    }
    if (self.activeIndex == index) {
        self.activeIndex = NSNotFound;
        self.activeOwner = nil;
    }
    self.completions[index].block(kind, callbackURL);
}

- (void)completeActiveWithCallbackURL:(NSURL *)callbackURL {
    NSUInteger index = self.activeIndex;
    CHECK(index != NSNotFound, "fake browser round is active");
    if (index != NSNotFound) {
        [self completeAtIndex:index
                         kind:RBAuthBrowserDriverCompletionKindCompleted
                  callbackURL:callbackURL];
    }
}
@end

@interface RBFakeExchangeClient : NSObject <RBAuthFlowExchangeClient>
@property(nonatomic, copy, nullable) RBAuthExchangeCompletion completion;
@property(nonatomic) BOOL startSucceeds;
@property(nonatomic) BOOL started;
@property(nonatomic) BOOL cancelled;
@property(nonatomic) NSUInteger startCalls;
@property(nonatomic) NSUInteger cancelCalls;
- (void)completeWithCode:(NSString * _Nullable)code
                   error:(RBAuthExchangeClientError)error;
@end

@implementation RBFakeExchangeClient
- (BOOL)startWithCompletion:(RBAuthExchangeCompletion)completion {
    self.startCalls++;
    if (!self.startSucceeds || self.started || self.cancelled || completion == nil) {
        return NO;
    }
    self.started = YES;
    self.completion = completion;
    return YES;
}

- (void)cancel {
    self.cancelCalls++;
    self.cancelled = YES;
}

- (void)completeWithCode:(NSString *)code error:(RBAuthExchangeClientError)error {
    RBAuthExchangeCompletion completion = self.completion;
    self.completion = nil;
    if (completion != nil) {
        completion(code, error);
    }
}
@end

@interface RBFakeExchangeFactory : NSObject
@property(nonatomic, strong) NSMutableArray<RBFakeExchangeClient *> *clients;
@property(nonatomic) NSUInteger requestsSeen;
@property(nonatomic, copy, nullable) dispatch_block_t makeReentrancyHandler;
- (id<RBAuthFlowExchangeClient>)makeClientForRequest:(RBAuthExchangeRequest *)request;
@end

@implementation RBFakeExchangeFactory
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _clients = [[NSMutableArray alloc] init];
    }
    return self;
}

- (id<RBAuthFlowExchangeClient>)makeClientForRequest:(RBAuthExchangeRequest *)request {
    self.requestsSeen++;
    CHECK(request != nil, "validated browser attempt yields an exchange request");
    CHECK([request.httpsOrigin isEqualToString:@"https://example.test:8443"],
          "exchange request remains endpoint-bound");
    if (self.makeReentrancyHandler != nil) {
        self.makeReentrancyHandler();
    }
    RBFakeExchangeClient *client = [[RBFakeExchangeClient alloc] init];
    client.startSucceeds = YES;
    [self.clients addObject:client];
    return client;
}
@end

@interface RBStatusRecorder : NSObject
@property(nonatomic, strong) NSMutableArray<NSNumber *> *statuses;
@property(nonatomic) BOOL callbacksStayedOnMainThread;
@end

@implementation RBStatusRecorder
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _statuses = [[NSMutableArray alloc] init];
        _callbacksStayedOnMainThread = YES;
    }
    return self;
}

- (void)record:(RBAuthFlowStatus)status {
    if (![NSThread isMainThread]) {
        self.callbacksStayedOnMainThread = NO;
    }
    [self.statuses addObject:@(status)];
}
@end

@interface RBFakeAuthCommitter : NSObject <RBAuthFlowCommitter>
@property(nonatomic, strong, nullable) id<RBAuthFlowCommitter> innerCommitter;
@property(nonatomic) BOOL shouldSucceed;
@property(nonatomic) NSUInteger commitCalls;
@property(nonatomic) BOOL committedOnMainThread;
@property(nonatomic, copy, nullable) NSString *lastUniqueCode;
@property(nonatomic, strong, nullable) RBEndpoint *lastEndpoint;
@property(nonatomic, copy, nullable) dispatch_block_t reentrancyHandler;
@end

@implementation RBFakeAuthCommitter
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _shouldSucceed = YES;
        _committedOnMainThread = YES;
    }
    return self;
}

- (BOOL)commitUniqueCode:(NSString *)uniqueCode
             forEndpoint:(RBEndpoint *)endpoint
                   error:(NSError * _Nullable * _Nullable)error {
    self.commitCalls++;
    if (![NSThread isMainThread]) {
        self.committedOnMainThread = NO;
    }
    self.lastUniqueCode = uniqueCode;
    self.lastEndpoint = endpoint;
    if (self.reentrancyHandler != nil) {
        self.reentrancyHandler();
    }
    if (self.innerCommitter != nil) {
        return [self.innerCommitter commitUniqueCode:uniqueCode
                                         forEndpoint:endpoint
                                               error:error];
    }
    if (!self.shouldSucceed) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:@"org.raspberry.test"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey : @"synthetic commit failure"}];
        }
        return NO;
    }
    return YES;
}
@end

@interface RBTestAuthStoreFixture : NSObject
@property(nonatomic, copy) NSString *rootPath;
@property(nonatomic, copy) NSString *basePath;
@property(nonatomic, copy) NSString *cachesPath;
@property(nonatomic, copy) NSString *cookiePath;
@property(nonatomic, copy) NSString *authJSONPath;
@property(nonatomic, strong) RBAuthStore *store;
- (BOOL)cookieExists;
- (BOOL)authJSONExists;
- (void)cleanup;
@end

@implementation RBTestAuthStoreFixture
- (nullable instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    NSString *baseTmp = NSTemporaryDirectory();
    char resolvedRoot[PATH_MAX];
    const char *rawTmp = baseTmp.fileSystemRepresentation;
    if (rawTmp == NULL || realpath(rawTmp, resolvedRoot) == NULL) {
        return nil;
    }
    NSString *templateStr = [[NSString stringWithUTF8String:resolvedRoot]
        stringByAppendingPathComponent:@"rb-flow-store-test.XXXXXX"];
    char dirTemplate[PATH_MAX];
    snprintf(dirTemplate, sizeof(dirTemplate), "%s", templateStr.fileSystemRepresentation);
    char *dirPath = mkdtemp(dirTemplate);
    if (dirPath == NULL) {
        return nil;
    }
    _rootPath = [NSString stringWithUTF8String:dirPath];
    _basePath = [_rootPath stringByAppendingPathComponent:@"base"];
    _cachesPath = [_rootPath stringByAppendingPathComponent:@"caches"];
    _cookiePath = [_cachesPath stringByAppendingPathComponent:@"avcookie.na"];
    _authJSONPath = [[_basePath stringByAppendingPathComponent:@"raspberry"]
        stringByAppendingPathComponent:@"auth.json"];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *dirAttrs = @{NSFilePosixPermissions : @0700};
    if (![fm createDirectoryAtPath:_basePath withIntermediateDirectories:NO attributes:dirAttrs error:NULL] ||
        ![fm createDirectoryAtPath:_cachesPath withIntermediateDirectories:NO attributes:dirAttrs error:NULL]) {
        [self cleanup];
        return nil;
    }
    int fd = open(_cookiePath.fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0) {
        [self cleanup];
        return nil;
    }
    const char cookieBytes[] = "stale-cookie";
    ssize_t written = write(fd, cookieBytes, sizeof(cookieBytes) - 1);
    close(fd);
    if (written != (ssize_t)(sizeof(cookieBytes) - 1)) {
        [self cleanup];
        return nil;
    }

    _store = [[RBAuthStore alloc]
        initWithBaseDirectoryURL:[NSURL fileURLWithPath:_basePath isDirectory:YES]
              cachesDirectoryURL:[NSURL fileURLWithPath:_cachesPath isDirectory:YES]];
    if (_store == nil) {
        [self cleanup];
        return nil;
    }
    return self;
}

- (BOOL)cookieExists {
    struct stat st;
    return lstat(_cookiePath.fileSystemRepresentation, &st) == 0;
}

- (BOOL)authJSONExists {
    struct stat st;
    return lstat(_authJSONPath.fileSystemRepresentation, &st) == 0;
}

- (void)cleanup {
    if (_rootPath != nil) {
        [[NSFileManager defaultManager] removeItemAtPath:_rootPath error:NULL];
    }
}
@end

@interface RBFlowTestRig : NSObject
@property(nonatomic, strong) RBAuthFlowCoordinator *coordinator;
@property(nonatomic, strong) RBFakeBrowserDriver *browser;
@property(nonatomic, strong) RBFakeScheduler *scheduler;
@property(nonatomic, strong) RBFakeExchangeFactory *exchangeFactory;
@property(nonatomic, strong) RBFakeClock *clock;
@property(nonatomic, strong) NSObject *application;
@property(nonatomic, strong) NSObject *presentationOwner;
@property(nonatomic, strong) RBFakeOwnerLiveness *ownerLiveness;
@property(nonatomic, strong) RBEndpoint *endpoint;
- (instancetype)initWithCommitter:(nullable id<RBAuthFlowCommitter>)committer;
- (void)startWithRecorder:(nullable RBStatusRecorder *)recorder;
- (void)completeActiveBrowserWithTicketForURL:(NSURL *)authorizationURL;
- (NSNotification *)activeNotification;
@end

@implementation RBFlowTestRig
- (instancetype)init {
    return [self initWithCommitter:nil];
}

- (instancetype)initWithCommitter:(id<RBAuthFlowCommitter>)committer {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    _browser = [[RBFakeBrowserDriver alloc] init];
    _scheduler = [[RBFakeScheduler alloc] init];
    _exchangeFactory = [[RBFakeExchangeFactory alloc] init];
    _clock = [[RBFakeClock alloc] init];
    _clock.now = 10.0;
    _application = [[NSObject alloc] init];
    _presentationOwner = [[NSObject alloc] init];
    _ownerLiveness = [[RBFakeOwnerLiveness alloc] init];
    _ownerLiveness.expectedApplication = _application;
    _ownerLiveness.expectedOwner = _presentationOwner;
    _ownerLiveness.active = YES;
    NSError *error = nil;
    NSData *json =
        [@"{\"v\":1,\"host\":\"example.test\",\"ports\":{\"443\":8443}}"
            dataUsingEncoding:NSUTF8StringEncoding];
    _endpoint = [RBEndpoint endpointWithJSONData:json error:&error];
    CHECK(_endpoint != nil && error == nil, "synthetic endpoint parses");

    __weak RBFakeExchangeFactory *weakFactory = _exchangeFactory;
    RBAuthFlowExchangeFactory factoryBlock =
        ^id<RBAuthFlowExchangeClient>(RBAuthExchangeRequest *request) {
            return [weakFactory makeClientForRequest:request];
        };
    if (committer == nil) {
        _coordinator = [[RBAuthFlowCoordinator alloc]
            initWithBrowserDriver:_browser
            owningApplication:_application
            applicationDidBecomeActiveNotificationName:TestForegroundNotificationName
            ownerLiveness:_ownerLiveness
            exchangeFactory:factoryBlock
            scheduler:_scheduler
            attemptClock:_clock];
    } else {
        _coordinator = [[RBAuthFlowCoordinator alloc]
            initWithBrowserDriver:_browser
            owningApplication:_application
            applicationDidBecomeActiveNotificationName:TestForegroundNotificationName
            ownerLiveness:_ownerLiveness
            exchangeFactory:factoryBlock
            scheduler:_scheduler
            attemptClock:_clock
            committer:committer];
    }
    CHECK(_coordinator != nil, "coordinator initializes with injected fakes");
    return self;
}

- (void)startWithRecorder:(RBStatusRecorder *)recorder {
    RBAuthFlowStatusHandler handler = nil;
    if (recorder != nil) {
        handler = ^(RBAuthFlowStatus value) {
            [recorder record:value];
        };
    }
    RBAuthFlowStatus status =
        [self.coordinator startWithEndpoint:self.endpoint
                            foregroundOwner:self.presentationOwner
                               statusHandler:handler];
    CHECK(status == RBAuthFlowStatusBrowserPresented,
          "one explicit start presents the injected browser");
}

- (void)completeActiveBrowserWithTicketForURL:(NSURL *)authorizationURL {
    NSURLComponents *components =
        [NSURLComponents componentsWithURL:authorizationURL
                   resolvingAgainstBaseURL:NO];
    NSString *state = nil;
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"state"]) {
            state = item.value;
        }
    }
    CHECK(state.length > 0, "synthetic state is present");
    NSString *ticket = [@"" stringByPaddingToLength:43
                                          withString:@"A"
                                     startingAtIndex:0];
    NSString *callback =
        [NSString stringWithFormat:@"raspberry://auth?ticket=%@&state=%@", ticket, state];
    [self.browser completeActiveWithCallbackURL:[NSURL URLWithString:callback]];
    PumpMainQueue(5);
}

- (NSNotification *)activeNotification {
    return [NSNotification notificationWithName:TestForegroundNotificationName
                                        object:self.application];
}
@end

static void PumpMainQueue(NSUInteger iterations) {
    for (NSUInteger i = 0; i < iterations; i++) {
        (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, true);
    }
}

static BOOL WaitForSemaphore(dispatch_semaphore_t semaphore) {
    return dispatch_semaphore_wait(
        semaphore, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0;
}

static NSString *SyntheticExchangeCode(void) {
    return @"00000000-0000-4000-8000-000000000001";
}

static void TestTicketArmsAndExactForegroundClaimsOnce(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    RBStatusRecorder *recorder = [[RBStatusRecorder alloc] init];
    [rig startWithRecorder:recorder];

    CHECK(rig.exchangeFactory.requestsSeen == 0 &&
              rig.exchangeFactory.clients.count == 0,
          "browser presentation alone starts no exchange");
    NSURL *firstAuthorizationURL = rig.browser.lastAuthorizationURL;
    [rig completeActiveBrowserWithTicketForURL:firstAuthorizationURL];
    CHECK(rig.coordinator.status ==
              RBAuthFlowStatusWaitingForOwningApplicationForeground,
          "validated ticket only arms a pending exchange");
    CHECK(rig.exchangeFactory.requestsSeen == 0,
          "validated callback does not exchange in background");

    NSNotification *wrongName =
        [NSNotification notificationWithName:@"unrelated"
                                      object:rig.application];
    NSUInteger livenessChecksBeforeWrongOwner = rig.ownerLiveness.checkCalls;
    [rig.coordinator applicationDidBecomeActive:wrongName];
    NSNotification *wrongOwner =
        [NSNotification notificationWithName:TestForegroundNotificationName
                                      object:[[NSObject alloc] init]];
    [rig.coordinator applicationDidBecomeActive:wrongOwner];
    CHECK(rig.exchangeFactory.requestsSeen == 0 &&
              rig.coordinator.status ==
                  RBAuthFlowStatusWaitingForOwningApplicationForeground,
          "name or object mismatch cannot claim the pending ticket");
    CHECK(rig.ownerLiveness.checkCalls == livenessChecksBeforeWrongOwner,
          "foreground event from another identity never reaches the liveness driver");

    NSNotification *active = [rig activeNotification];
    CHECK([rig.coordinator applicationDidBecomeActive:active] ==
              RBAuthFlowStatusExchangeInProgress,
          "exact owning-application foreground event claims and starts exchange");
    [rig.coordinator applicationDidBecomeActive:active];
    CHECK(rig.exchangeFactory.requestsSeen == 1 &&
              rig.exchangeFactory.clients.count == 1 &&
              rig.exchangeFactory.clients[0].startCalls == 1,
          "duplicate exact foreground event cannot claim a second exchange");
    CHECK(rig.scheduler.tasks.count == 3,
          "attempt, ticket and exchange deadlines are each armed");
    CHECK(rig.scheduler.tasks[1].cancelled,
          "foreground claim cancels pending-ticket deadline");
    CHECK(rig.ownerLiveness.checkCalls >= 3,
          "foreground checked at event, claim, and before transport start");

    [rig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status ==
              RBAuthFlowStatusExchangeValidatedNotCommitted,
          "exchange success stops at the fixed pre-commit status");
    CHECK(recorder.callbacksStayedOnMainThread,
          "fixed status callback is delivered on main");
    CHECK(recorder.statuses.count >= 4,
          "status observer sees a fixed sequence of state changes");
    for (NSNumber *status in recorder.statuses) {
        CHECK(status.integerValue >= RBAuthFlowStatusIdle &&
                  status.integerValue <= RBAuthFlowStatusCommitFailed &&
                  status.integerValue != RBAuthFlowStatusAuthorized &&
                  status.integerValue != RBAuthFlowStatusCommitFailed,
              "observer receives only fixed pre-commit status enum values");
    }
}

static void TestForegroundEventMustBeMainThread(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];

    __block RBAuthFlowStatus workerResult = RBAuthFlowStatusIdle;
    dispatch_semaphore_t finished = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        workerResult = [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
        dispatch_semaphore_signal(finished);
    });
    CHECK(WaitForSemaphore(finished), "off-main foreground event returns promptly");
    CHECK(workerResult == RBAuthFlowStatusMainThreadRequired,
          "off-main foreground event is refused synchronously");
    CHECK(rig.exchangeFactory.requestsSeen == 0 &&
              rig.coordinator.status ==
                  RBAuthFlowStatusWaitingForOwningApplicationForeground,
          "off-main event cannot claim or mutate the pending attempt");
}

static void TestForegroundEventBeforeCallbackNeedsValidatedTicket(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    RBStatusRecorder *recorder = [[RBStatusRecorder alloc] init];
    [rig startWithRecorder:recorder];

    NSNotification *wrongOwner =
        [NSNotification notificationWithName:TestForegroundNotificationName
                                      object:[[NSObject alloc] init]];
    [rig.coordinator applicationDidBecomeActive:wrongOwner];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    CHECK(rig.coordinator.status ==
              RBAuthFlowStatusWaitingForOwningApplicationForeground &&
              rig.exchangeFactory.requestsSeen == 0,
          "unowned foreground event before callback cannot authorize exchange");

    RBFlowTestRig *orderedRig = [[RBFlowTestRig alloc] init];
    RBStatusRecorder *orderedRecorder = [[RBStatusRecorder alloc] init];
    [orderedRig startWithRecorder:orderedRecorder];
    CHECK([orderedRig.coordinator applicationDidBecomeActive:[orderedRig activeNotification]] ==
              RBAuthFlowStatusBrowserPresented,
          "exact app-active event can be observed before browser callback");
    CHECK(orderedRig.exchangeFactory.requestsSeen == 0,
          "foreground event alone never starts exchange");
    [orderedRig completeActiveBrowserWithTicketForURL:orderedRig.browser.lastAuthorizationURL];
    CHECK(orderedRig.coordinator.status == RBAuthFlowStatusExchangeInProgress &&
              orderedRig.exchangeFactory.requestsSeen == 1,
          "validated callback consumes a previously observed exact foreground event");
    CHECK([orderedRecorder.statuses containsObject:
              @(RBAuthFlowStatusWaitingForOwningApplicationForeground)] &&
              [orderedRecorder.statuses containsObject:@(RBAuthFlowStatusExchangeInProgress)],
          "pending state is armed before latched foreground claim");

    RBFlowTestRig *inactiveRig = [[RBFlowTestRig alloc] init];
    [inactiveRig startWithRecorder:nil];
    [inactiveRig.coordinator applicationDidBecomeActive:[inactiveRig activeNotification]];
    inactiveRig.ownerLiveness.active = NO;
    [inactiveRig completeActiveBrowserWithTicketForURL:inactiveRig.browser.lastAuthorizationURL];
    CHECK(inactiveRig.coordinator.status == RBAuthFlowStatusForegroundLost &&
              inactiveRig.exchangeFactory.requestsSeen == 0 &&
              inactiveRig.exchangeFactory.clients.count == 0,
          "active then inactive before delayed callback fails closed without exchange");

    RBFlowTestRig *backgroundPendingRig = [[RBFlowTestRig alloc] init];
    [backgroundPendingRig startWithRecorder:nil];
    [backgroundPendingRig completeActiveBrowserWithTicketForURL:
        backgroundPendingRig.browser.lastAuthorizationURL];
    backgroundPendingRig.ownerLiveness.active = NO;
    [backgroundPendingRig.coordinator applicationDidBecomeActive:
        [backgroundPendingRig activeNotification]];
    CHECK(backgroundPendingRig.coordinator.status ==
              RBAuthFlowStatusWaitingForOwningApplicationForeground &&
              backgroundPendingRig.exchangeFactory.requestsSeen == 0,
          "callback-first background event leaves exchange pending without transport");
    backgroundPendingRig.ownerLiveness.active = YES;
    id originalOwner = backgroundPendingRig.ownerLiveness.expectedOwner;
    backgroundPendingRig.ownerLiveness.expectedOwner = [[NSObject alloc] init];
    [backgroundPendingRig.coordinator applicationDidBecomeActive:
        [backgroundPendingRig activeNotification]];
    CHECK(backgroundPendingRig.coordinator.status ==
              RBAuthFlowStatusWaitingForOwningApplicationForeground &&
              backgroundPendingRig.exchangeFactory.requestsSeen == 0,
          "same app with another active scene cannot claim this owner's ticket");
    backgroundPendingRig.ownerLiveness.expectedOwner = originalOwner;
    [backgroundPendingRig.coordinator applicationDidBecomeActive:
        [backgroundPendingRig activeNotification]];
    CHECK(backgroundPendingRig.coordinator.status == RBAuthFlowStatusExchangeInProgress &&
              backgroundPendingRig.exchangeFactory.requestsSeen == 1,
          "later live exact event claims the still-pending ticket once");
}

static void TestForegroundLossAfterClaimBeforeTaskStartIsTerminal(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    __weak RBFlowTestRig *weakRig = rig;
    rig.exchangeFactory.makeReentrancyHandler = ^{
        weakRig.ownerLiveness.active = NO;
    };
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];

    CHECK(rig.coordinator.status == RBAuthFlowStatusForegroundLost &&
              rig.exchangeFactory.requestsSeen == 1 &&
              rig.exchangeFactory.clients.count == 1 &&
              rig.exchangeFactory.clients[0].cancelled &&
              rig.exchangeFactory.clients[0].startCalls == 0,
          "owner loss during factory callback cancels before task start");
    rig.ownerLiveness.active = YES;
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    CHECK(rig.exchangeFactory.requestsSeen == 1 &&
              rig.exchangeFactory.clients[0].startCalls == 0,
          "terminal foreground loss never reuses claimed ticket or exchange");
}

static void TestReentrantStatusLossIsCheckedImmediatelyBeforeStart(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    RBAuthFlowStatus startStatus =
        [rig.coordinator startWithEndpoint:rig.endpoint
                           foregroundOwner:rig.presentationOwner
                              statusHandler:^(RBAuthFlowStatus status) {
        if (status == RBAuthFlowStatusExchangeInProgress) {
            rig.ownerLiveness.active = NO;
        }
    }];
    CHECK(startStatus == RBAuthFlowStatusBrowserPresented,
          "reentrant-liveness test starts browser");
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    CHECK(rig.coordinator.status == RBAuthFlowStatusForegroundLost &&
              rig.exchangeFactory.clients.count == 1 &&
              rig.exchangeFactory.clients[0].startCalls == 0 &&
              rig.exchangeFactory.clients[0].cancelled,
          "status-handler owner loss is rechecked before task start");
}

static void TestMissingLivenessDriverFailsClosed(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    RBAuthFlowCoordinator *missing =
        [[RBAuthFlowCoordinator alloc]
            initWithBrowserDriver:rig.browser
            owningApplication:rig.application
            applicationDidBecomeActiveNotificationName:TestForegroundNotificationName
            ownerLiveness:nil
            exchangeFactory:nil
            scheduler:rig.scheduler
            attemptClock:rig.clock];
    CHECK(missing == nil, "coordinator refuses to initialize without owner liveness");
}

static void TestNewAttemptFencesStaleBrowserCallback(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    NSUInteger staleIndex = rig.browser.activeIndex;

    [rig startWithRecorder:nil];
    CHECK(rig.browser.cancelCalls == 1 && rig.browser.startCalls == 2,
          "new explicit start cancels and replaces the old browser round");
    [rig.browser completeAtIndex:staleIndex
                             kind:RBAuthBrowserDriverCompletionKindCompleted
                      callbackURL:[NSURL URLWithString:
                          @"raspberry://auth?ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&state=AAAAAAAAAAAAAAAAAAAAAA"]];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status == RBAuthFlowStatusBrowserPresented &&
              rig.exchangeFactory.requestsSeen == 0,
          "old browser result cannot change the new attempt");

    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    CHECK(rig.coordinator.status ==
              RBAuthFlowStatusWaitingForOwningApplicationForeground,
          "new browser round still accepts its own validated callback");
}

static void TestNewAttemptFencesStaleExchangeResult(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    CHECK(rig.exchangeFactory.clients.count == 1,
          "first attempt starts one fake exchange");
    RBFakeExchangeClient *staleClient = rig.exchangeFactory.clients[0];

    [rig startWithRecorder:nil];
    CHECK(staleClient.cancelled && staleClient.cancelCalls == 1,
          "new attempt cancels the in-flight exchange");
    [staleClient completeWithCode:SyntheticExchangeCode()
                            error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status == RBAuthFlowStatusBrowserPresented &&
              rig.exchangeFactory.requestsSeen == 1,
          "late exchange success cannot affect the replacement attempt");

    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    CHECK(rig.exchangeFactory.requestsSeen == 2 &&
              rig.coordinator.status == RBAuthFlowStatusExchangeInProgress,
          "replacement attempt can proceed independently");
}

static void TestTicketTimeoutFencesForegroundClaim(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    CHECK(rig.scheduler.tasks.count == 2, "ticket deadline scheduled after callback");
    rig.clock.now = 130.0;
    [rig.scheduler fireTaskAtIndex:1];
    CHECK(rig.coordinator.status == RBAuthFlowStatusExpired,
          "ticket deadline expires the pending attempt");
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    CHECK(rig.exchangeFactory.requestsSeen == 0,
          "foreground event after timeout cannot claim an exchange");
}

static void TestExchangeTimeoutFencesLateSuccess(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    CHECK(rig.scheduler.tasks.count == 3, "exchange deadline scheduled");
    RBFakeExchangeClient *client = rig.exchangeFactory.clients[0];
    rig.clock.now = 40.0;
    [rig.scheduler fireTaskAtIndex:2];
    CHECK(rig.coordinator.status == RBAuthFlowStatusExchangeTimedOut &&
              client.cancelled,
          "exchange deadline cancels transport and terminates the attempt");
    [client completeWithCode:SyntheticExchangeCode()
                       error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status == RBAuthFlowStatusExchangeTimedOut,
          "stale success after exchange timeout is fenced");
}

static void TestCancellationFencesExchangeResult(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    RBFakeExchangeClient *client = rig.exchangeFactory.clients[0];

    CHECK([rig.coordinator cancelCurrentAttempt] == RBAuthFlowStatusCancelled &&
              client.cancelled,
          "explicit cancellation stops the in-flight exchange");
    [client completeWithCode:SyntheticExchangeCode()
                       error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status == RBAuthFlowStatusCancelled,
          "exchange success arriving after cancellation is fenced");
}

static void TestAttemptDeadlineCancelsBrowserAndFencesCallback(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    NSUInteger oldIndex = rig.browser.activeIndex;
    NSString *oldState = nil;
    NSURLComponents *components =
        [NSURLComponents componentsWithURL:rig.browser.lastAuthorizationURL
                   resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"state"]) {
            oldState = item.value;
        }
    }
    CHECK(oldState.length > 0, "old attempt state available to fake browser");

    rig.clock.now = 610.0;
    [rig.scheduler fireTaskAtIndex:0];
    CHECK(rig.coordinator.status == RBAuthFlowStatusExpired &&
              rig.browser.cancelCalls == 1,
          "attempt deadline cancels its live browser session");
    NSString *lateCallback =
        [NSString stringWithFormat:
            @"raspberry://auth?ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&state=%@",
            oldState];
    [rig.browser completeAtIndex:oldIndex
                             kind:RBAuthBrowserDriverCompletionKindCompleted
                      callbackURL:[NSURL URLWithString:lateCallback]];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status == RBAuthFlowStatusExpired &&
              rig.exchangeFactory.requestsSeen == 0,
          "late browser result after timeout cannot arm an exchange");
}

static void TestCancellationFencesBrowserAndOffMainCancelIsRefused(void) {
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] init];
    [rig startWithRecorder:nil];
    NSUInteger oldIndex = rig.browser.activeIndex;
    __block RBAuthFlowStatus workerResult = RBAuthFlowStatusIdle;
    dispatch_semaphore_t finished = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        workerResult = [rig.coordinator cancelCurrentAttempt];
        dispatch_semaphore_signal(finished);
    });
    CHECK(WaitForSemaphore(finished), "off-main cancel returns promptly");
    CHECK(workerResult == RBAuthFlowStatusMainThreadRequired &&
              rig.coordinator.status == RBAuthFlowStatusBrowserPresented,
          "off-main cancellation does not mutate the attempt");

    CHECK([rig.coordinator cancelCurrentAttempt] == RBAuthFlowStatusCancelled &&
              rig.browser.cancelCalls == 1,
          "main-thread cancellation stops the browser and attempt");
    NSString *lateCallback =
        @"raspberry://auth?ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&state=AAAAAAAAAAAAAAAAAAAAAA";
    [rig.browser completeAtIndex:oldIndex
                             kind:RBAuthBrowserDriverCompletionKindCompleted
                      callbackURL:[NSURL URLWithString:lateCallback]];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status == RBAuthFlowStatusCancelled &&
              rig.exchangeFactory.requestsSeen == 0,
          "late callback cannot revive a cancelled attempt");
}

static void AdvanceRigToExchangeInProgress(RBFlowTestRig *rig,
                                           RBStatusRecorder * _Nullable recorder) {
    [rig startWithRecorder:recorder];
    [rig completeActiveBrowserWithTicketForURL:rig.browser.lastAuthorizationURL];
    CHECK([rig.coordinator applicationDidBecomeActive:[rig activeNotification]] ==
              RBAuthFlowStatusExchangeInProgress,
          "rig advances to exchange in progress");
}

static void TestAuthorizedCommitWithRealAuthStore(void) {
    RBTestAuthStoreFixture *fixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(fixture != nil, "auth store temp fixture created");
    if (fixture == nil) {
        return;
    }
    CHECK([fixture.store conformsToProtocol:@protocol(RBAuthFlowCommitter)],
          "RBAuthStore conforms to RBAuthFlowCommitter");
    CHECK([fixture cookieExists] && ![fixture authJSONExists],
          "fixture starts with avcookie.na and no auth.json");

    RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:fixture.store];
    RBStatusRecorder *recorder = [[RBStatusRecorder alloc] init];
    AdvanceRigToExchangeInProgress(rig, recorder);

    [rig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);

    CHECK(rig.coordinator.status == RBAuthFlowStatusAuthorized,
          "real RBAuthStore commit transitions coordinator to Authorized");
    CHECK(recorder.callbacksStayedOnMainThread,
          "authorized status callback stays on main thread");
    CHECK(recorder.statuses.count >= 5 &&
              recorder.statuses.lastObject.integerValue == RBAuthFlowStatusAuthorized,
          "status recorder ends at RBAuthFlowStatusAuthorized");
    CHECK(![fixture cookieExists],
          "authorized commit removes avcookie.na");
    CHECK([fixture authJSONExists],
          "authorized commit persists auth.json");

    NSError *readError = nil;
    NSString *storedCode =
        [fixture.store authorizedUniqueCodeForEndpoint:rig.endpoint error:&readError];
    CHECK(readError == nil && [storedCode isEqualToString:SyntheticExchangeCode()],
          "store returns exact minted uniqueCode for endpoint");

    [rig.coordinator applicationDidBecomeActive:[rig activeNotification]];
    [rig.exchangeFactory.clients[0] completeWithCode:@"00000000-0000-4000-8000-000000000002"
                                                error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);
    CHECK(rig.coordinator.status == RBAuthFlowStatusAuthorized,
          "late events after Authorized cannot alter status or overwrite credential");
    storedCode =
        [fixture.store authorizedUniqueCodeForEndpoint:rig.endpoint error:&readError];
    CHECK(readError == nil && [storedCode isEqualToString:SyntheticExchangeCode()],
          "late delivery preserves original committed uniqueCode");

    [fixture cleanup];
}

static void TestFailingCommitterReturnsCommitFailed(void) {
    RBFakeAuthCommitter *failingCommitter = [[RBFakeAuthCommitter alloc] init];
    failingCommitter.shouldSucceed = NO;
    RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:failingCommitter];
    RBStatusRecorder *recorder = [[RBStatusRecorder alloc] init];
    AdvanceRigToExchangeInProgress(rig, recorder);

    [rig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);

    CHECK(failingCommitter.commitCalls == 1 && failingCommitter.committedOnMainThread,
          "failing committer is invoked once on main thread");
    CHECK(rig.coordinator.status == RBAuthFlowStatusCommitFailed,
          "failing committer transitions coordinator to CommitFailed");
    CHECK(recorder.statuses.lastObject.integerValue == RBAuthFlowStatusCommitFailed,
          "status handler observes CommitFailed");

    RBTestAuthStoreFixture *fixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(fixture != nil, "auth store failure fixture created");
    if (fixture == nil) {
        return;
    }
    RBFlowTestRig *storeRig = [[RBFlowTestRig alloc] initWithCommitter:fixture.store];
    RBStatusRecorder *storeRecorder = [[RBStatusRecorder alloc] init];
    AdvanceRigToExchangeInProgress(storeRig, storeRecorder);
    [storeRig.exchangeFactory.clients[0] completeWithCode:@"not-a-canonical-uuid"
                                                     error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);
    CHECK(storeRig.coordinator.status == RBAuthFlowStatusCommitFailed &&
              storeRecorder.statuses.lastObject.integerValue == RBAuthFlowStatusCommitFailed,
          "RBAuthStore commit rejection transitions to CommitFailed");
    CHECK([fixture cookieExists] && ![fixture authJSONExists],
          "failed RBAuthStore commit leaves avcookie.na intact and writes no auth.json");
    NSError *readError = nil;
    CHECK([fixture.store authorizedUniqueCodeForEndpoint:storeRig.endpoint error:&readError] == nil &&
              readError != nil &&
              [readError.domain isEqualToString:RBAuthStoreErrorDomain] &&
              readError.code == RBAuthStoreErrorNotFound,
          "failed commit writes no stored credential");
    [fixture cleanup];
}

static void TestAttemptTerminatedBeforeCommitDoesNotInvokeCommitter(void) {
    // 1. Cancelled before exchange completion arrives.
    RBTestAuthStoreFixture *cancelFixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(cancelFixture != nil, "cancel fixture created");
    if (cancelFixture != nil) {
        RBFakeAuthCommitter *spy = [[RBFakeAuthCommitter alloc] init];
        spy.innerCommitter = cancelFixture.store;
        RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:spy];
        AdvanceRigToExchangeInProgress(rig, nil);
        CHECK([rig.coordinator cancelCurrentAttempt] == RBAuthFlowStatusCancelled,
              "cancel during exchange is terminal");
        [rig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                    error:RBAuthExchangeClientErrorNone];
        PumpMainQueue(5);
        CHECK(rig.coordinator.status == RBAuthFlowStatusCancelled && spy.commitCalls == 0,
              "cancelled attempt never invokes committer");
        CHECK([cancelFixture cookieExists] && ![cancelFixture authJSONExists],
              "cancelled attempt preserves avcookie.na and writes no auth.json");
        [cancelFixture cleanup];
    }

    // 2. Superseded by new attempt before stale exchange completion arrives.
    RBTestAuthStoreFixture *supersedeFixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(supersedeFixture != nil, "supersede fixture created");
    if (supersedeFixture != nil) {
        RBFakeAuthCommitter *spy = [[RBFakeAuthCommitter alloc] init];
        spy.innerCommitter = supersedeFixture.store;
        RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:spy];
        AdvanceRigToExchangeInProgress(rig, nil);
        RBFakeExchangeClient *staleClient = rig.exchangeFactory.clients[0];
        [rig startWithRecorder:nil];
        [staleClient completeWithCode:SyntheticExchangeCode()
                                error:RBAuthExchangeClientErrorNone];
        PumpMainQueue(5);
        CHECK(rig.coordinator.status == RBAuthFlowStatusBrowserPresented && spy.commitCalls == 0,
              "superseded exchange result never invokes committer");
        CHECK([supersedeFixture cookieExists] && ![supersedeFixture authJSONExists],
              "superseded attempt preserves avcookie.na and writes no auth.json");
        [supersedeFixture cleanup];
    }

    // 3. Foreground lost before commit.
    RBTestAuthStoreFixture *fgFixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(fgFixture != nil, "foreground-loss fixture created");
    if (fgFixture != nil) {
        RBFakeAuthCommitter *spy = [[RBFakeAuthCommitter alloc] init];
        spy.innerCommitter = fgFixture.store;
        RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:spy];
        RBStatusRecorder *recorder = [[RBStatusRecorder alloc] init];
        AdvanceRigToExchangeInProgress(rig, recorder);
        rig.ownerLiveness.active = NO;
        [rig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                    error:RBAuthExchangeClientErrorNone];
        PumpMainQueue(5);
        CHECK(rig.coordinator.status == RBAuthFlowStatusForegroundLost &&
                  recorder.statuses.lastObject.integerValue == RBAuthFlowStatusForegroundLost &&
                  spy.commitCalls == 0,
              "foreground loss before commit transitions to ForegroundLost without invoking committer");
        CHECK([fgFixture cookieExists] && ![fgFixture authJSONExists],
              "foreground loss preserves avcookie.na and writes no auth.json");
        [fgFixture cleanup];
    }

    // 4. Attempt expired before exchange result is handled (without timer firing).
    RBTestAuthStoreFixture *expFixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(expFixture != nil, "expiry fixture created");
    if (expFixture != nil) {
        RBFakeAuthCommitter *spy = [[RBFakeAuthCommitter alloc] init];
        spy.innerCommitter = expFixture.store;
        RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:spy];
        RBStatusRecorder *recorder = [[RBStatusRecorder alloc] init];
        AdvanceRigToExchangeInProgress(rig, recorder);
        rig.clock.now = 135.0;
        [rig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                    error:RBAuthExchangeClientErrorNone];
        PumpMainQueue(5);
        CHECK(rig.coordinator.status == RBAuthFlowStatusExpired &&
                  recorder.statuses.lastObject.integerValue == RBAuthFlowStatusExpired &&
                  spy.commitCalls == 0,
              "expired attempt before commit transitions to Expired without invoking committer");
        CHECK([expFixture cookieExists] && ![expFixture authJSONExists],
              "expired attempt preserves avcookie.na and writes no auth.json");
        [expFixture cleanup];
    }

    // 5. Attempt expires during liveness probe right before commitWithWriter:.
    RBTestAuthStoreFixture *raceExpFixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(raceExpFixture != nil, "liveness-race expiry fixture created");
    if (raceExpFixture != nil) {
        RBFakeAuthCommitter *spy = [[RBFakeAuthCommitter alloc] init];
        spy.innerCommitter = raceExpFixture.store;
        RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:spy];
        RBStatusRecorder *recorder = [[RBStatusRecorder alloc] init];
        AdvanceRigToExchangeInProgress(rig, recorder);
        __weak RBFlowTestRig *weakRig = rig;
        rig.ownerLiveness.checkHook = ^{
            weakRig.clock.now = 135.0;
        };
        [rig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                    error:RBAuthExchangeClientErrorNone];
        PumpMainQueue(5);
        CHECK(rig.coordinator.status == RBAuthFlowStatusExpired &&
                  recorder.statuses.lastObject.integerValue == RBAuthFlowStatusExpired &&
                  spy.commitCalls == 0,
              "attempt expiry observed under commitWithWriter lock refuses writer invocation");
        CHECK([raceExpFixture cookieExists] && ![raceExpFixture authJSONExists],
              "lock-serialized expiry preserves avcookie.na and writes no auth.json");
        [raceExpFixture cleanup];
    }

    // 6. Exchange failure with committer configured does not invoke committer.
    RBTestAuthStoreFixture *errFixture = [[RBTestAuthStoreFixture alloc] init];
    CHECK(errFixture != nil, "exchange-error fixture created");
    if (errFixture != nil) {
        RBFakeAuthCommitter *spy = [[RBFakeAuthCommitter alloc] init];
        spy.innerCommitter = errFixture.store;
        RBFlowTestRig *rig = [[RBFlowTestRig alloc] initWithCommitter:spy];
        AdvanceRigToExchangeInProgress(rig, nil);
        [rig.exchangeFactory.clients[0] completeWithCode:nil
                                                    error:RBAuthExchangeClientErrorHTTPStatus];
        PumpMainQueue(5);
        CHECK(rig.coordinator.status == RBAuthFlowStatusFailed && spy.commitCalls == 0,
              "exchange error does not invoke committer");
        CHECK([errFixture cookieExists] && ![errFixture authJSONExists],
              "exchange error preserves avcookie.na and writes no auth.json");
        [errFixture cleanup];
    }

    // 7. Reentrant cancel inside committer leaves coordinator Cancelled and never Authorized.
    RBFakeAuthCommitter *reentrantCommitter = [[RBFakeAuthCommitter alloc] init];
    RBFlowTestRig *reentrantRig = [[RBFlowTestRig alloc] initWithCommitter:reentrantCommitter];
    RBStatusRecorder *reentrantRecorder = [[RBStatusRecorder alloc] init];
    __weak RBFlowTestRig *weakReentrantRig = reentrantRig;
    reentrantCommitter.reentrancyHandler = ^{
        [weakReentrantRig.coordinator cancelCurrentAttempt];
    };
    AdvanceRigToExchangeInProgress(reentrantRig, reentrantRecorder);
    [reentrantRig.exchangeFactory.clients[0] completeWithCode:SyntheticExchangeCode()
                                                         error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);
    CHECK(reentrantCommitter.commitCalls == 1 &&
              reentrantRig.coordinator.status == RBAuthFlowStatusCancelled &&
              reentrantRecorder.statuses.lastObject.integerValue == RBAuthFlowStatusCancelled &&
              ![reentrantRecorder.statuses containsObject:@(RBAuthFlowStatusAuthorized)] &&
              ![reentrantRecorder.statuses containsObject:@(RBAuthFlowStatusCommitFailed)],
          "reentrant cancel during committer stays Cancelled without Authorized or CommitFailed");
}

int main(void) {
    @autoreleasepool {
        TestTicketArmsAndExactForegroundClaimsOnce();
        TestForegroundEventMustBeMainThread();
        TestForegroundEventBeforeCallbackNeedsValidatedTicket();
        TestForegroundLossAfterClaimBeforeTaskStartIsTerminal();
        TestReentrantStatusLossIsCheckedImmediatelyBeforeStart();
        TestMissingLivenessDriverFailsClosed();
        TestNewAttemptFencesStaleBrowserCallback();
        TestNewAttemptFencesStaleExchangeResult();
        TestTicketTimeoutFencesForegroundClaim();
        TestExchangeTimeoutFencesLateSuccess();
        TestCancellationFencesExchangeResult();
        TestAttemptDeadlineCancelsBrowserAndFencesCallback();
        TestCancellationFencesBrowserAndOffMainCancelIsRefused();
        TestAuthorizedCommitWithRealAuthStore();
        TestFailingCommitterReturnsCommitFailed();
        TestAttemptTerminatedBeforeCommitDoesNotInvokeCommitter();
    }
    if (failures != 0) {
        fprintf(stderr, "%d auth-flow composition test(s) failed\n", failures);
        return 1;
    }
    puts("iOS auth-flow coordinator: host fake tests ok");
    return 0;
}
