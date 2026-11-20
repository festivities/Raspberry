#import "RBAuthGuestCredentialGate.h"

#import "RBAuthFlowCoordinator.h"
#import "RBAuthStore.h"
#import "RBEndpoint.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dispatch/dispatch.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(condition, label)                                                                    \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "FAIL: %s\n", label);                                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static NSString *const TestForegroundNotificationName =
    @"org.raspberry.test.gate.application-did-become-active";

static void PumpMainQueue(NSUInteger iterations) {
    for (NSUInteger i = 0; i < iterations; i++) {
        (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, true);
    }
}

static RBEndpoint *MakeEndpoint(NSString *host, uint16_t port443) {
    NSString *json = [NSString stringWithFormat:@"{\"v\":1,\"host\":\"%@\",\"ports\":{\"443\":%u}}",
                                                host, (unsigned)port443];
    NSError *error = nil;
    RBEndpoint *endpoint =
        [RBEndpoint endpointWithJSONData:[json dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    CHECK(endpoint != nil && error == nil, "make endpoint fixture");
    return endpoint;
}

@interface RBGateTestStoreFixture : NSObject
@property(nonatomic, copy) NSString *rootPath;
@property(nonatomic, copy) NSString *basePath;
@property(nonatomic, copy) NSString *cachesPath;
@property(nonatomic, copy) NSString *cookiePath;
@property(nonatomic, copy) NSString *authJSONPath;
@property(nonatomic, strong) RBAuthStore *store;
- (BOOL)writeCookie;
- (BOOL)cookieExists;
- (BOOL)authJSONExists;
- (void)cleanup;
@end

@implementation RBGateTestStoreFixture
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
        stringByAppendingPathComponent:@"rb-gate-test.XXXXXX"];
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
    if (![fm createDirectoryAtPath:_basePath
            withIntermediateDirectories:NO
                             attributes:dirAttrs
                                  error:NULL] ||
        ![fm createDirectoryAtPath:_cachesPath
            withIntermediateDirectories:NO
                             attributes:dirAttrs
                                  error:NULL]) {
        [self cleanup];
        return nil;
    }
    if (![self writeCookie]) {
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

- (BOOL)writeCookie {
    int fd = open(_cookiePath.fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0) {
        return NO;
    }
    const char cookieBytes[] = "stale-cookie";
    ssize_t written = write(fd, cookieBytes, sizeof(cookieBytes) - 1);
    close(fd);
    return written == (ssize_t)(sizeof(cookieBytes) - 1);
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

@interface RBGateFakeClock : NSObject <RBAuthAttemptClock>
@property(nonatomic) NSTimeInterval now;
@end

@implementation RBGateFakeClock
- (NSTimeInterval)monotonicTime {
    return self.now;
}
@end

@interface RBGateFakeOwnerLiveness : NSObject <RBAuthFlowOwnerLiveness>
@property(nonatomic, strong) id expectedApplication;
@property(nonatomic, strong) id expectedOwner;
@property(nonatomic) BOOL active;
@end

@implementation RBGateFakeOwnerLiveness
- (BOOL)isForegroundOwner:(id)foregroundOwner inOwningApplication:(id)owningApplication {
    return [NSThread isMainThread] && self.active &&
           foregroundOwner == self.expectedOwner &&
           owningApplication == self.expectedApplication;
}
@end

@interface RBGateFakeScheduledTask : NSObject <RBAuthFlowScheduledTask>
@property(nonatomic, copy, nullable) dispatch_block_t block;
@property(nonatomic) BOOL cancelled;
@end

@implementation RBGateFakeScheduledTask
- (void)cancel {
    self.cancelled = YES;
    self.block = nil;
}
@end

@interface RBGateFakeScheduler : NSObject <RBAuthFlowScheduler>
@property(nonatomic, strong) NSMutableArray<RBGateFakeScheduledTask *> *tasks;
@end

@implementation RBGateFakeScheduler
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
    RBGateFakeScheduledTask *task = [[RBGateFakeScheduledTask alloc] init];
    task.block = block;
    [self.tasks addObject:task];
    return task;
}
@end

@interface RBGateFakeBrowserDriver : NSObject <RBAuthBrowserSessionDriver>
@property(nonatomic, copy, nullable) RBAuthBrowserDriverCompletion activeCompletion;
@property(nonatomic, strong, nullable) NSURL *lastAuthorizationURL;
@end

@implementation RBGateFakeBrowserDriver
- (RBAuthBrowserDriverStartResult)startAuthorizationURL:(NSURL *)authorizationURL
                                           callbackScheme:(NSString *)callbackScheme
                                 prefersEphemeralSession:(BOOL)prefersEphemeralSession
                                         foregroundOwner:(id)foregroundOwner
                                              completion:(RBAuthBrowserDriverCompletion)completion {
    self.lastAuthorizationURL = authorizationURL;
    if (![callbackScheme isEqualToString:@"raspberry"] || !prefersEphemeralSession ||
        foregroundOwner == nil || completion == nil) {
        return RBAuthBrowserDriverStartResultFailed;
    }
    self.activeCompletion = completion;
    return RBAuthBrowserDriverStartResultStarted;
}

- (void)cancelCurrentSession {
    self.activeCompletion = nil;
}

- (void)completeWithAuthorizationCallbackFromURL:(NSURL *)authorizationURL {
    NSURLComponents *components =
        [NSURLComponents componentsWithURL:authorizationURL resolvingAgainstBaseURL:NO];
    NSString *state = nil;
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"state"]) {
            state = item.value;
        }
    }
    CHECK(state.length > 0, "authorization URL includes state");
    NSString *ticket = [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0];
    NSString *callback =
        [NSString stringWithFormat:@"raspberry://auth?ticket=%@&state=%@", ticket, state];
    RBAuthBrowserDriverCompletion completion = self.activeCompletion;
    self.activeCompletion = nil;
    CHECK(completion != nil, "browser completion block exists");
    if (completion != nil) {
        completion(RBAuthBrowserDriverCompletionKindCompleted, [NSURL URLWithString:callback]);
    }
    PumpMainQueue(5);
}
@end

@interface RBGateFakeExchangeClient : NSObject <RBAuthFlowExchangeClient>
@property(nonatomic, copy, nullable) RBAuthExchangeCompletion completion;
@property(nonatomic) BOOL cancelled;
- (void)completeWithCode:(NSString * _Nullable)code error:(RBAuthExchangeClientError)error;
@end

@implementation RBGateFakeExchangeClient
- (BOOL)startWithCompletion:(RBAuthExchangeCompletion)completion {
    if (self.cancelled || completion == nil) {
        return NO;
    }
    self.completion = completion;
    return YES;
}

- (void)cancel {
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

static void TestInitializerAndInitialState(void) {
    RBGateTestStoreFixture *fixture = [[RBGateTestStoreFixture alloc] init];
    CHECK(fixture != nil, "init test fixture");
    if (fixture == nil) {
        return;
    }
    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 443);

    RBEndpoint *nilEndpoint = nil;
    RBAuthStore *nilStore = nil;
    CHECK([[RBAuthGuestCredentialGate alloc] initWithEndpoint:nilEndpoint authStore:fixture.store] == nil,
          "init rejects nil endpoint");
    CHECK([[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:nilStore] == nil,
          "init rejects nil authStore");
    CHECK([[RBAuthGuestCredentialGate alloc] initWithEndpoint:nilEndpoint authStore:nilStore] == nil,
          "init rejects nil endpoint and authStore");

    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:fixture.store];
    CHECK(gate != nil, "init succeeds with valid endpoint and store");
    CHECK([gate conformsToProtocol:@protocol(RBAuthFlowCommitter)],
          "gate conforms to RBAuthFlowCommitter");
    CHECK(!gate.isAuthorized, "gate starts unauthorized");
    CHECK([gate authorizedUniqueCodeUTF8] == NULL, "gate starts with NULL UTF-8 pointer");

    char buf[37];
    memset(buf, 'X', sizeof(buf));
    CHECK(![gate copyAuthorizedUniqueCodeUTF8:NULL capacity:37],
          "copy rejects NULL buffer");
    CHECK(![gate copyAuthorizedUniqueCodeUTF8:buf capacity:0],
          "copy rejects zero capacity");
    CHECK(buf[0] == 'X', "zero capacity does not touch buffer");
    CHECK(![gate copyAuthorizedUniqueCodeUTF8:buf capacity:36],
          "copy rejects capacity < 37");
    CHECK(buf[0] == '\0', "short capacity zeros buffer[0]");

    memset(buf, 'Y', sizeof(buf));
    CHECK(![gate copyAuthorizedUniqueCodeUTF8:buf capacity:sizeof(buf)],
          "copy fails when unauthorized");
    CHECK(buf[0] == '\0', "unauthorized copy zeros buffer[0]");

    [fixture cleanup];
}

static void TestReloadFromStore(void) {
    RBGateTestStoreFixture *fixture = [[RBGateTestStoreFixture alloc] init];
    CHECK(fixture != nil, "reload test fixture");
    if (fixture == nil) {
        return;
    }

    RBEndpoint *endpointA = MakeEndpoint(@"cherry.example.org", 443);
    RBEndpoint *endpointB = MakeEndpoint(@"cherry.example.org", 8443);
    NSString *uuidA = @"123e4567-e89b-12d3-a456-426614174000";
    NSString *uuidB = @"999e4567-e89b-12d3-a456-426614174999";

    RBAuthGuestCredentialGate *gateA =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpointA authStore:fixture.store];
    NSError *err = nil;
    CHECK(![gateA reloadFromStoreError:&err], "reload fails when auth.json is missing");
    CHECK(err != nil && [err.domain isEqualToString:RBAuthStoreErrorDomain] &&
              err.code == RBAuthStoreErrorNotFound,
          "missing auth.json surfaces RBAuthStoreErrorNotFound");
    CHECK(!gateA.isAuthorized && [gateA authorizedUniqueCodeUTF8] == NULL,
          "failed reload leaves gate unauthorized");

    NSError *seedErr = nil;
    CHECK([fixture.store commitUniqueCode:uuidA forEndpoint:endpointA error:&seedErr] &&
              seedErr == nil,
          "seed store with uuidA for endpointA");

    err = nil;
    CHECK([gateA reloadFromStoreError:&err] && err == nil,
          "reload loads matching-origin authorization");
    CHECK(gateA.isAuthorized, "gateA is authorized after reload");
    const char *ptrA = [gateA authorizedUniqueCodeUTF8];
    CHECK(ptrA != NULL && strcmp(ptrA, uuidA.UTF8String) == 0,
          "authorizedUniqueCodeUTF8 matches pre-existing stored UUID");

    char copied[37];
    memset(copied, 0, sizeof(copied));
    CHECK([gateA copyAuthorizedUniqueCodeUTF8:copied capacity:sizeof(copied)] &&
              strcmp(copied, uuidA.UTF8String) == 0,
          "copyAuthorizedUniqueCodeUTF8 matches pre-existing stored UUID");

    RBAuthGuestCredentialGate *gateB =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpointB authStore:fixture.store];
    err = nil;
    CHECK(![gateB reloadFromStoreError:&err], "reload rejects wrong-origin authorization");
    CHECK(err != nil && [err.domain isEqualToString:RBAuthStoreErrorDomain] &&
              err.code == RBAuthStoreErrorOriginMismatch,
          "wrong-origin reload surfaces RBAuthStoreErrorOriginMismatch");
    CHECK(!gateB.isAuthorized && [gateB authorizedUniqueCodeUTF8] == NULL,
          "wrong-origin reload stays unauthorized");

    // Overwrite store with endpointB, then reload gateA -> gateA must clear active slot.
    CHECK([fixture.store commitUniqueCode:uuidB forEndpoint:endpointB error:&seedErr] &&
              seedErr == nil,
          "seed store with uuidB for endpointB");
    err = nil;
    CHECK(![gateA reloadFromStoreError:&err],
          "reload on gateA fails after store origin changed");
    CHECK(!gateA.isAuthorized && [gateA authorizedUniqueCodeUTF8] == NULL,
          "failed reload clears previously active in-memory authorization");
    memset(copied, 'Z', sizeof(copied));
    CHECK(![gateA copyAuthorizedUniqueCodeUTF8:copied capacity:sizeof(copied)] && copied[0] == '\0',
          "copy fails and zeros buffer after failed reload cleared gate");

    [fixture cleanup];
}

static void TestCoordinatorEndToEndWithGateCommitter(void) {
    RBGateTestStoreFixture *fixture = [[RBGateTestStoreFixture alloc] init];
    CHECK(fixture != nil, "coordinator test fixture");
    if (fixture == nil) {
        return;
    }

    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 8443);
    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:fixture.store];
    CHECK([fixture cookieExists] && ![fixture authJSONExists],
          "fixture starts with avcookie.na and no auth.json");

    RBGateFakeBrowserDriver *browser = [[RBGateFakeBrowserDriver alloc] init];
    RBGateFakeScheduler *scheduler = [[RBGateFakeScheduler alloc] init];
    RBGateFakeClock *clock = [[RBGateFakeClock alloc] init];
    clock.now = 100.0;
    NSObject *application = [[NSObject alloc] init];
    NSObject *owner = [[NSObject alloc] init];
    RBGateFakeOwnerLiveness *liveness = [[RBGateFakeOwnerLiveness alloc] init];
    liveness.expectedApplication = application;
    liveness.expectedOwner = owner;
    liveness.active = YES;

    NSMutableArray<RBGateFakeExchangeClient *> *clients = [[NSMutableArray alloc] init];
    RBAuthFlowCoordinator *coordinator = [[RBAuthFlowCoordinator alloc]
        initWithBrowserDriver:browser
        owningApplication:application
        applicationDidBecomeActiveNotificationName:TestForegroundNotificationName
        ownerLiveness:liveness
        exchangeFactory:^id<RBAuthFlowExchangeClient>(RBAuthExchangeRequest *request) {
            CHECK(request != nil && [request.httpsOrigin isEqualToString:endpoint.httpsOrigin],
                  "coordinator exchange request bound to configured endpoint");
            RBGateFakeExchangeClient *client = [[RBGateFakeExchangeClient alloc] init];
            [clients addObject:client];
            return client;
        }
        scheduler:scheduler
        attemptClock:clock
        committer:gate];
    CHECK(coordinator != nil, "coordinator initialized with RBAuthGuestCredentialGate committer");

    __block RBAuthFlowStatus lastObservedStatus = RBAuthFlowStatusIdle;
    __block BOOL authorizedInsideCallback = NO;
    __block const char *utf8InsideCallback = NULL;
    NSString *expectedUUID = @"00000000-0000-4000-8000-000000000042";

    RBAuthFlowStatus startStatus = [coordinator
        startWithEndpoint:endpoint
          foregroundOwner:owner
            statusHandler:^(RBAuthFlowStatus status) {
                lastObservedStatus = status;
                if (status == RBAuthFlowStatusAuthorized) {
                    authorizedInsideCallback = gate.isAuthorized;
                    utf8InsideCallback = [gate authorizedUniqueCodeUTF8];
                }
            }];
    CHECK(startStatus == RBAuthFlowStatusBrowserPresented, "coordinator presents browser");
    CHECK(!gate.isAuthorized, "gate stays unauthorized during browser presentation");

    [browser completeWithAuthorizationCallbackFromURL:browser.lastAuthorizationURL];
    NSNotification *foreground =
        [NSNotification notificationWithName:TestForegroundNotificationName object:application];
    CHECK([coordinator applicationDidBecomeActive:foreground] ==
              RBAuthFlowStatusExchangeInProgress,
          "foreground notification triggers exchange");
    CHECK(clients.count == 1, "one exchange client created");
    CHECK(!gate.isAuthorized, "gate stays unauthorized while exchange is in progress");

    [clients[0] completeWithCode:expectedUUID error:RBAuthExchangeClientErrorNone];
    PumpMainQueue(5);

    CHECK(coordinator.status == RBAuthFlowStatusAuthorized &&
              lastObservedStatus == RBAuthFlowStatusAuthorized,
          "coordinator reaches RBAuthFlowStatusAuthorized");
    CHECK(authorizedInsideCallback && utf8InsideCallback != NULL &&
              strcmp(utf8InsideCallback, expectedUUID.UTF8String) == 0,
          "gate is already authorized when Authorized status handler fires");
    CHECK(![fixture cookieExists], "coordinator+gate commit removes avcookie.na");
    CHECK([fixture authJSONExists], "coordinator+gate commit persists auth.json");
    CHECK(gate.isAuthorized, "gate.isAuthorized is YES after flow");
    CHECK([gate authorizedUniqueCodeUTF8] != NULL &&
              strcmp([gate authorizedUniqueCodeUTF8], expectedUUID.UTF8String) == 0,
          "gate.authorizedUniqueCodeUTF8 matches exchanged UUID");

    char buf[37];
    memset(buf, 0, sizeof(buf));
    CHECK([gate copyAuthorizedUniqueCodeUTF8:buf capacity:sizeof(buf)] &&
              strcmp(buf, expectedUUID.UTF8String) == 0,
          "copyAuthorizedUniqueCodeUTF8 matches exchanged UUID");

    // Verify failed exchange on a fresh gate leaves it unauthorized.
    RBAuthGuestCredentialGate *failedFlowGate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:fixture.store];
    RBGateFakeBrowserDriver *browser2 = [[RBGateFakeBrowserDriver alloc] init];
    NSMutableArray<RBGateFakeExchangeClient *> *clients2 = [[NSMutableArray alloc] init];
    RBAuthFlowCoordinator *coordinator2 = [[RBAuthFlowCoordinator alloc]
        initWithBrowserDriver:browser2
        owningApplication:application
        applicationDidBecomeActiveNotificationName:TestForegroundNotificationName
        ownerLiveness:liveness
        exchangeFactory:^id<RBAuthFlowExchangeClient>(RBAuthExchangeRequest *request) {
            (void)request;
            RBGateFakeExchangeClient *client = [[RBGateFakeExchangeClient alloc] init];
            [clients2 addObject:client];
            return client;
        }
        scheduler:scheduler
        attemptClock:clock
        committer:failedFlowGate];
    CHECK([coordinator2 startWithEndpoint:endpoint foregroundOwner:owner statusHandler:nil] ==
              RBAuthFlowStatusBrowserPresented,
          "second coordinator presents browser");
    [browser2 completeWithAuthorizationCallbackFromURL:browser2.lastAuthorizationURL];
    CHECK([coordinator2 applicationDidBecomeActive:foreground] ==
              RBAuthFlowStatusExchangeInProgress,
          "second coordinator triggers exchange");
    [clients2[0] completeWithCode:nil error:RBAuthExchangeClientErrorHTTPStatus];
    PumpMainQueue(5);
    CHECK(coordinator2.status == RBAuthFlowStatusFailed, "second coordinator fails");
    CHECK(!failedFlowGate.isAuthorized && [failedFlowGate authorizedUniqueCodeUTF8] == NULL,
          "failed exchange leaves gate unauthorized");

    [fixture cleanup];
}

static void TestCommitRejectsMismatchedOriginAndInvalidCode(void) {
    RBGateTestStoreFixture *fixture = [[RBGateTestStoreFixture alloc] init];
    CHECK(fixture != nil, "commit rejection test fixture");
    if (fixture == nil) {
        return;
    }

    RBEndpoint *endpointA = MakeEndpoint(@"cherry.example.org", 443);
    RBEndpoint *endpointB = MakeEndpoint(@"other.example.org", 443);
    NSString *uuidA = @"123e4567-e89b-12d3-a456-426614174000";
    NSString *uuidB = @"999e4567-e89b-12d3-a456-426614174999";

    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpointA authStore:fixture.store];

    NSError *err = nil;
    CHECK(![gate commitUniqueCode:uuidA forEndpoint:endpointB error:&err],
          "commit rejects different endpoint origin");
    CHECK(err != nil && [err.domain isEqualToString:RBAuthGuestCredentialGateErrorDomain] &&
              err.code == RBAuthGuestCredentialGateErrorOriginMismatch,
          "different endpoint origin reports OriginMismatch");
    CHECK(![err.localizedDescription containsString:uuidA] &&
              ![err.localizedDescription containsString:@"cherry.example.org"] &&
              ![err.localizedDescription containsString:@"other.example.org"],
          "gate error never leaks uniqueCode or host");
    CHECK([fixture cookieExists] && ![fixture authJSONExists],
          "origin mismatch fails closed without touching authStore");
    CHECK(!gate.isAuthorized && [gate authorizedUniqueCodeUTF8] == NULL,
          "origin mismatch leaves gate unauthorized");

    RBEndpoint *nilEndpoint = nil;
    err = nil;
    CHECK(![gate commitUniqueCode:uuidA forEndpoint:nilEndpoint error:&err],
          "commit rejects nil endpoint");
    CHECK(err != nil && [err.domain isEqualToString:RBAuthGuestCredentialGateErrorDomain] &&
              err.code == RBAuthGuestCredentialGateErrorInvalidInput,
          "nil endpoint reports InvalidInput");
    CHECK([fixture cookieExists] && ![fixture authJSONExists],
          "nil endpoint fails closed without touching authStore");

    // Commit valid uuidA for endpointA, then verify failed commits preserve existing state.
    err = nil;
    CHECK([gate commitUniqueCode:uuidA forEndpoint:endpointA error:&err] && err == nil,
          "valid commit succeeds");
    CHECK(![fixture cookieExists] && [fixture authJSONExists],
          "valid commit removes avcookie.na and writes auth.json");
    CHECK([fixture writeCookie], "restore marker cookie before negative commit checks");

    err = nil;
    CHECK(![gate commitUniqueCode:uuidB forEndpoint:endpointB error:&err],
          "mismatched endpoint commit fails while already authorized");
    CHECK([fixture cookieExists],
          "mismatched endpoint commit does not touch store or cookie");
    CHECK(gate.isAuthorized && [gate authorizedUniqueCodeUTF8] != NULL &&
              strcmp([gate authorizedUniqueCodeUTF8], uuidA.UTF8String) == 0,
          "mismatched endpoint commit preserves active in-memory uuidA");

    err = nil;
    CHECK(![gate commitUniqueCode:@"123E4567-E89B-12D3-A456-426614174000"
                      forEndpoint:endpointA
                            error:&err],
          "commit rejects uppercase UUID");
    CHECK([fixture cookieExists], "invalid UUID commit does not touch store cookie");
    CHECK(gate.isAuthorized && [gate authorizedUniqueCodeUTF8] != NULL &&
              strcmp([gate authorizedUniqueCodeUTF8], uuidA.UTF8String) == 0,
          "invalid UUID commit preserves active in-memory uuidA");
    NSString *persisted = [fixture.store authorizedUniqueCodeForEndpoint:endpointA error:NULL];
    CHECK([persisted isEqualToString:uuidA], "store retains uuidA after rejected commits");

    [fixture cleanup];
}

static void TestInvalidateInMemoryAndClearStore(void) {
    RBGateTestStoreFixture *fixture = [[RBGateTestStoreFixture alloc] init];
    CHECK(fixture != nil, "invalidate test fixture");
    if (fixture == nil) {
        return;
    }

    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 443);
    NSString *uuidA = @"123e4567-e89b-12d3-a456-426614174000";
    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:fixture.store];

    NSError *err = nil;
    CHECK([gate commitUniqueCode:uuidA forEndpoint:endpoint error:&err] && err == nil,
          "commit uuidA before invalidation");
    CHECK(gate.isAuthorized && [fixture authJSONExists],
          "authorized in memory and persisted on disk");

    // Invalidate memory only: disk auth.json stays intact and reload restores it.
    CHECK([gate invalidateInMemoryAndClearStore:NO error:&err] && err == nil,
          "invalidateInMemoryAndClearStore:NO succeeds");
    CHECK(!gate.isAuthorized && [gate authorizedUniqueCodeUTF8] == NULL,
          "memory cleared immediately after invalidate(NO)");
    char buf[37];
    memset(buf, 'A', sizeof(buf));
    CHECK(![gate copyAuthorizedUniqueCodeUTF8:buf capacity:sizeof(buf)] && buf[0] == '\0',
          "copy fails and zeros buffer after invalidate(NO)");
    CHECK([fixture authJSONExists], "auth.json remains on disk after invalidate(NO)");

    CHECK([gate reloadFromStoreError:&err] && err == nil,
          "reloadFromStore restores authorization after invalidate(NO)");
    CHECK(gate.isAuthorized && [gate authorizedUniqueCodeUTF8] != NULL &&
              strcmp([gate authorizedUniqueCodeUTF8], uuidA.UTF8String) == 0,
          "reloaded UTF-8 matches uuidA");

    // Invalidate memory AND clear store: both memory and auth.json are cleared.
    CHECK([gate invalidateInMemoryAndClearStore:YES error:&err] && err == nil,
          "invalidateInMemoryAndClearStore:YES succeeds");
    CHECK(!gate.isAuthorized && [gate authorizedUniqueCodeUTF8] == NULL,
          "memory cleared after invalidate(YES)");
    CHECK(![fixture authJSONExists], "auth.json removed after invalidate(YES)");
    CHECK(![gate reloadFromStoreError:&err] && err != nil &&
              err.code == RBAuthStoreErrorNotFound,
          "reload fails with NotFound after invalidate(YES)");

    [fixture cleanup];
}

static void TestSlotRingRotationPreservesPriorPointers(void) {
    RBGateTestStoreFixture *fixture = [[RBGateTestStoreFixture alloc] init];
    CHECK(fixture != nil, "slot ring test fixture");
    if (fixture == nil) {
        return;
    }

    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 443);
    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:fixture.store];

    NSString *uuids[9] = {
        @"00000000-0000-4000-8000-000000000000",
        @"11111111-1111-4000-8000-111111111111",
        @"22222222-2222-4000-8000-222222222222",
        @"33333333-3333-4000-8000-333333333333",
        @"44444444-4444-4000-8000-444444444444",
        @"55555555-5555-4000-8000-555555555555",
        @"66666666-6666-4000-8000-666666666666",
        @"77777777-7777-4000-8000-777777777777",
        @"88888888-8888-4000-8000-888888888888",
    };
    const char *ptrs[9] = {0};

    for (size_t i = 0; i < 8; i++) {
        NSError *err = nil;
        CHECK([gate commitUniqueCode:uuids[i] forEndpoint:endpoint error:&err] && err == nil,
              "slot ring commit succeeds");
        ptrs[i] = [gate authorizedUniqueCodeUTF8];
        CHECK(ptrs[i] != NULL && strcmp(ptrs[i], uuids[i].UTF8String) == 0,
              "active slot pointer matches committed UUID");
        for (size_t j = 0; j < i; j++) {
            CHECK(ptrs[j] != ptrs[i], "adjacent ring slots have distinct addresses");
            CHECK(strcmp(ptrs[j], uuids[j].UTF8String) == 0,
                  "previously returned slot pointer remains intact across adjacent updates");
        }
    }

    // 9th commit wraps slot 0 while keeping slots 1..7 intact.
    NSError *wrapErr = nil;
    CHECK([gate commitUniqueCode:uuids[8] forEndpoint:endpoint error:&wrapErr] && wrapErr == nil,
          "9th commit wraps ring cleanly");
    ptrs[8] = [gate authorizedUniqueCodeUTF8];
    CHECK(ptrs[8] == ptrs[0], "9th commit reuses first slot after full 8-slot ring");
    CHECK(strcmp(ptrs[8], uuids[8].UTF8String) == 0, "wrapped slot holds 9th UUID");
    for (size_t j = 1; j < 8; j++) {
        CHECK(strcmp(ptrs[j], uuids[j].UTF8String) == 0,
              "slots 1..7 remain intact after wrap to slot 0");
    }

    [fixture cleanup];
}

static void TestConcurrentReadersAndWriters(void) {
    RBGateTestStoreFixture *fixture = [[RBGateTestStoreFixture alloc] init];
    CHECK(fixture != nil, "concurrency test fixture");
    if (fixture == nil) {
        return;
    }

    RBEndpoint *endpoint = MakeEndpoint(@"cherry.example.org", 443);
    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:fixture.store];
    NSString *uuidA = @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    NSString *uuidB = @"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    CHECK([gate commitUniqueCode:uuidA forEndpoint:endpoint error:NULL],
          "seed gate before concurrency test");

    dispatch_group_t group = dispatch_group_create();
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
    __block int badCopy = 0;

    for (int w = 0; w < 2; w++) {
        dispatch_group_async(group, queue, ^{
            for (int i = 0; i < 40; i++) {
                NSString *code = ((i + w) % 2 == 0) ? uuidA : uuidB;
                (void)[gate commitUniqueCode:code forEndpoint:endpoint error:NULL];
                if ((i % 7) == 0) {
                    (void)[gate invalidateInMemoryAndClearStore:NO error:NULL];
                    (void)[gate reloadFromStoreError:NULL];
                }
            }
        });
    }

    for (int r = 0; r < 4; r++) {
        dispatch_group_async(group, queue, ^{
            char buf[37];
            for (int i = 0; i < 400; i++) {
                (void)gate.isAuthorized;
                (void)[gate authorizedUniqueCodeUTF8];
                memset(buf, '?', sizeof(buf));
                if ([gate copyAuthorizedUniqueCodeUTF8:buf capacity:sizeof(buf)]) {
                    if (strcmp(buf, uuidA.UTF8String) != 0 &&
                        strcmp(buf, uuidB.UTF8String) != 0) {
                        __sync_fetch_and_add(&badCopy, 1);
                    }
                } else if (buf[0] != '\0') {
                    __sync_fetch_and_add(&badCopy, 1);
                }
            }
        });
    }

    long waitResult = dispatch_group_wait(
        group, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
    CHECK(waitResult == 0, "concurrent reader/writer stress finishes in time");
    CHECK(badCopy == 0, "concurrent copies never observe torn or malformed UUID");

    [fixture cleanup];
}

int main(void) {
    @autoreleasepool {
        TestInitializerAndInitialState();
        TestReloadFromStore();
        TestCoordinatorEndToEndWithGateCommitter();
        TestCommitRejectsMismatchedOriginAndInvalidCode();
        TestInvalidateInMemoryAndClearStore();
        TestSlotRingRotationPreservesPriorPointers();
        TestConcurrentReadersAndWriters();
    }
    if (failures != 0) {
        fprintf(stderr, "auth_guest_credential_gate_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("auth_guest_credential_gate_test: ok\n");
    return 0;
}
