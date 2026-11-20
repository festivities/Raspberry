#import "RBAuthSignInSessionController.h"

#import "RBAuthStore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", label); \
        failures++; \
    } \
} while (0)

@interface RBFakeSignInAttemptBinding : NSObject <RBAuthSignInAttemptBinding>
@property(nonatomic, strong, nullable) id<RBAuthFlowCommitter> committer;
@property(nonatomic, strong, nullable) RBEndpoint *startedEndpoint;
@property(nonatomic, strong, nullable) id startedOwner;
@property(nonatomic, copy, nullable) RBAuthFlowStatusHandler statusHandler;
@property(nonatomic) RBAuthFlowStatus initialReturnStatus;
@property(nonatomic) NSUInteger startCalls;
@property(nonatomic) NSUInteger stopCalls;
@end

@implementation RBFakeSignInAttemptBinding

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _initialReturnStatus = RBAuthFlowStatusBrowserPresented;
    }
    return self;
}

- (RBAuthFlowStatus)startWithEndpoint:(RBEndpoint *)endpoint
                      foregroundOwner:(id)foregroundOwner
                        statusHandler:(RBAuthFlowStatusHandler)statusHandler {
    _startCalls += 1;
    _startedEndpoint = endpoint;
    _startedOwner = foregroundOwner;
    _statusHandler = [statusHandler copy];
    if (_statusHandler != nil) {
        _statusHandler(_initialReturnStatus);
    }
    return _initialReturnStatus;
}

- (BOOL)stop {
    _stopCalls += 1;
    return YES;
}

@end

static RBEndpoint *MakeTestEndpoint(NSString *host, int httpsPort) {
    NSString *json = [NSString stringWithFormat:
        @"{\"v\":1,\"host\":\"%@\",\"ports\":{\"443\":%d}}", host, httpsPort];
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error = nil;
    RBEndpoint *ep = [RBEndpoint endpointWithJSONData:data error:&error];
    CHECK(ep != nil && error == nil, "create test endpoint");
    return ep;
}

static NSString *MakeTempDir(void) {
    NSString *base = NSTemporaryDirectory();
    char tmpl[1024];
    snprintf(tmpl, sizeof(tmpl), "%sraspberry-signin-session-test.XXXXXX",
             base.fileSystemRepresentation);
    char *created = mkdtemp(tmpl);
    CHECK(created != NULL, "mkdtemp");
    if (created == NULL) {
        return nil;
    }
    chmod(created, 0700);
    char resolved[1024];
    if (realpath(created, resolved) != NULL) {
        return [NSString stringWithUTF8String:resolved];
    }
    return [NSString stringWithUTF8String:created];
}

static void TestUnauthorizedStartRetryAndCommitToAuthorized(void) {
    NSString *root = MakeTempDir();
    NSString *basePath = [root stringByAppendingPathComponent:@"support"];
    NSString *cachesPath = [root stringByAppendingPathComponent:@"caches"];
    mkdir(basePath.fileSystemRepresentation, 0700);
    mkdir(cachesPath.fileSystemRepresentation, 0700);

    NSString *cookiePath = [cachesPath stringByAppendingPathComponent:@"avcookie.na"];
    [@"old-cookie" writeToFile:cookiePath
                    atomically:YES
                      encoding:NSUTF8StringEncoding
                         error:NULL];

    RBEndpoint *endpoint = MakeTestEndpoint(@"cherry.example.org", 8443);
    RBAuthStore *store = [[RBAuthStore alloc]
        initWithBaseDirectoryURL:[NSURL fileURLWithPath:basePath isDirectory:YES]
              cachesDirectoryURL:[NSURL fileURLWithPath:cachesPath isDirectory:YES]];
    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:store];
    CHECK(gate != nil && !gate.isAuthorized, "gate starts unauthorized");

    __block NSMutableArray<RBFakeSignInAttemptBinding *> *bindings =
        [NSMutableArray array];
    RBAuthSignInSessionController *controller =
        [[RBAuthSignInSessionController alloc]
            initWithEndpoint:endpoint
              credentialGate:gate
              bindingFactory:^id<RBAuthSignInAttemptBinding>(id<RBAuthFlowCommitter> committer) {
                  RBFakeSignInAttemptBinding *b = [[RBFakeSignInAttemptBinding alloc] init];
                  b.committer = committer;
                  [bindings addObject:b];
                  return b;
              }];
    CHECK(controller != nil, "controller init succeeds");
    CHECK(controller.state == RBAuthSignInGateStateSignInRequired,
          "initial state is SignInRequired");
    CHECK(controller.requiresSignInOverlay, "requires overlay when unauthorized");
    CHECK(controller.canStartSignIn, "can start sign-in initially");

    NSObject *owner = [[NSObject alloc] init];
    __block RBAuthFlowStatus observedStatus = RBAuthFlowStatusIdle;
    RBAuthFlowStatus firstStart =
        [controller startSignInWithForegroundOwner:owner
                                     statusHandler:^(RBAuthFlowStatus status) {
                                         observedStatus = status;
                                     }];
    CHECK(firstStart == RBAuthFlowStatusBrowserPresented,
          "first start presents browser");
    CHECK(controller.state == RBAuthSignInGateStateAttemptInProgress,
          "state transitions to AttemptInProgress");
    CHECK(!controller.canStartSignIn,
          "cannot start duplicate attempt while in progress");
    CHECK([controller startSignInWithForegroundOwner:owner statusHandler:nil] ==
              RBAuthFlowStatusInvalidRequest,
          "duplicate start is refused");

    // Simulate user cancelling browser -> RetryRequired.
    RBFakeSignInAttemptBinding *firstBinding = bindings.firstObject;
    firstBinding.statusHandler(RBAuthFlowStatusCancelled);
    CHECK(observedStatus == RBAuthFlowStatusCancelled, "observed cancelled status");
    CHECK(controller.state == RBAuthSignInGateStateRetryRequired,
          "cancelled attempt transitions to RetryRequired");
    CHECK(controller.requiresSignInOverlay, "still requires overlay after cancel");
    CHECK(controller.canStartSignIn, "can start retry after cancel");

    // Second attempt succeeds and commits via committer.
    RBAuthFlowStatus secondStart =
        [controller startSignInWithForegroundOwner:owner
                                     statusHandler:^(RBAuthFlowStatus status) {
                                         observedStatus = status;
                                     }];
    CHECK(secondStart == RBAuthFlowStatusBrowserPresented,
          "second start presents browser");
    CHECK(bindings.count == 2, "second binding created");
    RBFakeSignInAttemptBinding *secondBinding = bindings[1];

    // Stale callback from first binding must be ignored.
    firstBinding.statusHandler(RBAuthFlowStatusFailed);
    CHECK(controller.state == RBAuthSignInGateStateAttemptInProgress,
          "stale callback from earlier binding is fenced");

    secondBinding.statusHandler(RBAuthFlowStatusExchangeInProgress);
    CHECK(controller.state == RBAuthSignInGateStateAttemptInProgress,
          "exchange in progress keeps attempt active");

    NSString *uuid = @"12345678-1234-4234-8234-123456789abc";
    NSError *commitErr = nil;
    BOOL committed = [secondBinding.committer commitUniqueCode:uuid
                                                   forEndpoint:endpoint
                                                         error:&commitErr];
    CHECK(committed && commitErr == nil, "committer persists UUID");
    secondBinding.statusHandler(RBAuthFlowStatusAuthorized);

    CHECK(observedStatus == RBAuthFlowStatusAuthorized,
          "observed Authorized status");
    CHECK(controller.state == RBAuthSignInGateStateAuthorized,
          "controller transitions to Authorized");
    CHECK(!controller.requiresSignInOverlay,
          "authorized controller does not require overlay");
    CHECK(!controller.canStartSignIn,
          "authorized controller does not start another sign-in");
    CHECK(gate.isAuthorized &&
              strcmp(gate.authorizedUniqueCodeUTF8, uuid.UTF8String) == 0,
          "credential gate supplies exact committed UUID");
    CHECK(![[NSFileManager defaultManager] fileExistsAtPath:cookiePath],
          "avcookie.na removed on fresh commit");

    // Invalidation (e.g. Delete Avatar / session loss) re-gates cleanly.
    CHECK([controller invalidateAuthorizationAndClearStore:YES],
          "invalidateAuthorizationAndClearStore succeeds");
    CHECK(controller.state == RBAuthSignInGateStateSignInRequired,
          "invalidated controller returns to SignInRequired");
    CHECK(controller.requiresSignInOverlay && controller.canStartSignIn,
          "invalidated controller requires overlay and allows sign-in");
    CHECK(!gate.isAuthorized && gate.authorizedUniqueCodeUTF8 == NULL,
          "gate is cleared after invalidation");

    [[NSFileManager defaultManager] removeItemAtPath:root error:NULL];
}

static void TestPreexistingStoreAuthorizationStartsAuthorized(void) {
    NSString *root = MakeTempDir();
    NSString *basePath = [root stringByAppendingPathComponent:@"support"];
    NSString *cachesPath = [root stringByAppendingPathComponent:@"caches"];
    mkdir(basePath.fileSystemRepresentation, 0700);
    mkdir(cachesPath.fileSystemRepresentation, 0700);

    RBEndpoint *endpoint = MakeTestEndpoint(@"cherry.example.org", 8443);
    RBAuthStore *store = [[RBAuthStore alloc]
        initWithBaseDirectoryURL:[NSURL fileURLWithPath:basePath isDirectory:YES]
              cachesDirectoryURL:[NSURL fileURLWithPath:cachesPath isDirectory:YES]];
    NSString *uuid = @"abcdef01-2345-4678-9abc-def012345678";
    CHECK([store commitUniqueCode:uuid forEndpoint:endpoint error:NULL],
          "pre-populate store");

    RBAuthGuestCredentialGate *gate =
        [[RBAuthGuestCredentialGate alloc] initWithEndpoint:endpoint authStore:store];
    __block NSUInteger factoryCalls = 0;
    RBAuthSignInSessionController *controller =
        [[RBAuthSignInSessionController alloc]
            initWithEndpoint:endpoint
              credentialGate:gate
              bindingFactory:^id<RBAuthSignInAttemptBinding>(id<RBAuthFlowCommitter> committer) {
                  (void)committer;
                  factoryCalls += 1;
                  return [[RBFakeSignInAttemptBinding alloc] init];
              }];
    CHECK(controller != nil, "controller init with pre-authorized store");
    CHECK(controller.state == RBAuthSignInGateStateAuthorized,
          "starts directly in Authorized state");
    CHECK(!controller.requiresSignInOverlay,
          "does not require sign-in overlay when pre-authorized");
    CHECK(!controller.canStartSignIn, "canStartSignIn is NO when pre-authorized");
    CHECK(factoryCalls == 0, "binding factory not invoked when pre-authorized");
    CHECK(gate.isAuthorized &&
              strcmp(gate.authorizedUniqueCodeUTF8, uuid.UTF8String) == 0,
          "gate loaded existing UUID from store");

    [[NSFileManager defaultManager] removeItemAtPath:root error:NULL];
}

int main(void) {
    @autoreleasepool {
        TestUnauthorizedStartRetryAndCommitToAuthorized();
        TestPreexistingStoreAuthorizationStartsAuthorized();
    }
    if (failures != 0) {
        fprintf(stderr, "auth_signin_session_controller_test: %d failure(s)\n",
                failures);
        return 1;
    }
    puts("auth_signin_session_controller_test: ok");
    return 0;
}
