#import "RBAuthAttempt.h"

#import "RBEndpoint.h"

#import <math.h>
#import <errno.h>
#import <pthread.h>
#import <signal.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <time.h>
#import <unistd.h>

static int failures = 0;

#define CHECK(condition, label)                                                                    \
    do {                                                                                            \
        if (!(condition)) {                                                                         \
            fprintf(stderr, "FAIL: %s\n", label);                                                   \
            failures++;                                                                             \
        }                                                                                           \
    } while (0)

@interface RBTestClock : NSObject <RBAuthAttemptClock> {
    NSTimeInterval _now;
}
- (instancetype)initWithTime:(NSTimeInterval)now;
- (void)setTime:(NSTimeInterval)now;
@end

@implementation RBTestClock

- (instancetype)initWithTime:(NSTimeInterval)now {
    self = [super init];
    if (self != nil) {
        _now = now;
    }
    return self;
}

- (NSTimeInterval)monotonicTime {
    @synchronized(self) {
        return _now;
    }
}

- (void)setTime:(NSTimeInterval)now {
    @synchronized(self) {
        _now = now;
    }
}

@end

static RBEndpoint *TestEndpoint(void) {
    NSError *error = nil;
    NSData *json = [@"{\"v\":1,\"host\":\"Example.Test\",\"ports\":{\"443\":8443}}"
                    dataUsingEncoding:NSUTF8StringEncoding];
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:json error:&error];
    if (endpoint == nil) {
        fprintf(stderr, "endpoint setup failed with fixed error code %ld\n", (long)error.code);
        failures++;
    }
    return endpoint;
}

static RBAuthAttempt *NewAttempt(RBTestClock *clock) {
    NSError *error = nil;
    RBAuthAttempt *attempt = [RBAuthAttempt attemptWithEndpoint:TestEndpoint() clock:clock error:&error];
    if (attempt == nil) {
        fprintf(stderr, "attempt setup failed with fixed error code %ld\n", (long)error.code);
        failures++;
    }
    return attempt;
}

static NSString *QueryValue(NSURL *url, NSString *key) {
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:key]) {
            return item.value;
        }
    }
    return nil;
}

static BOOL IsToken(NSString *value, NSUInteger length) {
    if (value.length != length) {
        return NO;
    }
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            return NO;
        }
    }
    return YES;
}

static NSString *CallbackString(NSString *field, NSString *value, NSString *state) {
    return [NSString stringWithFormat:@"raspberry://auth?%@=%@&state=%@", field, value, state];
}

static NSURL *Callback(NSString *field, NSString *value, NSString *state) {
    return [NSURL URLWithString:CallbackString(field, value, state)];
}

static void RBConcurrencyWatchdogExpired(int signalNumber) {
    static const char message[] = "FAIL: concurrency test watchdog expired (10 seconds)\n";
    (void)signalNumber;
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(EXIT_FAILURE);
}

static void RBArmConcurrencyWatchdog(void) {
    static BOOL installed = NO;
    if (!installed) {
        static const char message[] = "FAIL: cannot install concurrency watchdog\n";
        struct sigaction action = {0};
        action.sa_handler = RBConcurrencyWatchdogExpired;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGALRM, &action, NULL) != 0) {
            (void)write(STDERR_FILENO, message, sizeof(message) - 1);
            _exit(EXIT_FAILURE);
        }
        installed = YES;
    }
    alarm(10);
}

static void RBDisarmConcurrencyWatchdog(void) {
    alarm(0);
}

static BOOL RBWaitForFlag(pthread_cond_t *condition, pthread_mutex_t *mutex, BOOL *flag) {
    if (*flag) {
        return YES;
    }
    struct timespec deadline = {0};
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return NO;
    }
    deadline.tv_sec += 5;
    while (!*flag) {
        int error = pthread_cond_timedwait(condition, mutex, &deadline);
        if (error == ETIMEDOUT) {
            return NO;
        }
        if (error != 0) {
            return NO;
        }
    }
    return YES;
}

static void RBJoinThread(pthread_t thread, const char *failureLabel) {
    int error = pthread_join(thread, NULL);
    CHECK(error == 0, failureLabel);
    if (error != 0) {
        fflush(stderr);
        _exit(EXIT_FAILURE);
    }
}

static RBAuthAttempt *AttemptWithTicket(RBTestClock *clock, NSString **stateOut) {
    RBAuthAttempt *attempt = NewAttempt(clock);
    if (attempt == nil) {
        return nil;
    }
    NSString *state = QueryValue(attempt.authorizationURL, @"state");
    if (stateOut != NULL) {
        *stateOut = state;
    }
    NSURL *callback = Callback(@"ticket", [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0], state);
    CHECK([attempt acceptCallbackURL:callback] == RBAuthCallbackTicketAccepted, "ticket callback accepted");
    return attempt;
}

static void TestRFC7636AndAuthorizationURL(void) {
    NSError *error = nil;
    NSString *challenge = [RBAuthAttempt challengeForVerifier:@"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                                                        error:&error];
    CHECK(error == nil, "RFC challenge no error");
    CHECK([challenge isEqualToString:@"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"], "RFC7636 S256 vector");
    NSString *invalid = @"not-a-valid-verifier";
    NSString *bad = [RBAuthAttempt challengeForVerifier:invalid error:&error];
    CHECK(bad == nil && error.code == RBAuthAttemptErrorInvalidVerifier, "invalid verifier rejected");
    CHECK(![error.localizedDescription containsString:invalid], "verifier not echoed");

    RBTestClock *clock = [[RBTestClock alloc] initWithTime:42.0];
    RBAuthAttempt *attempt = NewAttempt(clock);
    if (attempt == nil) {
        return;
    }
    NSURL *url = attempt.authorizationURL;
    CHECK([url.host isEqualToString:@"example.test"], "authorization host canonical");
    CHECK([url.scheme isEqualToString:@"https"], "authorization HTTPS");
    CHECK([url.path isEqualToString:@"/auth/v1/discord/start"], "authorization path");
    CHECK([url.absoluteString containsString:@"return=raspberry%3A%2F%2Fauth"], "exact return percent encoded");
    NSString *state = QueryValue(url, @"state");
    NSString *challengeValue = QueryValue(url, @"challenge");
    CHECK(IsToken(state, 22), "generated 16-byte state shape");
    CHECK(IsToken(challengeValue, 43), "generated S256 challenge shape");
    CHECK(attempt.stage == RBAuthAttemptStageAwaitingCallback, "attempt initially active");
    CHECK(![attempt.description containsString:state], "attempt description omits state");

    NSString *ticket = [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0];
    CHECK([attempt acceptCallbackURL:Callback(@"ticket", ticket, state)] == RBAuthCallbackTicketAccepted,
          "generated callback accepted");
    RBAuthExchangeRequest *request = [attempt claimExchangeWithOwnerForeground:YES];
    CHECK(request != nil, "exchange explicitly claimed");
    if (request != nil) {
        CHECK(IsToken(request.verifier, 43), "generated 32-byte verifier shape");
        CHECK(IsToken(request.ticket, 43), "ticket shape");
        CHECK([request.httpsOrigin isEqualToString:@"https://example.test:8443"], "exchange origin");
        NSError *challengeError = nil;
        CHECK([[RBAuthAttempt challengeForVerifier:request.verifier error:&challengeError]
               isEqualToString:challengeValue], "generated verifier challenge matches authorization URL");
        CHECK(![request.description containsString:request.ticket], "request description omits ticket");
        CHECK(![request.description containsString:request.verifier], "request description omits verifier");
        CHECK(![request respondsToSelector:@selector(setTicket:)], "ticket property has no setter");
        CHECK(![request respondsToSelector:@selector(setVerifier:)], "verifier property has no setter");
        CHECK(![request respondsToSelector:@selector(setHttpsOrigin:)], "origin property has no setter");
        id copiedRequest = [request copy];
        CHECK(copiedRequest == request, "immutable request copy preserves identity");
    }
    [attempt cancel];
}

static void TestOptionalErrorPointers(void) {
    RBEndpoint *endpoint = TestEndpoint();
    if (endpoint == nil) {
        return;
    }
    NSString *validVerifier = @"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    NSString *invalidVerifier = @"not-a-valid-verifier";
    NSError *staleError =
        [NSError errorWithDomain:@"synthetic" code:99 userInfo:@{NSLocalizedDescriptionKey : @"stale"}];

    CHECK([RBAuthAttempt challengeForVerifier:validVerifier error:NULL] != nil,
          "valid challenge permits null error pointer");
    CHECK([RBAuthAttempt challengeForVerifier:invalidVerifier error:NULL] == nil,
          "invalid challenge permits null error pointer");

    NSError *error = staleError;
    CHECK([RBAuthAttempt challengeForVerifier:validVerifier error:&error] != nil && error == nil,
          "successful challenge clears stale error");
    error = staleError;
    CHECK([RBAuthAttempt challengeForVerifier:invalidVerifier error:&error] == nil &&
              error != nil && error != staleError && error.code == RBAuthAttemptErrorInvalidVerifier,
          "failed challenge replaces stale error");

    RBTestClock *clock = [[RBTestClock alloc] initWithTime:10.0];
    CHECK([RBAuthAttempt attemptWithEndpoint:endpoint clock:clock error:NULL] != nil,
          "valid attempt permits null error pointer");
    RBTestClock *invalidClock = [[RBTestClock alloc] initWithTime:INFINITY];
    CHECK([RBAuthAttempt attemptWithEndpoint:endpoint clock:invalidClock error:NULL] == nil,
          "failed attempt permits null error pointer");

    error = staleError;
    CHECK([RBAuthAttempt attemptWithEndpoint:endpoint clock:clock error:&error] != nil && error == nil,
          "successful attempt clears stale error");
    error = staleError;
    CHECK([RBAuthAttempt attemptWithEndpoint:endpoint clock:invalidClock error:&error] == nil &&
              error != nil && error != staleError && error.code == RBAuthAttemptErrorInvalidClock,
          "failed attempt replaces stale error");
}

static void TestStrictCallbackParsing(void) {
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:1.0];
    NSString *state = nil;
    RBAuthAttempt *attempt = NewAttempt(clock);
    if (attempt == nil) {
        return;
    }
    state = QueryValue(attempt.authorizationURL, @"state");
    CHECK(IsToken(state, 22), "callback state generated");
    if (!IsToken(state, 22)) {
        return;
    }
    NSString *ticket = [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0];
    NSString *replacement = [[state substringToIndex:1] isEqualToString:@"A"] ? @"B" : @"A";
    NSString *wrongState = [replacement stringByAppendingString:[state substringFromIndex:1]];
    CHECK(![wrongState isEqualToString:state], "wrong state differs from generated state");
    NSArray<NSString *> *invalidURLs = @[
        CallbackString(@"ticket", ticket, wrongState),
        [NSString stringWithFormat:@"raspberry://AUTH?ticket=%@&state=%@", ticket, state],
        [NSString stringWithFormat:@"raspberry://auth:443?ticket=%@&state=%@", ticket, state],
        [NSString stringWithFormat:@"raspberry://user@auth?ticket=%@&state=%@", ticket, state],
        [NSString stringWithFormat:@"raspberry://auth/path?ticket=%@&state=%@", ticket, state],
        [NSString stringWithFormat:@"raspberry://auth/?ticket=%@&state=%@", ticket, state],
        [NSString stringWithFormat:@"raspberry://auth?ticket=%@&state=%@#fragment", ticket, state],
        [NSString stringWithFormat:@"raspberry://auth?ticket=%@&state=%@#", ticket, state],
        @"raspberry://auth?",
        [NSString stringWithFormat:@"raspberry://auth?%%73tate=%@&ticket=%@", state, ticket],
        [NSString stringWithFormat:@"raspberry://auth?state=%%41%@&ticket=%@", [state substringFromIndex:1], ticket],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@&ticket=%@", state, ticket, ticket],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&state=%@&ticket=%@", state, state, ticket],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&error=denied&error=expired", state],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@&extra=x", state, ticket],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@&error=denied", state, ticket],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=", state],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@", state, [ticket substringFromIndex:1]],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@A", state, ticket],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@", state,
                  [@"" stringByPaddingToLength:513 withString:@"A" startingAtIndex:0]],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@", state,
                  [@"" stringByPaddingToLength:2049 withString:@"A" startingAtIndex:0]],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket", state],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&error=", state],
        [NSString stringWithFormat:@"raspberry://auth?ticket=%@&state=%@", @"bad=", state],
        [NSString stringWithFormat:@"raspberry://auth?state=%@&ticket=%@", state, [ticket stringByReplacingCharactersInRange:NSMakeRange(0, 1) withString:@"+"]],
        [NSString stringWithFormat:@"raspberry://auth?state=%@", state],
    ];
    for (NSString *raw in invalidURLs) {
        CHECK([attempt acceptCallbackURL:[NSURL URLWithString:raw]] == RBAuthCallbackRejected,
              "invalid callback rejected");
        CHECK(attempt.stage == RBAuthAttemptStageAwaitingCallback, "invalid callback does not consume attempt");
    }

    CHECK([attempt acceptCallbackURL:Callback(@"ticket", ticket, state)] == RBAuthCallbackTicketAccepted,
          "valid callback after invalid attempts");
    CHECK([attempt acceptCallbackURL:Callback(@"ticket", ticket, state)] == RBAuthCallbackRejected,
          "duplicate callback rejected");
    CHECK(attempt.stage == RBAuthAttemptStageTicketPending, "duplicate callback leaves pending ticket");
}

static void TestCrossAttemptCallbackRejected(void) {
    RBTestClock *clockA = [[RBTestClock alloc] initWithTime:2.0];
    RBAuthAttempt *attemptA = NewAttempt(clockA);
    if (attemptA == nil) {
        return;
    }
    NSString *stateA = QueryValue(attemptA.authorizationURL, @"state");
    CHECK(IsToken(stateA, 22), "first attempt state generated");
    if (!IsToken(stateA, 22)) {
        return;
    }
    RBAuthAttempt *attemptB = nil;
    NSString *stateB = nil;
    for (NSUInteger tries = 0; tries < 4; tries++) {
        RBTestClock *clockB = [[RBTestClock alloc] initWithTime:2.0];
        attemptB = NewAttempt(clockB);
        if (attemptB == nil) {
            return;
        }
        stateB = QueryValue(attemptB.authorizationURL, @"state");
        CHECK(IsToken(stateB, 22), "second attempt state generated");
        if (!IsToken(stateB, 22)) {
            return;
        }
        if (![stateA isEqualToString:stateB]) {
            break;
        }
    }
    CHECK(![stateA isEqualToString:stateB], "separate attempts have distinct random states");
    if ([stateA isEqualToString:stateB]) {
        return;
    }
    NSString *ticket = [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0];
    CHECK([attemptB acceptCallbackURL:Callback(@"ticket", ticket, stateA)] == RBAuthCallbackRejected,
          "callback state from another attempt rejected");
    CHECK(attemptB.stage == RBAuthAttemptStageAwaitingCallback,
          "cross-attempt callback does not consume target attempt");
}

static void TestServerErrorsAndReplay(void) {
    NSArray<NSString *> *allowed = @[@"denied", @"expired", @"banned", @"server"];
    for (NSString *serverError in allowed) {
        RBTestClock *clock = [[RBTestClock alloc] initWithTime:10.0];
        RBAuthAttempt *attempt = NewAttempt(clock);
        if (attempt == nil) {
            continue;
        }
        NSString *state = QueryValue(attempt.authorizationURL, @"state");
        NSURL *callback = Callback(@"error", serverError, state);
        CHECK([attempt acceptCallbackURL:callback] == RBAuthCallbackServerRejected, "allowed server error accepted as failure");
        CHECK(attempt.stage == RBAuthAttemptStageFailed, "server error fails attempt");
        CHECK([attempt claimExchangeWithOwnerForeground:YES] == nil, "error callback never authorizes");
        CHECK([attempt acceptCallbackURL:Callback(@"ticket", [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0], state)]
                  == RBAuthCallbackRejected,
              "callback cannot restore failed attempt");
    }

    RBTestClock *clock = [[RBTestClock alloc] initWithTime:10.0];
    RBAuthAttempt *attempt = NewAttempt(clock);
    NSString *state = QueryValue(attempt.authorizationURL, @"state");
    CHECK([attempt acceptCallbackURL:Callback(@"error", @"unknown", state)] == RBAuthCallbackRejected,
          "unknown server error rejected");
    CHECK(attempt.stage == RBAuthAttemptStageAwaitingCallback, "unknown error does not consume attempt");
}

static void TestForegroundClaimAndAtomicCommit(void) {
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:100.0];
    NSString *state = nil;
    RBAuthAttempt *attempt = AttemptWithTicket(clock, &state);
    if (attempt == nil) {
        return;
    }
    CHECK([attempt claimExchangeWithOwnerForeground:NO] == nil, "background owner cannot claim");
    CHECK(attempt.stage == RBAuthAttemptStageTicketPending, "background refusal preserves pending ticket");
    RBAuthExchangeRequest *request = [attempt claimExchangeWithOwnerForeground:YES];
    CHECK(request != nil, "foreground owner claims");
    CHECK([attempt claimExchangeWithOwnerForeground:YES] == nil, "claim is single-use");
    __block NSUInteger writes = 0;
    BOOL committed = [attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimed) {
        writes++;
        CHECK(claimed == request, "writer receives claimed request");
        CHECK([claimed.ticket isEqualToString:request.ticket], "writer ticket metadata");
        return YES;
    }];
    CHECK(committed && writes == 1, "atomic writer commits once");
    CHECK(attempt.stage == RBAuthAttemptStageAuthorized, "successful writer authorizes");
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimed) {
        (void)claimed;
        writes++;
        return YES;
    }], "second commit rejected");
    CHECK(writes == 1, "writer not re-entered after commit");
}

static void TestWriterFailureAndCancellation(void) {
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:0.0];
    NSString *state = nil;
    RBAuthAttempt *attempt = AttemptWithTicket(clock, &state);
    if (attempt == nil) {
        return;
    }
    [attempt cancel];
    __block NSUInteger writes = 0;
    CHECK([attempt claimExchangeWithOwnerForeground:YES] == nil, "cancel before claim");
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        writes++;
        return YES;
    }], "cancel before commit rejects");
    CHECK(writes == 0, "cancelled attempt does not write");
    CHECK([attempt acceptCallbackURL:Callback(@"ticket", [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0], state)]
              == RBAuthCallbackRejected,
          "cancelled attempt cannot be restored");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    RBAuthExchangeRequest *request = [attempt claimExchangeWithOwnerForeground:YES];
    CHECK(request != nil, "claim before cancel");
    [attempt cancel];
    writes = 0;
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimed) {
        (void)claimed;
        writes++;
        return YES;
    }], "cancelled in-flight request cannot commit");
    CHECK(writes == 0 && attempt.stage == RBAuthAttemptStageCancelled, "cancel blocks late writer");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before writer failures");
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimed) {
        (void)claimed;
        return NO;
    }], "false writer fails");
    CHECK(attempt.stage == RBAuthAttemptStageFailed, "false writer terminal");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before thrown writer");
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimed) {
        (void)claimed;
        @throw [NSException exceptionWithName:@"SyntheticFailure" reason:@"no-secret" userInfo:nil];
    }], "throwing writer fails");
    CHECK(attempt.stage == RBAuthAttemptStageFailed, "throwing writer terminal");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before expiry");
    clock.time = 120.0;
    writes = 0;
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimed) {
        (void)claimed;
        writes++;
        return YES;
    }], "expired claimed ticket cannot commit");
    CHECK(writes == 0 && attempt.stage == RBAuthAttemptStageExpired, "expired claim never invokes writer");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before explicit failure");
    [attempt failExchange];
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimed) {
        (void)claimed;
        writes++;
        return YES;
    }], "failed exchange cannot commit");
    CHECK(attempt.stage == RBAuthAttemptStageFailed, "explicit exchange failure terminal");
}

static void TestWriterReentrancyAndTerminalTransitions(void) {
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:0.0];
    RBAuthAttempt *attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before nested commit");
    __block NSUInteger outerCalls = 0;
    __block NSUInteger nestedCalls = 0;
    __block BOOL nestedCommitResult = YES;
    BOOL committed = [attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        outerCalls++;
        nestedCommitResult = [attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *nestedRequest) {
            (void)nestedRequest;
            nestedCalls++;
            return YES;
        }];
        return YES;
    }];
    CHECK(committed, "outer writer can commit after rejected nested commit");
    CHECK(!nestedCommitResult && nestedCalls == 0, "nested commit is refused before invoking writer");
    CHECK(outerCalls == 1 && attempt.stage == RBAuthAttemptStageAuthorized,
          "nested commit executes outer writer exactly once");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before writer cancellation");
    __block NSUInteger cancelCalls = 0;
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        cancelCalls++;
        [attempt cancel];
        return YES;
    }], "writer cancellation prevents outer commit");
    CHECK(cancelCalls == 1 && attempt.stage == RBAuthAttemptStageCancelled,
          "writer cancellation remains terminal without retry");
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        cancelCalls++;
        return YES;
    }], "cancelled writer cannot be retried");
    CHECK(cancelCalls == 1, "cancelled attempt never invokes another writer");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before writer failure");
    __block NSUInteger failCalls = 0;
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        failCalls++;
        [attempt failExchange];
        return YES;
    }], "writer failure transition prevents outer commit");
    CHECK(failCalls == 1 && attempt.stage == RBAuthAttemptStageFailed,
          "writer failure remains terminal without retry");
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        failCalls++;
        return YES;
    }], "failed writer cannot be retried");
    CHECK(failCalls == 1, "failed attempt never invokes another writer");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "claim before in-writer expiry");
    __block NSUInteger expiryCalls = 0;
    __block RBAuthAttemptStage observedStage = RBAuthAttemptStageExchangeClaimed;
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        expiryCalls++;
        clock.time = 120.0;
        observedStage = attempt.stage;
        return YES;
    }], "expiry observed by writer prevents outer commit");
    CHECK(expiryCalls == 1 && observedStage == RBAuthAttemptStageExpired &&
              attempt.stage == RBAuthAttemptStageExpired,
          "in-writer expiry remains terminal without resurrection or retry");
    CHECK(![attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
        (void)request;
        expiryCalls++;
        return YES;
    }], "expired writer cannot be retried");
    CHECK(expiryCalls == 1, "expired attempt never invokes another writer");
}

static void TestTicketAndAttemptDeadlines(void) {
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:0.0];
    NSString *state = nil;
    RBAuthAttempt *attempt = NewAttempt(clock);
    state = QueryValue(attempt.authorizationURL, @"state");
    clock.time = 10.0;
    CHECK([attempt acceptCallbackURL:Callback(@"ticket", [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0], state)]
              == RBAuthCallbackTicketAccepted,
          "ticket receipt starts TTL");
    clock.time = 129.999;
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "ticket valid before 120 seconds");

    clock = [[RBTestClock alloc] initWithTime:0.0];
    attempt = NewAttempt(clock);
    state = QueryValue(attempt.authorizationURL, @"state");
    clock.time = 10.0;
    CHECK([attempt acceptCallbackURL:Callback(@"ticket", [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0], state)]
              == RBAuthCallbackTicketAccepted,
          "second ticket receipt");
    clock.time = 130.0;
    CHECK([attempt claimExchangeWithOwnerForeground:YES] == nil, "ticket expires at 120 seconds");
    CHECK(attempt.stage == RBAuthAttemptStageExpired, "ticket expiry terminal");

    clock = [[RBTestClock alloc] initWithTime:100.0];
    attempt = NewAttempt(clock);
    state = QueryValue(attempt.authorizationURL, @"state");
    clock.time = 699.0;
    CHECK([attempt acceptCallbackURL:Callback(@"ticket", [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0], state)]
              == RBAuthCallbackTicketAccepted,
          "ticket near attempt deadline");
    clock.time = 700.0;
    CHECK([attempt claimExchangeWithOwnerForeground:YES] == nil, "attempt deadline caps ticket lifetime");
    CHECK(attempt.stage == RBAuthAttemptStageExpired, "attempt deadline terminal");

    clock = [[RBTestClock alloc] initWithTime:50.0];
    attempt = NewAttempt(clock);
    state = QueryValue(attempt.authorizationURL, @"state");
    clock.time = 650.0;
    CHECK([attempt acceptCallbackURL:Callback(@"ticket", [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0], state)]
              == RBAuthCallbackRejected,
          "callback at 10-minute deadline rejected");
    CHECK(attempt.stage == RBAuthAttemptStageExpired, "active attempt expires");
}

static void TestInvalidClock(void) {
    RBEndpoint *endpoint = TestEndpoint();
    NSError *error = nil;
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:INFINITY];
    RBAuthAttempt *attempt = [RBAuthAttempt attemptWithEndpoint:endpoint clock:clock error:&error];
    CHECK(attempt == nil && error.code == RBAuthAttemptErrorInvalidClock, "infinite initial clock rejected");
    CHECK([error.localizedDescription isEqualToString:@"auth attempt: invalid clock"], "fixed clock error");

    clock = [[RBTestClock alloc] initWithTime:20.0];
    attempt = NewAttempt(clock);
    clock.time = 19.0;
    CHECK(attempt.stage == RBAuthAttemptStageFailed, "backward clock fails attempt");

    clock = [[RBTestClock alloc] initWithTime:20.0];
    attempt = NewAttempt(clock);
    clock.time = NAN;
    CHECK(attempt.stage == RBAuthAttemptStageFailed, "nonfinite current clock fails attempt");
}

@interface RBClaimWorker : NSObject
@property(nonatomic, strong) RBAuthAttempt *attempt;
@property(nonatomic, strong) RBAuthExchangeRequest *request;
@end

@implementation RBClaimWorker
@end

static void *RBRunClaim(void *opaque) {
    @autoreleasepool {
        RBClaimWorker *worker = (__bridge RBClaimWorker *)opaque;
        worker.request = [worker.attempt claimExchangeWithOwnerForeground:YES];
    }
    return NULL;
}

static void TestConcurrentSingleClaim(void) {
    enum { workerCount = 16 };
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:0.0];
    RBAuthAttempt *attempt = AttemptWithTicket(clock, NULL);
    if (attempt == nil) {
        return;
    }
    NSMutableArray<RBClaimWorker *> *workers = [[NSMutableArray alloc] initWithCapacity:workerCount];
    pthread_t threads[workerCount];
    NSUInteger created = 0;
    RBArmConcurrencyWatchdog();
    for (NSUInteger i = 0; i < workerCount; i++) {
        RBClaimWorker *worker = [[RBClaimWorker alloc] init];
        worker.attempt = attempt;
        [workers addObject:worker];
        int err = pthread_create(&threads[i], NULL, RBRunClaim, (__bridge void *)worker);
        if (err != 0) {
            [workers removeLastObject];
            CHECK(NO, "claim thread created");
            break;
        }
        created++;
    }
    CHECK(created == workerCount, "all claim threads created");
    NSUInteger claims = 0;
    for (NSUInteger i = 0; i < created; i++) {
        RBJoinThread(threads[i], "claim thread joined");
        if (workers[i].request != nil) {
            claims++;
        }
    }
    CHECK(claims == 1, "exactly one concurrent claim");
    RBDisarmConcurrencyWatchdog();
}

typedef struct {
    RBAuthAttempt *__unsafe_unretained attempt;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    BOOL writerEntered;
    BOOL releaseWriter;
    BOOL cancelStarted;
    BOOL cancelFinished;
    BOOL writerWaitFailed;
    BOOL commitResult;
    NSUInteger writerCalls;
} RBBlockingContext;

static void *RBRunBlockingCommit(void *opaque) {
    @autoreleasepool {
        RBBlockingContext *context = opaque;
        context->commitResult = [context->attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *request) {
            (void)request;
            pthread_mutex_lock(&context->mutex);
            context->writerCalls++;
            context->writerEntered = YES;
            pthread_cond_broadcast(&context->condition);
            BOOL released = RBWaitForFlag(&context->condition, &context->mutex, &context->releaseWriter);
            if (!released) {
                context->writerWaitFailed = YES;
                pthread_cond_broadcast(&context->condition);
            }
            pthread_mutex_unlock(&context->mutex);
            return released;
        }];
    }
    return NULL;
}

static void *RBRunCancel(void *opaque) {
    RBBlockingContext *context = opaque;
    pthread_mutex_lock(&context->mutex);
    context->cancelStarted = YES;
    pthread_cond_broadcast(&context->condition);
    pthread_mutex_unlock(&context->mutex);
    [context->attempt cancel];
    pthread_mutex_lock(&context->mutex);
    context->cancelFinished = YES;
    pthread_cond_broadcast(&context->condition);
    pthread_mutex_unlock(&context->mutex);
    return NULL;
}

static void TestCommitSerializesCancellation(void) {
    RBTestClock *clock = [[RBTestClock alloc] initWithTime:0.0];
    RBAuthAttempt *attempt = AttemptWithTicket(clock, NULL);
    CHECK([attempt claimExchangeWithOwnerForeground:YES] != nil, "blocking commit claim");
    RBBlockingContext context = {0};
    context.attempt = attempt;
    RBArmConcurrencyWatchdog();
    int mutexError = pthread_mutex_init(&context.mutex, NULL);
    if (mutexError != 0) {
        CHECK(NO, "blocking test mutex initialized");
        RBDisarmConcurrencyWatchdog();
        return;
    }
    int conditionError = pthread_cond_init(&context.condition, NULL);
    if (conditionError != 0) {
        CHECK(NO, "blocking test condition initialized");
        pthread_mutex_destroy(&context.mutex);
        RBDisarmConcurrencyWatchdog();
        return;
    }

    pthread_t commitThread;
    pthread_t cancelThread;
    int commitCreateError = pthread_create(&commitThread, NULL, RBRunBlockingCommit, &context);
    if (commitCreateError != 0) {
        CHECK(NO, "commit thread created");
        pthread_cond_destroy(&context.condition);
        pthread_mutex_destroy(&context.mutex);
        RBDisarmConcurrencyWatchdog();
        return;
    }
    pthread_mutex_lock(&context.mutex);
    BOOL writerEntered = RBWaitForFlag(&context.condition, &context.mutex, &context.writerEntered);
    if (!writerEntered) {
        CHECK(NO, "writer entered within bounded wait");
        context.releaseWriter = YES;
        pthread_cond_broadcast(&context.condition);
        pthread_mutex_unlock(&context.mutex);
        RBJoinThread(commitThread, "commit thread joined after writer-entry timeout");
        CHECK(context.writerCalls == 0 || context.writerWaitFailed,
              "writer-entry timeout leaves no blocked writer");
        pthread_cond_destroy(&context.condition);
        pthread_mutex_destroy(&context.mutex);
        RBDisarmConcurrencyWatchdog();
        return;
    }
    pthread_mutex_unlock(&context.mutex);

    int cancelCreateError = pthread_create(&cancelThread, NULL, RBRunCancel, &context);
    BOOL cancelCreated = cancelCreateError == 0;
    if (!cancelCreated) {
        CHECK(NO, "cancel thread created");
    }
    pthread_mutex_lock(&context.mutex);
    if (cancelCreated && !RBWaitForFlag(&context.condition, &context.mutex, &context.cancelStarted)) {
        CHECK(NO, "cancel thread started within bounded wait");
    }
    context.releaseWriter = YES;
    pthread_cond_broadcast(&context.condition);
    pthread_mutex_unlock(&context.mutex);

    RBJoinThread(commitThread, "commit thread joined");
    if (cancelCreated) {
        RBJoinThread(cancelThread, "cancel thread joined");
    }
    CHECK(context.commitResult, "atomic commit wins while holding lock");
    CHECK(context.writerCalls == 1, "blocked writer invoked once");
    CHECK(!context.writerWaitFailed, "writer release received before timeout");
    CHECK(!cancelCreated || context.cancelFinished, "cancellation completes after writer");
    CHECK(attempt.stage == RBAuthAttemptStageAuthorized, "late cancel cannot undo committed state");
    pthread_cond_destroy(&context.condition);
    pthread_mutex_destroy(&context.mutex);
    RBDisarmConcurrencyWatchdog();
}

int main(void) {
    @autoreleasepool {
        TestRFC7636AndAuthorizationURL();
        TestOptionalErrorPointers();
        TestStrictCallbackParsing();
        TestCrossAttemptCallbackRejected();
        TestServerErrorsAndReplay();
        TestForegroundClaimAndAtomicCommit();
        TestWriterFailureAndCancellation();
        TestWriterReentrancyAndTerminalTransitions();
        TestTicketAndAttemptDeadlines();
        TestInvalidClock();
        TestConcurrentSingleClaim();
        TestCommitSerializesCancellation();
    }
    if (failures != 0) {
        fprintf(stderr, "%d auth attempt test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("iOS auth attempt tests: ok");
    return EXIT_SUCCESS;
}
