#import "RBAuthExchangeClient.h"

#import "RBEndpoint.h"

#import <dispatch/dispatch.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

@interface RBAuthExchangeClient (RBAuthExchangeTestOnly)
- (instancetype)initWithExchangeRequest:(RBAuthExchangeRequest *)request
                   sessionConfiguration:(NSURLSessionConfiguration *)configuration;
- (nullable NSURLSessionConfiguration *)testEffectiveSessionConfiguration;
@end

static int failures = 0;

#define CHECK(condition, label)                                                                    \
    do {                                                                                            \
        if (!(condition)) {                                                                         \
            fprintf(stderr, "FAIL: %s\n", label);                                                   \
            failures++;                                                                             \
        }                                                                                           \
    } while (0)

static const NSTimeInterval RBTestWaitSeconds = 5.0;
static const NSTimeInterval RBTestNoCallbackWindowSeconds = 0.1;
static NSString *const RBTestUniqueCode = @"123e4567-e89b-12d3-a456-426614174000";
static const NSTimeInterval RBExpectedTimeout = 30.0;

static NSData *ReadTestBodyStream(NSInputStream *stream) {
    if (stream == nil) {
        return nil;
    }
    NSMutableData *data = [[NSMutableData alloc] init];
    uint8_t buffer[256];
    [stream open];
    while (YES) {
        NSInteger count = [stream read:buffer maxLength:sizeof buffer];
        if (count < 0) {
            [stream close];
            return nil;
        }
        if (count == 0) {
            break;
        }
        if ((NSUInteger)count > 4u * 1024u - data.length) {
            [stream close];
            return nil;
        }
        [data appendBytes:buffer length:(NSUInteger)count];
    }
    [stream close];
    return data;
}

@interface RBExchangeTestClock : NSObject <RBAuthAttemptClock>
- (instancetype)initWithTime:(NSTimeInterval)time;
@end

@implementation RBExchangeTestClock {
    NSTimeInterval _time;
}

- (instancetype)initWithTime:(NSTimeInterval)time {
    self = [super init];
    if (self != nil) {
        _time = time;
    }
    return self;
}

- (NSTimeInterval)monotonicTime {
    return _time;
}

@end

@class RBExchangeTestURLProtocol;
@class RBExchangeTestScenario;

@interface RBExchangeTestURLProtocol : NSURLProtocol {
    BOOL _stopped;
    BOOL _responded;
    RBExchangeTestScenario *_scenario;
}
+ (void)setScenario:(nullable RBExchangeTestScenario *)scenario;
+ (nullable RBExchangeTestScenario *)scenario;
- (void)sendConfiguredResponse;
@end

@interface RBExchangeTestScenario : NSObject {
    NSURLRequest *_recordedRequest;
    NSData *_recordedBody;
    NSUInteger _requestCount;
    RBExchangeTestURLProtocol *_activeProtocol;
}
@property(nonatomic) NSInteger statusCode;
@property(nonatomic, copy) NSArray<NSData *> *responseChunks;
@property(nonatomic) BOOL holdResponse;
@property(nonatomic) BOOL redirect;
@property(nonatomic, strong, nullable) NSError *transportError;
@property(nonatomic, strong) dispatch_semaphore_t requestStarted;
@property(nonatomic, strong) dispatch_semaphore_t protocolStopped;
- (void)recordRequest:(NSURLRequest *)request;
- (void)setActiveProtocol:(RBExchangeTestURLProtocol *)protocol;
- (void)releaseHeldResponse;
- (nullable NSURLRequest *)recordedRequest;
- (nullable NSData *)recordedBody;
- (NSUInteger)requestCount;
- (void)clearRecordedRequest;
@end

@implementation RBExchangeTestScenario

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _requestStarted = dispatch_semaphore_create(0);
        _protocolStopped = dispatch_semaphore_create(0);
        _responseChunks = @[];
    }
    return self;
}

- (void)recordRequest:(NSURLRequest *)request {
    NSData *body = request.HTTPBody ?: ReadTestBodyStream(request.HTTPBodyStream);
    @synchronized(self) {
        _requestCount++;
        _recordedRequest = [request copy];
        _recordedBody = [body copy];
    }
}

- (void)setActiveProtocol:(RBExchangeTestURLProtocol *)protocol {
    @synchronized(self) {
        _activeProtocol = protocol;
    }
}

- (void)releaseHeldResponse {
    RBExchangeTestURLProtocol *activeProtocol = nil;
    @synchronized(self) {
        activeProtocol = _activeProtocol;
    }
    [activeProtocol sendConfiguredResponse];
}

- (NSURLRequest *)recordedRequest {
    @synchronized(self) {
        return _recordedRequest;
    }
}

- (NSData *)recordedBody {
    @synchronized(self) {
        return _recordedBody;
    }
}

- (NSUInteger)requestCount {
    @synchronized(self) {
        return _requestCount;
    }
}

- (void)clearRecordedRequest {
    @synchronized(self) {
        _recordedRequest = nil;
        _recordedBody = nil;
        _activeProtocol = nil;
    }
}

@end

@interface RBExchangeTestOutcome : NSObject
@property(nonatomic, strong) dispatch_semaphore_t completed;
@property(nonatomic, copy, nullable) NSString *uniqueCode;
@property(nonatomic) RBAuthExchangeClientError error;
@property(nonatomic) NSUInteger callbackCount;
@property(nonatomic) BOOL callbackOnMainThread;
@property(nonatomic) BOOL reentrantStartRejected;
@property(nonatomic) BOOL reentrantCancelReturned;
- (void)recordCode:(nullable NSString *)code error:(RBAuthExchangeClientError)error;
@end

@implementation RBExchangeTestOutcome

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _completed = dispatch_semaphore_create(0);
    }
    return self;
}

- (void)recordCode:(NSString *)code error:(RBAuthExchangeClientError)error {
    @synchronized(self) {
        _callbackCount++;
        _uniqueCode = [code copy];
        _error = error;
        _callbackOnMainThread = NSThread.isMainThread;
    }
    dispatch_semaphore_signal(_completed);
}

@end

@implementation RBExchangeTestURLProtocol

static RBExchangeTestScenario *RBCurrentScenario;

+ (void)setScenario:(RBExchangeTestScenario *)scenario {
    @synchronized(self) {
        RBCurrentScenario = scenario;
    }
}

+ (RBExchangeTestScenario *)scenario {
    @synchronized(self) {
        return RBCurrentScenario;
    }
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    (void)request;
    // Intercept every request made by the injected test session. No test request
    // can fall through to a socket, regardless of its URL.
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (BOOL)isStopped {
    @synchronized(self) {
        return _stopped;
    }
}

- (void)startLoading {
    RBExchangeTestScenario *scenario = [RBExchangeTestURLProtocol scenario];
    if (scenario == nil) {
        NSError *failure = [NSError errorWithDomain:@"RBExchangeTestURLProtocol"
                                                code:1
                                            userInfo:nil];
        [self.client URLProtocol:self didFailWithError:failure];
        return;
    }
    @synchronized(self) {
        _scenario = scenario;
    }
    [scenario recordRequest:self.request];
    [scenario setActiveProtocol:self];
    dispatch_semaphore_signal(scenario.requestStarted);
    if (scenario.holdResponse) {
        return;
    }

    [self sendConfiguredResponse];
}

- (void)sendConfiguredResponse {
    RBExchangeTestScenario *scenario = nil;
    @synchronized(self) {
        if (_stopped || _responded) {
            return;
        }
        _responded = YES;
        scenario = _scenario;
    }
    if (scenario == nil) {
        return;
    }
    if (scenario.transportError != nil) {
        [self.client URLProtocol:self didFailWithError:scenario.transportError];
        return;
    }

    if (scenario.redirect) {
        NSHTTPURLResponse *redirectResponse =
            [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
                                        statusCode:302
                                       HTTPVersion:@"HTTP/1.1"
                                      headerFields:@{@"Location" : @"https://redirect.example.test/"}];
        NSURLRequest *redirectRequest =
            [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://redirect.example.test/"]];
        [self.client URLProtocol:self
       wasRedirectedToRequest:redirectRequest
              redirectResponse:redirectResponse];
        return;
    }

    NSHTTPURLResponse *response =
        [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
                                    statusCode:scenario.statusCode
                                   HTTPVersion:@"HTTP/1.1"
                                  headerFields:@{@"Content-Type" : @"application/json"}];
    [self.client URLProtocol:self
          didReceiveResponse:response
           cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    for (NSData *chunk in scenario.responseChunks) {
        if ([self isStopped]) {
            return;
        }
        [self.client URLProtocol:self didLoadData:chunk];
    }
    if (![self isStopped]) {
        [self.client URLProtocolDidFinishLoading:self];
    }
}

- (void)stopLoading {
    RBExchangeTestScenario *scenario = nil;
    @synchronized(self) {
        _stopped = YES;
        scenario = _scenario;
    }
    if (scenario != nil) {
        dispatch_semaphore_signal(scenario.protocolStopped);
    }
}

@end

static BOOL WaitForSignal(dispatch_semaphore_t signal, const char *label) {
    dispatch_time_t deadline =
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(RBTestWaitSeconds * NSEC_PER_SEC));
    long result = dispatch_semaphore_wait(signal, deadline);
    CHECK(result == 0, label);
    return result == 0;
}

static void ExpectNoSignal(dispatch_semaphore_t signal, const char *label) {
    dispatch_time_t deadline = dispatch_time(
        DISPATCH_TIME_NOW, (int64_t)(RBTestNoCallbackWindowSeconds * NSEC_PER_SEC));
    CHECK(dispatch_semaphore_wait(signal, deadline) != 0, label);
}

static NSData *UTF8(NSString *value) {
    return [value dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *JSONResponse(NSString *uniqueCode) {
    NSMutableDictionary *body = [@{@"aid" : @"0", @"new" : @YES, @"unused" : @"ignored"} mutableCopy];
    if (uniqueCode != nil) {
        body[@"uniqueCode"] = uniqueCode;
    }
    return [NSJSONSerialization dataWithJSONObject:body options:0 error:NULL];
}

static NSData *PaddedJSONResponse(NSString *uniqueCode, NSUInteger exactLength) {
    NSMutableData *body = [JSONResponse(uniqueCode) mutableCopy];
    if (body.length > exactLength) {
        return nil;
    }
    NSUInteger paddingLength = exactLength - body.length;
    if (paddingLength != 0) {
        NSMutableData *padding = [NSMutableData dataWithLength:paddingLength];
        memset(padding.mutableBytes, ' ', padding.length);
        [body appendData:padding];
    }
    return body;
}

static RBAuthAttempt *NewClaimedAttempt(RBAuthExchangeRequest **requestOut) {
    if (requestOut != NULL) {
        *requestOut = nil;
    }
    NSError *error = nil;
    NSData *endpointJSON =
        UTF8(@"{\"v\":1,\"host\":\"Example.Test\",\"ports\":{\"443\":8443}}");
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:endpointJSON error:&error];
    if (endpoint == nil) {
        fprintf(stderr, "exchange test endpoint setup failed with fixed error code %ld\n",
                (long)error.code);
        failures++;
        return nil;
    }
    RBExchangeTestClock *clock = [[RBExchangeTestClock alloc] initWithTime:1.0];
    RBAuthAttempt *attempt = [RBAuthAttempt attemptWithEndpoint:endpoint clock:clock error:&error];
    if (attempt == nil) {
        fprintf(stderr, "exchange test attempt setup failed with fixed error code %ld\n",
                (long)error.code);
        failures++;
        return nil;
    }
    NSURLComponents *components =
        [NSURLComponents componentsWithURL:attempt.authorizationURL resolvingAgainstBaseURL:NO];
    NSString *state = nil;
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"state"]) {
            state = item.value;
            break;
        }
    }
    NSString *ticket = [@"" stringByPaddingToLength:43 withString:@"A" startingAtIndex:0];
    NSURL *callback =
        [NSURL URLWithString:[NSString stringWithFormat:@"raspberry://auth?ticket=%@&state=%@",
                                                        ticket, state]];
    CHECK([attempt acceptCallbackURL:callback] == RBAuthCallbackTicketAccepted,
          "synthetic claimed ticket accepted");
    RBAuthExchangeRequest *request = [attempt claimExchangeWithOwnerForeground:YES];
    CHECK(request != nil, "synthetic exchange request claimed");
    if (requestOut != NULL) {
        *requestOut = request;
    }
    return attempt;
}

static RBAuthExchangeRequest *NewClaimedRequest(void) {
    RBAuthExchangeRequest *request = nil;
    (void)NewClaimedAttempt(&request);
    return request;
}

static RBExchangeTestScenario *NewScenario(NSInteger statusCode, NSArray<NSData *> *chunks) {
    RBExchangeTestScenario *scenario = [[RBExchangeTestScenario alloc] init];
    scenario.statusCode = statusCode;
    scenario.responseChunks = chunks;
    return scenario;
}

static RBAuthExchangeClient *NewUnstartedClient(RBAuthExchangeRequest *request,
                                                RBExchangeTestScenario *scenario) {
    NSURLSessionConfiguration *configuration =
        [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.protocolClasses = @[[RBExchangeTestURLProtocol class]];
    [RBExchangeTestURLProtocol setScenario:scenario];
    return [[RBAuthExchangeClient alloc] initWithExchangeRequest:request
                                           sessionConfiguration:configuration];
}

static RBAuthExchangeClient *NewClient(RBAuthExchangeRequest *request,
                                       RBExchangeTestScenario *scenario,
                                       RBExchangeTestOutcome *outcome) {
    RBAuthExchangeClient *client = NewUnstartedClient(request, scenario);
    BOOL started = [client startWithCompletion:^(NSString *uniqueCode,
                                                 RBAuthExchangeClientError error) {
        [outcome recordCode:uniqueCode error:error];
    }];
    CHECK(started, "exchange client start accepted");
    return client;
}

static void CheckOutcome(RBExchangeTestOutcome *outcome,
                         RBAuthExchangeClientError expectedError,
                         NSString *expectedCode,
                         const char *label) {
    @synchronized(outcome) {
        CHECK(outcome.callbackCount == 1, label);
        CHECK(outcome.error == expectedError, "fixed exchange result error");
        if (expectedCode != nil) {
            CHECK([outcome.uniqueCode isEqualToString:expectedCode], "validated uniqueCode returned");
        } else {
            CHECK(outcome.uniqueCode == nil, "failure returns no uniqueCode");
        }
        CHECK(!outcome.callbackOnMainThread, "completion delivered off main queue");
    }
}

static void ClearScenario(RBExchangeTestScenario *scenario) {
    [RBExchangeTestURLProtocol setScenario:nil];
    [scenario clearRecordedRequest];
}

static void TestSuccessfulPOSTAndCookieIsolation(void) {
    NSData *response = JSONResponse(RBTestUniqueCode);
    NSUInteger split = response.length / 2;
    NSArray<NSData *> *chunks = @[
        [response subdataWithRange:NSMakeRange(0, split)],
        [response subdataWithRange:NSMakeRange(split, response.length - split)],
    ];
    RBExchangeTestScenario *scenario = NewScenario(200, chunks);
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeRequest *exchangeRequest = NewClaimedRequest();
    RBAuthExchangeClient *client = NewClient(exchangeRequest, scenario, outcome);
    if (!WaitForSignal(scenario.requestStarted, "synthetic POST observed") ||
        !WaitForSignal(outcome.completed, "successful exchange completed")) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }
    CheckOutcome(outcome, RBAuthExchangeClientErrorNone, RBTestUniqueCode,
                 "success callback delivered exactly once");

    NSURLRequest *request = [scenario recordedRequest];
    CHECK([request.HTTPMethod isEqualToString:@"POST"], "exchange uses POST");
    CHECK([request.URL.scheme isEqualToString:@"https"], "exchange uses HTTPS");
    CHECK([request.URL.host isEqualToString:@"example.test"], "exchange preserves configured host");
    CHECK(request.URL.port.integerValue == 8443, "exchange preserves configured HTTPS port");
    CHECK([request.URL.path isEqualToString:@"/auth/v1/exchange"], "exchange uses exact path");
    CHECK([[request valueForHTTPHeaderField:@"Content-Type"] isEqualToString:@"application/json"],
          "exchange sends JSON content type");
    CHECK(!request.HTTPShouldHandleCookies, "request disables cookie handling");
    CHECK([request valueForHTTPHeaderField:@"Cookie"] == nil, "request carries no cookie header");

    NSError *jsonError = nil;
    NSData *requestBody = [scenario recordedBody];
    CHECK(requestBody != nil, "exchange request body is available");
    id parsedBody = requestBody != nil
                        ? [NSJSONSerialization JSONObjectWithData:requestBody options:0 error:&jsonError]
                        : nil;
    CHECK(jsonError == nil && [parsedBody isKindOfClass:[NSDictionary class]],
          "exchange body is valid JSON");
    NSDictionary *body = [parsedBody isKindOfClass:[NSDictionary class]] ? parsedBody : @{};
    CHECK(body.count == 2, "exchange body contains exactly two fields");
    CHECK([body[@"ticket"] isEqualToString:exchangeRequest.ticket], "exchange body ticket matches claim");
    CHECK([body[@"verifier"] isEqualToString:exchangeRequest.verifier],
          "exchange body verifier matches claim");
    CHECK(scenario.requestCount == 1, "exchange creates one request task");
    CHECK(![client startWithCompletion:^(NSString *code, RBAuthExchangeClientError error) {
        (void)code;
        (void)error;
    }], "completed client cannot start twice");
    [client cancel];
    ClearScenario(scenario);
}

static void RunResponseFailure(NSInteger statusCode,
                               NSArray<NSData *> *chunks,
                               RBAuthExchangeClientError expectedError,
                               const char *label) {
    RBExchangeTestScenario *scenario = NewScenario(statusCode, chunks);
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewClient(NewClaimedRequest(), scenario, outcome);
    if (!WaitForSignal(scenario.requestStarted, "synthetic response request observed") ||
        !WaitForSignal(outcome.completed, label)) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }
    CheckOutcome(outcome, expectedError, nil, label);
    [client cancel];
    ClearScenario(scenario);
}

static void TestStatusAndMalformedResponses(void) {
    RunResponseFailure(403, @[UTF8(@"{\"error\":\"banned\"}")],
                       RBAuthExchangeClientErrorHTTPStatus, "non-200 status rejected");
    RunResponseFailure(200, @[UTF8(@"{")],
                       RBAuthExchangeClientErrorInvalidResponse, "malformed JSON rejected");
    RunResponseFailure(200, @[UTF8(@"[]")],
                       RBAuthExchangeClientErrorInvalidResponse, "top-level JSON array rejected");
    RunResponseFailure(200, @[UTF8(@"null")],
                       RBAuthExchangeClientErrorInvalidResponse, "top-level JSON null rejected");
    RunResponseFailure(200, @[JSONResponse(@"NOT-A-UUID")],
                       RBAuthExchangeClientErrorInvalidResponse, "malformed UUID rejected");
    RunResponseFailure(200, @[JSONResponse(@"123E4567-E89B-12D3-A456-426614174000")],
                       RBAuthExchangeClientErrorInvalidResponse, "uppercase UUID rejected");
    RunResponseFailure(200, @[UTF8(@"{\"uniqueCode\":42}")],
                       RBAuthExchangeClientErrorInvalidResponse, "wrong uniqueCode type rejected");
    RunResponseFailure(200, @[UTF8(@"{\"uniqueCode\":null}")],
                       RBAuthExchangeClientErrorInvalidResponse, "null uniqueCode rejected");
    RunResponseFailure(200, @[UTF8(@"{}")],
                       RBAuthExchangeClientErrorInvalidResponse, "object without uniqueCode rejected");
    RunResponseFailure(200, @[],
                       RBAuthExchangeClientErrorInvalidResponse, "missing uniqueCode rejected");
}

static void TestResponseBodyLimit(void) {
    NSData *exactly4096 = PaddedJSONResponse(RBTestUniqueCode, 4096);
    CHECK(exactly4096.length == 4096, "valid JSON fixture is exactly 4096 bytes");
    NSUInteger split = 2048;
    RBExchangeTestScenario *acceptedScenario =
        NewScenario(200, @[[exactly4096 subdataWithRange:NSMakeRange(0, split)],
                           [exactly4096 subdataWithRange:NSMakeRange(split, exactly4096.length - split)]]);
    RBExchangeTestOutcome *acceptedOutcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *acceptedClient =
        NewClient(NewClaimedRequest(), acceptedScenario, acceptedOutcome);
    if (!WaitForSignal(acceptedScenario.requestStarted, "4096-byte response request observed") ||
        !WaitForSignal(acceptedOutcome.completed, "4096-byte response completed")) {
        [acceptedClient cancel];
        ClearScenario(acceptedScenario);
        return;
    }
    CheckOutcome(acceptedOutcome, RBAuthExchangeClientErrorNone, RBTestUniqueCode,
                 "valid 4096-byte response accepted");
    [acceptedClient cancel];
    ClearScenario(acceptedScenario);

    NSData *over4096 = PaddedJSONResponse(RBTestUniqueCode, 4097);
    CHECK(over4096.length == 4097, "valid JSON fixture is exactly 4097 bytes");
    RunResponseFailure(200, @[[over4096 subdataWithRange:NSMakeRange(0, 2048)],
                              [over4096 subdataWithRange:NSMakeRange(2048, over4096.length - 2048)]],
                       RBAuthExchangeClientErrorResponseTooLarge,
                       "4097-byte response rejected");
}

static void TestRedirectRefusal(void) {
    RBExchangeTestScenario *scenario = NewScenario(302, @[]);
    scenario.redirect = YES;
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewClient(NewClaimedRequest(), scenario, outcome);
    if (!WaitForSignal(scenario.requestStarted, "synthetic redirect request observed") ||
        !WaitForSignal(outcome.completed, "redirect refusal completed")) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }
    CheckOutcome(outcome, RBAuthExchangeClientErrorRedirectRefused, nil,
                 "redirect is refused");
    CHECK(scenario.requestCount == 1, "redirect target is never requested");
    [client cancel];
    ClearScenario(scenario);
}

static void TestCancellationRepeatedStartAndExactlyOnce(void) {
    RBExchangeTestScenario *scenario = NewScenario(200, @[JSONResponse(RBTestUniqueCode)]);
    scenario.holdResponse = YES;
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBExchangeTestOutcome *rejectedStartOutcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewClient(NewClaimedRequest(), scenario, outcome);
    if (!WaitForSignal(scenario.requestStarted, "held synthetic request observed")) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }
    BOOL secondStart = [client startWithCompletion:^(NSString *code, RBAuthExchangeClientError error) {
        [rejectedStartOutcome recordCode:code error:error];
    }];
    CHECK(!secondStart, "second start rejected");
    [client cancel];
    [client cancel];
    if (!WaitForSignal(outcome.completed, "cancel callback completed") ||
        !WaitForSignal(scenario.protocolStopped, "cancel stops protocol task")) {
        ClearScenario(scenario);
        return;
    }
    [client cancel];
    CheckOutcome(outcome, RBAuthExchangeClientErrorCancelled, nil,
                 "cancellation callback delivered exactly once");
    @synchronized(rejectedStartOutcome) {
        CHECK(rejectedStartOutcome.callbackCount == 0, "rejected start does not invoke its callback");
    }
    CHECK(scenario.requestCount == 1, "one-shot client creates no second task");
    ClearScenario(scenario);
}

static void TestCancelBeforeStart(void) {
    RBExchangeTestScenario *scenario = NewScenario(200, @[JSONResponse(RBTestUniqueCode)]);
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewUnstartedClient(NewClaimedRequest(), scenario);
    [client cancel];
    BOOL started = [client startWithCompletion:^(NSString *code, RBAuthExchangeClientError error) {
        [outcome recordCode:code error:error];
    }];
    CHECK(!started, "cancelled-before-start client rejects start");
    ExpectNoSignal(outcome.completed, "cancel-before-start invokes no completion");
    @synchronized(outcome) {
        CHECK(outcome.callbackCount == 0, "cancel-before-start callback count stays zero");
    }
    CHECK(scenario.requestCount == 0, "cancel-before-start creates no request task");
    ClearScenario(scenario);
}

static void TestEffectiveSessionConfiguration(void) {
    RBExchangeTestScenario *scenario = NewScenario(200, @[JSONResponse(RBTestUniqueCode)]);
    scenario.holdResponse = YES;
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewUnstartedClient(NewClaimedRequest(), scenario);
    BOOL started = [client startWithCompletion:^(NSString *code, RBAuthExchangeClientError error) {
        [outcome recordCode:code error:error];
    }];
    CHECK(started, "configuration test client starts");
    if (!WaitForSignal(scenario.requestStarted, "configuration request held")) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }

    NSURLSessionConfiguration *configuration = [client testEffectiveSessionConfiguration];
    CHECK(configuration != nil, "effective test session configuration is available");
    if (configuration != nil) {
        CHECK(configuration.HTTPCookieStorage == nil, "effective session has no cookie storage");
        CHECK(configuration.URLCredentialStorage == nil,
              "effective session has no credential storage");
        CHECK(configuration.URLCache == nil, "effective session has no URL cache");
        CHECK(!configuration.HTTPShouldSetCookies, "effective session disables cookie setting");
        CHECK(configuration.timeoutIntervalForRequest == RBExpectedTimeout,
              "effective request timeout is 30 seconds");
        CHECK(configuration.timeoutIntervalForResource == RBExpectedTimeout,
              "effective resource timeout is 30 seconds");
        CHECK(configuration.requestCachePolicy == NSURLRequestReloadIgnoringLocalCacheData,
              "effective session ignores local request cache");
    }

    [client cancel];
    if (!WaitForSignal(outcome.completed, "configuration-test cancellation callback") ||
        !WaitForSignal(scenario.protocolStopped, "configuration-test task stopped")) {
        ClearScenario(scenario);
        return;
    }
    CheckOutcome(outcome, RBAuthExchangeClientErrorCancelled, nil,
                 "configuration test ends with fixed cancellation");
    ClearScenario(scenario);
}

static void TestSyntheticTransportErrorRedaction(void) {
    RBExchangeTestScenario *scenario = NewScenario(200, @[]);
    scenario.transportError =
        [NSError errorWithDomain:@"RBExchangeSyntheticTransport"
                            code:-71
                        userInfo:@{
                            NSLocalizedDescriptionKey : @"synthetic ticket=not-a-real-ticket",
                            @"verifier" : @"synthetic-verifier-not-a-credential",
                            @"credential" : @"synthetic-secret-placeholder",
                        }];
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewClient(NewClaimedRequest(), scenario, outcome);
    if (!WaitForSignal(scenario.requestStarted, "synthetic transport error request observed") ||
        !WaitForSignal(outcome.completed, "synthetic transport error completed")) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }
    CheckOutcome(outcome, RBAuthExchangeClientErrorTransport, nil,
                 "transport NSError is reduced to fixed error and nil code");
    [client cancel];
    ClearScenario(scenario);
}

static void TestCompletionReentrancy(void) {
    RBExchangeTestScenario *scenario = NewScenario(200, @[JSONResponse(RBTestUniqueCode)]);
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewUnstartedClient(NewClaimedRequest(), scenario);
    BOOL started = [client startWithCompletion:^(NSString *code, RBAuthExchangeClientError error) {
        [client cancel];
        BOOL restartAccepted = [client startWithCompletion:^(NSString *nestedCode,
                                                            RBAuthExchangeClientError nestedError) {
            (void)nestedCode;
            (void)nestedError;
        }];
        @synchronized(outcome) {
            outcome.reentrantCancelReturned = YES;
            outcome.reentrantStartRejected = !restartAccepted;
        }
        [outcome recordCode:code error:error];
    }];
    CHECK(started, "reentrancy test client starts");
    if (!WaitForSignal(scenario.requestStarted, "reentrancy request observed") ||
        !WaitForSignal(outcome.completed, "reentrant completion returned")) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }
    CheckOutcome(outcome, RBAuthExchangeClientErrorNone, RBTestUniqueCode,
                 "reentrant callback receives success exactly once");
    @synchronized(outcome) {
        CHECK(outcome.reentrantCancelReturned, "completion safely reenters cancel");
        CHECK(outcome.reentrantStartRejected, "completion safely reenters and rejects start");
    }
    CHECK(scenario.requestCount == 1, "reentrant operations create no second request");
    ClearScenario(scenario);
}

static void TestLateSuccessCannotAuthorizeCancelledAttempt(void) {
    RBAuthExchangeRequest *request = nil;
    RBAuthAttempt *attempt = NewClaimedAttempt(&request);
    if (attempt == nil || request == nil) {
        return;
    }
    RBExchangeTestScenario *scenario = NewScenario(200, @[JSONResponse(RBTestUniqueCode)]);
    scenario.holdResponse = YES;
    RBExchangeTestOutcome *outcome = [[RBExchangeTestOutcome alloc] init];
    RBAuthExchangeClient *client = NewClient(request, scenario, outcome);
    if (!WaitForSignal(scenario.requestStarted, "late-success request held")) {
        [attempt cancel];
        [client cancel];
        ClearScenario(scenario);
        return;
    }

    [attempt cancel];
    [scenario releaseHeldResponse];
    if (!WaitForSignal(outcome.completed, "late synthetic success completed")) {
        [client cancel];
        ClearScenario(scenario);
        return;
    }
    CheckOutcome(outcome, RBAuthExchangeClientErrorNone, RBTestUniqueCode,
                 "transport may complete after owning attempt cancellation");
    CHECK(attempt.stage == RBAuthAttemptStageCancelled, "cancelled attempt remains terminal");
    __block NSUInteger writerCalls = 0;
    BOOL committed = [attempt commitWithWriter:^BOOL(RBAuthExchangeRequest *claimedRequest) {
        (void)claimedRequest;
        writerCalls++;
        return YES;
    }];
    CHECK(!committed, "late success cannot commit a cancelled attempt");
    CHECK(writerCalls == 0, "cancelled attempt never invokes credential writer");
    [client cancel];
    ClearScenario(scenario);
}

int main(void) {
    @autoreleasepool {
        TestSuccessfulPOSTAndCookieIsolation();
        TestStatusAndMalformedResponses();
        TestResponseBodyLimit();
        TestRedirectRefusal();
        TestCancellationRepeatedStartAndExactlyOnce();
        TestCancelBeforeStart();
        TestEffectiveSessionConfiguration();
        TestSyntheticTransportErrorRedaction();
        TestCompletionReentrancy();
        TestLateSuccessCannotAuthorizeCancelledAttempt();
    }
    if (failures != 0) {
        fprintf(stderr, "%d auth exchange test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("iOS auth exchange tests: ok");
    return EXIT_SUCCESS;
}
