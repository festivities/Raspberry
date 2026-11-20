#import "RBNoticeRouteClient.h"
#import "RBNoticeRouteErrorAdapter.h"

#import <Foundation/Foundation.h>
#import <string.h>

static const NSTimeInterval RBTestWaitSeconds = 3.0;
static const NSTimeInterval RBTestNoDuplicateSeconds = 0.2;
static int gFailures;
static NSLock *gScenarioLock;

typedef NS_ENUM(NSInteger, RBFakeMode) {
    RBFakeModeResponse = 0,
    RBFakeModeTransport,
    RBFakeModeRedirect,
    RBFakeModeStall,
};

@interface RBFakeScenario : NSObject
@property(nonatomic) RBFakeMode mode;
@property(nonatomic) NSInteger statusCode;
@property(nonatomic, copy) NSData *body;
@property(nonatomic, copy) NSString *redirectURL;
@property(nonatomic) BOOL omitContentLength;
@property(nonatomic, strong) dispatch_semaphore_t started;
@property(nonatomic, strong) dispatch_semaphore_t stoppedSignal;
@property(nonatomic, copy) NSURLRequest *request;
@property(nonatomic) BOOL stopped;
@property(nonatomic) NSUInteger requestCount;
- (void)recordRequest:(NSURLRequest *)request;
- (void)markStopped;
- (BOOL)waitUntilStarted;
@end

@implementation RBFakeScenario {
    NSLock *_lock;
}

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _lock = [[NSLock alloc] init];
        _started = dispatch_semaphore_create(0);
        _stoppedSignal = dispatch_semaphore_create(0);
        _body = [NSData data];
        _redirectURL = @"https://redirect.example.test/elsewhere";
    }
    return self;
}

- (void)recordRequest:(NSURLRequest *)request {
    [_lock lock];
    _request = [request copy];
    _requestCount++;
    [_lock unlock];
    dispatch_semaphore_signal(_started);
}

- (void)markStopped {
    [_lock lock];
    _stopped = YES;
    [_lock unlock];
    dispatch_semaphore_signal(_stoppedSignal);
}

- (BOOL)waitUntilStarted {
    return dispatch_semaphore_wait(_started,
        dispatch_time(DISPATCH_TIME_NOW,
            (int64_t)(RBTestWaitSeconds * (NSTimeInterval)NSEC_PER_SEC))) == 0;
}

- (NSURLRequest *)request {
    [_lock lock];
    NSURLRequest *request = _request;
    [_lock unlock];
    return request;
}

- (BOOL)stopped {
    [_lock lock];
    BOOL stopped = _stopped;
    [_lock unlock];
    return stopped;
}

- (BOOL)waitUntilStopped {
    return dispatch_semaphore_wait(_stoppedSignal,
        dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) == 0;
}

- (NSUInteger)requestCount {
    [_lock lock];
    NSUInteger count = _requestCount;
    [_lock unlock];
    return count;
}

@end

@interface RBFakeErrorObject : NSObject
@property(nonatomic, readonly) RBNoticeRouteErrorKind kind;
- (instancetype)initWithKind:(RBNoticeRouteErrorKind)kind;
@end

@implementation RBFakeErrorObject

- (instancetype)initWithKind:(RBNoticeRouteErrorKind)kind {
    self = [super init];
    if (self != nil) {
        _kind = kind;
    }
    return self;
}

@end

@interface RBFakeErrorFactory : NSObject
@property(nonatomic, readonly) NSUInteger count;
@property(nonatomic, readonly) RBNoticeRouteErrorKind lastKind;
- (id)makeObjectForKind:(RBNoticeRouteErrorKind)kind;
@end

@implementation RBFakeErrorFactory {
    NSLock *_lock;
    NSUInteger _count;
    RBNoticeRouteErrorKind _lastKind;
}

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _lock = [[NSLock alloc] init];
    }
    return self;
}

- (NSUInteger)count {
    [_lock lock];
    NSUInteger count = _count;
    [_lock unlock];
    return count;
}

- (RBNoticeRouteErrorKind)lastKind {
    [_lock lock];
    RBNoticeRouteErrorKind kind = _lastKind;
    [_lock unlock];
    return kind;
}

- (id)makeObjectForKind:(RBNoticeRouteErrorKind)kind {
    [_lock lock];
    _count++;
    _lastKind = kind;
    [_lock unlock];
    return [[RBFakeErrorObject alloc] initWithKind:kind];
}

@end

@interface RBFakeAdapterResult : NSObject
@property(nonatomic, strong) dispatch_semaphore_t completed;
@property(nonatomic, strong) id object;
@property(nonatomic) RBNoticeRouteErrorKind kind;
- (void)recordObject:(id)object kind:(RBNoticeRouteErrorKind)kind;
@end

@implementation RBFakeAdapterResult

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _completed = dispatch_semaphore_create(0);
    }
    return self;
}

- (void)recordObject:(id)object kind:(RBNoticeRouteErrorKind)kind {
    _object = object;
    _kind = kind;
    dispatch_semaphore_signal(_completed);
}

@end

@interface RBFakeCompletion : NSObject
@property(nonatomic, strong) dispatch_semaphore_t completed;
@property(nonatomic, copy) NSData *body;
@property(nonatomic) RBNoticeRouteResult result;
@property(nonatomic) NSUInteger count;
- (void)recordBody:(NSData *)body result:(RBNoticeRouteResult)result;
- (BOOL)wait;
- (NSUInteger)completionCount;
@end

@implementation RBFakeCompletion {
    NSLock *_lock;
}

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _lock = [[NSLock alloc] init];
        _completed = dispatch_semaphore_create(0);
        _body = nil;
    }
    return self;
}

- (void)recordBody:(NSData *)body result:(RBNoticeRouteResult)result {
    [_lock lock];
    _count++;
    _body = [body copy];
    _result = result;
    [_lock unlock];
    dispatch_semaphore_signal(_completed);
}

- (BOOL)wait {
    return dispatch_semaphore_wait(_completed,
        dispatch_time(DISPATCH_TIME_NOW,
            (int64_t)(RBTestWaitSeconds * (NSTimeInterval)NSEC_PER_SEC))) == 0;
}

- (NSUInteger)completionCount {
    [_lock lock];
    NSUInteger count = _count;
    [_lock unlock];
    return count;
}

- (NSData *)body {
    [_lock lock];
    NSData *body = _body;
    [_lock unlock];
    return body;
}

- (RBNoticeRouteResult)result {
    [_lock lock];
    RBNoticeRouteResult result = _result;
    [_lock unlock];
    return result;
}

@end

static RBFakeScenario *gCurrentScenario;

static void RBCheck(BOOL condition, const char *name) {
    if (!condition) {
        fprintf(stderr, "notice_route_client_test: %s\n", name);
        gFailures++;
    }
}

@interface RBNoticeFakeURLProtocol : NSURLProtocol
@end

@implementation RBNoticeFakeURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    (void)request;
    // A catch-all fake ensures the test session cannot fall through to a
    // real-network protocol, even if a future regression changes the URL.
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    [gScenarioLock lock];
    RBFakeScenario *scenario = gCurrentScenario;
    [gScenarioLock unlock];
    if (scenario == nil) {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
            code:NSURLErrorCancelled userInfo:nil];
        [self.client URLProtocol:self didFailWithError:error];
        return;
    }
    [scenario recordRequest:self.request];

    if (scenario.mode == RBFakeModeStall) {
        return;
    }
    if (scenario.mode == RBFakeModeTransport) {
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
            code:NSURLErrorCannotConnectToHost userInfo:nil];
        [self.client URLProtocol:self didFailWithError:error];
        return;
    }
    if (scenario.mode == RBFakeModeRedirect) {
        NSDictionary *headers = @{@"Location" : scenario.redirectURL};
        NSHTTPURLResponse *response =
            [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
                statusCode:302 HTTPVersion:@"HTTP/1.1"
                headerFields:headers];
        NSURLRequest *redirectRequest =
            [NSURLRequest requestWithURL:
                [NSURL URLWithString:scenario.redirectURL]];
        [self.client URLProtocol:self
            wasRedirectedToRequest:redirectRequest
            redirectResponse:response];
        return;
    }

    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    if (scenario.body != nil && !scenario.omitContentLength) {
        headers[@"Content-Length"] =
            [NSString stringWithFormat:@"%lu",
                (unsigned long)scenario.body.length];
    }
    NSHTTPURLResponse *response =
        [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
            statusCode:scenario.statusCode HTTPVersion:@"HTTP/1.1"
            headerFields:headers];
    [self.client URLProtocol:self didReceiveResponse:response
        cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (scenario.statusCode == 200 && scenario.body.length != 0) {
        [self.client URLProtocol:self didLoadData:scenario.body];
    }
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {
    [gScenarioLock lock];
    RBFakeScenario *scenario = gCurrentScenario;
    [gScenarioLock unlock];
    [scenario markStopped];
}

@end

static RBEndpoint *RBTestEndpoint(void) {
    NSError *error = nil;
    NSData *data = [@"{\"v\":1,\"host\":\"notice.operator.example\","
        "\"ports\":{\"443\":8443}}"
        dataUsingEncoding:NSUTF8StringEncoding];
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:data error:&error];
    RBCheck(endpoint != nil && error == nil, "validated-endpoint-fixture");
    return endpoint;
}

static void RBSetScenario(RBFakeScenario *scenario) {
    [gScenarioLock lock];
    gCurrentScenario = scenario;
    [gScenarioLock unlock];
}

static RBFakeCompletion *RBStart(RBNoticeRouteClient *client) {
    RBFakeCompletion *completion = [[RBFakeCompletion alloc] init];
    BOOL started = [client startWithCompletion:
        ^(NSData *body, RBNoticeRouteResult result) {
            [completion recordBody:body result:result];
        }];
    RBCheck(started, "accepted-start");
    RBCheck([completion wait], "completion-arrives-before-deadline");
    return completion;
}

static RBFakeScenario *RBScenario(RBFakeMode mode, NSInteger statusCode,
                                  NSData *body) {
    RBFakeScenario *scenario = [[RBFakeScenario alloc] init];
    scenario.mode = mode;
    scenario.statusCode = statusCode;
    scenario.body = body;
    RBSetScenario(scenario);
    return scenario;
}

static RBNoticeRouteClient *RBClient(NSString *stockURL, RBEndpoint *endpoint,
                                     NSTimeInterval deadlineInterval) {
    return [[RBNoticeRouteClient alloc]
        initWithStockURLString:stockURL endpoint:endpoint
        protocolClasses:@[ [RBNoticeFakeURLProtocol class] ]
        deadlineInterval:deadlineInterval];
}

static RBNoticeRouteClient *RBClientWithUserAgent(NSString *stockURL,
                                                  RBEndpoint *endpoint,
                                                  NSString *userAgent,
                                                  NSTimeInterval deadlineInterval) {
    return [[RBNoticeRouteClient alloc]
        initWithStockURLString:stockURL endpoint:endpoint userAgent:userAgent
        protocolClasses:@[ [RBNoticeFakeURLProtocol class] ]
        deadlineInterval:deadlineInterval];
}

static RBNoticeRouteErrorAdapter *RBAdapter(
    RBNoticeRouteClient *client, RBFakeErrorFactory *factory,
    NSTimeInterval deadlineInterval) {
    return [[RBNoticeRouteErrorAdapter alloc]
        initWithOwnedClient:client
        fakeErrorFactory:^id(RBNoticeRouteErrorKind kind) {
            RBCheck(!NSThread.isMainThread,
                "fake-error-factory-runs-off-main");
            return [factory makeObjectForKind:kind];
        }
        deadlineInterval:deadlineInterval];
}

static RBFakeAdapterResult *RBRunAdapterOffMain(
    RBNoticeRouteErrorAdapter *adapter) {
    RBFakeAdapterResult *result = [[RBFakeAdapterResult alloc] init];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        RBNoticeRouteErrorKind kind = RBNoticeRouteErrorKindInvalidRequest;
        id object = [adapter performSynchronouslyWithErrorKind:&kind];
        [result recordObject:object kind:kind];
    });
    BOOL completed = dispatch_semaphore_wait(result.completed,
        dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0;
    RBCheck(completed, "sync-facade-returns-before-test-bound");
    return result;
}

static void RBCheckOneCompletion(RBFakeCompletion *completion,
                                 const char *name) {
    BOOL duplicate = dispatch_semaphore_wait(completion.completed,
        dispatch_time(DISPATCH_TIME_NOW,
            (int64_t)(RBTestNoDuplicateSeconds *
                (NSTimeInterval)NSEC_PER_SEC))) == 0;
    RBCheck(!duplicate && [completion completionCount] == 1, name);
}

static NSString *RBHeaderValueCaseInsensitive(NSURLRequest *request,
                                              NSString *headerName) {
    NSString *target = headerName.lowercaseString;
    for (NSString *name in request.allHTTPHeaderFields) {
        if ([name.lowercaseString isEqualToString:target]) {
            return request.allHTTPHeaderFields[name];
        }
    }
    return nil;
}

static void RBCheckRequestAndPolicy(RBNoticeRouteClient *client,
                                    RBFakeScenario *scenario) {
    NSURLRequest *request = scenario.request;
    RBCheck(request != nil, "fake-intercepted-request");
    RBCheck([request.URL.absoluteString isEqualToString:
        @"https://notice.operator.example:8443/v1/lineplay/ios"
         @"?notificationLocalRv=0&noticeTimestamp=17&noticeNewTerm=3"
         @"&lgNoticeCategoryAndTimestamp=4%2F6+%252F"],
        "exact-authority-rewrite-and-encoded-query-retention");
    RBCheck([request.HTTPMethod isEqualToString:@"GET"], "method-get");
    RBCheck(request.HTTPBody == nil && request.HTTPBodyStream == nil,
        "no-request-body");
    RBCheck(!request.HTTPShouldHandleCookies, "request-cookie-handling-off");
    for (NSString *name in request.allHTTPHeaderFields) {
        NSString *lower = name.lowercaseString;
        RBCheck(![lower isEqualToString:@"host"] &&
                ![lower isEqualToString:@"cookie"] &&
                ![lower isEqualToString:@"authorization"],
            "no-manual-host-cookie-or-auth-header");
    }

    NSURLSessionConfiguration *configuration =
        [client testEffectiveSessionConfiguration];
    RBCheck(configuration != nil, "test-policy-snapshot-present");
    RBCheck(configuration.HTTPCookieStorage == nil,
        "cookie-storage-disabled");
    RBCheck(configuration.URLCredentialStorage == nil,
        "credential-storage-disabled");
    RBCheck(configuration.URLCache == nil, "url-cache-disabled");
    RBCheck(!configuration.HTTPShouldSetCookies,
        "session-cookie-setting-disabled");
    RBCheck(configuration.HTTPAdditionalHeaders == nil,
        "no-default-header-injection");
    RBCheck(configuration.requestCachePolicy ==
        NSURLRequestReloadIgnoringLocalCacheData, "reload-without-cache");
    RBCheck(configuration.timeoutIntervalForRequest == 1.0 &&
            configuration.timeoutIntervalForResource == 1.0,
        "task-deadlines-configured");
    RBCheck(configuration.protocolClasses.count == 1 &&
        configuration.protocolClasses.firstObject ==
            [RBNoticeFakeURLProtocol class], "all-test-requests-intercepted");
}

static void RBCheckInvalidRoute(NSString *URLString, RBEndpoint *endpoint,
                                const char *name) {
    RBFakeScenario *scenario = RBScenario(RBFakeModeStall, 0, nil);
    RBNoticeRouteClient *client = RBClient(URLString, endpoint, 1.0);
    RBFakeCompletion *completion = RBStart(client);
    RBCheck(completion.result == RBNoticeRouteResultInvalidRequest, name);
    RBCheck(scenario.request == nil, "invalid-route-never-starts-session");
    RBCheckOneCompletion(completion, "invalid-route-completes-once");
}

static void RBCheckInvalidUserAgent(NSString *stockURL, RBEndpoint *endpoint,
                                    NSString *userAgent, const char *name) {
    RBFakeScenario *scenario = RBScenario(RBFakeModeStall, 0, nil);
    RBNoticeRouteClient *client =
        RBClientWithUserAgent(stockURL, endpoint, userAgent, 1.0);
    RBFakeCompletion *completion = RBStart(client);
    RBCheck(completion.result == RBNoticeRouteResultInvalidRequest, name);
    RBCheck(scenario.request == nil, "invalid-user-agent-never-starts-session");
    RBCheckOneCompletion(completion, "invalid-user-agent-completes-once");
}

static NSData *RBDataOfLength(NSUInteger length, uint8_t byte) {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    memset(data.mutableBytes, byte, length);
    return data;
}

int main(void) {
    @autoreleasepool {
        gScenarioLock = [[NSLock alloc] init];
        RBEndpoint *endpoint = RBTestEndpoint();
        NSString *stockURL =
            @"https://lan3rd.line.me/v1/lineplay/ios"
             @"?notificationLocalRv=0&noticeTimestamp=17&noticeNewTerm=3"
             @"&lgNoticeCategoryAndTimestamp=4%2F6+%252F";

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 200,
                [@"opaque synthetic notice bytes"
                    dataUsingEncoding:NSUTF8StringEncoding]);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result == RBNoticeRouteResultSuccess,
                "http-200-success");
            RBCheck([completion.body isEqualToData:scenario.body],
                "200-body-returned-opaque");
            RBCheckRequestAndPolicy(client, scenario);
            RBCheck(RBHeaderValueCaseInsensitive(scenario.request,
                @"User-Agent") == nil, "nil-user-agent-omits-header");
            RBCheckOneCompletion(completion, "success-completes-once");
            RBCheck(![client startWithCompletion:
                ^(NSData *body, RBNoticeRouteResult result) {
                    (void)body;
                    (void)result;
                    RBCheck(NO, "second-start-must-not-complete");
                }], "second-start-refused");
            RBCheck(scenario.requestCount == 1,
                "one-request-per-client");
        }

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 200,
                [@"ua-nil-explicit" dataUsingEncoding:NSUTF8StringEncoding]);
            RBNoticeRouteClient *client =
                RBClientWithUserAgent(stockURL, endpoint, nil, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result == RBNoticeRouteResultSuccess,
                "explicit-nil-user-agent-succeeds");
            RBCheck(RBHeaderValueCaseInsensitive(scenario.request,
                @"User-Agent") == nil,
                "explicit-nil-user-agent-omits-header");
            RBCheckOneCompletion(completion,
                "explicit-nil-user-agent-completes-once");
        }

        {
            NSMutableString *mutableUA =
                [NSMutableString stringWithString:@"SampleClient/10.1.0 (iOS 15.0)"];
            NSString *expectedUA = [mutableUA copy];
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 200,
                [@"ua-valid" dataUsingEncoding:NSUTF8StringEncoding]);
            RBNoticeRouteClient *client =
                RBClientWithUserAgent(stockURL, endpoint, mutableUA, 1.0);
            [mutableUA appendString:@" mutated"];
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result == RBNoticeRouteResultSuccess,
                "valid-user-agent-succeeds");
            RBCheckRequestAndPolicy(client, scenario);
            NSString *sentUA = RBHeaderValueCaseInsensitive(scenario.request,
                @"User-Agent");
            RBCheck([sentUA isEqualToString:expectedUA],
                "valid-user-agent-forwarded-and-copied");
            RBCheckOneCompletion(completion,
                "valid-user-agent-completes-once");
        }

        {
            NSString *maxUA =
                [@" ~" stringByPaddingToLength:512 withString:@"A"
                               startingAtIndex:0];
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 200,
                [@"ua-max" dataUsingEncoding:NSUTF8StringEncoding]);
            RBNoticeRouteClient *client =
                RBClientWithUserAgent(stockURL, endpoint, maxUA, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result == RBNoticeRouteResultSuccess,
                "max-length-user-agent-succeeds");
            NSString *sentUA = RBHeaderValueCaseInsensitive(scenario.request,
                @"User-Agent");
            RBCheck([sentUA isEqualToString:maxUA],
                "max-length-user-agent-forwarded");
            RBCheckOneCompletion(completion,
                "max-length-user-agent-completes-once");
        }

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 404,
                [@"ignored body" dataUsingEncoding:NSUTF8StringEncoding]);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result == RBNoticeRouteResultNoNotice &&
                    completion.body == nil, "404-fixed-no-notice-result");
            RBCheck(scenario.request != nil, "404-request-intercepted");
            RBCheckOneCompletion(completion, "404-completes-once");
        }

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 503,
                [NSData data]);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result == RBNoticeRouteResultUnexpectedStatus &&
                    completion.body == nil, "unexpected-status-is-distinct");
            RBCheck(scenario.request != nil,
                "unexpected-status-request-intercepted");
            RBCheckOneCompletion(completion, "unexpected-completes-once");
        }

        {
            RBFakeScenario *scenario =
                RBScenario(RBFakeModeTransport, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result ==
                RBNoticeRouteResultTransportFailure &&
                completion.body == nil, "transport-failure-is-distinct");
            RBCheck(scenario.request != nil, "transport-request-intercepted");
            RBCheckOneCompletion(completion, "transport-completes-once");
        }

        {
            RBFakeScenario *scenario =
                RBScenario(RBFakeModeRedirect, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result ==
                RBNoticeRouteResultRedirectRefused &&
                completion.body == nil, "redirect-refused");
            RBCheck(scenario.request != nil, "redirect-request-intercepted");
            RBCheckOneCompletion(completion, "redirect-completes-once");
        }

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 200,
                RBDataOfLength(64u * 1024u, 0x41));
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result == RBNoticeRouteResultSuccess &&
                    completion.body.length == 64u * 1024u,
                "body-limit-inclusive");
            RBCheckOneCompletion(completion, "bounded-body-completes-once");
            (void)scenario;
        }

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 200,
                RBDataOfLength(64u * 1024u + 1u, 0x42));
            scenario.omitContentLength = YES;
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion = RBStart(client);
            RBCheck(completion.result ==
                RBNoticeRouteResultResponseTooLarge &&
                completion.body == nil, "body-over-limit-rejected");
            RBCheck(scenario.request != nil, "oversize-request-intercepted");
            RBCheck(scenario.requestCount == 1,
                "oversize-stream-does-not-retry");
            RBCheckOneCompletion(completion, "oversize-completes-once");
        }

        {
            RBFakeScenario *scenario =
                RBScenario(RBFakeModeStall, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 0.1);
            RBFakeCompletion *completion =
                [[RBFakeCompletion alloc] init];
            BOOL started = [client startWithCompletion:
                ^(NSData *body, RBNoticeRouteResult result) {
                    [completion recordBody:body result:result];
                }];
            RBCheck(started && [scenario waitUntilStarted],
                "deadline-request-entered-fake");
            RBCheck([completion wait], "deadline-completes-boundedly");
            RBCheck(completion.result == RBNoticeRouteResultTimedOut &&
                    completion.body == nil, "deadline-result-distinct");
            RBCheckOneCompletion(completion, "deadline-completes-once");
        }

        {
            RBFakeScenario *scenario =
                RBScenario(RBFakeModeStall, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 1.0);
            RBFakeCompletion *completion =
                [[RBFakeCompletion alloc] init];
            BOOL started = [client startWithCompletion:
                ^(NSData *body, RBNoticeRouteResult result) {
                    [completion recordBody:body result:result];
                }];
            RBCheck(started && [scenario waitUntilStarted],
                "cancel-request-entered-fake");
            [client cancel];
            RBCheck([completion wait], "cancel-completes-boundedly");
            RBCheck(completion.result == RBNoticeRouteResultCancelled &&
                    completion.body == nil, "cancel-result-distinct");
            RBCheckOneCompletion(completion, "cancel-completes-once");
        }

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 404,
                [@"must not reach parser" dataUsingEncoding:NSUTF8StringEncoding]);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 2.0);
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 1.0);
            RBFakeAdapterResult *result = RBRunAdapterOffMain(adapter);
            RBCheck(result.kind == RBNoticeRouteErrorKindHTTP404 &&
                    [result.object isKindOfClass:
                        [RBFakeErrorObject class]] &&
                    ((RBFakeErrorObject *)result.object).kind ==
                        RBNoticeRouteErrorKindHTTP404,
                "404-maps-to-fixed-http-404-kind");
            RBCheck(factory.count == 1 &&
                    factory.lastKind == RBNoticeRouteErrorKindHTTP404,
                "404-factory-gets-only-fixed-kind");
            RBCheck(scenario.requestCount == 1,
                "404-adapter-uses-one-owned-task");

            RBFakeAdapterResult *second = RBRunAdapterOffMain(adapter);
            RBCheck(second.kind == RBNoticeRouteErrorKindAlreadyUsed &&
                    factory.count == 2,
                "adapter-is-one-shot");
            RBCheck(scenario.requestCount == 1,
                "second-call-does-not-start-another-task");
        }

        {
            (void)RBScenario(RBFakeModeRedirect, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 2.0);
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 1.0);
            RBFakeAdapterResult *result = RBRunAdapterOffMain(adapter);
            RBCheck(result.kind ==
                RBNoticeRouteErrorKindRedirectRefused,
                "redirect-error-kind-distinct");
        }

        {
            (void)RBScenario(RBFakeModeTransport, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 2.0);
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 1.0);
            RBFakeAdapterResult *result = RBRunAdapterOffMain(adapter);
            RBCheck(result.kind == RBNoticeRouteErrorKindTransport,
                "transport-error-kind-distinct");
        }

        {
            (void)RBScenario(RBFakeModeResponse, 503, [NSData data]);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 2.0);
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 1.0);
            RBFakeAdapterResult *result = RBRunAdapterOffMain(adapter);
            RBCheck(result.kind ==
                RBNoticeRouteErrorKindUnexpectedStatus,
                "unexpected-status-kind-distinct");
        }

        {
            RBFakeScenario *scenario = RBScenario(RBFakeModeResponse, 200,
                [@"synthetic-success-never-parsed"
                    dataUsingEncoding:NSUTF8StringEncoding]);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 2.0);
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 1.0);
            RBFakeAdapterResult *result = RBRunAdapterOffMain(adapter);
            RBCheck(result.kind ==
                RBNoticeRouteErrorKindFixtureSuccessRefused &&
                [result.object isKindOfClass:[RBFakeErrorObject class]] &&
                ((RBFakeErrorObject *)result.object).kind ==
                    RBNoticeRouteErrorKindFixtureSuccessRefused,
                "200-refused-without-parser-or-cache");
            RBCheck(scenario.requestCount == 1,
                "200-fixture-uses-one-owned-task");
        }

        {
            RBFakeScenario *scenario =
                RBScenario(RBFakeModeStall, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 3.0);
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 0.1);
            RBFakeAdapterResult *result = RBRunAdapterOffMain(adapter);
            RBCheck(result.kind == RBNoticeRouteErrorKindTimeout,
                "sync-deadline-is-distinct");
            RBCheck(scenario.requestCount == 1,
                "timeout-is-one-task");
            RBCheck([scenario waitUntilStopped],
                "sync-timeout-cancels-owned-task");
        }

        {
            RBFakeScenario *scenario =
                RBScenario(RBFakeModeStall, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 2.0);
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 1.0);
            RBNoticeRouteErrorKind mainKind =
                RBNoticeRouteErrorKindInvalidRequest;
            id mainObject =
                [adapter performSynchronouslyWithErrorKind:&mainKind];
            RBCheck(mainObject == nil &&
                    mainKind ==
                        RBNoticeRouteErrorKindWrongExecutionQueue,
                "main-thread-refused-without-wait");
            RBCheck(factory.count == 0 && scenario.request == nil,
                "main-thread-refusal-does-not-start-or-factory");
        }

        {
            RBFakeScenario *scenario =
                RBScenario(RBFakeModeStall, 0, nil);
            RBNoticeRouteClient *client = RBClient(stockURL, endpoint, 2.0);
            RBFakeCompletion *clientCompletion =
                [[RBFakeCompletion alloc] init];
            BOOL started = [client startWithCompletion:
                ^(NSData *body, RBNoticeRouteResult result) {
                    [clientCompletion recordBody:body result:result];
                }];
            RBCheck(started && [scenario waitUntilStarted],
                "session-callback-queue-fixture-started");
            RBFakeErrorFactory *factory = [[RBFakeErrorFactory alloc] init];
            RBNoticeRouteErrorAdapter *adapter =
                RBAdapter(client, factory, 1.0);
            dispatch_semaphore_t queueDone = dispatch_semaphore_create(0);
            __block id queueObject = nil;
            __block RBNoticeRouteErrorKind queueKind =
                RBNoticeRouteErrorKindInvalidRequest;
            BOOL queued = [client testPerformBlockOnSessionCallbackQueue:^{
                queueObject = [adapter
                    performSynchronouslyWithErrorKind:&queueKind];
                dispatch_semaphore_signal(queueDone);
            }];
            RBCheck(queued, "enqueue-callback-queue-check");
            BOOL checked = dispatch_semaphore_wait(queueDone,
                dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) == 0;
            RBCheck(checked && queueObject == nil &&
                    queueKind ==
                        RBNoticeRouteErrorKindWrongExecutionQueue,
                "session-callback-queue-refused-without-wait");
            RBCheck(factory.count == 0 && scenario.requestCount == 1,
                "callback-queue-refusal-does-not-start-second-task");
            [client cancel];
            RBCheck([clientCompletion wait] &&
                    clientCompletion.result ==
                        RBNoticeRouteResultCancelled,
                "callback-queue-fixture-cancelled");
            RBCheck([scenario waitUntilStopped],
                "callback-queue-fixture-stop-confirmed");
        }

        RBCheckInvalidRoute(
            @"http://lan3rd.line.me/v1/lineplay/ios?x=1",
            endpoint, "plain-http-rejected");
        RBCheckInvalidRoute(
            @"https://lan3rd.line.me:443/v1/lineplay/ios?x=1",
            endpoint, "explicit-stock-port-rejected");
        RBCheckInvalidRoute(
            @"https://lan3rd.line.me/v1/lineplay/android?x=1",
            endpoint, "android-route-rejected");
        RBCheckInvalidRoute(
            @"https://lan3rd.line.me/v1/lineplay/ios/extra?x=1",
            endpoint, "path-suffix-rejected");
        RBCheckInvalidRoute(
            @"https://lan3rd.line.me/v1/lineplay/ios#fragment",
            endpoint, "fragment-rejected");
        RBCheckInvalidRoute(
            @"https://lan3rd.line.me/v1/lineplay/ios?bad=%Q0",
            endpoint, "malformed-query-escape-rejected");
        RBCheckInvalidRoute(
            @"https://other.example.test/v1/lineplay/ios?x=1",
            endpoint, "unrelated-origin-rejected");
        RBCheckInvalidRoute(stockURL, nil, "missing-endpoint-rejected");

        RBCheckInvalidUserAgent(stockURL, endpoint, @"",
            "empty-user-agent-rejected");
        RBCheckInvalidUserAgent(stockURL, endpoint, @"Agent\rX-Injected: 1",
            "cr-user-agent-rejected");
        RBCheckInvalidUserAgent(stockURL, endpoint, @"Agent\nX-Injected: 1",
            "lf-user-agent-rejected");
        {
            const unichar nulChars[3] = { 'U', 0, 'A' };
            NSString *nulUA =
                [NSString stringWithCharacters:nulChars length:3];
            RBCheckInvalidUserAgent(stockURL, endpoint, nulUA,
                "nul-user-agent-rejected");
        }
        RBCheckInvalidUserAgent(stockURL, endpoint, @"Agent\t1",
            "tab-user-agent-rejected");
        {
            const unichar delChars[3] = { 'U', 0x7F, 'A' };
            NSString *delUA =
                [NSString stringWithCharacters:delChars length:3];
            RBCheckInvalidUserAgent(stockURL, endpoint, delUA,
                "del-user-agent-rejected");
        }
        RBCheckInvalidUserAgent(stockURL, endpoint, @"Agent/\u00E9",
            "non-ascii-user-agent-rejected");
        RBCheckInvalidUserAgent(stockURL, endpoint,
            [@"A" stringByPaddingToLength:513 withString:@"B" startingAtIndex:0],
            "oversized-user-agent-rejected");

        if (gFailures != 0) {
            fprintf(stderr, "notice_route_client_test: %d failure(s)\n",
                gFailures);
            return 1;
        }
        puts("notice_route_client_test: all synthetic cases passed");
    }
    return 0;
}
