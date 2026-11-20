#import "RBNoticeRouteClient.h"

#import "RBURLRewrite.h"

#import <dispatch/dispatch.h>

static const NSUInteger RBNoticeRouteURLLimit = 8u * 1024u;
static const NSUInteger RBNoticeRouteBodyLimit = 64u * 1024u;
static const NSUInteger RBNoticeRouteUserAgentLimit = 512u;
static const NSTimeInterval RBNoticeRouteDeadline = 15.0;
static NSString *const RBNoticeRoutePath = @"/v1/lineplay/ios";
static NSString *const RBNoticeRouteStockPrefix =
    @"https://lan3rd.line.me/v1/lineplay/ios";

static BOOL RBNoticeRouteHexDigit(unichar character) {
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f') ||
           (character >= 'A' && character <= 'F');
}

static BOOL RBNoticeRouteQueryCharacter(unichar character) {
    if ((character >= 'a' && character <= 'z') ||
        (character >= 'A' && character <= 'Z') ||
        (character >= '0' && character <= '9')) {
        return YES;
    }
    switch (character) {
        case '-': case '.': case '_': case '~':
        case '!': case '$': case '&': case '\'': case '(':
        case ')': case '*': case '+': case ',': case ';':
        case '=': case ':': case '@': case '/': case '?':
            return YES;
        default:
            return NO;
    }
}

static BOOL RBNoticeRouteValidEncodedQuery(NSString *query) {
    for (NSUInteger index = 0; index < query.length; index++) {
        unichar character = [query characterAtIndex:index];
        if (character == '%') {
            if (index + 2 >= query.length ||
                !RBNoticeRouteHexDigit([query characterAtIndex:index + 1]) ||
                !RBNoticeRouteHexDigit([query characterAtIndex:index + 2])) {
                return NO;
            }
            index += 2;
        } else if (!RBNoticeRouteQueryCharacter(character)) {
            return NO;
        }
    }
    return YES;
}

static BOOL RBNoticeRouteValidUserAgent(NSString *userAgent) {
    if (userAgent.length == 0 || userAgent.length > RBNoticeRouteUserAgentLimit) {
        return NO;
    }
    for (NSUInteger index = 0; index < userAgent.length; index++) {
        unichar character = [userAgent characterAtIndex:index];
        if (character < 0x20 || character > 0x7E) {
            return NO;
        }
    }
    return YES;
}

/// The raw-prefix check intentionally requires the canonical stock origin:
/// lowercase scheme/host, implicit HTTPS port, exact path, and only an optional
/// encoded query. No URLComponents-normalized alias is accepted.
static NSURL *RBNoticeRouteURL(NSString * _Nullable stockURLString,
                               RBEndpoint * _Nullable endpoint) {
    if (stockURLString == nil || endpoint == nil ||
        stockURLString.length == 0 ||
        stockURLString.length > RBNoticeRouteURLLimit ||
        [stockURLString rangeOfCharacterFromSet:
            [NSCharacterSet controlCharacterSet]].location != NSNotFound ||
        [stockURLString rangeOfString:@"#"].location != NSNotFound ||
        ![stockURLString hasPrefix:RBNoticeRouteStockPrefix]) {
        return nil;
    }

    NSString *tail = [stockURLString substringFromIndex:
        RBNoticeRouteStockPrefix.length];
    NSString *rawQuery = nil;
    if (tail.length != 0) {
        if (![tail hasPrefix:@"?"]) {
            return nil;
        }
        rawQuery = [tail substringFromIndex:1];
        if (!RBNoticeRouteValidEncodedQuery(rawQuery)) {
            return nil;
        }
    }

    NSURLComponents *stockComponents =
        [NSURLComponents componentsWithString:stockURLString];
    if (stockComponents == nil ||
        ![stockComponents.scheme isEqualToString:@"https"] ||
        ![stockComponents.host isEqualToString:@"lan3rd.line.me"] ||
        stockComponents.port != nil ||
        stockComponents.user != nil ||
        stockComponents.password != nil ||
        ![stockComponents.percentEncodedPath isEqualToString:RBNoticeRoutePath] ||
        stockComponents.fragment != nil ||
        ((rawQuery == nil && stockComponents.percentEncodedQuery != nil) ||
         (rawQuery != nil &&
          ![stockComponents.percentEncodedQuery isEqualToString:rawQuery])) ||
        stockComponents.URL == nil) {
        return nil;
    }

    BOOL didRewrite = NO;
    NSString *rewritten = [RBURLRewrite rewriteURLString:stockURLString
        endpoint:endpoint didRewrite:&didRewrite error:NULL];
    if (rewritten == nil || !didRewrite) {
        return nil;
    }

    NSString *expectedPrefix =
        [endpoint.httpsOrigin stringByAppendingString:RBNoticeRoutePath];
    if (![rewritten hasPrefix:expectedPrefix] ||
        rewritten.length != expectedPrefix.length + tail.length ||
        ![[rewritten substringFromIndex:expectedPrefix.length]
            isEqualToString:tail]) {
        return nil;
    }

    NSURLComponents *destinationComponents =
        [NSURLComponents componentsWithString:rewritten];
    uint16_t mappedPort =
        [endpoint mappedPortForOriginalClientPort:443];
    BOOL portMatches = mappedPort == 443
        ? destinationComponents.port == nil
        : destinationComponents.port.unsignedIntegerValue == mappedPort;
    if (destinationComponents == nil ||
        ![destinationComponents.scheme isEqualToString:@"https"] ||
        ![destinationComponents.host isEqualToString:endpoint.host] ||
        !portMatches ||
        destinationComponents.user != nil ||
        destinationComponents.password != nil ||
        ![destinationComponents.percentEncodedPath
            isEqualToString:RBNoticeRoutePath] ||
        destinationComponents.fragment != nil ||
        ((rawQuery == nil &&
          destinationComponents.percentEncodedQuery != nil) ||
         (rawQuery != nil &&
          ![destinationComponents.percentEncodedQuery
              isEqualToString:rawQuery])) ||
        destinationComponents.URL == nil) {
        return nil;
    }
    return destinationComponents.URL;
}

static void RBNoticeRouteDeliver(RBNoticeRouteCompletion completion,
                                 NSData * _Nullable responseBody,
                                 RBNoticeRouteResult result) {
    if (completion == nil) {
        return;
    }
    NSData *body = [responseBody copy];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(body, result);
    });
}

@class RBNoticeRouteSessionDelegate;

@interface RBNoticeRouteClient () {
    NSString *_stockURLString;
    RBEndpoint *_endpoint;
    NSString *_userAgent;
    NSTimeInterval _deadlineInterval;
#if defined(RB_NOTICE_ROUTE_TESTING)
    NSArray<Class> *_testingProtocolClasses;
    NSURLSessionConfiguration *_testingEffectiveConfiguration;
#endif
    NSURLSession *_session;
    RBNoticeRouteSessionDelegate *_sessionDelegate;
    NSOperationQueue *_delegateQueue;
    NSURLSessionDataTask *_task;
    RBNoticeRouteCompletion _completion;
    NSMutableData *_responseData;
    NSString *_expectedURLString;
    NSInteger _responseStatus;
    BOOL _started;
    BOOL _receivedResponse;
    BOOL _terminal;
}

- (void)noticeSession:(NSURLSession *)session
             dataTask:(NSURLSessionDataTask *)dataTask
   didReceiveResponse:(NSURLResponse *)response
    completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler;
- (void)noticeSession:(NSURLSession *)session
             dataTask:(NSURLSessionDataTask *)dataTask
       didReceiveData:(NSData *)data;
- (void)noticeSession:(NSURLSession *)session
                 task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
           newRequest:(NSURLRequest *)request
    completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler;
- (void)noticeSession:(NSURLSession *)session
                 task:(NSURLSessionTask *)task
 didCompleteWithError:(NSError * _Nullable)error;
- (void)finishWithBody:(NSData * _Nullable)body
                result:(RBNoticeRouteResult)result
            cancelTask:(BOOL)cancelTask;

@end

@interface RBNoticeRouteSessionDelegate : NSObject
    <NSURLSessionDataDelegate, NSURLSessionTaskDelegate> {
    __weak RBNoticeRouteClient *_owner;
}
- (instancetype)initWithOwner:(RBNoticeRouteClient *)owner;
@end

@implementation RBNoticeRouteSessionDelegate

- (instancetype)initWithOwner:(RBNoticeRouteClient *)owner {
    self = [super init];
    if (self != nil) {
        _owner = owner;
    }
    return self;
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    RBNoticeRouteClient *owner = _owner;
    if (owner != nil) {
        [owner noticeSession:session dataTask:dataTask
            didReceiveResponse:response completionHandler:completionHandler];
    } else {
        completionHandler(NSURLSessionResponseCancel);
    }
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data {
    RBNoticeRouteClient *owner = _owner;
    if (owner != nil) {
        [owner noticeSession:session dataTask:dataTask didReceiveData:data];
    } else {
        [dataTask cancel];
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    RBNoticeRouteClient *owner = _owner;
    if (owner != nil) {
        [owner noticeSession:session task:task
            willPerformHTTPRedirection:response newRequest:request
            completionHandler:completionHandler];
    } else {
        completionHandler(nil);
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
 didCompleteWithError:(NSError *)error {
    RBNoticeRouteClient *owner = _owner;
    if (owner != nil) {
        [owner noticeSession:session task:task didCompleteWithError:error];
    }
}

@end

@implementation RBNoticeRouteClient

- (instancetype)initWithStockURLString:(NSString *)URLString
                              endpoint:(RBEndpoint *)endpoint
                             userAgent:(NSString *)userAgent {
    self = [super init];
    if (self != nil) {
        _stockURLString = [URLString copy];
        _endpoint = [endpoint copy];
        _userAgent = [userAgent copy];
        _deadlineInterval = RBNoticeRouteDeadline;
    }
    return self;
}

- (instancetype)initWithStockURLString:(NSString *)URLString
                              endpoint:(RBEndpoint *)endpoint {
    return [self initWithStockURLString:URLString endpoint:endpoint userAgent:nil];
}

#if defined(RB_NOTICE_ROUTE_TESTING)
- (instancetype)initWithStockURLString:(NSString *)URLString
                              endpoint:(RBEndpoint *)endpoint
                       protocolClasses:(NSArray<Class> *)protocolClasses
                      deadlineInterval:(NSTimeInterval)deadlineInterval {
    return [self initWithStockURLString:URLString
                               endpoint:endpoint
                              userAgent:nil
                        protocolClasses:protocolClasses
                       deadlineInterval:deadlineInterval];
}

- (instancetype)initWithStockURLString:(NSString *)URLString
                              endpoint:(RBEndpoint *)endpoint
                             userAgent:(NSString *)userAgent
                       protocolClasses:(NSArray<Class> *)protocolClasses
                      deadlineInterval:(NSTimeInterval)deadlineInterval {
    self = [self initWithStockURLString:URLString
                               endpoint:endpoint
                              userAgent:userAgent];
    if (self != nil) {
        _testingProtocolClasses = [protocolClasses copy];
        if (deadlineInterval > 0.0 && deadlineInterval <= 60.0) {
            _deadlineInterval = deadlineInterval;
        } else {
            _deadlineInterval = 0.0;
        }
    }
    return self;
}

- (NSURLSessionConfiguration *)testEffectiveSessionConfiguration {
    @synchronized(self) {
        return [_testingEffectiveConfiguration copy];
    }
}

- (BOOL)testPerformBlockOnSessionCallbackQueue:(dispatch_block_t)block {
    if (block == nil) {
        return NO;
    }
    NSOperationQueue *queue = nil;
    @synchronized(self) {
        queue = _delegateQueue;
    }
    if (queue == nil) {
        return NO;
    }
    [queue addOperationWithBlock:block];
    return YES;
}
#endif

- (NSString *)description {
    return @"<RBNoticeRouteClient>";
}

- (void)dealloc {
    [_task cancel];
    [_session invalidateAndCancel];
}

- (BOOL)startWithCompletion:(RBNoticeRouteCompletion)completion {
    if (completion == nil) {
        return NO;
    }

    NSString *stockURLString = nil;
    RBEndpoint *endpoint = nil;
    NSString *userAgent = nil;
    NSTimeInterval deadlineInterval = 0.0;
#if defined(RB_NOTICE_ROUTE_TESTING)
    NSArray<Class> *testingProtocolClasses = nil;
#endif
    @synchronized(self) {
        if (_started || _terminal) {
            return NO;
        }
        _started = YES;
        _completion = [completion copy];
        stockURLString = _stockURLString;
        endpoint = _endpoint;
        userAgent = _userAgent;
        deadlineInterval = _deadlineInterval;
#if defined(RB_NOTICE_ROUTE_TESTING)
        testingProtocolClasses = _testingProtocolClasses;
#endif
    }

    NSURL *url = RBNoticeRouteURL(stockURLString, endpoint);
    BOOL userAgentValid = (userAgent == nil) || RBNoticeRouteValidUserAgent(userAgent);
    if (url == nil || !userAgentValid || deadlineInterval <= 0.0) {
        [self finishWithBody:nil result:RBNoticeRouteResultInvalidRequest
            cancelTask:NO];
        return YES;
    }

    NSMutableURLRequest *request =
        [NSMutableURLRequest requestWithURL:url
                                cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                            timeoutInterval:deadlineInterval];
    request.HTTPMethod = @"GET";
    request.HTTPBody = nil;
    request.HTTPBodyStream = nil;
    request.HTTPShouldHandleCookies = NO;
    if (userAgent != nil) {
        [request setValue:userAgent forHTTPHeaderField:@"User-Agent"];
    }

    NSURLSessionConfiguration *configuration =
        [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.HTTPCookieStorage = nil;
    configuration.URLCredentialStorage = nil;
    configuration.URLCache = nil;
    configuration.HTTPShouldSetCookies = NO;
    configuration.HTTPAdditionalHeaders = nil;
    configuration.requestCachePolicy =
        NSURLRequestReloadIgnoringLocalCacheData;
    configuration.timeoutIntervalForRequest = deadlineInterval;
    configuration.timeoutIntervalForResource = deadlineInterval;
#if defined(RB_NOTICE_ROUTE_TESTING)
    configuration.protocolClasses = testingProtocolClasses;
    @synchronized(self) {
        _testingEffectiveConfiguration = [configuration copy];
    }
#endif

    NSOperationQueue *delegateQueue = [[NSOperationQueue alloc] init];
    delegateQueue.maxConcurrentOperationCount = 1;
    delegateQueue.name = @"org.raspberry.ios-notice-route";
    RBNoticeRouteSessionDelegate *sessionDelegate =
        [[RBNoticeRouteSessionDelegate alloc] initWithOwner:self];
    NSURLSession *session =
        [NSURLSession sessionWithConfiguration:configuration
                                      delegate:sessionDelegate
                                 delegateQueue:delegateQueue];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request];
    if (session == nil || task == nil) {
        [session invalidateAndCancel];
        [self finishWithBody:nil result:RBNoticeRouteResultInvalidRequest
            cancelTask:NO];
        return YES;
    }

    BOOL installed = NO;
    @synchronized(self) {
        if (!_terminal) {
            _session = session;
            _sessionDelegate = sessionDelegate;
            _delegateQueue = delegateQueue;
            _task = task;
            _expectedURLString = [url.absoluteString copy];
            _responseData = [[NSMutableData alloc] init];
            _responseStatus = 0;
            _receivedResponse = NO;
            installed = YES;
        }
    }
    if (!installed) {
        [session invalidateAndCancel];
        return YES;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
        (int64_t)(deadlineInterval * (NSTimeInterval)NSEC_PER_SEC)),
        dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            [self finishWithBody:nil result:RBNoticeRouteResultTimedOut
                cancelTask:YES];
        });

    @synchronized(self) {
        if (!_terminal && _task == task) {
            [task resume];
        }
    }
    return YES;
}

- (void)cancel {
    [self finishWithBody:nil result:RBNoticeRouteResultCancelled
        cancelTask:YES];
}

- (BOOL)isExecutingOnSessionCallbackQueue {
    NSOperationQueue *currentQueue = [NSOperationQueue currentQueue];
    @synchronized(self) {
        return _delegateQueue != nil && currentQueue == _delegateQueue;
    }
}

- (void)finishWithBody:(NSData *)body
                result:(RBNoticeRouteResult)result
            cancelTask:(BOOL)cancelTask {
    RBNoticeRouteCompletion completion = nil;
    NSURLSession *session = nil;
    NSURLSessionDataTask *task = nil;
    @synchronized(self) {
        if (_terminal) {
            return;
        }
        _terminal = YES;
        completion = _completion;
        _completion = nil;
        session = _session;
        _session = nil;
        _sessionDelegate = nil;
        _delegateQueue = nil;
        task = _task;
        _task = nil;
        _responseData = nil;
        _expectedURLString = nil;
        _stockURLString = nil;
        _endpoint = nil;
        _userAgent = nil;
    }
    if (cancelTask) {
        [task cancel];
    }
    [session invalidateAndCancel];
    RBNoticeRouteDeliver(completion, body, result);
}

- (void)noticeSession:(NSURLSession *)session
             dataTask:(NSURLSessionDataTask *)dataTask
   didReceiveResponse:(NSURLResponse *)response
    completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    BOOL accepted = NO;
    BOOL finishNow = NO;
    RBNoticeRouteResult result = RBNoticeRouteResultInvalidResponse;
    @synchronized(self) {
        if (!_terminal && session == _session && dataTask == _task) {
            if (![response isKindOfClass:[NSHTTPURLResponse class]] ||
                ![response.URL.absoluteString
                    isEqualToString:_expectedURLString]) {
                finishNow = YES;
                result = RBNoticeRouteResultInvalidResponse;
            } else {
                NSInteger status = ((NSHTTPURLResponse *)response).statusCode;
                if (status == 404) {
                    finishNow = YES;
                    result = RBNoticeRouteResultNoNotice;
                } else if (status != 200) {
                    finishNow = YES;
                    result = RBNoticeRouteResultUnexpectedStatus;
                } else if (response.expectedContentLength >= 0 &&
                    (uint64_t)response.expectedContentLength >
                        (uint64_t)RBNoticeRouteBodyLimit) {
                    finishNow = YES;
                    result = RBNoticeRouteResultResponseTooLarge;
                } else {
                    _receivedResponse = YES;
                    _responseStatus = status;
                    _responseData = [[NSMutableData alloc] init];
                    accepted = YES;
                }
            }
        }
    }
    completionHandler(accepted ? NSURLSessionResponseAllow
                               : NSURLSessionResponseCancel);
    if (finishNow) {
        [self finishWithBody:nil result:result cancelTask:YES];
    }
}

- (void)noticeSession:(NSURLSession *)session
             dataTask:(NSURLSessionDataTask *)dataTask
       didReceiveData:(NSData *)data {
    BOOL invalid = NO;
    BOOL tooLarge = NO;
    @synchronized(self) {
        if (_terminal || session != _session || dataTask != _task) {
            return;
        }
        if (!_receivedResponse || _responseData == nil) {
            invalid = YES;
        } else if (_responseData.length > RBNoticeRouteBodyLimit ||
                   data.length >
                       RBNoticeRouteBodyLimit - _responseData.length) {
            tooLarge = YES;
        } else {
            [_responseData appendData:data];
        }
    }
    if (tooLarge) {
        [self finishWithBody:nil result:RBNoticeRouteResultResponseTooLarge
            cancelTask:YES];
    } else if (invalid) {
        [self finishWithBody:nil result:RBNoticeRouteResultInvalidResponse
            cancelTask:YES];
    }
}

- (void)noticeSession:(NSURLSession *)session
                 task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
           newRequest:(NSURLRequest *)request
    completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    (void)response;
    (void)request;
    BOOL isCurrent = NO;
    @synchronized(self) {
        isCurrent = !_terminal && session == _session && task == _task;
    }
    completionHandler(nil);
    if (isCurrent) {
        [self finishWithBody:nil
            result:RBNoticeRouteResultRedirectRefused cancelTask:YES];
    }
}

- (void)noticeSession:(NSURLSession *)session
                 task:(NSURLSessionTask *)task
 didCompleteWithError:(NSError *)error {
    NSData *body = nil;
    RBNoticeRouteResult result = RBNoticeRouteResultSuccess;
    @synchronized(self) {
        if (_terminal || session != _session || task != _task) {
            return;
        }
        if (error != nil) {
            result = [error.domain isEqualToString:NSURLErrorDomain] &&
                     error.code == NSURLErrorTimedOut
                ? RBNoticeRouteResultTimedOut
                : RBNoticeRouteResultTransportFailure;
        } else if (!_receivedResponse || _responseStatus != 200 ||
                   _responseData == nil) {
            result = RBNoticeRouteResultInvalidResponse;
        } else {
            body = [_responseData copy];
        }
    }
    [self finishWithBody:body result:result cancelTask:NO];
}

@end
