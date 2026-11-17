#import "RBAuthExchangeClient.h"

#import <dispatch/dispatch.h>

static const NSTimeInterval RBAuthExchangeTimeout = 30.0;
static const NSUInteger RBAuthExchangeResponseLimit = 4u * 1024u;
static NSString *const RBAuthExchangePath = @"/auth/v1/exchange";

static BOOL RBExchangeToken(NSString *value, NSUInteger minimumLength, NSUInteger maximumLength) {
    if (value == nil || value.length < minimumLength || value.length > maximumLength) {
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

static BOOL RBExchangeUUIDShape(NSString *value) {
    if (value.length != 36) {
        return NO;
    }
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') {
                return NO;
            }
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return NO;
        }
    }
    return YES;
}

static NSURL *RBExchangeURL(NSString *origin) {
    NSURLComponents *components = [NSURLComponents componentsWithString:origin];
    if (components == nil || ![components.scheme isEqualToString:@"https"] ||
        components.host.length == 0 || components.user != nil || components.password != nil ||
        components.path.length != 0 || components.query != nil || components.fragment != nil ||
        ![components.string isEqualToString:origin]) {
        return nil;
    }
    components.path = RBAuthExchangePath;
    NSURL *url = components.URL;
    if (url == nil || ![url.scheme isEqualToString:@"https"] ||
        ![url.path isEqualToString:RBAuthExchangePath] || url.query != nil || url.fragment != nil) {
        return nil;
    }
    return url;
}

static void RBDeliverExchangeCompletion(RBAuthExchangeCompletion completion,
                                        NSString *uniqueCode,
                                        RBAuthExchangeClientError error) {
    if (completion == nil) {
        return;
    }
    NSString *code = [uniqueCode copy];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(code, error);
    });
}

@class RBAuthExchangeSessionDelegate;

@interface RBAuthExchangeClient () {
    RBAuthExchangeRequest *_exchangeRequest;
    NSURLSessionConfiguration *_injectedConfiguration;
    NSURLSession *_session;
    RBAuthExchangeSessionDelegate *_sessionDelegate;
    NSURLSessionDataTask *_task;
    RBAuthExchangeCompletion _completion;
    NSMutableData *_responseData;
    RBAuthExchangeClientError _pendingError;
    NSInteger _responseStatus;
    BOOL _started;
    BOOL _receivedResponse;
    BOOL _terminal;
}

#if defined(RB_AUTH_EXCHANGE_TESTING)
- (instancetype)initWithExchangeRequest:(RBAuthExchangeRequest *)request
                   sessionConfiguration:(NSURLSessionConfiguration *)configuration;
- (nullable NSURLSessionConfiguration *)testEffectiveSessionConfiguration;
#endif

- (void)exchangeSession:(NSURLSession *)session
               dataTask:(NSURLSessionDataTask *)dataTask
     didReceiveResponse:(NSURLResponse *)response
      completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler;
- (void)exchangeSession:(NSURLSession *)session
               dataTask:(NSURLSessionDataTask *)dataTask
         didReceiveData:(NSData *)data;
- (void)exchangeSession:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
             newRequest:(NSURLRequest *)request
      completionHandler:(void (^)(NSURLRequest *_Nullable))completionHandler;
- (void)exchangeSession:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
     didCompleteWithError:(NSError *)error;

@end

@interface RBAuthExchangeSessionDelegate : NSObject <NSURLSessionDataDelegate, NSURLSessionTaskDelegate> {
    __weak RBAuthExchangeClient *_owner;
}
- (instancetype)initWithOwner:(RBAuthExchangeClient *)owner;
@end

@implementation RBAuthExchangeSessionDelegate

- (instancetype)initWithOwner:(RBAuthExchangeClient *)owner {
    self = [super init];
    if (self != nil) {
        _owner = owner;
    }
    return self;
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler {
    RBAuthExchangeClient *owner = _owner;
    if (owner != nil) {
        [owner exchangeSession:session
                      dataTask:dataTask
            didReceiveResponse:response
             completionHandler:completionHandler];
    } else {
        completionHandler(NSURLSessionResponseCancel);
    }
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data {
    RBAuthExchangeClient *owner = _owner;
    if (owner != nil) {
        [owner exchangeSession:session dataTask:dataTask didReceiveData:data];
    } else {
        [dataTask cancel];
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest *_Nullable))completionHandler {
    RBAuthExchangeClient *owner = _owner;
    if (owner != nil) {
        [owner exchangeSession:session
                          task:task
     willPerformHTTPRedirection:response
                    newRequest:request
             completionHandler:completionHandler];
    } else {
        completionHandler(nil);
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error {
    RBAuthExchangeClient *owner = _owner;
    if (owner != nil) {
        [owner exchangeSession:session task:task didCompleteWithError:error];
    }
}

@end

@implementation RBAuthExchangeClient

- (instancetype)initWithExchangeRequest:(RBAuthExchangeRequest *)request {
    self = [super init];
    if (self != nil) {
        _exchangeRequest = [request copy];
    }
    return self;
}

#if defined(RB_AUTH_EXCHANGE_TESTING)
- (instancetype)initWithExchangeRequest:(RBAuthExchangeRequest *)request
                   sessionConfiguration:(NSURLSessionConfiguration *)configuration {
    self = [self initWithExchangeRequest:request];
    if (self != nil) {
        _injectedConfiguration = [configuration copy];
    }
    return self;
}
#endif

- (NSString *)description {
    return @"<RBAuthExchangeClient>";
}

#if defined(RB_AUTH_EXCHANGE_TESTING)
- (NSURLSessionConfiguration *)testEffectiveSessionConfiguration {
    @synchronized(self) {
        return [_session.configuration copy];
    }
}
#endif

- (void)dealloc {
    [_task cancel];
    [_session invalidateAndCancel];
}

- (BOOL)startWithCompletion:(RBAuthExchangeCompletion)completion {
    if (completion == nil) {
        return NO;
    }

    RBAuthExchangeRequest *exchangeRequest = nil;
    NSURLSessionConfiguration *injectedConfiguration = nil;
    @synchronized(self) {
        if (_started || _terminal) {
            return NO;
        }
        _started = YES;
        _completion = [completion copy];
        exchangeRequest = _exchangeRequest;
        injectedConfiguration = _injectedConfiguration;
    }

    if (exchangeRequest == nil ||
        !RBExchangeToken(exchangeRequest.ticket, 43, 43) ||
        !RBExchangeToken(exchangeRequest.verifier, 43, 128)) {
        [self finishWithUniqueCode:nil error:RBAuthExchangeClientErrorInvalidRequest];
        return YES;
    }

    NSURL *url = RBExchangeURL(exchangeRequest.httpsOrigin);
    NSDictionary<NSString *, NSString *> *bodyObject = @{
        @"ticket" : exchangeRequest.ticket,
        @"verifier" : exchangeRequest.verifier,
    };
    NSData *body = [NSJSONSerialization dataWithJSONObject:bodyObject options:0 error:NULL];
    if (url == nil || body == nil) {
        [self finishWithUniqueCode:nil error:RBAuthExchangeClientErrorInvalidRequest];
        return YES;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:RBAuthExchangeTimeout];
    request.HTTPMethod = @"POST";
    request.HTTPBody = body;
    request.HTTPShouldHandleCookies = NO;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    NSURLSessionConfiguration *configuration =
        injectedConfiguration != nil ? [injectedConfiguration copy]
                                    : [NSURLSessionConfiguration ephemeralSessionConfiguration];
    if (configuration == nil) {
        [self finishWithUniqueCode:nil error:RBAuthExchangeClientErrorInvalidRequest];
        return YES;
    }
    configuration.HTTPCookieStorage = nil;
    configuration.URLCredentialStorage = nil;
    configuration.URLCache = nil;
    configuration.HTTPShouldSetCookies = NO;
    configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    configuration.timeoutIntervalForRequest = RBAuthExchangeTimeout;
    configuration.timeoutIntervalForResource = RBAuthExchangeTimeout;

    NSOperationQueue *delegateQueue = [[NSOperationQueue alloc] init];
    delegateQueue.maxConcurrentOperationCount = 1;
    delegateQueue.name = @"org.raspberry.auth-exchange";
    RBAuthExchangeSessionDelegate *sessionDelegate =
        [[RBAuthExchangeSessionDelegate alloc] initWithOwner:self];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
                                                          delegate:sessionDelegate
                                                     delegateQueue:delegateQueue];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request];
    if (session == nil || task == nil) {
        [session invalidateAndCancel];
        [self finishWithUniqueCode:nil error:RBAuthExchangeClientErrorInvalidRequest];
        return YES;
    }

    BOOL resumeTask = NO;
    @synchronized(self) {
        if (!_terminal) {
            _session = session;
            _sessionDelegate = sessionDelegate;
            _task = task;
            _responseData = [[NSMutableData alloc] init];
            _pendingError = RBAuthExchangeClientErrorNone;
            _responseStatus = 0;
            _receivedResponse = NO;
            resumeTask = YES;
        }
    }
    if (resumeTask) {
        [task resume];
    } else {
        [session invalidateAndCancel];
    }
    return YES;
}

- (void)cancel {
    RBAuthExchangeCompletion completion = nil;
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
        task = _task;
        _task = nil;
        _responseData = nil;
        _exchangeRequest = nil;
        _injectedConfiguration = nil;
    }
    [task cancel];
    [session invalidateAndCancel];
    RBDeliverExchangeCompletion(completion, nil, RBAuthExchangeClientErrorCancelled);
}

- (void)finishWithUniqueCode:(NSString *)uniqueCode error:(RBAuthExchangeClientError)error {
    RBAuthExchangeCompletion completion = nil;
    NSURLSession *session = nil;
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
        _task = nil;
        _responseData = nil;
        _exchangeRequest = nil;
        _injectedConfiguration = nil;
    }
    [session invalidateAndCancel];
    RBDeliverExchangeCompletion(completion, uniqueCode, error);
}

- (void)exchangeSession:(NSURLSession *)session
               dataTask:(NSURLSessionDataTask *)dataTask
     didReceiveResponse:(NSURLResponse *)response
      completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler {
    (void)session;
    (void)dataTask;
    BOOL acceptResponse = NO;
    @synchronized(self) {
        if (!_terminal && _pendingError == RBAuthExchangeClientErrorNone) {
            if (![response isKindOfClass:[NSHTTPURLResponse class]] || _receivedResponse) {
                _pendingError = RBAuthExchangeClientErrorInvalidResponse;
            } else {
                NSInteger status = ((NSHTTPURLResponse *)response).statusCode;
                if (status != 200) {
                    _pendingError = RBAuthExchangeClientErrorHTTPStatus;
                } else {
                    _responseStatus = status;
                    _receivedResponse = YES;
                    _responseData = [[NSMutableData alloc] init];
                    acceptResponse = YES;
                }
            }
        }
    }
    completionHandler(acceptResponse ? NSURLSessionResponseAllow : NSURLSessionResponseCancel);
}

- (void)exchangeSession:(NSURLSession *)session
               dataTask:(NSURLSessionDataTask *)dataTask
         didReceiveData:(NSData *)data {
    (void)session;
    NSURLSessionDataTask *taskToCancel = nil;
    @synchronized(self) {
        if (_terminal || _pendingError != RBAuthExchangeClientErrorNone) {
            return;
        }
        if (!_receivedResponse || _responseData == nil) {
            _pendingError = RBAuthExchangeClientErrorInvalidResponse;
            taskToCancel = dataTask;
        } else if (_responseData.length > RBAuthExchangeResponseLimit ||
                   data.length > RBAuthExchangeResponseLimit - _responseData.length) {
            _pendingError = RBAuthExchangeClientErrorResponseTooLarge;
            taskToCancel = dataTask;
        } else {
            [_responseData appendData:data];
        }
    }
    [taskToCancel cancel];
}

- (void)exchangeSession:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
             newRequest:(NSURLRequest *)request
      completionHandler:(void (^)(NSURLRequest *_Nullable))completionHandler {
    (void)session;
    (void)task;
    (void)response;
    (void)request;
    @synchronized(self) {
        if (!_terminal && _pendingError == RBAuthExchangeClientErrorNone) {
            _pendingError = RBAuthExchangeClientErrorRedirectRefused;
        }
    }
    completionHandler(nil);
    [self finishWithUniqueCode:nil error:RBAuthExchangeClientErrorRedirectRefused];
}

- (void)exchangeSession:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
     didCompleteWithError:(NSError *)error {
    (void)session;
    (void)task;
    RBAuthExchangeClientError resultError = RBAuthExchangeClientErrorNone;
    NSData *body = nil;
    @synchronized(self) {
        if (_terminal) {
            return;
        }
        if (_pendingError != RBAuthExchangeClientErrorNone) {
            resultError = _pendingError;
        } else if (error != nil) {
            resultError = RBAuthExchangeClientErrorTransport;
        } else if (!_receivedResponse || _responseStatus != 200 || _responseData == nil) {
            resultError = RBAuthExchangeClientErrorInvalidResponse;
        } else {
            body = [_responseData copy];
        }
    }
    if (resultError != RBAuthExchangeClientErrorNone) {
        [self finishWithUniqueCode:nil error:resultError];
        return;
    }

    id object = [NSJSONSerialization JSONObjectWithData:body options:0 error:NULL];
    if (![object isKindOfClass:[NSDictionary class]]) {
        [self finishWithUniqueCode:nil error:RBAuthExchangeClientErrorInvalidResponse];
        return;
    }
    id code = ((NSDictionary *)object)[@"uniqueCode"];
    if (![code isKindOfClass:[NSString class]] || !RBExchangeUUIDShape((NSString *)code)) {
        [self finishWithUniqueCode:nil error:RBAuthExchangeClientErrorInvalidResponse];
        return;
    }
    [self finishWithUniqueCode:(NSString *)code error:RBAuthExchangeClientErrorNone];
}

// No authentication-challenge delegate is implemented: NSURLSession performs
// its normal platform TLS validation without a trust override.

@end
