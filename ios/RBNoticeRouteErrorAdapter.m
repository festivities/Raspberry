#import "RBNoticeRouteErrorAdapter.h"

#import <dispatch/dispatch.h>

static const NSTimeInterval RBNoticeRouteAdapterDeadline = 10.0;

@interface RBNoticeRouteWaitState : NSObject {
    NSLock *_lock;
    dispatch_semaphore_t _semaphore;
    NSTimeInterval _deadlineUptime;
    RBNoticeRouteResult _result;
    BOOL _completed;
}
- (instancetype)initWithDeadlineUptime:(NSTimeInterval)deadlineUptime;
- (BOOL)completeOnceWithResult:(RBNoticeRouteResult)result;
- (RBNoticeRouteResult)result;
- (long)waitUntil:(dispatch_time_t)deadline;
@end

@implementation RBNoticeRouteWaitState

- (instancetype)initWithDeadlineUptime:(NSTimeInterval)deadlineUptime {
    self = [super init];
    if (self != nil) {
        _lock = [[NSLock alloc] init];
        _semaphore = dispatch_semaphore_create(0);
        _deadlineUptime = deadlineUptime;
        _result = RBNoticeRouteResultInvalidResponse;
    }
    return self;
}

- (BOOL)completeOnceWithResult:(RBNoticeRouteResult)result {
    BOOL completed = NO;
    [_lock lock];
    if (!_completed) {
        NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
        _result = now >= _deadlineUptime
            ? RBNoticeRouteResultTimedOut
            : result;
        _completed = YES;
        completed = YES;
    }
    [_lock unlock];
    if (completed) {
        dispatch_semaphore_signal(_semaphore);
    }
    return completed;
}

- (RBNoticeRouteResult)result {
    [_lock lock];
    RBNoticeRouteResult result = _result;
    [_lock unlock];
    return result;
}

- (long)waitUntil:(dispatch_time_t)deadline {
    return dispatch_semaphore_wait(_semaphore, deadline);
}

@end

static RBNoticeRouteErrorKind
RBNoticeRouteErrorKindForResult(RBNoticeRouteResult result) {
    switch (result) {
        case RBNoticeRouteResultNoNotice:
            return RBNoticeRouteErrorKindHTTP404;
        case RBNoticeRouteResultRedirectRefused:
            return RBNoticeRouteErrorKindRedirectRefused;
        case RBNoticeRouteResultTransportFailure:
            return RBNoticeRouteErrorKindTransport;
        case RBNoticeRouteResultTimedOut:
            return RBNoticeRouteErrorKindTimeout;
        case RBNoticeRouteResultUnexpectedStatus:
            return RBNoticeRouteErrorKindUnexpectedStatus;
        case RBNoticeRouteResultSuccess:
            return RBNoticeRouteErrorKindFixtureSuccessRefused;
        case RBNoticeRouteResultResponseTooLarge:
            return RBNoticeRouteErrorKindResponseTooLarge;
        case RBNoticeRouteResultInvalidResponse:
            return RBNoticeRouteErrorKindInvalidResponse;
        case RBNoticeRouteResultCancelled:
            return RBNoticeRouteErrorKindCancelled;
        case RBNoticeRouteResultInvalidRequest:
            return RBNoticeRouteErrorKindInvalidRequest;
    }
    return RBNoticeRouteErrorKindInvalidResponse;
}

@interface RBNoticeRouteErrorAdapter () {
    RBNoticeRouteClient *_client;
    RBNoticeRouteFakeErrorObjectFactory _fakeErrorFactory;
    NSTimeInterval _deadlineInterval;
    BOOL _used;
}
- (nullable id)fakeErrorObjectForKind:(RBNoticeRouteErrorKind)kind
                           outputKind:
                               (RBNoticeRouteErrorKind *)outputKind;
@end

@implementation RBNoticeRouteErrorAdapter

- (nullable instancetype)initWithOwnedClient:(RBNoticeRouteClient *)client
                           fakeErrorFactory:
                               (RBNoticeRouteFakeErrorObjectFactory)factory {
    if (client == nil || factory == nil) {
        return nil;
    }
    self = [super init];
    if (self != nil) {
        _client = client;
        _fakeErrorFactory = [factory copy];
        _deadlineInterval = RBNoticeRouteAdapterDeadline;
    }
    return self;
}

#if defined(RB_NOTICE_ROUTE_TESTING)
- (nullable instancetype)initWithOwnedClient:(RBNoticeRouteClient *)client
                           fakeErrorFactory:
                               (RBNoticeRouteFakeErrorObjectFactory)factory
                            deadlineInterval:(NSTimeInterval)deadlineInterval {
    if (deadlineInterval <= 0.0 || deadlineInterval > 10.0) {
        return nil;
    }
    self = [self initWithOwnedClient:client fakeErrorFactory:factory];
    if (self != nil) {
        _deadlineInterval = deadlineInterval;
    }
    return self;
}
#endif

- (NSString *)description {
    return @"<RBNoticeRouteErrorAdapter>";
}

- (id)fakeErrorObjectForKind:(RBNoticeRouteErrorKind)kind
                   outputKind:(RBNoticeRouteErrorKind *)outputKind {
    id object = nil;
    @try {
        object = _fakeErrorFactory(kind);
    } @catch (NSException *exception) {
        (void)exception;
    }
    if (object == nil) {
        if (outputKind != NULL) {
            *outputKind = RBNoticeRouteErrorKindFactoryFailure;
        }
        return nil;
    }
    if (outputKind != NULL) {
        *outputKind = kind;
    }
    return object;
}

- (id)performSynchronouslyWithErrorKind:
    (RBNoticeRouteErrorKind *)errorKind {
    if (errorKind != NULL) {
        *errorKind = RBNoticeRouteErrorKindInvalidRequest;
    }

    if (NSThread.isMainThread ||
        [_client isExecutingOnSessionCallbackQueue]) {
        if (errorKind != NULL) {
            *errorKind = RBNoticeRouteErrorKindWrongExecutionQueue;
        }
        return nil;
    }

    BOOL alreadyUsed = NO;
    @synchronized(self) {
        alreadyUsed = _used;
        if (!alreadyUsed) {
            _used = YES;
        }
    }
    if (alreadyUsed) {
        return [self fakeErrorObjectForKind:
            RBNoticeRouteErrorKindAlreadyUsed outputKind:errorKind];
    }

    NSTimeInterval startUptime = NSProcessInfo.processInfo.systemUptime;
    NSTimeInterval deadlineUptime = startUptime + _deadlineInterval;
    dispatch_time_t waitDeadline = dispatch_time(DISPATCH_TIME_NOW,
        (int64_t)(_deadlineInterval * (NSTimeInterval)NSEC_PER_SEC));
    RBNoticeRouteWaitState *state =
        [[RBNoticeRouteWaitState alloc]
            initWithDeadlineUptime:deadlineUptime];
    RBNoticeRouteClient *client = _client;

    BOOL started = [client startWithCompletion:
        ^(NSData *responseBody, RBNoticeRouteResult result) {
            (void)responseBody;
            BOOL accepted = [state completeOnceWithResult:result];
            if (accepted &&
                [state result] == RBNoticeRouteResultTimedOut) {
                [client cancel];
            }
        }];
    if (!started) {
        return [self fakeErrorObjectForKind:
            RBNoticeRouteErrorKindStartRefused outputKind:errorKind];
    }

    // startWithCompletion creates a fresh private serial delegate queue. The
    // identity check is repeated after task creation and before any wait.
    if ([client isExecutingOnSessionCallbackQueue]) {
        [client cancel];
        return [self fakeErrorObjectForKind:
            RBNoticeRouteErrorKindWrongExecutionQueue outputKind:errorKind];
    }

    long waitResult = [state waitUntil:waitDeadline];
    if (waitResult != 0) {
        BOOL wonTimeout = [state completeOnceWithResult:
            RBNoticeRouteResultTimedOut];
        RBNoticeRouteResult currentResult = [state result];
        if (wonTimeout || currentResult == RBNoticeRouteResultTimedOut) {
            [client cancel];
        }
    }

    RBNoticeRouteErrorKind resultKind =
        RBNoticeRouteErrorKindForResult([state result]);
    return [self fakeErrorObjectForKind:resultKind outputKind:errorKind];
}

@end
