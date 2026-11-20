#import "RBASWebAuthenticationSessionDriver.h"

#import "RBAuthUIKitOwnerConditions.h"

#import <dispatch/dispatch.h>

@interface RBASWebAuthenticationSessionDriver ()
@property(nonatomic, strong, nullable) ASWebAuthenticationSession *session;
@property(nonatomic, strong, nullable) UIWindow *retainedPresentationAnchor;
@property(nonatomic, strong, nullable) UIViewController *retainedForegroundOwner;
@property(nonatomic, copy, nullable) RBAuthBrowserDriverCompletion completion;
@property(nonatomic, strong, nullable) NSObject *activeRoundToken;
- (void)completeRoundToken:(NSObject *)roundToken
                      kind:(RBAuthBrowserDriverCompletionKind)kind
               callbackURL:(NSURL * _Nullable)callbackURL;
@end

@implementation RBASWebAuthenticationSessionDriver

- (RBAuthBrowserDriverStartResult)startAuthorizationURL:(NSURL *)authorizationURL
                                          callbackScheme:(NSString *)callbackScheme
                                prefersEphemeralSession:(BOOL)prefersEphemeralSession
                                        foregroundOwner:(id)foregroundOwner
                                             completion:(RBAuthBrowserDriverCompletion)completion {
    if (![NSThread isMainThread]) {
        return RBAuthBrowserDriverStartResultOwnerNotForeground;
    }
    if (![callbackScheme isEqualToString:RBAuthBrowserCallbackScheme] ||
        !prefersEphemeralSession ||
        ![authorizationURL.scheme isEqualToString:@"https"] ||
        authorizationURL.host.length == 0 ||
        authorizationURL.user != nil || authorizationURL.password != nil ||
        authorizationURL.fragment != nil) {
        return RBAuthBrowserDriverStartResultFailed;
    }

    UIViewController *owner = (UIViewController *)foregroundOwner;
    UIWindow *anchor = nil;
    UIApplication *application = UIApplication.sharedApplication;
    if (!RBAuthUIKitOwnerIsForeground(foregroundOwner, application, &anchor)) {
        return RBAuthBrowserDriverStartResultOwnerNotForeground;
    }

    NSObject *roundToken = [[NSObject alloc] init];
    @synchronized(self) {
        if (self.session != nil || self.activeRoundToken != nil) {
            return RBAuthBrowserDriverStartResultFailed;
        }
        self.activeRoundToken = roundToken;
        self.retainedPresentationAnchor = anchor;
        self.retainedForegroundOwner = owner;
        self.completion = [completion copy];
    }

    __weak typeof(self) weakSelf = self;
    ASWebAuthenticationSession *session =
        [[ASWebAuthenticationSession alloc] initWithURL:authorizationURL
                                      callbackURLScheme:RBAuthBrowserCallbackScheme
                                      completionHandler:^(NSURL * _Nullable callbackURL,
                                                          NSError * _Nullable error) {
        RBAuthBrowserDriverCompletionKind completionKind =
            RBAuthBrowserDriverCompletionKindCompleted;
        if (error != nil) {
            BOOL cancelled =
                [error.domain isEqualToString:ASWebAuthenticationSessionErrorDomain] &&
                error.code == ASWebAuthenticationSessionErrorCodeCanceledLogin;
            completionKind = cancelled
                ? RBAuthBrowserDriverCompletionKindCancelled
                : RBAuthBrowserDriverCompletionKindFailed;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            RBASWebAuthenticationSessionDriver *strongSelf = weakSelf;
            [strongSelf completeRoundToken:roundToken
                                      kind:completionKind
                               callbackURL:error == nil ? callbackURL : nil];
        });
    }];

    @synchronized(self) {
        self.session = session;
    }
    session.presentationContextProvider = self;
    session.prefersEphemeralWebBrowserSession = YES;

    if (![session start]) {
        @synchronized(self) {
            if (self.activeRoundToken == roundToken) {
                self.activeRoundToken = nil;
                self.session = nil;
                self.completion = nil;
                self.retainedPresentationAnchor = nil;
                self.retainedForegroundOwner = nil;
            }
        }
        return RBAuthBrowserDriverStartResultFailed;
    }
    return RBAuthBrowserDriverStartResultStarted;
}

- (void)cancelCurrentSession {
    (void)RBAuthBrowserPerformDriverCancellationOnMainThread(^{
        ASWebAuthenticationSession *session = nil;
        @synchronized(self) {
            session = self.session;
            self.activeRoundToken = nil;
            self.session = nil;
            self.completion = nil;
            self.retainedPresentationAnchor = nil;
            self.retainedForegroundOwner = nil;
        }
        [session cancel];
    });
}

- (void)completeRoundToken:(NSObject *)roundToken
                      kind:(RBAuthBrowserDriverCompletionKind)kind
               callbackURL:(NSURL *)callbackURL {
    if (![NSThread isMainThread]) {
        __weak typeof(self) weakSelf = self;
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf completeRoundToken:roundToken
                                    kind:kind
                             callbackURL:callbackURL];
        });
        return;
    }

    RBAuthBrowserDriverCompletion completionHandler = nil;
    @synchronized(self) {
        if (self.activeRoundToken != roundToken || self.session == nil) {
            return;
        }
        completionHandler = self.completion;
        self.activeRoundToken = nil;
        self.completion = nil;
        self.session = nil;
        self.retainedPresentationAnchor = nil;
        self.retainedForegroundOwner = nil;
    }
    if (completionHandler != nil) {
        completionHandler(kind, callbackURL);
    }
}

- (ASPresentationAnchor)presentationAnchorForWebAuthenticationSession:
    (ASWebAuthenticationSession *)session {
    @synchronized(self) {
        if (self.session != session || self.activeRoundToken == nil) {
            return (ASPresentationAnchor)nil;
        }
        return self.retainedPresentationAnchor;
    }
}

@end
