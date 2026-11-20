#import "RBWebURLRouter.h"

#import "RBURLRewrite.h"

static NSURL * _Nullable RBWebURLRouterRewriteURL(
    NSURL *url,
    RBEndpoint * _Nullable endpoint,
    BOOL *didRewrite,
    BOOL *blocked) {
    *didRewrite = NO;
    *blocked = NO;

    BOOL rewrote = NO;
    NSError *err = nil;
    NSString *rewritten = [RBURLRewrite rewriteURLString:url.absoluteString
                                                endpoint:endpoint
                                              didRewrite:&rewrote
                                                   error:&err];
    if (err != nil || rewritten == nil) {
        *blocked = YES;
        return nil;
    }
    if (!rewrote) {
        return url;
    }

    NSURL *newURL = [NSURL URLWithString:rewritten];
    if (newURL == nil) {
        *blocked = YES;
        return nil;
    }
    *didRewrite = YES;
    return newURL;
}

@implementation RBWebURLRouter

+ (nullable NSURLRequest *)rewrittenRequest:(nullable NSURLRequest *)request
                                   endpoint:(nullable RBEndpoint *)endpoint
                                 didRewrite:(BOOL * _Nullable)didRewrite
                                    blocked:(BOOL * _Nullable)blocked {
    if (didRewrite != NULL) {
        *didRewrite = NO;
    }
    if (blocked != NULL) {
        *blocked = NO;
    }
    if (request == nil || request.URL == nil) {
        return request;
    }

    BOOL localDidRewrite = NO;
    BOOL localBlocked = NO;
    NSURL *newURL = RBWebURLRouterRewriteURL(
        request.URL, endpoint, &localDidRewrite, &localBlocked);
    if (localBlocked || newURL == nil) {
        if (blocked != NULL) {
            *blocked = YES;
        }
        return nil;
    }
    if (!localDidRewrite) {
        return request;
    }

    NSMutableURLRequest *mut = [request mutableCopy];
    if (mut == nil) {
        if (blocked != NULL) {
            *blocked = YES;
        }
        return nil;
    }
    mut.URL = newURL;
    if (didRewrite != NULL) {
        *didRewrite = YES;
    }
    return [mut copy];
}

+ (nullable NSURL *)rewrittenExternalURL:(nullable NSURL *)url
                                endpoint:(nullable RBEndpoint *)endpoint
                              didRewrite:(BOOL * _Nullable)didRewrite
                                 blocked:(BOOL * _Nullable)blocked {
    if (didRewrite != NULL) {
        *didRewrite = NO;
    }
    if (blocked != NULL) {
        *blocked = NO;
    }
    if (url == nil) {
        return nil;
    }

    BOOL localDidRewrite = NO;
    BOOL localBlocked = NO;
    NSURL *newURL = RBWebURLRouterRewriteURL(
        url, endpoint, &localDidRewrite, &localBlocked);
    if (localBlocked || newURL == nil) {
        if (blocked != NULL) {
            *blocked = YES;
        }
        return nil;
    }
    if (didRewrite != NULL) {
        *didRewrite = localDidRewrite;
    }
    return newURL;
}

@end
