#import "RBURLRewrite.h"

#import <Foundation/Foundation.h>

static int g_failures;

static void RBCheck(BOOL condition, const char *name) {
    if (!condition) {
        fprintf(stderr, "url_rewrite_test: %s\n", name);
        g_failures++;
    }
}

static RBEndpoint *RBEndpointFromJSON(NSString *json) {
    NSError *error = nil;
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    RBEndpoint *endpoint = [RBEndpoint endpointWithJSONData:data error:&error];
    RBCheck(endpoint != nil && error == nil, "endpoint-fixture");
    return endpoint;
}

static NSString *RBRewrite(NSString *URLString, RBEndpoint *endpoint,
    BOOL expectedRewrite, NSString *expected, const char *name) {
    BOOL didRewrite = !expectedRewrite;
    NSError *error = nil;
    NSString *actual = [RBURLRewrite rewriteURLString:URLString
        endpoint:endpoint didRewrite:&didRewrite error:&error];
    RBCheck(actual != nil && [actual isEqualToString:expected], name);
    RBCheck(didRewrite == expectedRewrite, "did-rewrite-value");
    RBCheck(error == nil, "successful-result-has-no-error");
    return actual;
}

static void RBCheckFailClosed(NSString *URLString, RBEndpoint *endpoint,
    RBURLRewriteErrorCode expectedCode, const char *name) {
    BOOL didRewrite = YES;
    NSError *error = nil;
    NSString *actual = [RBURLRewrite rewriteURLString:URLString
        endpoint:endpoint didRewrite:&didRewrite error:&error];
    RBCheck(actual == nil, name);
    RBCheck(!didRewrite, "failed-result-did-not-rewrite");
    RBCheck(error.domain == RBURLRewriteErrorDomain, "fixed-error-domain");
    RBCheck(error.code == expectedCode, "fixed-error-code");
    RBCheck(error.localizedDescription.length > 0, "fixed-error-description");
    RBCheck([error.localizedDescription rangeOfString:@"event.play.naver.jp"].location ==
        NSNotFound, "error-does-not-disclose-host");
    RBCheck([error.localizedDescription rangeOfString:@"secret"].location ==
        NSNotFound, "error-does-not-disclose-query");
}

static BOOL RBMutationIsRejected(NSString *string) {
    @try {
        [(NSMutableString *)string appendString:@"x"];
    } @catch (NSException *exception) {
        (void)exception;
        return YES;
    }
    return NO;
}

int main(void) {
    @autoreleasepool {
        RBEndpoint *mapped = RBEndpointFromJSON(
            @"{\"v\":1,\"host\":\"Operator.Example.Test\","
             "\"ports\":{\"80\":8080,\"443\":8443}}");
        RBEndpoint *defaults = RBEndpointFromJSON(
            @"{\"v\":1,\"host\":\"default.example.test\"}");
        RBEndpoint *crossMapped = RBEndpointFromJSON(
            @"{\"v\":1,\"host\":\"cross.example.test\","
             "\"ports\":{\"80\":443,\"443\":80}}");

        RBRewrite(@"http://play-static.line-scdn.net/a%2Fb?q=%2F",
            mapped, YES,
            @"http://operator.example.test:8080/a%2Fb?q=%2F",
            "http-map-80");
        RBRewrite(@"https://event.play.naver.jp:443/a%2Fb",
            mapped, YES,
            @"https://operator.example.test:8443/a%2Fb",
            "https-map-443");
        RBRewrite(@"http://lan3rd.line.me:80/a", defaults, YES,
            @"http://default.example.test/a", "http-default-port-omitted");
        RBRewrite(@"https://terms.line.me:443/a", defaults, YES,
            @"https://default.example.test/a", "https-default-port-omitted");
        RBRewrite(@"http://notice2.line.me", defaults, YES,
            @"http://default.example.test", "bare-url-no-added-tail");
        RBRewrite(@"http://event.play.naver.jp/a", crossMapped, YES,
            @"http://cross.example.test:443/a", "http-maps-to-https-number-port");
        RBRewrite(@"https://event.play.naver.jp/a", crossMapped, YES,
            @"https://cross.example.test:80/a", "https-maps-to-http-number-port");

        RBRewrite(@"HTTPS://EVENT.PLAY.NAVER.JP./a%2Fb/%252F+z"
            @"?q=1%2F+%252F#f%2F+%252F",
            mapped, YES,
            @"HTTPS://operator.example.test:8443/a%2Fb/%252F+z"
             @"?q=1%2F+%252F#f%2F+%252F",
            "raw-tail-and-host-normalization");
        RBRewrite(@"http://notice2.line.me/a?", mapped, YES,
            @"http://operator.example.test:8080/a?", "empty-query-preserved");
        RBRewrite(@"https://help2.line.me/a#", mapped, YES,
            @"https://operator.example.test:8443/a#", "empty-fragment-preserved");

        NSString *encodedAlias = @"https://%65vent.play.naver.jp/a%2F";
        BOOL encodedDidRewrite = NO;
        NSError *encodedError = nil;
        NSString *encodedResult = [RBURLRewrite rewriteURLString:encodedAlias
            endpoint:mapped didRewrite:&encodedDidRewrite error:&encodedError];
        RBCheck(encodedResult == nil && !encodedDidRewrite &&
            encodedError.code == RBURLRewriteErrorMalformedTarget,
            "encoded-owned-host-fails-closed");

        RBRewrite(@"https://xplay.naver.jp/a", mapped, NO,
            @"https://xplay.naver.jp/a", "suffix-label-boundary");
        RBRewrite(@"https://event.play.naver.jp.evil.example/a", mapped, NO,
            @"https://event.play.naver.jp.evil.example/a",
            "longer-host-suffix-not-owned");
        RBRewrite(@"https://event.play.naver.jp.evil.example:444/a", mapped,
            NO, @"https://event.play.naver.jp.evil.example:444/a",
            "unknown-port-on-nontarget-untouched");
        RBRewrite(@"https://unrelated.example/event.play.naver.jp?q=event.play.naver.jp",
            mapped, NO,
            @"https://unrelated.example/event.play.naver.jp?q=event.play.naver.jp",
            "path-and-query-lookalike");
        RBRewrite(@"https://event.play.naver.jpé.evil.example/a", mapped, NO,
            @"https://event.play.naver.jpé.evil.example/a",
            "unicode-idna-label-not-truncated");
        RBRewrite(@"https://access.line.me/oauth", mapped, NO,
            @"https://access.line.me/oauth", "unrelated-line-host");
        RBRewrite(@"https://event.play.naver.jp@unrelated.example/a", mapped,
            NO, @"https://event.play.naver.jp@unrelated.example/a",
            "owned-name-only-in-userinfo");
        RBRewrite(@"https://evil.line.me/a", mapped, NO,
            @"https://evil.line.me/a", "no-broad-line-me-suffix");
        RBRewrite(@"ftp://event.play.naver.jp/a", mapped, NO,
            @"ftp://event.play.naver.jp/a", "ftp-untouched");
        RBRewrite(@"https://[2001:db8::1]:443/a%2F", mapped, NO,
            @"https://[2001:db8::1]:443/a%2F", "ipv6-untouched");

        RBCheckFailClosed(@"https://user:secret@event.play.naver.jp/a",
            mapped, RBURLRewriteErrorMalformedTarget, "userinfo-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp:444/a",
            mapped, RBURLRewriteErrorMalformedTarget, "unknown-port-fails-closed");
        RBCheckFailClosed(@"http://event.play.naver.jp:81/a",
            mapped, RBURLRewriteErrorMalformedTarget, "http-unknown-port");
        RBCheckFailClosed(@"https://event.play.naver.jp:/a",
            mapped, RBURLRewriteErrorMalformedTarget, "empty-port-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp:bad/a",
            mapped, RBURLRewriteErrorMalformedTarget, "malformed-port-fails-closed");
        RBCheckFailClosed(@"http://event.play.naver.jp:080/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "leading-zero-port-rejected");
        RBCheckFailClosed(@"https://event.play.naver.jp:443:444/a",
            mapped, RBURLRewriteErrorMalformedTarget, "ambiguous-port-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp spacejunk/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "space-in-owned-host-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp!junk/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "punctuation-in-owned-host-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp%/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "trailing-percent-in-owned-host-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp%2e/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "encoded-trailing-dot-host-fails-closed");
        RBCheckFailClosed(@"https://event%2eplay.naver.jp/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "encoded-dot-host-alias-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp\t:443/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "authority-control-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp\\@unrelated.example/a",
            mapped, RBURLRewriteErrorMalformedTarget,
            "backslash-authority-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp/a\nb",
            mapped, RBURLRewriteErrorMalformedTarget, "control-fails-closed");

        unichar nulCharacter = 0;
        NSString *nul = [NSString stringWithCharacters:&nulCharacter length:1];
        NSString *nulURL = [@"https://event.play.naver.jp"
            stringByAppendingString:[nul stringByAppendingString:@"/a"]];
        RBCheckFailClosed(nulURL, mapped, RBURLRewriteErrorMalformedTarget,
            "nul-fails-closed");
        NSString *nulPath = [@"https://event.play.naver.jp/a"
            stringByAppendingString:[nul stringByAppendingString:@"b"]];
        RBCheckFailClosed(nulPath, mapped, RBURLRewriteErrorMalformedTarget,
            "nul-path-fails-closed");
        RBCheckFailClosed(@"https://event.play.naver.jp/a", nil,
            RBURLRewriteErrorEndpointRequired, "target-needs-endpoint");
        RBRewrite(@"https://unrelated.example/a", nil, NO,
            @"https://unrelated.example/a", "unrelated-needs-no-endpoint");

        BOOL nilDidRewrite = YES;
        NSError *nilError = nil;
        NSString *nilResult = [RBURLRewrite rewriteURLString:nil endpoint:mapped
            didRewrite:&nilDidRewrite error:&nilError];
        RBCheck(nilResult == nil && !nilDidRewrite &&
            nilError.code == RBURLRewriteErrorInvalidInput,
            "nil-input-fails-with-fixed-error");

        RBCheckFailClosed(@"https://event.play.naver.jp:444/a", mapped,
            RBURLRewriteErrorMalformedTarget, "error-optional-control");
        RBCheck([RBURLRewrite rewriteURLString:
                    @"https://event.play.naver.jp:444/a"
                endpoint:mapped didRewrite:NULL error:NULL] == nil,
            "null-output-pointers-safe");
        NSString *withoutOutputs = [RBURLRewrite rewriteURLString:
            @"https://event.play.naver.jp/a" endpoint:mapped
            didRewrite:NULL error:NULL];
        RBCheck([withoutOutputs isEqualToString:
            @"https://operator.example.test:8443/a"],
            "null-output-pointers-success-safe");
        NSError *staleError = [NSError errorWithDomain:@"stale"
            code:99 userInfo:nil];
        NSString *clearedErrorResult = [RBURLRewrite rewriteURLString:
            @"https://event.play.naver.jp/a" endpoint:mapped
            didRewrite:NULL error:&staleError];
        RBCheck([clearedErrorResult isEqualToString:
            @"https://operator.example.test:8443/a"] && staleError == nil,
            "success-clears-stale-error");

        NSMutableString *mutableInput =
            [NSMutableString stringWithString:@"https://event.play.naver.jp/a%2F"];
        NSString *stableResult = [RBURLRewrite rewriteURLString:mutableInput
            endpoint:mapped didRewrite:NULL error:NULL];
        [mutableInput setString:@"https://unrelated.example/changed"];
        RBCheck([stableResult isEqualToString:
            @"https://operator.example.test:8443/a%2F"],
            "mutable-source-independent-result");
        RBCheck(RBMutationIsRejected(stableResult),
            "result-is-immutable-string");

        NSMutableString *mutableUnrelated =
            [NSMutableString stringWithString:@"https://unrelated.example/a"];
        NSString *stableUnchanged = [RBURLRewrite rewriteURLString:mutableUnrelated
            endpoint:mapped didRewrite:NULL error:NULL];
        [mutableUnrelated setString:@"changed"];
        RBCheck([stableUnchanged isEqualToString:
            @"https://unrelated.example/a"] &&
            RBMutationIsRejected(stableUnchanged),
            "unchanged-input-returned-as-immutable-copy");

        if (g_failures != 0) {
            fprintf(stderr, "url_rewrite_test: %d failure(s)\n", g_failures);
            return 1;
        }
        puts("url_rewrite_test: all rewrite cases passed");
    }
    return 0;
}
