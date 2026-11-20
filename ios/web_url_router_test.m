#import "RBWebURLRouter.h"

#import <Foundation/Foundation.h>
#include <stdio.h>

static int g_failures;

static void RBCheck(BOOL condition, const char *name) {
    if (!condition) {
        fprintf(stderr, "web_url_router_test: %s\n", name);
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

static NSMutableURLRequest *RBMakeRequest(NSString *URLString) {
    NSURL *url = [NSURL URLWithString:URLString];
    RBCheck(url != nil, "valid-test-url");
    NSMutableURLRequest *request =
        [NSMutableURLRequest requestWithURL:url
                                cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                            timeoutInterval:45.0];
    request.HTTPMethod = @"POST";
    request.HTTPBody = [@"payload=v1%26test" dataUsingEncoding:NSUTF8StringEncoding];
    [request setValue:@"AV_AUTH=tok123; cc=US" forHTTPHeaderField:@"Cookie"];
    [request setValue:@"en-US,en;q=0.9" forHTTPHeaderField:@"Accept-Language"];
    return request;
}

static void RBAssertRequestMetadataPreserved(NSURLRequest *actual,
    NSURLRequest *expected, const char *label) {
    RBCheck([actual.HTTPMethod isEqualToString:expected.HTTPMethod], label);
    RBCheck([actual.HTTPBody isEqualToData:expected.HTTPBody], label);
    RBCheck(actual.timeoutInterval == expected.timeoutInterval, label);
    RBCheck(actual.cachePolicy == expected.cachePolicy, label);
    RBCheck([[actual valueForHTTPHeaderField:@"Cookie"]
        isEqualToString:[expected valueForHTTPHeaderField:@"Cookie"]], label);
    RBCheck([[actual valueForHTTPHeaderField:@"Accept-Language"]
        isEqualToString:[expected valueForHTTPHeaderField:@"Accept-Language"]],
        label);
    RBCheck([actual.allHTTPHeaderFields isEqualToDictionary:
        expected.allHTTPHeaderFields], label);
}

int main(void) {
    @autoreleasepool {
        RBEndpoint *mapped = RBEndpointFromJSON(
            @"{\"v\":1,\"host\":\"Operator.Example.Test\","
             "\"ports\":{\"80\":8080,\"443\":8443}}");
        RBEndpoint *defaults = RBEndpointFromJSON(
            @"{\"v\":1,\"host\":\"default.example.test\"}");

        // 1. Allowlisted LINE HTTPS/HTTP requests preserve headers, method, body,
        // timeout, cache policy, and raw path/query/fragment.
        struct {
            const char *name;
            NSString *input;
            NSString *expectedMapped;
            NSString *expectedDefaults;
        } allowlistedCases[] = {
            {
                "event-terms-https",
                @"https://event.play.naver.jp/webpage/policy/terms?lang=en#top",
                @"https://operator.example.test:8443/webpage/policy/terms?lang=en#top",
                @"https://default.example.test/webpage/policy/terms?lang=en#top",
            },
            {
                "line-rules-https",
                @"https://terms.line.me/line_rules/sp?lang=en",
                @"https://operator.example.test:8443/line_rules/sp?lang=en",
                @"https://default.example.test/line_rules/sp?lang=en",
            },
            {
                "lan3rd-http",
                @"http://lan3rd.line.me/v1/lineplay/ios",
                @"http://operator.example.test:8080/v1/lineplay/ios",
                @"http://default.example.test/v1/lineplay/ios",
            },
            {
                "raw-path-query-fragment",
                @"https://event.play.naver.jp/a%2Fb/%252F+z?q=1%2F+%252F#f%2F+%252F",
                @"https://operator.example.test:8443/a%2Fb/%252F+z?q=1%2F+%252F#f%2F+%252F",
                @"https://default.example.test/a%2Fb/%252F+z?q=1%2F+%252F#f%2F+%252F",
            },
        };

        for (size_t i = 0;
             i < sizeof(allowlistedCases) / sizeof(allowlistedCases[0]); i++) {
            NSMutableURLRequest *original =
                RBMakeRequest(allowlistedCases[i].input);
            BOOL didRewrite = NO;
            BOOL blocked = YES;
            NSURLRequest *rewritten = [RBWebURLRouter rewrittenRequest:original
                                                              endpoint:mapped
                                                            didRewrite:&didRewrite
                                                               blocked:&blocked];
            RBCheck(rewritten != nil && didRewrite && !blocked,
                allowlistedCases[i].name);
            RBCheck([rewritten.URL.absoluteString
                isEqualToString:allowlistedCases[i].expectedMapped],
                allowlistedCases[i].name);
            RBAssertRequestMetadataPreserved(
                rewritten, original, allowlistedCases[i].name);

            // Idempotency on rewritten request.
            BOOL secondRewrite = YES;
            BOOL secondBlocked = YES;
            NSURLRequest *again = [RBWebURLRouter rewrittenRequest:rewritten
                                                          endpoint:mapped
                                                        didRewrite:&secondRewrite
                                                           blocked:&secondBlocked];
            RBCheck(again == rewritten && !secondRewrite && !secondBlocked,
                "request-rewrite-idempotent");

            // Default-port endpoint check.
            BOOL defRewrite = NO;
            BOOL defBlocked = YES;
            NSURLRequest *defReq = [RBWebURLRouter rewrittenRequest:original
                                                           endpoint:defaults
                                                         didRewrite:&defRewrite
                                                            blocked:&defBlocked];
            RBCheck(defReq != nil && defRewrite && !defBlocked,
                "request-defaults-port");
            RBCheck([defReq.URL.absoluteString
                isEqualToString:allowlistedCases[i].expectedDefaults],
                "request-defaults-port-url");

            // External URL rewrite + idempotency.
            BOOL extRewrite = NO;
            BOOL extBlocked = YES;
            NSURL *extURL = [RBWebURLRouter rewrittenExternalURL:original.URL
                                                        endpoint:mapped
                                                      didRewrite:&extRewrite
                                                         blocked:&extBlocked];
            RBCheck(extURL != nil && extRewrite && !extBlocked,
                "external-url-rewrite");
            RBCheck([extURL.absoluteString
                isEqualToString:allowlistedCases[i].expectedMapped],
                "external-url-rewrite-string");

            BOOL extSecondRewrite = YES;
            BOOL extSecondBlocked = YES;
            NSURL *extAgain = [RBWebURLRouter rewrittenExternalURL:extURL
                                                          endpoint:mapped
                                                        didRewrite:&extSecondRewrite
                                                           blocked:&extSecondBlocked];
            RBCheck(extAgain == extURL && !extSecondRewrite && !extSecondBlocked,
                "external-url-idempotent");
        }

        // 2. Non-LINE URLs pass through unchanged.
        NSArray<NSString *> *passthroughURLs = @[
            @"https://discord.com/oauth2/authorize?client_id=123&state=abc",
            @"raspberry://auth?code=1&state=xyz",
            @"itms-apps://itunes.apple.com/app/id1",
            @"https://operator.example.test:8443/webpage/policy/terms?lang=en#top",
            @"https://event.play.naver.jp.evil.example/a",
            @"https://evil.line.me/a",
            @"about:blank",
        ];
        for (NSString *raw in passthroughURLs) {
            NSMutableURLRequest *req = RBMakeRequest(raw);
            BOOL reqRewrite = YES;
            BOOL reqBlocked = YES;
            NSURLRequest *outReq = [RBWebURLRouter rewrittenRequest:req
                                                           endpoint:mapped
                                                         didRewrite:&reqRewrite
                                                            blocked:&reqBlocked];
            RBCheck(outReq == req && !reqRewrite && !reqBlocked,
                "passthrough-request");

            BOOL urlRewrite = YES;
            BOOL urlBlocked = YES;
            NSURL *outURL = [RBWebURLRouter rewrittenExternalURL:req.URL
                                                        endpoint:mapped
                                                      didRewrite:&urlRewrite
                                                         blocked:&urlBlocked];
            RBCheck(outURL == req.URL && !urlRewrite && !urlBlocked,
                "passthrough-external-url");
        }

        // Non-LINE URL passes through even when endpoint is nil.
        {
            NSURL *discordURL =
                [NSURL URLWithString:@"https://discord.com/oauth2/authorize"];
            BOOL rw = YES;
            BOOL blk = YES;
            NSURL *outURL = [RBWebURLRouter rewrittenExternalURL:discordURL
                                                        endpoint:nil
                                                      didRewrite:&rw
                                                         blocked:&blk];
            RBCheck(outURL == discordURL && !rw && !blk,
                "passthrough-without-endpoint");
        }

        // 3. Fail-closed on malformed allowlisted URLs and nil endpoint.
        NSArray<NSString *> *malformedURLs = @[
            @"https://event.play.naver.jp:444/a",
            @"https://user:secret@event.play.naver.jp/a",
            @"http://lan3rd.line.me:81/v1/lineplay/ios",
            @"http://lan3rd.line.me:080/v1/lineplay/ios",
            @"https://%65vent.play.naver.jp/a",
        ];
        for (NSString *bad in malformedURLs) {
            NSURL *badURL = [NSURL URLWithString:bad];
            RBCheck(badURL != nil, "malformed-fixture-constructs-nsurl");
            NSURLRequest *badReq = [NSURLRequest requestWithURL:badURL];

            BOOL reqRW = YES;
            BOOL reqBlk = NO;
            NSURLRequest *outReq = [RBWebURLRouter rewrittenRequest:badReq
                                                           endpoint:mapped
                                                         didRewrite:&reqRW
                                                            blocked:&reqBlk];
            RBCheck(outReq == nil && !reqRW && reqBlk,
                "malformed-request-fails-closed");

            BOOL urlRW = YES;
            BOOL urlBlk = NO;
            NSURL *outURL = [RBWebURLRouter rewrittenExternalURL:badURL
                                                        endpoint:mapped
                                                      didRewrite:&urlRW
                                                         blocked:&urlBlk];
            RBCheck(outURL == nil && !urlRW && urlBlk,
                "malformed-external-url-fails-closed");
        }

        {
            NSURL *lineURL = [NSURL URLWithString:
                @"https://event.play.naver.jp/webpage/policy/terms?lang=en#top"];
            NSURLRequest *lineReq = [NSURLRequest requestWithURL:lineURL];
            BOOL reqRW = YES;
            BOOL reqBlk = NO;
            NSURLRequest *outReq = [RBWebURLRouter rewrittenRequest:lineReq
                                                           endpoint:nil
                                                         didRewrite:&reqRW
                                                            blocked:&reqBlk];
            RBCheck(outReq == nil && !reqRW && reqBlk,
                "nil-endpoint-request-fails-closed");

            BOOL urlRW = YES;
            BOOL urlBlk = NO;
            NSURL *outURL = [RBWebURLRouter rewrittenExternalURL:lineURL
                                                        endpoint:nil
                                                      didRewrite:&urlRW
                                                         blocked:&urlBlk];
            RBCheck(outURL == nil && !urlRW && urlBlk,
                "nil-endpoint-external-url-fails-closed");
        }

        // 4. nil request / nil URL / request with nil URL / NULL out-params.
        {
            BOOL rw = YES;
            BOOL blk = YES;
            NSURLRequest *nilReqOut = [RBWebURLRouter rewrittenRequest:nil
                                                              endpoint:mapped
                                                            didRewrite:&rw
                                                               blocked:&blk];
            RBCheck(nilReqOut == nil && !rw && !blk, "nil-request-unblocked");

            NSURLRequest *emptyReq = [[NSURLRequest alloc] init];
            RBCheck(emptyReq.URL == nil, "empty-request-has-nil-url");
            rw = YES;
            blk = YES;
            NSURLRequest *emptyReqOut = [RBWebURLRouter rewrittenRequest:emptyReq
                                                                endpoint:mapped
                                                              didRewrite:&rw
                                                                 blocked:&blk];
            RBCheck(emptyReqOut == emptyReq && !rw && !blk,
                "empty-url-request-unblocked");

            rw = YES;
            blk = YES;
            NSURL *nilURLOut = [RBWebURLRouter rewrittenExternalURL:nil
                                                           endpoint:mapped
                                                         didRewrite:&rw
                                                            blocked:&blk];
            RBCheck(nilURLOut == nil && !rw && !blk, "nil-url-unblocked");

            NSURL *lineURL =
                [NSURL URLWithString:@"https://terms.line.me/line_rules/sp?lang=en"];
            NSURL *nullPtrOut = [RBWebURLRouter rewrittenExternalURL:lineURL
                                                            endpoint:mapped
                                                          didRewrite:NULL
                                                             blocked:NULL];
            RBCheck([nullPtrOut.absoluteString
                isEqualToString:@"https://operator.example.test:8443/line_rules/sp?lang=en"],
                "null-out-params-allowed");
        }
    }

    if (g_failures != 0) {
        return 1;
    }
    printf("iOS Web URL router tests: ok\n");
    return 0;
}
