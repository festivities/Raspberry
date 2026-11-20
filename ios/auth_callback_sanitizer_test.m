#import "RBAuthCallbackSanitizer.h"

#include <stdio.h>

static int failures = 0;

#define CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", label); \
        failures++; \
    } \
} while (0)

@interface RBStubMalformedURL : NSURL
- (instancetype)initWithStubScheme:(nullable NSString *)scheme
                    absoluteString:(nullable NSString *)absoluteString;
@end

@implementation RBStubMalformedURL {
    NSString *_stubScheme;
    NSString *_stubAbsoluteString;
}

- (instancetype)initWithStubScheme:(nullable NSString *)scheme
                    absoluteString:(nullable NSString *)absoluteString {
    self = [super initWithString:@"https://placeholder.invalid/"];
    if (self != nil) {
        _stubScheme = [scheme copy];
        _stubAbsoluteString = [absoluteString copy];
    }
    return self;
}

- (nullable NSString *)scheme {
    return _stubScheme;
}

- (nullable NSString *)absoluteString {
    return _stubAbsoluteString;
}

@end

static void TestConsumedOpenURLs(void) {
    NSArray<NSString *> *consumedURLStrings = @[
        @"raspberry://auth?ticket=secret&state=123",
        @"RASPBERRY://AUTH?ticket=secret&state=123",
        @"RaSpBeRrY://auth?ticket=secret&state=123",
        @"raspberry:opaque",
        @"raspberry://other-path",
        @"raspberry://",
    ];
    for (NSString *raw in consumedURLStrings) {
        NSURL *url = [NSURL URLWithString:raw];
        CHECK(url != nil, "consumed test URL parses with NSURL");
        CHECK([RBAuthCallbackSanitizer shouldConsumeOpenURL:url],
              "reserved raspberry NSURL is consumed");
        CHECK([RBAuthCallbackSanitizer shouldConsumeRawURLString:raw],
              "reserved raspberry raw string is consumed");
    }

    NSURL *malformedURL = [NSURL URLWithString:@"raspberry://auth?bad=%ZZ"];
    if (malformedURL != nil) {
        CHECK([RBAuthCallbackSanitizer shouldConsumeOpenURL:malformedURL],
              "Foundation-parsed malformed raspberry NSURL is consumed");
    }
    CHECK([RBAuthCallbackSanitizer shouldConsumeRawURLString:@"raspberry://auth?bad=%ZZ"],
          "malformed raspberry raw string is consumed");
    CHECK([RBAuthCallbackSanitizer shouldConsumeRawURLString:@" \t\r\n\x01RaSpBeRrY://auth?bad=%ZZ"],
          "malformed raspberry raw string with leading ASCII control/whitespace is consumed");

    RBStubMalformedURL *nilSchemeMalformed =
        [[RBStubMalformedURL alloc] initWithStubScheme:nil
                                        absoluteString:@"  raspberry://auth?bad=%ZZ"];
    CHECK([RBAuthCallbackSanitizer shouldConsumeOpenURL:nilSchemeMalformed],
          "NSURL with nil scheme and malformed raspberry absoluteString is consumed");

    RBStubMalformedURL *schemeOnlyStub =
        [[RBStubMalformedURL alloc] initWithStubScheme:@"RaSpBeRrY"
                                        absoluteString:nil];
    CHECK([RBAuthCallbackSanitizer shouldConsumeOpenURL:schemeOnlyStub],
          "NSURL with raspberry scheme and nil absoluteString is consumed");
}

static void TestPassedThroughOpenURLs(void) {
    CHECK(![RBAuthCallbackSanitizer shouldConsumeOpenURL:nil],
          "nil NSURL is not consumed");
    CHECK(![RBAuthCallbackSanitizer shouldConsumeRawURLString:nil],
          "nil raw string is not consumed");
    CHECK(![RBAuthCallbackSanitizer shouldConsumeRawURLString:@""],
          "empty raw string is not consumed");
    CHECK(![RBAuthCallbackSanitizer shouldConsumeRawURLString:@"   \t\r\n\x1f"],
          "whitespace-only raw string is not consumed");
    CHECK(![RBAuthCallbackSanitizer shouldConsumeRawURLString:@"raspberry"],
          "scheme name without colon is not consumed");

    NSArray<NSString *> *unrelatedURLStrings = @[
        @"line3rdp.jp.naver.lineplay://authorize",
        @"fbconnect://success",
        @"https://lan3rd.line.me/v1/lineplay/ios",
        @"http://cherry.example.org/login",
        @"https://example.org/?return=raspberry://auth",
        @"raspberryhttps://example.org",
        @"https://raspberry://auth",
    ];
    for (NSString *raw in unrelatedURLStrings) {
        NSURL *url = [NSURL URLWithString:raw];
        CHECK(url != nil, "unrelated test URL parses with NSURL");
        CHECK(![RBAuthCallbackSanitizer shouldConsumeOpenURL:url],
              "unrelated NSURL is passed through");
        CHECK(![RBAuthCallbackSanitizer shouldConsumeRawURLString:raw],
              "unrelated raw string is passed through");
    }

    RBStubMalformedURL *unrelatedNilScheme =
        [[RBStubMalformedURL alloc] initWithStubScheme:nil
                                        absoluteString:@"https://example.org/?next=raspberry://auth"];
    CHECK(![RBAuthCallbackSanitizer shouldConsumeOpenURL:unrelatedNilScheme],
          "NSURL with nil scheme and unrelated absoluteString is passed through");
}

static void TestSanitizedLaunchOptions(void) {
    NSString *const urlKey = @"UIApplicationLaunchOptionsURLKey";
    NSString *const sourceAppKey = @"UIApplicationLaunchOptionsSourceApplicationKey";
    NSString *const remoteNotifKey = @"UIApplicationLaunchOptionsRemoteNotificationKey";

    // nil launchOptions returns nil and sets didStripReservedURL = NO.
    BOOL stripped = YES;
    NSDictionary *nilResult = [RBAuthCallbackSanitizer sanitizedLaunchOptions:nil
                                                                       urlKey:urlKey
                                                          didStripReservedURL:&stripped];
    CHECK(nilResult == nil, "nil launchOptions returns nil");
    CHECK(!stripped, "nil launchOptions sets didStripReservedURL to NO");

    // NULL didStripReservedURL is accepted safely.
    NSDictionary *nullFlagResult =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:@{
            urlKey: [NSURL URLWithString:@"raspberry://auth?ticket=secret&state=123"],
            sourceAppKey: @"com.apple.SafariViewService",
        }
                                                 urlKey:urlKey
                                    didStripReservedURL:NULL];
    CHECK(nullFlagResult != nil && nullFlagResult[urlKey] == nil &&
          [nullFlagResult[sourceAppKey] isEqualToString:@"com.apple.SafariViewService"],
          "NULL didStripReservedURL still strips reserved URL and keeps sibling keys");

    // Reserved NSURL is stripped while preserving sibling keys.
    NSDictionary *notifPayload = @{@"aps": @{@"badge": @1}};
    NSDictionary *reservedInput = @{
        urlKey: [NSURL URLWithString:@"RASPBERRY://auth?ticket=secret&state=123"],
        sourceAppKey: @"com.apple.mobilesafari",
        remoteNotifKey: notifPayload,
    };
    stripped = NO;
    NSDictionary *reservedOutput =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:reservedInput
                                                 urlKey:urlKey
                                    didStripReservedURL:&stripped];
    CHECK(stripped, "reserved NSURL sets didStripReservedURL to YES");
    CHECK(reservedOutput[urlKey] == nil, "reserved NSURL is removed from launchOptions");
    CHECK([reservedOutput[sourceAppKey] isEqualToString:@"com.apple.mobilesafari"],
          "source application key preserved when reserved URL is stripped");
    CHECK([reservedOutput[remoteNotifKey] isEqualToDictionary:notifPayload],
          "remote notification payload preserved when reserved URL is stripped");
    CHECK(reservedOutput.count == 2, "only urlKey is removed when reserved URL is stripped");

    // Reserved raw NSString (malformed) is stripped while preserving sibling keys.
    NSDictionary *rawStringInput = @{
        urlKey: @" \n\traspberry://auth?bad=%ZZ",
        sourceAppKey: @"com.apple.SafariViewService",
    };
    stripped = NO;
    NSDictionary *rawStringOutput =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:rawStringInput
                                                 urlKey:urlKey
                                    didStripReservedURL:&stripped];
    CHECK(stripped, "reserved raw NSString sets didStripReservedURL to YES");
    CHECK(rawStringOutput[urlKey] == nil, "reserved raw NSString is removed");
    CHECK([rawStringOutput[sourceAppKey] isEqualToString:@"com.apple.SafariViewService"],
          "sibling key preserved when reserved raw NSString is stripped");

    // Reserved malformed NSURL subclass is stripped.
    RBStubMalformedURL *malformedStub =
        [[RBStubMalformedURL alloc] initWithStubScheme:nil
                                        absoluteString:@"raspberry://auth?bad=%ZZ"];
    stripped = NO;
    NSDictionary *malformedOutput =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:@{
            urlKey: malformedStub,
            sourceAppKey: @"com.apple.mobilesafari",
        }
                                                 urlKey:urlKey
                                    didStripReservedURL:&stripped];
    CHECK(stripped, "malformed reserved NSURL subclass sets didStripReservedURL to YES");
    CHECK(malformedOutput[urlKey] == nil && malformedOutput.count == 1,
          "malformed reserved NSURL subclass is removed");

    // Unexpected non-URL/non-string object under urlKey fails closed.
    stripped = NO;
    NSDictionary *unexpectedOutput =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:@{
            urlKey: @42,
            sourceAppKey: @"jp.naver.lineplay",
        }
                                                 urlKey:urlKey
                                    didStripReservedURL:&stripped];
    CHECK(stripped, "unexpected type under urlKey fails closed with didStripReservedURL = YES");
    CHECK(unexpectedOutput[urlKey] == nil, "unexpected type under urlKey is removed");
    CHECK([unexpectedOutput[sourceAppKey] isEqualToString:@"jp.naver.lineplay"],
          "sibling key preserved when unexpected urlKey object is stripped");

    // Unrelated NSURL is preserved with didStripReservedURL = NO.
    NSURL *lineURL = [NSURL URLWithString:@"line3rdp.jp.naver.lineplay://authorize"];
    NSMutableDictionary *mutableUnrelated = [@{
        urlKey: lineURL,
        sourceAppKey: @"jp.naver.line",
        remoteNotifKey: notifPayload,
    } mutableCopy];
    stripped = YES;
    NSDictionary *unrelatedOutput =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:mutableUnrelated
                                                 urlKey:urlKey
                                    didStripReservedURL:&stripped];
    [mutableUnrelated setObject:@"mutated-after" forKey:@"extra"];
    CHECK(!stripped, "unrelated NSURL sets didStripReservedURL to NO");
    CHECK(![unrelatedOutput isKindOfClass:[NSMutableDictionary class]],
          "preserved launchOptions copy is immutable");
    CHECK([unrelatedOutput[urlKey] isEqual:lineURL],
          "unrelated NSURL is preserved under urlKey");
    CHECK([unrelatedOutput[sourceAppKey] isEqualToString:@"jp.naver.line"] &&
          [unrelatedOutput[remoteNotifKey] isEqualToDictionary:notifPayload] &&
          unrelatedOutput[@"extra"] == nil && unrelatedOutput.count == 3,
          "all sibling keys preserved as immutable snapshot");

    // Mutable input with reserved URL also returns an immutable snapshot.
    NSMutableDictionary *mutableReserved = [@{
        urlKey: [NSURL URLWithString:@"raspberry://auth?ticket=t&state=s"],
        sourceAppKey: @"com.apple.SafariViewService",
    } mutableCopy];
    stripped = NO;
    NSDictionary *mutableReservedOutput =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:mutableReserved
                                                 urlKey:urlKey
                                    didStripReservedURL:&stripped];
    [mutableReserved setObject:@"mutated-after" forKey:@"extra"];
    CHECK(stripped, "mutable reserved launchOptions sets didStripReservedURL to YES");
    CHECK(![mutableReservedOutput isKindOfClass:[NSMutableDictionary class]],
          "stripped launchOptions copy is immutable");
    CHECK(mutableReservedOutput[urlKey] == nil &&
          mutableReservedOutput[@"extra"] == nil &&
          mutableReservedOutput.count == 1,
          "stripped immutable snapshot unaffected by later input mutation");

    // Missing urlKey preserves all keys with didStripReservedURL = NO.
    stripped = YES;
    NSDictionary *noURLKeyOutput =
        [RBAuthCallbackSanitizer sanitizedLaunchOptions:@{sourceAppKey: @"com.example"}
                                                 urlKey:urlKey
                                    didStripReservedURL:&stripped];
    CHECK(!stripped, "launchOptions without urlKey sets didStripReservedURL to NO");
    CHECK([noURLKeyOutput[sourceAppKey] isEqualToString:@"com.example"] &&
          noURLKeyOutput.count == 1,
          "launchOptions without urlKey preserves existing keys");
}

int main(void) {
    @autoreleasepool {
        TestConsumedOpenURLs();
        TestPassedThroughOpenURLs();
        TestSanitizedLaunchOptions();
    }

    if (failures != 0) {
        fprintf(stderr, "auth callback sanitizer tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("auth callback sanitizer tests: ok");
    return 0;
}
