#import "RBURLRewrite.h"

#import "../native/endpoint.h"

NSString *const RBURLRewriteErrorDomain = @"org.raspberry.url-rewrite";

static NSError *RBURLRewriteMakeError(RBURLRewriteErrorCode code,
    NSString *message) {
    return [NSError errorWithDomain:RBURLRewriteErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

static BOOL RBIsOwnedHost(NSString * _Nullable host) {
    if (host == nil || host.length == 0 || host.length > RB_HOST_MAX + 1) {
        return NO;
    }
    char ascii[RB_HOST_MAX + 2];
    for (NSUInteger i = 0; i < host.length; i++) {
        unichar c = [host characterAtIndex:i];
        if (c == 0 || c > 0x7f) {
            return NO;
        }
        ascii[i] = (char)c;
    }
    ascii[host.length] = '\0';
    return rb_redirect(ascii) != 0;
}

static NSString * _Nullable RBRemoveControlCharacters(NSString *value) {
    NSCharacterSet *controls = [NSCharacterSet controlCharacterSet];
    NSMutableString *result = [NSMutableString stringWithCapacity:value.length];
    BOOL removed = NO;
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if ([controls characterIsMember:c]) {
            removed = YES;
        } else {
            [result appendFormat:@"%C", c];
        }
    }
    return removed ? [result copy] : nil;
}

static BOOL RBHostCandidateIsOwned(NSString * _Nullable host) {
    if (RBIsOwnedHost(host)) {
        return YES;
    }
    if (host == nil) {
        return NO;
    }

    NSString *decoded = [host stringByRemovingPercentEncoding];
    if (RBIsOwnedHost(decoded)) {
        return YES;
    }

    NSString *withoutControls = RBRemoveControlCharacters(host);
    if (RBIsOwnedHost(withoutControls)) {
        return YES;
    }
    if (decoded != nil && RBIsOwnedHost(RBRemoveControlCharacters(decoded))) {
        return YES;
    }

    // A malformed escape after an otherwise-owned host is still an invalid
    // target authority, not a pass-through URL.
    if (decoded == nil) {
        NSRange percent = [host rangeOfString:@"%"];
        if (percent.location != NSNotFound &&
            RBIsOwnedHost([host substringToIndex:percent.location])) {
            return YES;
        }
    } else {
        NSRange decodedControl = [decoded rangeOfCharacterFromSet:
            [NSCharacterSet controlCharacterSet]];
        if (decodedControl.location != NSNotFound &&
            RBIsOwnedHost([decoded substringToIndex:decodedControl.location])) {
            return YES;
        }
    }

    // An ASCII syntax error after a complete owned name is a malformed
    // authority. Never truncate a non-ASCII IDNA label to an owned prefix.
    NSUInteger invalid = 0;
    while (invalid < host.length) {
        unichar c = [host characterAtIndex:invalid];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '%') {
            invalid++;
            continue;
        }
        if (c > 0x7f) {
            return NO;
        }
        break;
    }
    return invalid > 0 &&
        RBIsOwnedHost([host substringToIndex:invalid]);
}

static BOOL RBLocateHTTPAuthority(NSString *URLString, BOOL *isHTTPS,
    NSUInteger *authorityStart, NSUInteger *authorityEnd) {
    NSRange colon = [URLString rangeOfString:@":"];
    if (colon.location == NSNotFound ||
        (colon.location != 4 && colon.location != 5) ||
        colon.location + 2 >= URLString.length) {
        return NO;
    }
    NSString *scheme = [URLString substringToIndex:colon.location];
    if ([scheme caseInsensitiveCompare:@"http"] == NSOrderedSame) {
        *isHTTPS = NO;
    } else if ([scheme caseInsensitiveCompare:@"https"] == NSOrderedSame) {
        *isHTTPS = YES;
    } else {
        return NO;
    }
    if ([URLString characterAtIndex:colon.location + 1] != '/' ||
        [URLString characterAtIndex:colon.location + 2] != '/') {
        return NO;
    }

    NSUInteger start = colon.location + 3;
    NSUInteger end = start;
    while (end < URLString.length) {
        unichar c = [URLString characterAtIndex:end];
        if (c == '/' || c == '?' || c == '#') {
            break;
        }
        end++;
    }
    *authorityStart = start;
    *authorityEnd = end;
    return YES;
}

static NSString * _Nullable RBHostFromRawAuthority(NSString *authority,
    BOOL *hasUserInfo, BOOL *hasBackslash, NSUInteger *colonCount,
    NSString **portString) {
    if (authority.length == 0 || [authority hasPrefix:@"["]) {
        return nil;
    }
    *hasUserInfo = [authority rangeOfString:@"@"].location != NSNotFound;
    *hasBackslash = [authority rangeOfString:@"\\"].location != NSNotFound;

    NSString *hostPort = authority;
    NSRange at = [authority rangeOfString:@"@" options:NSBackwardsSearch];
    if (at.location != NSNotFound) {
        hostPort = [authority substringFromIndex:at.location + 1];
    }

    NSUInteger firstColon = NSNotFound;
    NSUInteger count = 0;
    for (NSUInteger i = 0; i < hostPort.length; i++) {
        if ([hostPort characterAtIndex:i] == ':') {
            if (firstColon == NSNotFound) {
                firstColon = i;
            }
            count++;
        }
    }
    *colonCount = count;
    if (firstColon == NSNotFound) {
        *portString = nil;
        return hostPort;
    }
    *portString = [hostPort substringFromIndex:firstColon + 1];
    return [hostPort substringToIndex:firstColon];
}

static BOOL RBURLContainsControl(NSString *URLString) {
    return [URLString rangeOfCharacterFromSet:
        [NSCharacterSet controlCharacterSet]].location != NSNotFound;
}

static BOOL RBParsePort(NSString *portString, uint16_t *port) {
    if (portString.length == 0 || portString.length > 5 ||
        (portString.length > 1 &&
            [portString characterAtIndex:0] == '0')) {
        return NO;
    }
    unsigned value = 0;
    for (NSUInteger i = 0; i < portString.length; i++) {
        unichar c = [portString characterAtIndex:i];
        if (c < '0' || c > '9') {
            return NO;
        }
        value = value * 10 + (unsigned)(c - '0');
        if (value > 65535) {
            return NO;
        }
    }
    if (value == 0) {
        return NO;
    }
    *port = (uint16_t)value;
    return YES;
}

static NSString *RBImmutableCopy(NSString *string) {
    return [string copy];
}

@implementation RBURLRewrite

+ (nullable NSString *)rewriteURLString:(nullable NSString *)URLString
                               endpoint:(nullable RBEndpoint *)endpoint
                             didRewrite:(BOOL * _Nullable)didRewrite
                                  error:(NSError * _Nullable * _Nullable)error {
    if (didRewrite != NULL) {
        *didRewrite = NO;
    }
    if (error != NULL) {
        *error = nil;
    }
    if (URLString == nil) {
        if (error != NULL) {
            *error = RBURLRewriteMakeError(RBURLRewriteErrorInvalidInput,
                @"URL rewrite: invalid input");
        }
        return nil;
    }
    NSString *input = [URLString copy];

    BOOL isHTTPS = NO;
    NSUInteger authorityStart = 0;
    NSUInteger authorityEnd = 0;
    if (!RBLocateHTTPAuthority(input, &isHTTPS, &authorityStart,
            &authorityEnd)) {
        return RBImmutableCopy(input);
    }

    NSURLComponents *components =
        [NSURLComponents componentsWithString:input];
    NSString *authority =
        [input substringWithRange:NSMakeRange(authorityStart,
            authorityEnd - authorityStart)];
    BOOL hasUserInfo = NO;
    BOOL hasBackslash = NO;
    NSUInteger colonCount = 0;
    NSString *portString = nil;
    NSString *rawHost = RBHostFromRawAuthority(authority, &hasUserInfo,
        &hasBackslash, &colonCount, &portString);
    BOOL recognized = RBHostCandidateIsOwned(rawHost) ||
        RBHostCandidateIsOwned(components.host);
    if (!recognized && hasBackslash) {
        NSRange slash = [authority rangeOfString:@"\\"];
        NSString *prefix = [authority substringToIndex:slash.location];
        BOOL ignoredUserInfo = NO;
        BOOL ignoredBackslash = NO;
        NSUInteger ignoredColons = 0;
        NSString *ignoredPort = nil;
        NSString *prefixHost = RBHostFromRawAuthority(prefix,
            &ignoredUserInfo, &ignoredBackslash, &ignoredColons, &ignoredPort);
        recognized = RBHostCandidateIsOwned(prefixHost);
    }
    if (!recognized) {
        return RBImmutableCopy(input);
    }

    uint16_t expectedPort = isHTTPS ? 443 : 80;
    uint16_t explicitPort = 0;
    BOOL validExplicitPort = portString == nil ||
        (colonCount == 1 && RBParsePort(portString, &explicitPort) &&
            explicitPort == expectedPort);
    BOOL encodedRawHost = rawHost != nil &&
        [rawHost rangeOfString:@"%"].location != NSNotFound;
    NSString *parsedScheme = components.scheme;
    BOOL parsedSchemeMatches = parsedScheme != nil &&
        [parsedScheme caseInsensitiveCompare:isHTTPS ? @"https" : @"http"] ==
            NSOrderedSame;
    NSNumber *parsedPort = components.port;
    BOOL parsedPortMatches = portString == nil
        ? parsedPort == nil
        : parsedPort != nil &&
            parsedPort.unsignedIntegerValue == explicitPort;
    BOOL parsedHostMatches = RBIsOwnedHost(components.host);
    if (components == nil || !parsedSchemeMatches || !parsedPortMatches ||
        !parsedHostMatches || rawHost == nil || encodedRawHost ||
        !RBIsOwnedHost(rawHost) || hasUserInfo || hasBackslash ||
        RBURLContainsControl(input) ||
        components.user != nil || components.password != nil ||
        colonCount > 1 || !validExplicitPort) {
        if (error != NULL) {
            *error = RBURLRewriteMakeError(
                RBURLRewriteErrorMalformedTarget,
                @"URL rewrite: malformed target URL");
        }
        return nil;
    }

    if (endpoint == nil) {
        if (error != NULL) {
            *error = RBURLRewriteMakeError(
                RBURLRewriteErrorEndpointRequired,
                @"URL rewrite: endpoint required");
        }
        return nil;
    }

    uint16_t mappedPort =
        [endpoint mappedPortForOriginalClientPort:expectedPort];
    NSMutableString *rewritten =
        [NSMutableString stringWithString:
            [input substringToIndex:authorityStart]];
    [rewritten appendString:endpoint.host];
    if (mappedPort != expectedPort) {
        [rewritten appendFormat:@":%u", (unsigned)mappedPort];
    }
    [rewritten appendString:
        [input substringFromIndex:authorityEnd]];

    if (didRewrite != NULL) {
        *didRewrite = YES;
    }
    return RBImmutableCopy(rewritten);
}

@end
