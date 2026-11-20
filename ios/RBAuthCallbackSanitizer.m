#import "RBAuthCallbackSanitizer.h"

static BOOL RBASCIIHasCaseInsensitivePrefix(NSString *string,
                                            NSUInteger start,
                                            const char *asciiLowerPrefix,
                                            NSUInteger prefixLength) {
    NSUInteger length = string.length;
    if (start > length || length - start < prefixLength) {
        return NO;
    }
    for (NSUInteger i = 0; i < prefixLength; i++) {
        unichar ch = [string characterAtIndex:(start + i)];
        if (ch > 0x7F) {
            return NO;
        }
        if (ch >= 'A' && ch <= 'Z') {
            ch = (unichar)(ch + ('a' - 'A'));
        }
        if (ch != (unichar)(unsigned char)asciiLowerPrefix[i]) {
            return NO;
        }
    }
    return YES;
}

@implementation RBAuthCallbackSanitizer

+ (BOOL)shouldConsumeRawURLString:(nullable NSString *)rawURLString {
    if (rawURLString == nil || ![rawURLString isKindOfClass:[NSString class]]) {
        return NO;
    }

    NSUInteger length = rawURLString.length;
    NSUInteger start = 0;
    while (start < length && [rawURLString characterAtIndex:start] <= 0x20) {
        start++;
    }

    static const char kReservedSchemePrefix[] = "raspberry:";
    static const NSUInteger kReservedSchemePrefixLength = sizeof(kReservedSchemePrefix) - 1;
    return RBASCIIHasCaseInsensitivePrefix(rawURLString,
                                           start,
                                           kReservedSchemePrefix,
                                           kReservedSchemePrefixLength);
}

+ (BOOL)shouldConsumeOpenURL:(nullable NSURL *)url {
    if (url == nil || ![url isKindOfClass:[NSURL class]]) {
        return NO;
    }

    NSString *scheme = url.scheme;
    if (scheme != nil && [scheme caseInsensitiveCompare:@"raspberry"] == NSOrderedSame) {
        return YES;
    }

    return [self shouldConsumeRawURLString:url.absoluteString];
}

+ (nullable NSDictionary *)sanitizedLaunchOptions:(nullable NSDictionary *)launchOptions
                                           urlKey:(NSString *)urlKey
                              didStripReservedURL:(BOOL * _Nullable)didStripReservedURL {
    if (didStripReservedURL != NULL) {
        *didStripReservedURL = NO;
    }
    if (launchOptions == nil) {
        return nil;
    }

    id candidate = (urlKey != nil) ? launchOptions[urlKey] : nil;
    if (candidate == nil) {
        return [launchOptions copy];
    }

    BOOL shouldStrip = NO;
    if ([candidate isKindOfClass:[NSURL class]]) {
        shouldStrip = [self shouldConsumeOpenURL:(NSURL *)candidate];
    } else if ([candidate isKindOfClass:[NSString class]]) {
        shouldStrip = [self shouldConsumeRawURLString:(NSString *)candidate];
    } else {
        // Unexpected non-URL/non-string value under urlKey: fail closed.
        shouldStrip = YES;
    }

    if (!shouldStrip) {
        return [launchOptions copy];
    }

    NSMutableDictionary *sanitized = [launchOptions mutableCopy];
    [sanitized removeObjectForKey:urlKey];
    if (didStripReservedURL != NULL) {
        *didStripReservedURL = YES;
    }
    return [sanitized copy];
}

@end
