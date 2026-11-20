#ifndef RB_AUTH_CALLBACK_SANITIZER_H
#define RB_AUTH_CALLBACK_SANITIZER_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Pure Foundation policy for Raspberry's reserved auth-callback scheme.
/// Consumes even malformed `raspberry:` URLs and strips reserved URLs from
/// launch options before stock logging or third-party SDK forwarding can
/// observe them, while leaving unrelated keys and schemes untouched.
@interface RBAuthCallbackSanitizer : NSObject

+ (BOOL)shouldConsumeOpenURL:(nullable NSURL *)url;
+ (BOOL)shouldConsumeRawURLString:(nullable NSString *)rawURLString;
+ (nullable NSDictionary *)sanitizedLaunchOptions:(nullable NSDictionary *)launchOptions
                                           urlKey:(NSString *)urlKey
                              didStripReservedURL:(BOOL * _Nullable)didStripReservedURL;

+ (instancetype)new NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END

#endif
