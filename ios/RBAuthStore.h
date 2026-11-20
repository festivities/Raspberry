#ifndef RB_AUTH_STORE_H
#define RB_AUTH_STORE_H

#import <Foundation/Foundation.h>

@class RBEndpoint;

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const RBAuthStoreErrorDomain;

typedef NS_ENUM(NSInteger, RBAuthStoreErrorCode) {
    RBAuthStoreErrorInvalidInput = 1,
    RBAuthStoreErrorNotFound,
    RBAuthStoreErrorOriginMismatch,
    RBAuthStoreErrorCorrupt,
    RBAuthStoreErrorIO,
};

/// Origin-bound persistence for Raspberry's Discord-minted uniqueCode.
/// Touches only <baseDirectory>/raspberry/auth.json and (on commit)
/// <cachesDirectory>/avcookie.na, never modifying the stock Keychain UUID.
@interface RBAuthStore : NSObject

- (nullable instancetype)initWithBaseDirectoryURL:(nullable NSURL *)baseDirectoryURL
                               cachesDirectoryURL:(nullable NSURL *)cachesDirectoryURL
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

/// Reads the persisted uniqueCode if and only if <baseDirectory>/raspberry/auth.json
/// is a secure regular file whose stored origin matches endpoint.httpsOrigin.
- (nullable NSString *)authorizedUniqueCodeForEndpoint:(nullable RBEndpoint *)endpoint
                                                 error:(NSError * _Nullable * _Nullable)error;

/// Validates uniqueCode and endpoint, removes only <cachesDirectory>/avcookie.na
/// (refusing symlinks; ENOENT succeeds), then atomically persists auth.json (0600).
- (BOOL)commitUniqueCode:(nullable NSString *)uniqueCode
             forEndpoint:(nullable RBEndpoint *)endpoint
                   error:(NSError * _Nullable * _Nullable)error;

/// Removes <baseDirectory>/raspberry/auth.json (refusing symlinks; ENOENT succeeds)
/// without touching avcookie.na or any other file.
- (BOOL)clearAuthorizationError:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END

#endif
