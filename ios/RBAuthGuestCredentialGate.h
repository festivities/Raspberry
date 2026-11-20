#ifndef RB_AUTH_GUEST_CREDENTIAL_GATE_H
#define RB_AUTH_GUEST_CREDENTIAL_GATE_H

#import <Foundation/Foundation.h>
#include <stddef.h>

#import "RBAuthFlowCoordinator.h"

@class RBAuthStore;
@class RBEndpoint;

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const RBAuthGuestCredentialGateErrorDomain;

typedef NS_ENUM(NSInteger, RBAuthGuestCredentialGateErrorCode) {
    RBAuthGuestCredentialGateErrorInvalidInput = 1,
    RBAuthGuestCredentialGateErrorOriginMismatch,
    RBAuthGuestCredentialGateErrorInvalidCredential,
};

/// Thread-safe, fail-closed in-memory credential gate bridging RBAuthStore +
/// RBEndpoint to native C guest/generate calls and RBAuthFlowCoordinator commits.
@interface RBAuthGuestCredentialGate : NSObject <RBAuthFlowCommitter>

@property(nonatomic, readonly, getter=isAuthorized) BOOL authorized;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

- (nullable instancetype)initWithEndpoint:(nullable RBEndpoint *)endpoint
                                authStore:(nullable RBAuthStore *)authStore
    NS_DESIGNATED_INITIALIZER;

/// Reloads persisted origin-bound authorization from RBAuthStore. Clears active
/// in-memory authorization and returns NO on missing, mismatched, or corrupt state.
- (BOOL)reloadFromStoreError:(NSError * _Nullable * _Nullable)error;

/// RBAuthFlowCommitter: verifies endpoint.httpsOrigin matches the configured
/// endpoint before committing to RBAuthStore and updating the active slot.
- (BOOL)commitUniqueCode:(NSString *)uniqueCode
             forEndpoint:(RBEndpoint *)endpoint
                   error:(NSError * _Nullable * _Nullable)error;

/// Thread-safe copy of the 36-char lowercase UUID + NUL terminator into buffer
/// (requires buffer != NULL && capacity >= 37). On failure or when unauthorized,
/// zeros buffer[0] (when buffer != NULL && capacity > 0) and returns NO.
- (BOOL)copyAuthorizedUniqueCodeUTF8:(char * _Nullable)buffer capacity:(size_t)capacity;

/// Thread-safe accessor returning a NUL-terminated pointer to an immutable
/// pinned 37-byte slot within an internal ring, or NULL when unauthorized.
- (nullable const char *)authorizedUniqueCodeUTF8;

/// Clears active in-memory authorization immediately; when clearStore is YES,
/// also removes persisted authorization via RBAuthStore.
- (BOOL)invalidateInMemoryAndClearStore:(BOOL)clearStore
                                  error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END

#endif
