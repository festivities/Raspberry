#import "RBAuthGuestCredentialGate.h"

#import "RBAuthStore.h"
#import "RBEndpoint.h"

#import <os/lock.h>
#import <string.h>

NSString *const RBAuthGuestCredentialGateErrorDomain =
    @"org.raspberry.auth-guest-credential-gate";

enum {
    RBAuthGuestCredentialGateUUIDLength = 36,
    RBAuthGuestCredentialGateUUIDBufferSize = 37,
    RBAuthGuestCredentialGateSlotCount = 8,
};

static NSError *RBMakeGateError(RBAuthGuestCredentialGateErrorCode code, NSString *message) {
    return [NSError errorWithDomain:RBAuthGuestCredentialGateErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey : message}];
}

static void RBSetGateError(NSError * _Nullable * _Nullable outError,
                           RBAuthGuestCredentialGateErrorCode code,
                           NSString *message) {
    if (outError != NULL) {
        *outError = RBMakeGateError(code, message);
    }
}

static BOOL RBExtractCanonicalLowercaseUUIDUTF8(
    NSString * _Nullable value,
    char outUTF8[RBAuthGuestCredentialGateUUIDBufferSize]) {
    if (![value isKindOfClass:[NSString class]] ||
        value.length != RBAuthGuestCredentialGateUUIDLength) {
        return NO;
    }
    char temp[RBAuthGuestCredentialGateUUIDBufferSize];
    for (NSUInteger i = 0; i < RBAuthGuestCredentialGateUUIDLength; i++) {
        unichar c = [value characterAtIndex:i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') {
                return NO;
            }
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return NO;
        }
        temp[i] = (char)c;
    }
    temp[RBAuthGuestCredentialGateUUIDLength] = '\0';
    memcpy(outUTF8, temp, RBAuthGuestCredentialGateUUIDBufferSize);
    return YES;
}

static void RBSecureZeroBytes(void *ptr, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (size > 0) {
        *p++ = 0;
        size--;
    }
}

@interface RBAuthGuestCredentialGate () {
    RBEndpoint *_endpoint;
    RBAuthStore *_authStore;
    os_unfair_lock _stateLock;
    NSInteger _activeSlotIndex;
    NSUInteger _nextSlotIndex;
    char _slots[RBAuthGuestCredentialGateSlotCount][RBAuthGuestCredentialGateUUIDBufferSize];
}
@end

@implementation RBAuthGuestCredentialGate

- (nullable instancetype)initWithEndpoint:(nullable RBEndpoint *)endpoint
                                authStore:(nullable RBAuthStore *)authStore {
    if (![endpoint isKindOfClass:[RBEndpoint class]] ||
        ![authStore isKindOfClass:[RBAuthStore class]]) {
        return nil;
    }
    RBEndpoint *endpointCopy = [endpoint copy];
    if (endpointCopy == nil || endpointCopy.httpsOrigin.length == 0) {
        return nil;
    }
    self = [super init];
    if (self != nil) {
        _endpoint = endpointCopy;
        _authStore = authStore;
        _stateLock = OS_UNFAIR_LOCK_INIT;
        _activeSlotIndex = -1;
        _nextSlotIndex = 0;
        memset(_slots, 0, sizeof(_slots));
    }
    return self;
}

- (void)dealloc {
    RBSecureZeroBytes(_slots, sizeof(_slots));
}

- (void)publishUUIDUTF8:(const char[RBAuthGuestCredentialGateUUIDBufferSize])utf8 {
    os_unfair_lock_lock(&_stateLock);
    NSUInteger slot = _nextSlotIndex;
    if (slot >= RBAuthGuestCredentialGateSlotCount) {
        slot = 0;
    }
    memcpy(_slots[slot], utf8, RBAuthGuestCredentialGateUUIDBufferSize);
    _activeSlotIndex = (NSInteger)slot;
    _nextSlotIndex = (slot + 1) % RBAuthGuestCredentialGateSlotCount;
    os_unfair_lock_unlock(&_stateLock);
}

- (void)clearActiveSlot {
    os_unfair_lock_lock(&_stateLock);
    _activeSlotIndex = -1;
    os_unfair_lock_unlock(&_stateLock);
}

- (BOOL)isAuthorized {
    os_unfair_lock_lock(&_stateLock);
    BOOL authorized =
        (_activeSlotIndex >= 0 && _activeSlotIndex < RBAuthGuestCredentialGateSlotCount);
    os_unfair_lock_unlock(&_stateLock);
    return authorized;
}

- (BOOL)reloadFromStoreError:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }

    @synchronized(self) {
        NSError *storeError = nil;
        NSString *code = [_authStore authorizedUniqueCodeForEndpoint:_endpoint error:&storeError];
        char utf8[RBAuthGuestCredentialGateUUIDBufferSize];
        if (code == nil || !RBExtractCanonicalLowercaseUUIDUTF8(code, utf8)) {
            [self clearActiveSlot];
            if (error != NULL) {
                if (storeError != nil) {
                    *error = storeError;
                } else {
                    *error = RBMakeGateError(RBAuthGuestCredentialGateErrorInvalidCredential,
                                             @"credential gate: invalid stored credential");
                }
            }
            RBSecureZeroBytes(utf8, sizeof(utf8));
            return NO;
        }

        [self publishUUIDUTF8:utf8];
        RBSecureZeroBytes(utf8, sizeof(utf8));
        return YES;
    }
}

- (BOOL)commitUniqueCode:(NSString *)uniqueCode
             forEndpoint:(RBEndpoint *)endpoint
                   error:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }
    if (![endpoint isKindOfClass:[RBEndpoint class]]) {
        RBSetGateError(error,
                       RBAuthGuestCredentialGateErrorInvalidInput,
                       @"credential gate: invalid endpoint");
        return NO;
    }
    if (![endpoint.httpsOrigin isEqualToString:_endpoint.httpsOrigin]) {
        RBSetGateError(error,
                       RBAuthGuestCredentialGateErrorOriginMismatch,
                       @"credential gate: endpoint origin mismatch");
        return NO;
    }

    NSString *codeCopy =
        [uniqueCode isKindOfClass:[NSString class]] ? [uniqueCode copy] : nil;

    @synchronized(self) {
        NSError *storeError = nil;
        if (![_authStore commitUniqueCode:codeCopy forEndpoint:_endpoint error:&storeError]) {
            if (error != NULL) {
                if (storeError != nil) {
                    *error = storeError;
                } else {
                    *error = RBMakeGateError(RBAuthGuestCredentialGateErrorInvalidCredential,
                                             @"credential gate: commit rejected");
                }
            }
            return NO;
        }

        char utf8[RBAuthGuestCredentialGateUUIDBufferSize];
        if (!RBExtractCanonicalLowercaseUUIDUTF8(codeCopy, utf8)) {
            RBSecureZeroBytes(utf8, sizeof(utf8));
            RBSetGateError(error,
                           RBAuthGuestCredentialGateErrorInvalidCredential,
                           @"credential gate: invalid committed credential");
            return NO;
        }

        [self publishUUIDUTF8:utf8];
        RBSecureZeroBytes(utf8, sizeof(utf8));
        return YES;
    }
}

- (BOOL)copyAuthorizedUniqueCodeUTF8:(char * _Nullable)buffer capacity:(size_t)capacity {
    if (buffer == NULL || capacity == 0) {
        return NO;
    }
    if (capacity < RBAuthGuestCredentialGateUUIDBufferSize) {
        buffer[0] = '\0';
        return NO;
    }

    os_unfair_lock_lock(&_stateLock);
    NSInteger idx = _activeSlotIndex;
    if (idx >= 0 && idx < RBAuthGuestCredentialGateSlotCount) {
        memcpy(buffer, _slots[idx], RBAuthGuestCredentialGateUUIDBufferSize);
        os_unfair_lock_unlock(&_stateLock);
        return YES;
    }
    os_unfair_lock_unlock(&_stateLock);

    buffer[0] = '\0';
    return NO;
}

- (nullable const char *)authorizedUniqueCodeUTF8 {
    os_unfair_lock_lock(&_stateLock);
    NSInteger idx = _activeSlotIndex;
    const char *ptr = (idx >= 0 && idx < RBAuthGuestCredentialGateSlotCount)
                          ? _slots[idx]
                          : NULL;
    os_unfair_lock_unlock(&_stateLock);
    return ptr;
}

- (BOOL)invalidateInMemoryAndClearStore:(BOOL)clearStore
                                  error:(NSError * _Nullable * _Nullable)error {
    if (error != NULL) {
        *error = nil;
    }
    [self clearActiveSlot];

    @synchronized(self) {
        [self clearActiveSlot];
        if (!clearStore) {
            return YES;
        }
        return [_authStore clearAuthorizationError:error];
    }
}

@end
