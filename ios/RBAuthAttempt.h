#ifndef RB_AUTH_ATTEMPT_H
#define RB_AUTH_ATTEMPT_H

#import <Foundation/Foundation.h>

@class RBEndpoint;

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const RBAuthAttemptErrorDomain;

typedef NS_ENUM(NSInteger, RBAuthAttemptErrorCode) {
    RBAuthAttemptErrorInvalidEndpoint = 1,
    RBAuthAttemptErrorRandomSource,
    RBAuthAttemptErrorInvalidVerifier,
    RBAuthAttemptErrorInvalidClock,
};

typedef NS_ENUM(NSInteger, RBAuthAttemptStage) {
    RBAuthAttemptStageAwaitingCallback = 0,
    RBAuthAttemptStageTicketPending,
    RBAuthAttemptStageExchangeClaimed,
    RBAuthAttemptStageAuthorized,
    RBAuthAttemptStageFailed,
    RBAuthAttemptStageCancelled,
    RBAuthAttemptStageExpired,
};

typedef NS_ENUM(NSInteger, RBAuthCallbackResult) {
    RBAuthCallbackRejected = 0,
    RBAuthCallbackTicketAccepted,
    RBAuthCallbackServerRejected,
};

/// Clock values are monotonic seconds. Production uses systemUptime; injection
/// exists for deterministic synthetic tests and must never move backwards.
@protocol RBAuthAttemptClock <NSObject>
- (NSTimeInterval)monotonicTime;
@end

/// One-use, immutable metadata returned only by an explicit exchange claim.
@interface RBAuthExchangeRequest : NSObject <NSCopying>

@property(nonatomic, copy, readonly) NSString *ticket;
@property(nonatomic, copy, readonly) NSString *verifier;
@property(nonatomic, copy, readonly) NSString *httpsOrigin;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

typedef BOOL (^RBAuthCommitWriter)(RBAuthExchangeRequest *request);

/// In-memory PKCE/auth callback state. It performs no network or persistence.
@interface RBAuthAttempt : NSObject

@property(nonatomic, strong, readonly) NSURL *authorizationURL;
@property(nonatomic, readonly) RBAuthAttemptStage stage;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

+ (nullable instancetype)attemptWithEndpoint:(RBEndpoint *)endpoint
                                       error:(NSError * _Nullable * _Nullable)error;

/// Clock-injectable factory for deterministic tests. Pass nil for systemUptime.
+ (nullable instancetype)attemptWithEndpoint:(RBEndpoint *)endpoint
                                       clock:(nullable id<RBAuthAttemptClock>)clock
                                       error:(NSError * _Nullable * _Nullable)error;

/// RFC 7636 S256 helper; accepts 43–128 base64url ASCII characters
/// ([A-Za-z0-9_-]) only.
+ (nullable NSString *)challengeForVerifier:(NSString *)verifier
                                      error:(NSError * _Nullable * _Nullable)error;

/// Accepts only raspberry://auth with one matching state and either one valid
/// ticket or one allowlisted server error. Invalid callbacks leave an active
/// attempt active; a valid error callback fails it.
- (RBAuthCallbackResult)acceptCallbackURL:(NSURL *)callbackURL;

/// Explicit, foreground-controlled, single-use exchange claim.
- (nullable RBAuthExchangeRequest *)claimExchangeWithOwnerForeground:(BOOL)ownerForeground;

/// Checks the still-current claim and invokes a short synchronous writer under
/// the attempt lock. Other-thread cancellation serializes before or after this
/// commit. The writer must not reenter this attempt or perform network work;
/// nested commits are refused defensively. Do not assume writer side effects
/// can be rolled back if the clock expires while it runs.
- (BOOL)commitWithWriter:(nullable RBAuthCommitWriter)writer;

/// Terminates an in-flight claim after a request failure, without credentials.
- (void)failExchange;

- (void)cancel;

@end

NS_ASSUME_NONNULL_END

#endif
