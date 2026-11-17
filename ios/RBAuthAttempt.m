#import "RBAuthAttempt.h"

#import "RBEndpoint.h"

#import <CommonCrypto/CommonDigest.h>
#import <Security/SecRandom.h>
#import <math.h>
#import <string.h>

NSString *const RBAuthAttemptErrorDomain = @"org.raspberry.auth-attempt";

static const NSTimeInterval RBAuthAttemptLifetime = 600.0;
static const NSTimeInterval RBAuthTicketLifetime = 120.0;
static const NSUInteger RBAuthCallbackQueryLimit = 512;
static const NSUInteger RBAuthCallbackURLLimit = 2048;
static NSString *const RBAuthReturnURL = @"raspberry://auth";
static NSString *const RBAuthEncodedReturnURL = @"raspberry%3A%2F%2Fauth";
static NSString *const RBAuthStartPath = @"/auth/v1/discord/start";

@interface RBSystemAuthClock : NSObject <RBAuthAttemptClock>
@end

@implementation RBSystemAuthClock

- (NSTimeInterval)monotonicTime {
    return NSProcessInfo.processInfo.systemUptime;
}

@end

@interface RBAuthExchangeRequest () {
    NSString *_ticket;
    NSString *_verifier;
    NSString *_httpsOrigin;
}

- (instancetype)initWithTicket:(NSString *)ticket verifier:(NSString *)verifier origin:(NSString *)origin;

@end

@implementation RBAuthExchangeRequest

- (instancetype)initWithTicket:(NSString *)ticket verifier:(NSString *)verifier origin:(NSString *)origin {
    self = [super init];
    if (self != nil) {
        _ticket = [ticket copy];
        _verifier = [verifier copy];
        _httpsOrigin = [origin copy];
    }
    return self;
}

- (NSString *)ticket {
    return _ticket;
}

- (NSString *)verifier {
    return _verifier;
}

- (NSString *)httpsOrigin {
    return _httpsOrigin;
}

- (id)copyWithZone:(NSZone *)zone {
    (void)zone;
    return self;
}

@end

@interface RBParsedAuthCallback : NSObject
@property(nonatomic, copy) NSString *state;
@property(nonatomic, copy, nullable) NSString *ticket;
@property(nonatomic, copy, nullable) NSString *error;
@end

@implementation RBParsedAuthCallback
@end

@interface RBAuthAttempt () {
    id<RBAuthAttemptClock> _clock;
    NSURL *_authorizationURL;
    NSTimeInterval _lastTime;
    NSTimeInterval _deadline;
    NSTimeInterval _ticketDeadline;
    NSString *_origin;
    NSString *_state;
    NSString *_verifier;
    NSString *_ticket;
    RBAuthExchangeRequest *_claimedRequest;
    RBAuthAttemptStage _stage;
    BOOL _commitInProgress;
}

- (instancetype)initPrivateWithClock:(id<RBAuthAttemptClock>)clock
                                origin:(NSString *)origin
                                 state:(NSString *)state
                              verifier:(NSString *)verifier
                             challenge:(NSString *)challenge
                             startTime:(NSTimeInterval)startTime;

@end

static NSError *RBAuthError(RBAuthAttemptErrorCode code, NSString *message) {
    return [NSError errorWithDomain:RBAuthAttemptErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey : message}];
}

static NSString *RBBase64URL(NSData *data) {
    NSString *encoded = [data base64EncodedStringWithOptions:0];
    encoded = [encoded stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    encoded = [encoded stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSRange padding = [encoded rangeOfString:@"="];
    if (padding.location != NSNotFound) {
        encoded = [encoded substringToIndex:padding.location];
    }
    return encoded;
}

static BOOL RBToken(NSString *value, NSUInteger minLength, NSUInteger maxLength) {
    if (value == nil || value.length < minLength || value.length > maxLength) {
        return NO;
    }
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        BOOL ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok) {
            return NO;
        }
    }
    return YES;
}

static BOOL RBStateEqual(NSString *a, NSString *b) {
    NSUInteger maxLength = MAX(a.length, b.length);
    NSUInteger difference = a.length ^ b.length;
    for (NSUInteger i = 0; i < maxLength; i++) {
        unichar ca = i < a.length ? [a characterAtIndex:i] : 0;
        unichar cb = i < b.length ? [b characterAtIndex:i] : 0;
        difference |= (NSUInteger)(ca ^ cb);
    }
    return difference == 0;
}

static BOOL RBAllowedCallbackError(NSString *value) {
    return [value isEqualToString:@"denied"] || [value isEqualToString:@"expired"] ||
           [value isEqualToString:@"banned"] || [value isEqualToString:@"server"];
}

static RBParsedAuthCallback *RBParseCallbackURL(NSURL *url) {
    if (url == nil || url.absoluteString.length > RBAuthCallbackURLLimit) {
        return nil;
    }
    NSString *absolute = url.absoluteString;
    NSRange qmark = [absolute rangeOfString:@"?"];
    if (qmark.location == NSNotFound ||
        ![[absolute substringToIndex:qmark.location] isEqualToString:RBAuthReturnURL] ||
        [absolute rangeOfString:@"#"].location != NSNotFound) {
        return nil;
    }

    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (components == nil || ![components.scheme isEqualToString:@"raspberry"] ||
        ![components.host isEqualToString:@"auth"] || components.user != nil ||
        components.password != nil || components.port != nil ||
        ![components.percentEncodedPath isEqualToString:@""] ||
        components.percentEncodedFragment != nil || components.percentEncodedQuery.length == 0 ||
        components.percentEncodedQuery.length > RBAuthCallbackQueryLimit) {
        return nil;
    }

    NSString *state = nil;
    NSString *ticket = nil;
    NSString *serverError = nil;
    NSArray<NSString *> *pairs = [components.percentEncodedQuery componentsSeparatedByString:@"&"];
    if (pairs.count == 0 || pairs.count > 3) {
        return nil;
    }
    for (NSString *pair in pairs) {
        if (pair.length == 0) {
            return nil;
        }
        NSRange equals = [pair rangeOfString:@"="];
        if (equals.location == NSNotFound || equals.location == 0 ||
            [pair rangeOfString:@"=" options:0
                          range:NSMakeRange(equals.location + 1, pair.length - equals.location - 1)]
                  .location != NSNotFound) {
            return nil;
        }
        NSString *key = [pair substringToIndex:equals.location];
        NSString *value = [pair substringFromIndex:equals.location + 1];
        if (value.length == 0 || [key rangeOfString:@"%"].location != NSNotFound ||
            [key rangeOfString:@"+"].location != NSNotFound || [value rangeOfString:@"%"].location != NSNotFound ||
            [value rangeOfString:@"+"].location != NSNotFound) {
            return nil;
        }
        if ([key isEqualToString:@"state"] && state == nil) {
            state = value;
        } else if ([key isEqualToString:@"ticket"] && ticket == nil) {
            ticket = value;
        } else if ([key isEqualToString:@"error"] && serverError == nil) {
            serverError = value;
        } else {
            return nil;
        }
    }
    BOOL hasTicket = ticket != nil;
    BOOL hasError = serverError != nil;
    if (!RBToken(state, 16, 64) || hasTicket == hasError ||
        (hasTicket && !RBToken(ticket, 43, 43)) ||
        (hasError && !RBAllowedCallbackError(serverError))) {
        return nil;
    }
    RBParsedAuthCallback *parsed = [[RBParsedAuthCallback alloc] init];
    parsed.state = state;
    parsed.ticket = ticket;
    parsed.error = serverError;
    return parsed;
}

@implementation RBAuthAttempt

+ (nullable instancetype)attemptWithEndpoint:(RBEndpoint *)endpoint error:(NSError **)error {
    return [self attemptWithEndpoint:endpoint clock:nil error:error];
}

+ (nullable instancetype)attemptWithEndpoint:(RBEndpoint *)endpoint
                                       clock:(id<RBAuthAttemptClock>)clock
                                       error:(NSError **)error {
    if (error != NULL) {
        *error = nil;
    }
    if (endpoint == nil) {
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorInvalidEndpoint, @"auth attempt: invalid endpoint");
        }
        return nil;
    }

    NSString *origin = endpoint.httpsOrigin;
    NSString *expectedOrigin = [endpoint mappedPortForOriginalClientPort:443] == 443
                                   ? [NSString stringWithFormat:@"https://%@", endpoint.host]
                                   : [NSString stringWithFormat:@"https://%@:%u", endpoint.host,
                                                                [endpoint mappedPortForOriginalClientPort:443]];
    if (origin.length == 0 || ![origin isEqualToString:expectedOrigin]) {
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorInvalidEndpoint, @"auth attempt: invalid endpoint");
        }
        return nil;
    }

    id<RBAuthAttemptClock> selectedClock = clock ?: [[RBSystemAuthClock alloc] init];
    NSTimeInterval now = [selectedClock monotonicTime];
    NSTimeInterval deadline = now + RBAuthAttemptLifetime;
    if (!isfinite(now) || now < 0 || !isfinite(deadline) || deadline <= now) {
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorInvalidClock, @"auth attempt: invalid clock");
        }
        return nil;
    }

    uint8_t verifierBytes[32] = {0};
    uint8_t stateBytes[16] = {0};
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof verifierBytes, verifierBytes) != errSecSuccess ||
        SecRandomCopyBytes(kSecRandomDefault, sizeof stateBytes, stateBytes) != errSecSuccess) {
        memset(verifierBytes, 0, sizeof verifierBytes);
        memset(stateBytes, 0, sizeof stateBytes);
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorRandomSource, @"auth attempt: secure random unavailable");
        }
        return nil;
    }
    NSString *verifier = RBBase64URL([NSData dataWithBytes:verifierBytes length:sizeof verifierBytes]);
    NSString *state = RBBase64URL([NSData dataWithBytes:stateBytes length:sizeof stateBytes]);
    memset(verifierBytes, 0, sizeof verifierBytes);
    memset(stateBytes, 0, sizeof stateBytes);

    NSError *challengeError = nil;
    NSString *challenge = [self challengeForVerifier:verifier error:&challengeError];
    if (challenge == nil) {
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorInvalidVerifier, @"auth attempt: PKCE generation failed");
        }
        return nil;
    }
    RBAuthAttempt *attempt = [[self alloc] initPrivateWithClock:selectedClock
                                                        origin:origin
                                                         state:state
                                                      verifier:verifier
                                                     challenge:challenge
                                                     startTime:now];
    if (attempt == nil && error != NULL) {
        *error = RBAuthError(RBAuthAttemptErrorInvalidEndpoint, @"auth attempt: invalid endpoint");
    }
    return attempt;
}

+ (nullable NSString *)challengeForVerifier:(NSString *)verifier error:(NSError **)error {
    if (error != NULL) {
        *error = nil;
    }
    if (!RBToken(verifier, 43, 128)) {
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorInvalidVerifier, @"auth attempt: invalid verifier");
        }
        return nil;
    }
    NSData *ascii = [verifier dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:NO];
    if (ascii == nil || ascii.length != verifier.length || ascii.length > UINT32_MAX) {
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorInvalidVerifier, @"auth attempt: invalid verifier");
        }
        return nil;
    }
    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    if (CC_SHA256(ascii.bytes, (CC_LONG)ascii.length, digest) == NULL) {
        memset(digest, 0, sizeof digest);
        if (error != NULL) {
            *error = RBAuthError(RBAuthAttemptErrorInvalidVerifier, @"auth attempt: challenge failed");
        }
        return nil;
    }
    NSString *challenge = RBBase64URL([NSData dataWithBytes:digest length:sizeof digest]);
    memset(digest, 0, sizeof digest);
    return challenge;
}

- (instancetype)initPrivateWithClock:(id<RBAuthAttemptClock>)clock
                                origin:(NSString *)origin
                                 state:(NSString *)state
                              verifier:(NSString *)verifier
                             challenge:(NSString *)challenge
                             startTime:(NSTimeInterval)startTime {
    NSString *urlString = [NSString stringWithFormat:@"%@%@?challenge=%@&return=%@&state=%@",
                                                     origin, RBAuthStartPath, challenge,
                                                     RBAuthEncodedReturnURL, state];
    NSURL *url = [NSURL URLWithString:urlString];
    if (url == nil) {
        return nil;
    }
    self = [super init];
    if (self != nil) {
        _clock = clock;
        _origin = [origin copy];
        _state = [state copy];
        _verifier = [verifier copy];
        _deadline = startTime + RBAuthAttemptLifetime;
        _lastTime = startTime;
        _stage = RBAuthAttemptStageAwaitingCallback;
        _authorizationURL = url;
    }
    return self;
}

- (NSURL *)authorizationURL {
    return _authorizationURL;
}

- (RBAuthAttemptStage)stage {
    @synchronized(self) {
        [self refreshTimeLocked];
        return _stage;
    }
}

- (RBAuthCallbackResult)acceptCallbackURL:(NSURL *)callbackURL {
    RBParsedAuthCallback *parsed = RBParseCallbackURL(callbackURL);
    if (parsed == nil) {
        return RBAuthCallbackRejected;
    }
    @synchronized(self) {
        if (![self refreshTimeLocked] || _stage != RBAuthAttemptStageAwaitingCallback ||
            !RBStateEqual(_state, parsed.state)) {
            return RBAuthCallbackRejected;
        }
        if (parsed.error != nil) {
            [self clearSecretsLocked];
            _stage = RBAuthAttemptStageFailed;
            return RBAuthCallbackServerRejected;
        }
        if (parsed.ticket == nil) {
            return RBAuthCallbackRejected;
        }
        _ticket = [parsed.ticket copy];
        _state = nil;
        NSTimeInterval now = _lastTime;
        _ticketDeadline = now >= _deadline - RBAuthTicketLifetime ? _deadline : now + RBAuthTicketLifetime;
        _stage = RBAuthAttemptStageTicketPending;
        return RBAuthCallbackTicketAccepted;
    }
}

- (nullable RBAuthExchangeRequest *)claimExchangeWithOwnerForeground:(BOOL)ownerForeground {
    @synchronized(self) {
        if (![self refreshTimeLocked] || _stage != RBAuthAttemptStageTicketPending ||
            _ticket == nil || _verifier == nil || !ownerForeground) {
            return nil;
        }
        _claimedRequest = [[RBAuthExchangeRequest alloc] initWithTicket:_ticket
                                                               verifier:_verifier
                                                                  origin:_origin];
        _ticket = nil;
        _verifier = nil;
        _state = nil;
        _stage = RBAuthAttemptStageExchangeClaimed;
        return _claimedRequest;
    }
}

- (BOOL)commitWithWriter:(RBAuthCommitWriter)writer {
    @synchronized(self) {
        if (_commitInProgress || ![self refreshTimeLocked] ||
            _stage != RBAuthAttemptStageExchangeClaimed ||
            _claimedRequest == nil) {
            return NO;
        }
        if (writer == nil) {
            [self clearSecretsLocked];
            _stage = RBAuthAttemptStageFailed;
            return NO;
        }
        RBAuthExchangeRequest *claimedRequest = _claimedRequest;
        _commitInProgress = YES;
        BOOL committed = NO;
        @try {
            committed = writer(claimedRequest);
        } @catch (NSException *exception) {
            (void)exception;
            committed = NO;
        }
        _commitInProgress = NO;
        // A recursive writer may call cancel, failExchange, or stage (which can
        // observe expiry). Never overwrite any such terminal transition.
        if (_stage != RBAuthAttemptStageExchangeClaimed ||
            ![self refreshTimeLocked] || _stage != RBAuthAttemptStageExchangeClaimed) {
            return NO;
        }
        if (!committed) {
            [self clearSecretsLocked];
            _stage = RBAuthAttemptStageFailed;
            return NO;
        }
        [self clearSecretsLocked];
        _stage = RBAuthAttemptStageAuthorized;
        return YES;
    }
}

- (void)failExchange {
    @synchronized(self) {
        if (_stage == RBAuthAttemptStageExchangeClaimed) {
            [self clearSecretsLocked];
            _stage = RBAuthAttemptStageFailed;
        }
    }
}

- (void)cancel {
    @synchronized(self) {
        if (_stage == RBAuthAttemptStageAwaitingCallback ||
            _stage == RBAuthAttemptStageTicketPending ||
            _stage == RBAuthAttemptStageExchangeClaimed) {
            [self clearSecretsLocked];
            _stage = RBAuthAttemptStageCancelled;
        }
    }
}

- (BOOL)refreshTimeLocked {
    if (_stage == RBAuthAttemptStageAuthorized || _stage == RBAuthAttemptStageFailed ||
        _stage == RBAuthAttemptStageCancelled || _stage == RBAuthAttemptStageExpired) {
        return NO;
    }
    NSTimeInterval now = [_clock monotonicTime];
    if (!isfinite(now) || now < _lastTime) {
        [self clearSecretsLocked];
        _stage = RBAuthAttemptStageFailed;
        return NO;
    }
    _lastTime = now;
    if (now >= _deadline ||
        ((_stage == RBAuthAttemptStageTicketPending || _stage == RBAuthAttemptStageExchangeClaimed) &&
         now >= _ticketDeadline)) {
        [self clearSecretsLocked];
        _stage = RBAuthAttemptStageExpired;
        return NO;
    }
    return YES;
}

- (void)clearSecretsLocked {
    _state = nil;
    _ticket = nil;
    _verifier = nil;
    _claimedRequest = nil;
}

@end
