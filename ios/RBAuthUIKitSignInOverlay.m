#import "RBAuthUIKitSignInOverlay.h"

#import "RBAuthUIKitOwnerConditions.h"

NSString *const RBAuthSignInOverlayAccessibilityIdentifier =
    @"raspberry.auth.signin.overlay";
NSString *const RBAuthSignInStatusAccessibilityIdentifier =
    @"raspberry.auth.signin.status";
NSString *const RBAuthSignInButtonAccessibilityIdentifier =
    @"raspberry.auth.signin.button";

@interface RBAuthUIKitSignInOverlay ()
@property(nonatomic, strong) RBAuthSignInSessionController *sessionController;
@property(nonatomic, weak, nullable) UIViewController *foregroundOwner;
@property(nonatomic, strong, nullable) UIView *overlayView;
@property(nonatomic, strong, nullable) UIView *cardView;
@property(nonatomic, strong, nullable) UILabel *titleLabel;
@property(nonatomic, strong, nullable) UILabel *statusLabel;
@property(nonatomic, strong, nullable) UIButton *signInButton;
- (void)ensureViewsCreated;
- (void)updateContentsForCurrentState;
- (void)handleSignInButtonTap:(id)sender;
@end

@implementation RBAuthUIKitSignInOverlay

- (nullable instancetype)initWithSessionController:
    (RBAuthSignInSessionController *)sessionController {
    if (![NSThread isMainThread] || sessionController == nil) {
        return nil;
    }
    self = [super init];
    if (self == nil) {
        return nil;
    }
    _sessionController = sessionController;
    return self;
}

- (BOOL)isAttached {
    return _overlayView != nil && _overlayView.superview != nil;
}

- (BOOL)syncWithForegroundOwner:(UIViewController *)foregroundOwner {
    if (![NSThread isMainThread]) {
        return NO;
    }
    if (!_sessionController.requiresSignInOverlay) {
        [self detachOverlay];
        return YES;
    }
    if (![foregroundOwner isKindOfClass:[UIViewController class]] ||
        !RBAuthUIKitOwnerIsForeground(
            foregroundOwner, UIApplication.sharedApplication, NULL)) {
        return NO;
    }
    UIView *hostView = foregroundOwner.viewIfLoaded;
    if (hostView == nil) {
        return NO;
    }

    _foregroundOwner = foregroundOwner;
    [self ensureViewsCreated];
    if (_overlayView.superview != hostView) {
        [_overlayView removeFromSuperview];
        _overlayView.frame = hostView.bounds;
        [hostView addSubview:_overlayView];
    } else {
        _overlayView.frame = hostView.bounds;
        [hostView bringSubviewToFront:_overlayView];
    }
    [self updateContentsForCurrentState];
    return YES;
}

- (RBAuthFlowStatus)triggerSignIn {
    if (![NSThread isMainThread]) {
        return RBAuthFlowStatusMainThreadRequired;
    }
    if (!_sessionController.requiresSignInOverlay) {
        [self detachOverlay];
        return RBAuthFlowStatusAuthorized;
    }
    UIViewController *owner = _foregroundOwner;
    if (owner == nil ||
        !RBAuthUIKitOwnerIsForeground(
            owner, UIApplication.sharedApplication, NULL)) {
        [self updateContentsForCurrentState];
        return RBAuthFlowStatusInvalidRequest;
    }

    __weak typeof(self) weakSelf = self;
    RBAuthFlowStatus status = [_sessionController
        startSignInWithForegroundOwner:owner
                         statusHandler:^(RBAuthFlowStatus flowStatus) {
                             RBAuthUIKitSignInOverlay *strongSelf = weakSelf;
                             if (strongSelf == nil || ![NSThread isMainThread]) {
                                 return;
                             }
                             if (flowStatus == RBAuthFlowStatusAuthorized ||
                                 !strongSelf->_sessionController
                                      .requiresSignInOverlay) {
                                 [strongSelf detachOverlay];
                                 return;
                             }
                             [strongSelf updateContentsForCurrentState];
                         }];
    if (!_sessionController.requiresSignInOverlay) {
        [self detachOverlay];
    } else {
        [self updateContentsForCurrentState];
    }
    return status;
}

- (void)detachOverlay {
    if (![NSThread isMainThread]) {
        return;
    }
    [_overlayView removeFromSuperview];
}

- (void)ensureViewsCreated {
    if (_overlayView != nil) {
        return;
    }

    UIView *overlay = [[UIView alloc] initWithFrame:CGRectZero];
    overlay.autoresizingMask =
        UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    overlay.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.72];
    overlay.userInteractionEnabled = YES;
    overlay.accessibilityIdentifier =
        RBAuthSignInOverlayAccessibilityIdentifier;

    UIView *card = [[UIView alloc] initWithFrame:CGRectZero];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor colorWithRed:0.12
                                           green:0.13
                                            blue:0.16
                                           alpha:0.96];
    card.layer.cornerRadius = 16.0;
    card.clipsToBounds = YES;

    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    titleLabel.text = @"Sign in to LINE PLAY";
    titleLabel.textColor = UIColor.whiteColor;
    titleLabel.font = [UIFont boldSystemFontOfSize:20.0];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    titleLabel.numberOfLines = 0;

    UILabel *statusLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    statusLabel.textColor = [UIColor colorWithWhite:0.88 alpha:1.0];
    statusLabel.font = [UIFont systemFontOfSize:14.0];
    statusLabel.textAlignment = NSTextAlignmentCenter;
    statusLabel.numberOfLines = 0;
    statusLabel.accessibilityIdentifier =
        RBAuthSignInStatusAccessibilityIdentifier;

    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    button.backgroundColor = [UIColor colorWithRed:0.35
                                             green:0.40
                                              blue:0.95
                                             alpha:1.0];
    [button setTitle:@"Sign in with Discord" forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [button setTitleColor:[UIColor colorWithWhite:1.0 alpha:0.45]
                 forState:UIControlStateDisabled];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    button.layer.cornerRadius = 10.0;
    button.clipsToBounds = YES;
    button.accessibilityIdentifier = RBAuthSignInButtonAccessibilityIdentifier;
    [button addTarget:self
               action:@selector(handleSignInButtonTap:)
     forControlEvents:UIControlEventTouchUpInside];

    [card addSubview:titleLabel];
    [card addSubview:statusLabel];
    [card addSubview:button];
    [overlay addSubview:card];

    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:overlay.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:overlay.centerYAnchor],
        [card.widthAnchor constraintLessThanOrEqualToConstant:320.0],
        [card.leadingAnchor
            constraintGreaterThanOrEqualToAnchor:overlay.leadingAnchor
                                        constant:24.0],
        [overlay.trailingAnchor
            constraintGreaterThanOrEqualToAnchor:card.trailingAnchor
                                        constant:24.0],

        [titleLabel.topAnchor constraintEqualToAnchor:card.topAnchor
                                             constant:24.0],
        [titleLabel.leadingAnchor constraintEqualToAnchor:card.leadingAnchor
                                                 constant:20.0],
        [card.trailingAnchor constraintEqualToAnchor:titleLabel.trailingAnchor
                                            constant:20.0],

        [statusLabel.topAnchor constraintEqualToAnchor:titleLabel.bottomAnchor
                                              constant:12.0],
        [statusLabel.leadingAnchor constraintEqualToAnchor:card.leadingAnchor
                                                  constant:20.0],
        [card.trailingAnchor constraintEqualToAnchor:statusLabel.trailingAnchor
                                            constant:20.0],

        [button.topAnchor constraintEqualToAnchor:statusLabel.bottomAnchor
                                         constant:20.0],
        [button.leadingAnchor constraintEqualToAnchor:card.leadingAnchor
                                             constant:20.0],
        [card.trailingAnchor constraintEqualToAnchor:button.trailingAnchor
                                            constant:20.0],
        [button.heightAnchor constraintEqualToConstant:46.0],
        [card.bottomAnchor constraintEqualToAnchor:button.bottomAnchor
                                          constant:24.0],
    ]];

    _overlayView = overlay;
    _cardView = card;
    _titleLabel = titleLabel;
    _statusLabel = statusLabel;
    _signInButton = button;
}

- (void)updateContentsForCurrentState {
    if (_overlayView == nil) {
        return;
    }
    RBAuthSignInGateState state = _sessionController.state;
    switch (state) {
    case RBAuthSignInGateStateSignInRequired:
        _statusLabel.text =
            @"Sign in with Discord to connect to this server.";
        break;
    case RBAuthSignInGateStateAttemptInProgress:
        _statusLabel.text = @"Completing Discord sign-in...";
        break;
    case RBAuthSignInGateStateRetryRequired:
        if (_sessionController.lastFlowStatus == RBAuthFlowStatusCancelled) {
            _statusLabel.text =
                @"Sign-in was cancelled. Tap below to try again.";
        } else {
            _statusLabel.text =
                @"Sign-in could not be completed. Tap below to try again.";
        }
        break;
    case RBAuthSignInGateStateAuthorized:
        _statusLabel.text = @"Signed in.";
        break;
    }

    BOOL canStart = _sessionController.canStartSignIn;
    _signInButton.enabled = canStart;
    _signInButton.alpha = canStart ? 1.0 : 0.6;
}

- (void)handleSignInButtonTap:(id)sender {
    (void)sender;
    [self triggerSignIn];
}

@end
