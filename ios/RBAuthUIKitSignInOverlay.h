#ifndef RB_AUTH_UIKIT_SIGNIN_OVERLAY_H
#define RB_AUTH_UIKIT_SIGNIN_OVERLAY_H

#import <UIKit/UIKit.h>

#import "RBAuthSignInSessionController.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const RBAuthSignInOverlayAccessibilityIdentifier;
FOUNDATION_EXPORT NSString *const RBAuthSignInStatusAccessibilityIdentifier;
FOUNDATION_EXPORT NSString *const RBAuthSignInButtonAccessibilityIdentifier;

/// Main-thread-only UIKit sign-in gate overlay backed by
/// RBAuthSignInSessionController. While unauthorized, attaches a full-screen
/// touch-blocking overlay to the verified foreground owner's view and drives
/// Discord sign-in on button tap. Automatically detaches once authorized.
@interface RBAuthUIKitSignInOverlay : NSObject

@property(nonatomic, readonly) RBAuthSignInSessionController *sessionController;
@property(nonatomic, readonly, getter=isAttached) BOOL attached;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

- (nullable instancetype)initWithSessionController:
    (nullable RBAuthSignInSessionController *)sessionController
    NS_DESIGNATED_INITIALIZER;

/// Main-thread-only. Verifies the supplied foregroundOwner with
/// RBAuthUIKitOwnerIsForeground and attaches, updates, or detaches the overlay
/// view according to sessionController.requiresSignInOverlay.
- (BOOL)syncWithForegroundOwner:(nullable UIViewController *)foregroundOwner;

/// Main-thread-only. Triggers a sign-in attempt using the currently synced
/// foreground owner. Exposed for programmatic/test invocation as well as the
/// button control action.
- (RBAuthFlowStatus)triggerSignIn;

/// Main-thread-only. Removes the overlay view from its superview.
- (void)detachOverlay;

@end

NS_ASSUME_NONNULL_END

#endif
