#ifndef RB_AUTH_UIKIT_OWNER_CONDITIONS_H
#define RB_AUTH_UIKIT_OWNER_CONDITIONS_H

#import <UIKit/UIKit.h>

#import "RBAuthBrowserSession.h"
#import "RBAuthFlowCoordinator.h"

NS_ASSUME_NONNULL_BEGIN

/// One public UIKit gate shared by browser presentation and flow liveness.
/// Inspects only the exact borrowed owner and application arguments; it never
/// searches for or substitutes another window/controller. On success,
/// presentationAnchorOut receives that owner's visible key window.
FOUNDATION_EXPORT BOOL RBAuthUIKitOwnerIsForeground(
    id _Nullable foregroundOwner,
    id _Nullable owningApplication,
    UIWindow * _Nullable * _Nullable presentationAnchorOut);

/// Stateless synchronous adapter for RBAuthFlowOwnerLiveness.
@interface RBAuthUIKitOwnerLiveness : NSObject <RBAuthFlowOwnerLiveness>
@end

NS_ASSUME_NONNULL_END

#endif
