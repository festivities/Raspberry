#import "RBAuthUIKitOwnerConditions.h"

static BOOL RBAuthUIKitViewIsVisibleInWindow(UIView *view, UIWindow *window) {
    if (view.window != window || window.hidden || window.alpha <= 0.0) {
        return NO;
    }

    for (UIView *candidate = view; candidate != nil;
         candidate = candidate.superview) {
        if (candidate.hidden || candidate.alpha <= 0.0) {
            return NO;
        }
        if (candidate == window) {
            return YES;
        }
    }
    return NO;
}

BOOL RBAuthUIKitOwnerIsForeground(
    id foregroundOwner,
    id owningApplication,
    UIWindow * _Nullable * _Nullable presentationAnchorOut) {
    if (presentationAnchorOut != NULL) {
        *presentationAnchorOut = nil;
    }
    if (![NSThread isMainThread]) {
        return NO;
    }

    UIApplication *currentApplication = UIApplication.sharedApplication;
    if (owningApplication == nil ||
        owningApplication != currentApplication) {
        return NO;
    }
    UIApplication *application = (UIApplication *)owningApplication;

    RBAuthBrowserOwnerFacts facts = {0};
    facts.onMainThread = YES;
    facts.exactOwningApplication = YES;

    UIViewController *owner = nil;
    if ([foregroundOwner isKindOfClass:[UIViewController class]]) {
        facts.foregroundOwnerIsViewController = YES;
        owner = (UIViewController *)foregroundOwner;
    }

    UIView *ownerView = owner.viewIfLoaded;
    facts.ownerViewLoaded = ownerView != nil;
    UIWindow *window = ownerView.window;
    if (ownerView != nil && window != nil) {
        facts.ownerViewAttachedToWindow = YES;
        facts.ownerViewAndWindowVisible =
            RBAuthUIKitViewIsVisibleInWindow(ownerView, window);
        facts.windowIsKey = window.isKeyWindow;

        UIWindowScene *scene = window.windowScene;
        if (scene != nil) {
            for (UIScene *connectedScene in application.connectedScenes) {
                if (connectedScene == scene) {
                    facts.sceneConnectedToOwningApplication = YES;
                    break;
                }
            }
            facts.sceneIsForegroundActive =
                scene.activationState == UISceneActivationStateForegroundActive;
        }
    }
    facts.applicationIsActive =
        application.applicationState == UIApplicationStateActive;

    RBAuthBrowserOwnerConditions conditions =
        RBAuthBrowserOwnerConditionsFromFacts(facts);
    if (!RBAuthBrowserOwnerConditionsAllowPresentation(conditions)) {
        return NO;
    }
    if (presentationAnchorOut != NULL) {
        *presentationAnchorOut = window;
    }
    return YES;
}

@implementation RBAuthUIKitOwnerLiveness

- (BOOL)isForegroundOwner:(id)foregroundOwner
       inOwningApplication:(id)owningApplication {
    return RBAuthUIKitOwnerIsForeground(
        foregroundOwner, owningApplication, NULL);
}

@end
