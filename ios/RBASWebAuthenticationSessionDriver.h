#ifndef RB_AS_WEB_AUTHENTICATION_SESSION_DRIVER_H
#define RB_AS_WEB_AUTHENTICATION_SESSION_DRIVER_H

#import <AuthenticationServices/AuthenticationServices.h>
#import <UIKit/UIKit.h>

#import "RBAuthBrowserSession.h"

NS_ASSUME_NONNULL_BEGIN

/// UIKit-backed public AuthenticationServices driver. It has no URL delegate,
/// plist registration, logging, or callback-forwarding API.
@interface RBASWebAuthenticationSessionDriver : NSObject
    <RBAuthBrowserSessionDriver, ASWebAuthenticationPresentationContextProviding>

@end

NS_ASSUME_NONNULL_END

#endif
