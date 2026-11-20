#ifndef RB_AUTH_UIKIT_LIFECYCLE_STATUS_GATE_H
#define RB_AUTH_UIKIT_LIFECYCLE_STATUS_GATE_H

#import <Foundation/Foundation.h>

#import "RBAuthFlowCoordinator.h"

NS_ASSUME_NONNULL_BEGIN

/// Foundation-only status forwarding policy for one lifecycle binding.
/// Terminal status cleanup runs before the caller's status handler; a terminal
/// status and any later status are delivered at most once. This class does not
/// own or cancel the coordinator.
@interface RBAuthUIKitLifecycleStatusGate : NSObject

@property(nonatomic, readonly) BOOL terminalStatusDelivered;

- (void)forwardStatus:(RBAuthFlowStatus)status
      terminalCleanup:(nullable dispatch_block_t)terminalCleanup
        statusHandler:(nullable RBAuthFlowStatusHandler)statusHandler;

@end

NS_ASSUME_NONNULL_END

#endif
