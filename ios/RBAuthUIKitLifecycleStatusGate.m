#import "RBAuthUIKitLifecycleStatusGate.h"

static BOOL RBAuthUIKitLifecycleStatusIsTerminal(RBAuthFlowStatus status) {
    switch (status) {
        case RBAuthFlowStatusBrowserStarting:
        case RBAuthFlowStatusBrowserPresented:
        case RBAuthFlowStatusWaitingForOwningApplicationForeground:
        case RBAuthFlowStatusExchangeInProgress:
            return NO;
        default:
            // The binding is one-attempt-only. Unknown future states fail
            // closed so they cannot leave a stale application observer alive.
            return YES;
    }
}

@interface RBAuthUIKitLifecycleStatusGate ()
@property(nonatomic) BOOL terminalStatusDelivered;
@end

@implementation RBAuthUIKitLifecycleStatusGate

- (void)forwardStatus:(RBAuthFlowStatus)status
      terminalCleanup:(dispatch_block_t)terminalCleanup
        statusHandler:(RBAuthFlowStatusHandler)statusHandler {
    if (_terminalStatusDelivered) {
        return;
    }

    if (RBAuthUIKitLifecycleStatusIsTerminal(status)) {
        // Fence reentrant/duplicate delivery before cleanup or caller code.
        _terminalStatusDelivered = YES;
        if (terminalCleanup != nil) {
            terminalCleanup();
        }
    }

    if (statusHandler != nil) {
        statusHandler(status);
    }
}

@end
