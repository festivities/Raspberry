#import "RBAuthUIKitLifecycleStatusGate.h"

#include <stdio.h>

static int failures = 0;
static int events[8];
static NSUInteger eventCount = 0;
static NSUInteger cleanupCalls = 0;
static NSUInteger terminalHandlerCalls = 0;

#define CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", label); \
        failures++; \
    } \
} while (0)

static void RecordTerminalCleanup(void) {
    cleanupCalls++;
    events[eventCount++] = 1;
}

int main(void) {
    @autoreleasepool {
        RBAuthUIKitLifecycleStatusGate *gate =
            [[RBAuthUIKitLifecycleStatusGate alloc] init];

        [gate forwardStatus:RBAuthFlowStatusBrowserPresented
            terminalCleanup:^{ RecordTerminalCleanup(); }
              statusHandler:^(RBAuthFlowStatus status) {
                  CHECK(status == RBAuthFlowStatusBrowserPresented,
                        "nonterminal status is forwarded unchanged");
                  events[eventCount++] = 2;
              }];
        CHECK(!gate.terminalStatusDelivered,
              "browser-presented status keeps the lifecycle observer");
        CHECK(eventCount == 1 && events[0] == 2,
              "nonterminal status does not run terminal cleanup");

        [gate forwardStatus:RBAuthFlowStatusFailed
            terminalCleanup:^{ RecordTerminalCleanup(); }
              statusHandler:^(RBAuthFlowStatus status) {
                  CHECK(status == RBAuthFlowStatusFailed,
                        "terminal status is forwarded unchanged");
                  terminalHandlerCalls++;
                  events[eventCount++] = 3;
                  // A caller may reenter; the duplicate must be fenced before
                  // the nested cleanup or handler can run.
                  [gate forwardStatus:RBAuthFlowStatusCancelled
                      terminalCleanup:^{ RecordTerminalCleanup(); }
                        statusHandler:^(RBAuthFlowStatus nestedStatus) {
                            (void)nestedStatus;
                            terminalHandlerCalls++;
                        }];
              }];

        [gate forwardStatus:RBAuthFlowStatusCancelled
            terminalCleanup:^{ RecordTerminalCleanup(); }
              statusHandler:^(RBAuthFlowStatus status) {
                  (void)status;
                  terminalHandlerCalls++;
              }];

        CHECK(gate.terminalStatusDelivered,
              "terminal status closes the one-attempt gate");
        CHECK(cleanupCalls == 1,
              "terminal cleanup runs exactly once");
        CHECK(terminalHandlerCalls == 1,
              "reentrant and later terminal statuses are not duplicated");
        CHECK(eventCount == 3 && events[1] == 1 && events[2] == 3,
              "cleanup runs before caller terminal notification");
    }

    if (failures != 0) {
        fprintf(stderr, "lifecycle status-gate tests: %d failure(s)\n",
                failures);
        return 1;
    }
    puts("lifecycle status-gate tests: ok");
    return 0;
}
