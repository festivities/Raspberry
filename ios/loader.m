#import <os/log.h>

// Default os_log is visible to a bounded unified-log query
// (`log show --predicate 'eventMessage CONTAINS "raspberry-ios loader-ready"'`).
// No extra telemetry.

__attribute__((constructor))
static void raspberry_ios_loader_ready(void) {
	os_log(OS_LOG_DEFAULT, "raspberry-ios loader-ready");
}
