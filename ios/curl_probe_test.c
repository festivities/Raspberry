#include "RBCurlProbe.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct Curl_easy {
	int unused;
};

struct curl_slist {
	const char *data;
	struct curl_slist *next;
};

enum {
	FAKE_EVENT_EASY_CLEANUP = 1,
	FAKE_EVENT_SLIST_FREE = 2,
	FAKE_BAD_CALL_CODE = 90,
	FAKE_GETINFO_ERROR = 48,
};

enum fake_writer_mode {
	FAKE_WRITER_NORMAL = 0,
	FAKE_WRITER_FILL_CAP,
	FAKE_WRITER_SIZE_OVERFLOW,
};

struct fake_state {
	enum rb_curl_probe_test_case test_case;
	const char *ca_info_path;
	rb_curl_easy *easy;
	struct curl_slist headers;
	rb_curl_write_callback write_callback;
	void *write_data;
	int option_count;
	int perform_count;
	int getinfo_count;
	int cleanup_count;
	int free_count;
	int events[2];
	int event_count;
	int fail_init;
	int fail_append;
	int fail_getinfo;
	int fail_option;
	int fail_option_code;
	rb_curl_code perform_code;
	long status;
	enum fake_writer_mode writer_mode;
	int bad_call;
};

static struct fake_state g;
static struct Curl_easy g_easy;
static int expected_option_at(int index) {
	static const int options[] = {
		RB_CURL_PROBE_OPT_URL,
		RB_CURL_PROBE_OPT_SSL_VERIFYPEER,
		RB_CURL_PROBE_OPT_SSL_VERIFYHOST,
		RB_CURL_PROBE_OPT_FOLLOWLOCATION,
		RB_CURL_PROBE_OPT_PROXY,
		RB_CURL_PROBE_OPT_NOPROXY,
		RB_CURL_PROBE_OPT_TIMEOUT,
		RB_CURL_PROBE_OPT_CONNECTTIMEOUT,
		RB_CURL_PROBE_OPT_NOSIGNAL,
		RB_CURL_PROBE_OPT_FRESH_CONNECT,
		RB_CURL_PROBE_OPT_FORBID_REUSE,
		RB_CURL_PROBE_OPT_WRITEFUNCTION,
		RB_CURL_PROBE_OPT_WRITEDATA,
		RB_CURL_PROBE_OPT_HTTPHEADER,
	};
	const int count = (int)(sizeof(options) / sizeof(options[0]));

	if (index < count) {
		return options[index];
	}
	if (g.ca_info_path != NULL && index == count) {
		return RB_CURL_PROBE_OPT_CAINFO;
	}
	return -1;
}

static const char *expected_url(void) {
	if (g.test_case == RB_CURL_PROBE_TEST_EXPECTED_NAME) {
		return "https://rb-curl-probe-expected.invalid/";
	}
	return "https://rb-curl-probe-wrong-name.invalid/";
}

static void reset_fake(enum rb_curl_probe_test_case test_case,
    const char *ca_info_path) {
	memset(&g, 0, sizeof(g));
	g.test_case = test_case;
	g.ca_info_path = ca_info_path;
	g.status = 200;
	g.fail_option = -1;
}

static rb_curl_easy *fake_easy_init(void) {
	if (g.fail_init) {
		return NULL;
	}
	return &g_easy;
}

static rb_curl_code fake_easy_setopt(rb_curl_easy *easy,
    rb_curl_option option, ...) {
	va_list args;
	rb_curl_code result = RB_CURL_PROBE_CURLE_OK;
	int expected;

	if (easy != &g_easy) {
		g.bad_call = 1;
		return FAKE_BAD_CALL_CODE;
	}
	expected = expected_option_at(g.option_count);
	if (option != expected) {
		g.bad_call = 1;
		return FAKE_BAD_CALL_CODE;
	}

	va_start(args, option);
	switch (option) {
	case RB_CURL_PROBE_OPT_URL: {
		char *value = va_arg(args, char *);
		if (value == NULL || strcmp(value, expected_url()) != 0) {
			g.bad_call = 1;
		}
		break;
	}
	case RB_CURL_PROBE_OPT_SSL_VERIFYPEER:
		if (va_arg(args, long) != 1L) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_SSL_VERIFYHOST:
		if (va_arg(args, long) != 2L) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_FOLLOWLOCATION:
		if (va_arg(args, long) != 0L) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_PROXY: {
		char *value = va_arg(args, char *);
		if (value == NULL || strcmp(value, "") != 0) {
			g.bad_call = 1;
		}
		break;
	}
	case RB_CURL_PROBE_OPT_NOPROXY: {
		char *value = va_arg(args, char *);
		if (value == NULL || strcmp(value, "*") != 0) {
			g.bad_call = 1;
		}
		break;
	}
	case RB_CURL_PROBE_OPT_TIMEOUT:
		if (va_arg(args, long) != RB_CURL_PROBE_TIMEOUT_SECONDS) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_CONNECTTIMEOUT:
		if (va_arg(args, long) != RB_CURL_PROBE_CONNECT_TIMEOUT_SECONDS) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_NOSIGNAL:
	case RB_CURL_PROBE_OPT_FRESH_CONNECT:
	case RB_CURL_PROBE_OPT_FORBID_REUSE:
		if (va_arg(args, long) != 1L) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_WRITEFUNCTION:
		g.write_callback = va_arg(args, rb_curl_write_callback);
		if (g.write_callback == NULL) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_WRITEDATA:
		g.write_data = va_arg(args, void *);
		if (g.write_data == NULL) {
			g.bad_call = 1;
		}
		break;
	case RB_CURL_PROBE_OPT_HTTPHEADER: {
		struct curl_slist *value = va_arg(args, struct curl_slist *);
		if (value != &g.headers || value->data == NULL ||
		    strcmp(value->data, "Host: rb-curl-probe-http-host.invalid") != 0) {
			g.bad_call = 1;
		}
		break;
	}
	case RB_CURL_PROBE_OPT_CAINFO: {
		char *value = va_arg(args, char *);
		if (g.ca_info_path == NULL || value != g.ca_info_path) {
			g.bad_call = 1;
		}
		break;
	}
	default:
		g.bad_call = 1;
		break;
	}
	va_end(args);
	g.option_count++;

	if (option == g.fail_option) {
		result = g.fail_option_code;
	}
	return result;
}

static rb_curl_code fake_easy_perform(rb_curl_easy *easy) {
	char byte = 'x';
	size_t callback_result;
	int expected_count = g.ca_info_path == NULL ? 14 : 15;

	g.perform_count++;
	if (easy != &g_easy || g.perform_count != 1 ||
	    g.option_count != expected_count ||
	    g.write_callback == NULL || g.write_data == NULL ||
	    g.headers.data == NULL ||
	    strcmp(g.headers.data, "Host: rb-curl-probe-http-host.invalid") != 0) {
		g.bad_call = 1;
	}

	switch (g.writer_mode) {
	case FAKE_WRITER_NORMAL:
		callback_result = g.write_callback(&byte, 1, 3, g.write_data);
		if (callback_result != 3) {
			g.bad_call = 1;
		}
		break;
	case FAKE_WRITER_FILL_CAP:
		callback_result = g.write_callback(&byte, 1,
		    RB_CURL_PROBE_RESPONSE_CAP, g.write_data);
		if (callback_result != RB_CURL_PROBE_RESPONSE_CAP) {
			g.bad_call = 1;
		}
		callback_result = g.write_callback(&byte, 1, 1, g.write_data);
		if (callback_result != 0) {
			g.bad_call = 1;
		}
		break;
	case FAKE_WRITER_SIZE_OVERFLOW:
		callback_result = g.write_callback(&byte, SIZE_MAX, 2, g.write_data);
		if (callback_result != 0) {
			g.bad_call = 1;
		}
		break;
	}
	return g.perform_code;
}

static rb_curl_code fake_easy_getinfo(rb_curl_easy *easy,
    rb_curl_info info, ...) {
	va_list args;
	long *status;

	g.getinfo_count++;
	if (easy != &g_easy || g.perform_count != 1 ||
	    g.getinfo_count != 1 ||
	    info != RB_CURL_PROBE_INFO_RESPONSE_CODE) {
		g.bad_call = 1;
		return FAKE_BAD_CALL_CODE;
	}
	va_start(args, info);
	status = va_arg(args, long *);
	va_end(args);
	if (status == NULL) {
		g.bad_call = 1;
		return FAKE_BAD_CALL_CODE;
	}
	if (g.fail_getinfo) {
		return FAKE_GETINFO_ERROR;
	}
	*status = g.status;
	return RB_CURL_PROBE_CURLE_OK;
}

static void fake_easy_cleanup(rb_curl_easy *easy) {
	if (easy != &g_easy || g.event_count >= 2) {
		g.bad_call = 1;
		return;
	}
	g.cleanup_count++;
	g.events[g.event_count++] = FAKE_EVENT_EASY_CLEANUP;
}

static rb_curl_slist *fake_slist_append(rb_curl_slist *list,
    const char *line) {
	if (list != NULL || line == NULL ||
	    strcmp(line, "Host: rb-curl-probe-http-host.invalid") != 0) {
		g.bad_call = 1;
		return NULL;
	}
	if (g.fail_append) {
		return NULL;
	}
	g.headers.data = line;
	g.headers.next = NULL;
	return (rb_curl_slist *)&g.headers;
}

static void fake_slist_free_all(rb_curl_slist *list) {
	if ((list != NULL && list != (rb_curl_slist *)&g.headers) ||
	    g.event_count >= 2) {
		g.bad_call = 1;
		return;
	}
	g.free_count++;
	g.events[g.event_count++] = FAKE_EVENT_SLIST_FREE;
}

static const struct rb_curl_probe_api g_api = {
	.easy_init = fake_easy_init,
	.easy_setopt = fake_easy_setopt,
	.easy_perform = fake_easy_perform,
	.easy_getinfo = fake_easy_getinfo,
	.easy_cleanup = fake_easy_cleanup,
	.slist_append = fake_slist_append,
	.slist_free_all = fake_slist_free_all,
};

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "curl_probe_test:%d: %s\n", \
		    __LINE__, #condition); \
		return 1; \
	} \
} while (0)

static int check_cleanup_order(void) {
	CHECK(g.cleanup_count == 1);
	CHECK(g.free_count == 1);
	CHECK(g.event_count == 2);
	CHECK(g.events[0] == FAKE_EVENT_EASY_CLEANUP);
	CHECK(g.events[1] == FAKE_EVENT_SLIST_FREE);
	CHECK(g.bad_call == 0);
	return 0;
}

static int test_preflight_rejects_implicit_case(void) {
	const struct rb_curl_probe_config config = {
		.test_case = (enum rb_curl_probe_test_case)0,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_result result;

	reset_fake(RB_CURL_PROBE_TEST_EXPECTED_NAME, NULL);
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_PREFLIGHT);
	CHECK(result.curl_code == RB_CURL_PROBE_NO_CURL_CODE);
	CHECK(result.http_status == 0);
	CHECK(g.perform_count == 0);
	CHECK(g.option_count == 0);
	CHECK(g.event_count == 0);
	CHECK(g.bad_call == 0);
	return 0;
}

static int test_preflight_rejects_empty_ca_path(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = "",
	};
	struct rb_curl_probe_result result;

	reset_fake(RB_CURL_PROBE_TEST_EXPECTED_NAME, "");
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_PREFLIGHT);
	CHECK(g.perform_count == 0);
	CHECK(g.option_count == 0);
	CHECK(g.event_count == 0);
	CHECK(g.bad_call == 0);
	return 0;
}

static int test_preflight_rejects_incomplete_api(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_api incomplete = g_api;
	struct rb_curl_probe_result result;

	incomplete.easy_perform = NULL;
	reset_fake(RB_CURL_PROBE_TEST_EXPECTED_NAME, NULL);
	result = rb_curl_probe_run(&incomplete, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_PREFLIGHT);
	CHECK(g.perform_count == 0);
	CHECK(g.option_count == 0);
	CHECK(g.event_count == 0);
	CHECK(g.bad_call == 0);
	return 0;
}

static int test_expected_authority_and_http_error_status(void) {
	static const char ca_path[] = "/synthetic/fixture-root.pem";
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
	g.status = 404;
	g.writer_mode = FAKE_WRITER_NORMAL;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_COMPLETE);
	CHECK(result.curl_code == RB_CURL_PROBE_CURLE_OK);
	CHECK(result.getinfo_code == RB_CURL_PROBE_CURLE_OK);
	CHECK(result.http_status == 404);
	CHECK(g.perform_count == 1);
	CHECK(g.getinfo_count == 1);
	return check_cleanup_order();
}

static int test_wrong_name_authority_is_explicit(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_WRONG_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, NULL);
	g.status = 200;
	g.writer_mode = FAKE_WRITER_NORMAL;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_COMPLETE);
	CHECK(result.curl_code == RB_CURL_PROBE_CURLE_OK);
	CHECK(result.http_status == 200);
	CHECK(g.perform_count == 1);
	CHECK(g.getinfo_count == 1);
	return check_cleanup_order();
}

static int test_easy_init_failure_does_not_cleanup_null_handle(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, NULL);
	g.fail_init = 1;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_EASY_INIT);
	CHECK(result.curl_code == RB_CURL_PROBE_NO_CURL_CODE);
	CHECK(g.perform_count == 0);
	CHECK(g.cleanup_count == 0);
	CHECK(g.free_count == 0);
	CHECK(g.bad_call == 0);
	return 0;
}

static int test_header_allocation_failure_cleans_up(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, NULL);
	g.fail_append = 1;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_HEADER_LIST);
	CHECK(result.curl_code == RB_CURL_PROBE_NO_CURL_CODE);
	CHECK(g.perform_count == 0);
	return check_cleanup_order();
}

static int test_first_setopt_error_stops_and_cleans_up(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, NULL);
	g.fail_option = RB_CURL_PROBE_OPT_SSL_VERIFYHOST;
	g.fail_option_code = 77;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_SETOPT_SSL_VERIFYHOST);
	CHECK(result.curl_code == 77);
	CHECK(g.option_count == 3);
	CHECK(g.perform_count == 0);
	CHECK(g.getinfo_count == 0);
	return check_cleanup_order();
}

static int test_response_cap_and_write_overflow(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, NULL);
	g.writer_mode = FAKE_WRITER_FILL_CAP;
	g.perform_code = RB_CURL_PROBE_CURLE_WRITE_ERROR;
	g.status = 200;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_PERFORM);
	CHECK(result.curl_code == RB_CURL_PROBE_CURLE_WRITE_ERROR);
	CHECK(result.getinfo_code == RB_CURL_PROBE_CURLE_OK);
	CHECK(result.http_status == 200);
	CHECK(g.perform_count == 1);
	CHECK(g.getinfo_count == 1);
	if (check_cleanup_order() != 0) {
		return 1;
	}

	reset_fake(config.test_case, NULL);
	g.writer_mode = FAKE_WRITER_SIZE_OVERFLOW;
	g.perform_code = RB_CURL_PROBE_CURLE_WRITE_ERROR;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_PERFORM);
	CHECK(result.curl_code == RB_CURL_PROBE_CURLE_WRITE_ERROR);
	CHECK(result.http_status == 200);
	CHECK(g.perform_count == 1);
	return check_cleanup_order();
}

static int test_getinfo_failure_keeps_status_unset(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, NULL);
	g.status = 503;
	g.fail_getinfo = 1;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_GETINFO);
	CHECK(result.curl_code == RB_CURL_PROBE_CURLE_OK);
	CHECK(result.getinfo_code == FAKE_GETINFO_ERROR);
	CHECK(result.http_status == 0);
	CHECK(g.perform_count == 1);
	CHECK(g.getinfo_count == 1);
	return check_cleanup_order();
}

int main(void) {
	if (test_preflight_rejects_implicit_case() != 0 ||
	    test_preflight_rejects_empty_ca_path() != 0 ||
	    test_preflight_rejects_incomplete_api() != 0 ||
	    test_expected_authority_and_http_error_status() != 0 ||
	    test_wrong_name_authority_is_explicit() != 0 ||
	    test_easy_init_failure_does_not_cleanup_null_handle() != 0 ||
	    test_header_allocation_failure_cleans_up() != 0 ||
	    test_first_setopt_error_stops_and_cleans_up() != 0 ||
	    test_response_cap_and_write_overflow() != 0 ||
	    test_getinfo_failure_keeps_status_unset() != 0) {
		return 1;
	}
	puts("curl_probe_test: all host-fake cases passed");
	return 0;
}
