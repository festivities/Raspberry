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
	FAKE_EVENT_HEADER_FREE = 2,
	FAKE_EVENT_RESOLVE_FREE = 3,
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
	struct curl_slist headers;
	struct curl_slist resolves;
	rb_curl_write_callback write_callback;
	void *write_data;
	struct curl_slist *header_option_value;
	struct curl_slist *resolve_option_value;
	int option_count;
	int append_count;
	int perform_count;
	int getinfo_count;
	int cleanup_count;
	int free_count;
	int events[3];
	struct curl_slist *freed_lists[2];
	int event_count;
	int fail_init;
	int fail_append_at;
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
static const char g_test_ca_path[] = "/synthetic/fixture-root.pem";

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
		RB_CURL_PROBE_OPT_RESOLVE,
		RB_CURL_PROBE_OPT_CAINFO,
	};
	const int count = (int)(sizeof(options) / sizeof(options[0]));

	if (index >= 0 && index < count) {
		return options[index];
	}
	return -1;
}

static const char *expected_url(void) {
	if (g.test_case == RB_CURL_PROBE_TEST_EXPECTED_NAME) {
		return "https://rb-curl-probe-expected.invalid:18443/";
	}
	return "https://rb-curl-probe-wrong-name.invalid:18443/";
}

static const char *expected_resolve_entry(void) {
	if (g.test_case == RB_CURL_PROBE_TEST_EXPECTED_NAME) {
		return "rb-curl-probe-expected.invalid:18443:127.0.0.1";
	}
	return "rb-curl-probe-wrong-name.invalid:18443:127.0.0.1";
}

static void reset_fake(enum rb_curl_probe_test_case test_case,
    const char *ca_info_path) {
	memset(&g, 0, sizeof(g));
	g.test_case = test_case;
	g.ca_info_path = ca_info_path;
	g.status = 200;
	g.fail_append_at = -1;
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
		    value->next != NULL ||
		    strcmp(value->data, "Host: rb-curl-probe-http-host.invalid") != 0) {
			g.bad_call = 1;
		}
		g.header_option_value = value;
		break;
	}
	case RB_CURL_PROBE_OPT_RESOLVE: {
		struct curl_slist *value = va_arg(args, struct curl_slist *);
		if (value != &g.resolves || value == &g.headers ||
		    value->data == NULL || value->next != NULL ||
		    strcmp(value->data, expected_resolve_entry()) != 0) {
			g.bad_call = 1;
		}
		g.resolve_option_value = value;
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

	g.perform_count++;
	if (easy != &g_easy || g.perform_count != 1 ||
	    g.option_count != 16 ||
	    g.write_callback == NULL || g.write_data == NULL ||
	    g.header_option_value != &g.headers ||
	    g.resolve_option_value != &g.resolves ||
	    g.resolve_option_value == g.header_option_value ||
	    g.headers.data == NULL ||
	    strcmp(g.headers.data, "Host: rb-curl-probe-http-host.invalid") != 0 ||
	    g.resolves.data == NULL ||
	    strcmp(g.resolves.data, expected_resolve_entry()) != 0 ||
	    g.headers.next != NULL || g.resolves.next != NULL) {
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
	if (easy != &g_easy || g.event_count >= 3) {
		g.bad_call = 1;
		return;
	}
	g.cleanup_count++;
	g.events[g.event_count++] = FAKE_EVENT_EASY_CLEANUP;
}

static rb_curl_slist *fake_slist_append(rb_curl_slist *list,
    const char *line) {
	int append_number = g.append_count++;

	if (line == NULL || g.append_count > 2) {
		g.bad_call = 1;
		return NULL;
	}
	if (append_number == 0) {
		if (list != NULL ||
		    strcmp(line, "Host: rb-curl-probe-http-host.invalid") != 0) {
			g.bad_call = 1;
			return NULL;
		}
		if (g.fail_append_at == append_number) {
			return NULL;
		}
		g.headers.data = line;
		g.headers.next = NULL;
		return (rb_curl_slist *)&g.headers;
	}
	if (append_number == 1) {
		if (list != NULL || strcmp(line, expected_resolve_entry()) != 0) {
			g.bad_call = 1;
			return NULL;
		}
		if (g.fail_append_at == append_number) {
			return NULL;
		}
		g.resolves.data = line;
		g.resolves.next = NULL;
		return (rb_curl_slist *)&g.resolves;
	}
	g.bad_call = 1;
	return NULL;
}

static void fake_slist_free_all(rb_curl_slist *list) {
	struct curl_slist *expected;
	int event;

	if (g.cleanup_count != 1 || g.event_count >= 3 ||
	    g.free_count >= 2) {
		g.bad_call = 1;
		return;
	}
	if (g.free_count == 0) {
		expected = g.headers.data == NULL ? NULL : &g.headers;
		event = FAKE_EVENT_HEADER_FREE;
	} else {
		expected = g.resolves.data == NULL ? NULL : &g.resolves;
		event = FAKE_EVENT_RESOLVE_FREE;
	}
	if (list != (rb_curl_slist *)expected) {
		g.bad_call = 1;
	}
	g.free_count++;
	g.freed_lists[g.free_count - 1] = (struct curl_slist *)list;
	g.events[g.event_count++] = event;
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
	CHECK(g.free_count == 2);
	CHECK(g.event_count == 3);
	CHECK(g.events[0] == FAKE_EVENT_EASY_CLEANUP);
	CHECK(g.events[1] == FAKE_EVENT_HEADER_FREE);
	CHECK(g.events[2] == FAKE_EVENT_RESOLVE_FREE);
	CHECK(g.bad_call == 0);
	return 0;
}

static int test_preflight_rejects_implicit_case(void) {
	const struct rb_curl_probe_config config = {
		.test_case = (enum rb_curl_probe_test_case)0,
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(RB_CURL_PROBE_TEST_EXPECTED_NAME, g_test_ca_path);
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

static int test_preflight_requires_bounded_ca_path(void) {
	char oversized_path[RB_CURL_PROBE_CAINFO_PATH_MAX + 2];
	const struct rb_curl_probe_config missing = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = NULL,
	};
	struct rb_curl_probe_config oversized = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = oversized_path,
	};
	struct rb_curl_probe_result result;

	memset(oversized_path, 'x', sizeof(oversized_path));
	oversized_path[sizeof(oversized_path) - 1] = '\0';
	reset_fake(missing.test_case, NULL);
	result = rb_curl_probe_run(&g_api, &missing);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_PREFLIGHT);
	CHECK(g.perform_count == 0);
	CHECK(g.option_count == 0);
	CHECK(g.event_count == 0);
	CHECK(g.bad_call == 0);

	reset_fake(oversized.test_case, oversized.ca_info_path);
	result = rb_curl_probe_run(&g_api, &oversized);
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
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_api incomplete = g_api;
	struct rb_curl_probe_result result;

	incomplete.easy_setopt = NULL;
	reset_fake(RB_CURL_PROBE_TEST_EXPECTED_NAME, g_test_ca_path);
	result = rb_curl_probe_run(&incomplete, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_PREFLIGHT);
	CHECK(g.perform_count == 0);
	CHECK(g.option_count == 0);
	CHECK(g.event_count == 0);
	CHECK(g.bad_call == 0);
	return 0;
}

static int test_expected_authority_and_http_error_status(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = g_test_ca_path,
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
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
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
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
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

static int test_header_allocation_failure_cleans_up_both_lists(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
	g.fail_append_at = 0;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_HEADER_LIST);
	CHECK(result.curl_code == RB_CURL_PROBE_NO_CURL_CODE);
	CHECK(g.append_count == 1);
	CHECK(g.perform_count == 0);
	if (check_cleanup_order() != 0) {
		return 1;
	}
	CHECK(g.freed_lists[0] == NULL);
	CHECK(g.freed_lists[1] == NULL);
	return 0;
}

static int test_resolve_allocation_failure_frees_partial_list(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
	g.fail_append_at = 1;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_RESOLVE_LIST);
	CHECK(result.curl_code == RB_CURL_PROBE_NO_CURL_CODE);
	CHECK(g.append_count == 2);
	CHECK(g.perform_count == 0);
	if (check_cleanup_order() != 0) {
		return 1;
	}
	CHECK(g.freed_lists[0] == &g.headers);
	CHECK(g.freed_lists[1] == NULL);
	return 0;
}

static int test_first_setopt_error_stops_and_cleans_up(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
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

static int test_resolve_setopt_error_prevents_perform(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_WRONG_NAME,
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
	g.fail_option = RB_CURL_PROBE_OPT_RESOLVE;
	g.fail_option_code = 78;
	result = rb_curl_probe_run(&g_api, &config);
	CHECK(result.phase == RB_CURL_PROBE_PHASE_SETOPT_RESOLVE);
	CHECK(result.curl_code == 78);
	CHECK(g.option_count == 15);
	CHECK(g.perform_count == 0);
	CHECK(g.getinfo_count == 0);
	return check_cleanup_order();
}

static int test_response_cap_and_write_overflow(void) {
	const struct rb_curl_probe_config config = {
		.test_case = RB_CURL_PROBE_TEST_EXPECTED_NAME,
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
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

	reset_fake(config.test_case, config.ca_info_path);
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
		.ca_info_path = g_test_ca_path,
	};
	struct rb_curl_probe_result result;

	reset_fake(config.test_case, config.ca_info_path);
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
	    test_preflight_requires_bounded_ca_path() != 0 ||
	    test_preflight_rejects_incomplete_api() != 0 ||
	    test_expected_authority_and_http_error_status() != 0 ||
	    test_wrong_name_authority_is_explicit() != 0 ||
	    test_easy_init_failure_does_not_cleanup_null_handle() != 0 ||
	    test_header_allocation_failure_cleans_up_both_lists() != 0 ||
	    test_resolve_allocation_failure_frees_partial_list() != 0 ||
	    test_first_setopt_error_stops_and_cleans_up() != 0 ||
	    test_resolve_setopt_error_prevents_perform() != 0 ||
	    test_response_cap_and_write_overflow() != 0 ||
	    test_getinfo_failure_keeps_status_unset() != 0) {
		return 1;
	}
	puts("curl_probe_test: all host-fake cases passed");
	return 0;
}
