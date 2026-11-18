#include "RBCurlProbe.h"

#include <stdint.h>

/* Both authorities are reserved synthetic names and are never caller-supplied. */
static char rb_test_url_expected[] =
    "https://rb-curl-probe-expected.invalid:18443/";
static char rb_test_url_wrong_name[] =
    "https://rb-curl-probe-wrong-name.invalid:18443/";
static char rb_test_host_header[] =
    "Host: rb-curl-probe-http-host.invalid";
static char rb_test_resolve_expected[] =
    "rb-curl-probe-expected.invalid:18443:127.0.0.1";
static char rb_test_resolve_wrong_name[] =
    "rb-curl-probe-wrong-name.invalid:18443:127.0.0.1";
static char rb_empty_proxy[] = "";
static char rb_no_proxy[] = "*";

struct rb_curl_probe_sink {
	size_t accepted;
	int overflow;
};

static size_t bounded_write(char *data, size_t size, size_t nmemb,
    void *user_data) {
	struct rb_curl_probe_sink *sink =
	    (struct rb_curl_probe_sink *)user_data;
	size_t byte_count;

	if (sink == NULL) {
		return 0;
	}
	if (sink->overflow) {
		return 0;
	}
	if (size != 0 && nmemb > SIZE_MAX / size) {
		sink->overflow = 1;
		return 0;
	}
	byte_count = size * nmemb;
	if (byte_count != 0 && data == NULL) {
		sink->overflow = 1;
		return 0;
	}
	if (byte_count > RB_CURL_PROBE_RESPONSE_CAP - sink->accepted) {
		sink->overflow = 1;
		return 0;
	}

	sink->accepted += byte_count;
	return byte_count;
}

static int has_required_length(const char *value, size_t maximum_length) {
	size_t i;

	if (value == NULL) {
		return 0;
	}
	for (i = 0; i <= maximum_length; i++) {
		if (value[i] == '\0') {
			return i != 0;
		}
	}
	return 0;
}

static int valid_api(const struct rb_curl_probe_api *api) {
	return api != NULL &&
	    api->easy_init != NULL &&
	    api->easy_setopt != NULL &&
	    api->easy_perform != NULL &&
	    api->easy_getinfo != NULL &&
	    api->easy_cleanup != NULL &&
	    api->slist_append != NULL &&
	    api->slist_free_all != NULL;
}

static rb_curl_code set_long(const struct rb_curl_probe_api *api,
    rb_curl_easy *easy, rb_curl_option option, long value) {
	return api->easy_setopt(easy, option, value);
}

/* CURLOPT string/object-point arguments use the reviewed char * ABI type. */
static rb_curl_code set_string(const struct rb_curl_probe_api *api,
    rb_curl_easy *easy, rb_curl_option option, char *value) {
	return api->easy_setopt(easy, option, value);
}

static rb_curl_code set_write_function(const struct rb_curl_probe_api *api,
    rb_curl_easy *easy, rb_curl_write_callback callback) {
	return api->easy_setopt(easy, RB_CURL_PROBE_OPT_WRITEFUNCTION, callback);
}

static rb_curl_code set_write_data(const struct rb_curl_probe_api *api,
    rb_curl_easy *easy, void *user_data) {
	return api->easy_setopt(easy, RB_CURL_PROBE_OPT_WRITEDATA, user_data);
}

static rb_curl_code set_header_list(const struct rb_curl_probe_api *api,
    rb_curl_easy *easy, rb_curl_slist *headers) {
	return api->easy_setopt(easy, RB_CURL_PROBE_OPT_HTTPHEADER, headers);
}

static rb_curl_code set_resolve_list(const struct rb_curl_probe_api *api,
    rb_curl_easy *easy, rb_curl_slist *resolves) {
	return api->easy_setopt(easy, RB_CURL_PROBE_OPT_RESOLVE, resolves);
}

static void cleanup(const struct rb_curl_probe_api *api, rb_curl_easy *easy,
    rb_curl_slist *headers, rb_curl_slist *resolves) {
	api->easy_cleanup(easy);
	api->slist_free_all(headers);
	api->slist_free_all(resolves);
}

struct rb_curl_probe_result rb_curl_probe_run(
    const struct rb_curl_probe_api *api,
    const struct rb_curl_probe_config *config) {
	struct rb_curl_probe_result result = {
		.phase = RB_CURL_PROBE_PHASE_PREFLIGHT,
		.curl_code = RB_CURL_PROBE_NO_CURL_CODE,
		.getinfo_code = RB_CURL_PROBE_NO_CURL_CODE,
		.http_status = 0,
	};
	struct rb_curl_probe_sink sink = { 0, 0 };
	rb_curl_easy *easy;
	rb_curl_slist *headers = NULL;
	rb_curl_slist *resolves = NULL;
	char *url;
	char *resolve_entry;
	rb_curl_code code;
	long status = 0;

	if (!valid_api(api) || config == NULL ||
	    (config->test_case != RB_CURL_PROBE_TEST_EXPECTED_NAME &&
	     config->test_case != RB_CURL_PROBE_TEST_WRONG_NAME) ||
	    !has_required_length(config->ca_info_path,
	        RB_CURL_PROBE_CAINFO_PATH_MAX)) {
		return result;
	}
	if (config->test_case == RB_CURL_PROBE_TEST_EXPECTED_NAME) {
		url = rb_test_url_expected;
		resolve_entry = rb_test_resolve_expected;
	} else {
		url = rb_test_url_wrong_name;
		resolve_entry = rb_test_resolve_wrong_name;
	}

	easy = api->easy_init();
	if (easy == NULL) {
		result.phase = RB_CURL_PROBE_PHASE_EASY_INIT;
		return result;
	}

	{
		rb_curl_slist *appended =
		    api->slist_append(headers, rb_test_host_header);
		if (appended == NULL) {
			result.phase = RB_CURL_PROBE_PHASE_HEADER_LIST;
			goto done;
		}
		headers = appended;
	}
	{
		rb_curl_slist *appended =
		    api->slist_append(resolves, resolve_entry);
		if (appended == NULL) {
			result.phase = RB_CURL_PROBE_PHASE_RESOLVE_LIST;
			goto done;
		}
		resolves = appended;
	}

#define RB_SET_LONG(option_value, phase_value, long_value) do { \
	code = set_long(api, easy, (option_value), (long)(long_value)); \
	if (code != RB_CURL_PROBE_CURLE_OK) { \
		result.phase = (phase_value); \
		result.curl_code = code; \
		goto done; \
	} \
} while (0)

#define RB_SET_STRING(option_value, phase_value, string_value) do { \
	code = set_string(api, easy, (option_value), (string_value)); \
	if (code != RB_CURL_PROBE_CURLE_OK) { \
		result.phase = (phase_value); \
		result.curl_code = code; \
		goto done; \
	} \
} while (0)

	RB_SET_STRING(RB_CURL_PROBE_OPT_URL,
	    RB_CURL_PROBE_PHASE_SETOPT_URL, url);
	RB_SET_LONG(RB_CURL_PROBE_OPT_SSL_VERIFYPEER,
	    RB_CURL_PROBE_PHASE_SETOPT_SSL_VERIFYPEER, 1L);
	RB_SET_LONG(RB_CURL_PROBE_OPT_SSL_VERIFYHOST,
	    RB_CURL_PROBE_PHASE_SETOPT_SSL_VERIFYHOST, 2L);
	RB_SET_LONG(RB_CURL_PROBE_OPT_FOLLOWLOCATION,
	    RB_CURL_PROBE_PHASE_SETOPT_FOLLOWLOCATION, 0L);
	RB_SET_STRING(RB_CURL_PROBE_OPT_PROXY,
	    RB_CURL_PROBE_PHASE_SETOPT_PROXY, rb_empty_proxy);
	RB_SET_STRING(RB_CURL_PROBE_OPT_NOPROXY,
	    RB_CURL_PROBE_PHASE_SETOPT_NOPROXY, rb_no_proxy);
	RB_SET_LONG(RB_CURL_PROBE_OPT_TIMEOUT,
	    RB_CURL_PROBE_PHASE_SETOPT_TIMEOUT,
	    RB_CURL_PROBE_TIMEOUT_SECONDS);
	RB_SET_LONG(RB_CURL_PROBE_OPT_CONNECTTIMEOUT,
	    RB_CURL_PROBE_PHASE_SETOPT_CONNECTTIMEOUT,
	    RB_CURL_PROBE_CONNECT_TIMEOUT_SECONDS);
	RB_SET_LONG(RB_CURL_PROBE_OPT_NOSIGNAL,
	    RB_CURL_PROBE_PHASE_SETOPT_NOSIGNAL, 1L);
	RB_SET_LONG(RB_CURL_PROBE_OPT_FRESH_CONNECT,
	    RB_CURL_PROBE_PHASE_SETOPT_FRESH_CONNECT, 1L);
	RB_SET_LONG(RB_CURL_PROBE_OPT_FORBID_REUSE,
	    RB_CURL_PROBE_PHASE_SETOPT_FORBID_REUSE, 1L);

	code = set_write_function(api, easy, bounded_write);
	if (code != RB_CURL_PROBE_CURLE_OK) {
		result.phase = RB_CURL_PROBE_PHASE_SETOPT_WRITEFUNCTION;
		result.curl_code = code;
		goto done;
	}
	code = set_write_data(api, easy, &sink);
	if (code != RB_CURL_PROBE_CURLE_OK) {
		result.phase = RB_CURL_PROBE_PHASE_SETOPT_WRITEDATA;
		result.curl_code = code;
		goto done;
	}
	code = set_header_list(api, easy, headers);
	if (code != RB_CURL_PROBE_CURLE_OK) {
		result.phase = RB_CURL_PROBE_PHASE_SETOPT_HTTPHEADER;
		result.curl_code = code;
		goto done;
	}
	code = set_resolve_list(api, easy, resolves);
	if (code != RB_CURL_PROBE_CURLE_OK) {
		result.phase = RB_CURL_PROBE_PHASE_SETOPT_RESOLVE;
		result.curl_code = code;
		goto done;
	}

	/*
	 * The reviewed target duplicates CAINFO. The required caller-owned path
	 * remains live through this call; this code performs no file access.
	 */
	RB_SET_STRING(RB_CURL_PROBE_OPT_CAINFO,
	    RB_CURL_PROBE_PHASE_SETOPT_CAINFO,
	    (char *)config->ca_info_path);

#undef RB_SET_LONG
#undef RB_SET_STRING

	result.curl_code = api->easy_perform(easy);
	result.phase = RB_CURL_PROBE_PHASE_PERFORM;
	result.getinfo_code = api->easy_getinfo(easy,
	    RB_CURL_PROBE_INFO_RESPONSE_CODE, &status);
	if (result.getinfo_code == RB_CURL_PROBE_CURLE_OK) {
		result.http_status = status;
		if (result.curl_code == RB_CURL_PROBE_CURLE_OK) {
			result.phase = RB_CURL_PROBE_PHASE_COMPLETE;
		}
	} else if (result.curl_code == RB_CURL_PROBE_CURLE_OK) {
		result.phase = RB_CURL_PROBE_PHASE_GETINFO;
	}

done:
	cleanup(api, easy, headers, resolves);
	return result;
}
