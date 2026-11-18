#ifndef RASPBERRY_RB_CURL_PROBE_H
#define RASPBERRY_RB_CURL_PROBE_H

#include <stddef.h>

/*
 * Host-fake-only cURL orchestration. No adapter to the app's internal static
 * cURL is provided. Do not connect this table to a real transfer until both
 * the binding and a synthetic-only resolver/route have been reviewed.
 */
typedef struct Curl_easy rb_curl_easy;
typedef struct curl_slist rb_curl_slist;
typedef int rb_curl_code;
typedef int rb_curl_option;
typedef int rb_curl_info;

typedef size_t (*rb_curl_write_callback)(char *data, size_t size,
    size_t nmemb, void *user_data);

/*
 * CURLOPT/CURLINFO are C enums passed in the integer argument register on the
 * reviewed arm64 target. These prototypes preserve the variadic call ABI;
 * they are not declarations of exported symbols in the app.
 */
typedef rb_curl_code (*rb_curl_easy_setopt_fn)(rb_curl_easy *easy,
    rb_curl_option option, ...);
typedef rb_curl_code (*rb_curl_easy_getinfo_fn)(rb_curl_easy *easy,
    rb_curl_info info, ...);

struct rb_curl_probe_api {
	/* Must produce a new, unshared easy handle; reset/reuse is not accepted. */
	rb_curl_easy *(*easy_init)(void);
	rb_curl_easy_setopt_fn easy_setopt;
	rb_curl_code (*easy_perform)(rb_curl_easy *easy);
	rb_curl_easy_getinfo_fn easy_getinfo;
	void (*easy_cleanup)(rb_curl_easy *easy);
	rb_curl_slist *(*slist_append)(rb_curl_slist *list, const char *line);
	void (*slist_free_all)(rb_curl_slist *list);
};

enum rb_curl_probe_test_case {
	/* The caller must choose one explicitly; there is no default URL. */
	RB_CURL_PROBE_TEST_EXPECTED_NAME = 1,
	RB_CURL_PROBE_TEST_WRONG_NAME = 2,
};

struct rb_curl_probe_config {
	enum rb_curl_probe_test_case test_case;
	/* Optional caller-owned PEM path; no file access is performed here. */
	const char *ca_info_path;
};

enum rb_curl_probe_option {
	RB_CURL_PROBE_OPT_TIMEOUT = 13,
	RB_CURL_PROBE_OPT_SSL_VERIFYPEER = 64,
	RB_CURL_PROBE_OPT_FRESH_CONNECT = 74,
	RB_CURL_PROBE_OPT_FORBID_REUSE = 75,
	RB_CURL_PROBE_OPT_CONNECTTIMEOUT = 78,
	RB_CURL_PROBE_OPT_SSL_VERIFYHOST = 81,
	RB_CURL_PROBE_OPT_NOSIGNAL = 99,
	RB_CURL_PROBE_OPT_WRITEDATA = 10001,
	RB_CURL_PROBE_OPT_URL = 10002,
	RB_CURL_PROBE_OPT_PROXY = 10004,
	RB_CURL_PROBE_OPT_FOLLOWLOCATION = 52,
	RB_CURL_PROBE_OPT_HTTPHEADER = 10023,
	RB_CURL_PROBE_OPT_CAINFO = 10065,
	RB_CURL_PROBE_OPT_NOPROXY = 10177,
	RB_CURL_PROBE_OPT_WRITEFUNCTION = 20011,
	RB_CURL_PROBE_INFO_RESPONSE_CODE = 0x200002,
};

enum {
	RB_CURL_PROBE_RESPONSE_CAP = 16 * 1024,
	RB_CURL_PROBE_CAINFO_PATH_MAX = 1024,
	RB_CURL_PROBE_TIMEOUT_SECONDS = 5,
	RB_CURL_PROBE_CONNECT_TIMEOUT_SECONDS = 2,
	RB_CURL_PROBE_NO_CURL_CODE = -1,
	RB_CURL_PROBE_CURLE_OK = 0,
	RB_CURL_PROBE_CURLE_WRITE_ERROR = 23,
};

enum rb_curl_probe_phase {
	RB_CURL_PROBE_PHASE_PREFLIGHT = 0,
	RB_CURL_PROBE_PHASE_EASY_INIT,
	RB_CURL_PROBE_PHASE_HEADER_LIST,
	RB_CURL_PROBE_PHASE_SETOPT_URL,
	RB_CURL_PROBE_PHASE_SETOPT_SSL_VERIFYPEER,
	RB_CURL_PROBE_PHASE_SETOPT_SSL_VERIFYHOST,
	RB_CURL_PROBE_PHASE_SETOPT_FOLLOWLOCATION,
	RB_CURL_PROBE_PHASE_SETOPT_PROXY,
	RB_CURL_PROBE_PHASE_SETOPT_NOPROXY,
	RB_CURL_PROBE_PHASE_SETOPT_TIMEOUT,
	RB_CURL_PROBE_PHASE_SETOPT_CONNECTTIMEOUT,
	RB_CURL_PROBE_PHASE_SETOPT_NOSIGNAL,
	RB_CURL_PROBE_PHASE_SETOPT_FRESH_CONNECT,
	RB_CURL_PROBE_PHASE_SETOPT_FORBID_REUSE,
	RB_CURL_PROBE_PHASE_SETOPT_WRITEFUNCTION,
	RB_CURL_PROBE_PHASE_SETOPT_WRITEDATA,
	RB_CURL_PROBE_PHASE_SETOPT_HTTPHEADER,
	RB_CURL_PROBE_PHASE_SETOPT_CAINFO,
	RB_CURL_PROBE_PHASE_PERFORM,
	RB_CURL_PROBE_PHASE_GETINFO,
	RB_CURL_PROBE_PHASE_COMPLETE,
};

struct rb_curl_probe_result {
	enum rb_curl_probe_phase phase;
	/* NO_CURL_CODE means no corresponding cURL call produced this field. */
	rb_curl_code curl_code;
	rb_curl_code getinfo_code;
	long http_status;
};

/*
 * Runs at most one perform using only injected callbacks. Inputs are never
 * logged. This is not a network-safety boundary: current use is limited to
 * host fakes until binding and loopback mapping are independently reviewed.
 */
struct rb_curl_probe_result rb_curl_probe_run(
    const struct rb_curl_probe_api *api,
    const struct rb_curl_probe_config *config);

#endif
