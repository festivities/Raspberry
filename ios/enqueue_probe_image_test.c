#include "enqueue_probe_image.h"

#include <stdio.h>
#include <string.h>

static struct mach_header_64 g_dylib;
static struct mach_header_64 g_main_a;
static struct mach_header_64 g_main_b;
static struct mach_header_64 g_invalid;
static struct mach_header_64 g_many[RB_ENQUEUE_PROBE_MAX_IMAGES];
static const struct mach_header *g_images[RB_ENQUEUE_PROBE_MAX_IMAGES];
static uint32_t g_image_count;
static uint32_t g_getter_calls;
static int g_getter_out_of_bounds;

static const struct mach_header *get_synthetic_header(uint32_t index) {
	g_getter_calls++;
	if (index >= g_image_count ||
	    index >= RB_ENQUEUE_PROBE_MAX_IMAGES) {
		g_getter_out_of_bounds = 1;
		return NULL;
	}
	return g_images[index];
}

static void initialize_header(struct mach_header_64 *header,
    uint32_t filetype, int32_t cputype, uint32_t magic) {
	memset(header, 0, sizeof(*header));
	header->magic = magic;
	header->cputype = cputype;
	header->filetype = filetype;
}

static void reset_synthetic_images(uint32_t image_count) {
	memset(g_images, 0, sizeof(g_images));
	g_image_count = image_count;
	g_getter_calls = 0;
	g_getter_out_of_bounds = 0;
}

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "enqueue_probe_image_test:%d: %s\n", \
		    __LINE__, #condition); \
		return 1; \
	} \
} while (0)

static int test_dylib_before_main(void) {
	initialize_header(&g_dylib, MH_DYLIB, CPU_TYPE_ARM64, MH_MAGIC_64);
	initialize_header(&g_main_a, MH_EXECUTE, CPU_TYPE_ARM64, MH_MAGIC_64);
	reset_synthetic_images(2);
	g_images[0] = (const struct mach_header *)&g_dylib;
	g_images[1] = (const struct mach_header *)&g_main_a;

	CHECK(rb_select_executable_image(2, get_synthetic_header) == &g_main_a);
	CHECK(g_getter_calls == 2);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_main_at_index_zero(void) {
	initialize_header(&g_dylib, MH_DYLIB, CPU_TYPE_ARM64, MH_MAGIC_64);
	initialize_header(&g_main_a, MH_EXECUTE, CPU_TYPE_ARM64, MH_MAGIC_64);
	reset_synthetic_images(2);
	g_images[0] = (const struct mach_header *)&g_main_a;
	g_images[1] = (const struct mach_header *)&g_dylib;

	CHECK(rb_select_executable_image(2, get_synthetic_header) == &g_main_a);
	CHECK(g_getter_calls == 2);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_no_executable(void) {
	initialize_header(&g_dylib, MH_DYLIB, CPU_TYPE_ARM64, MH_MAGIC_64);
	reset_synthetic_images(1);
	g_images[0] = (const struct mach_header *)&g_dylib;

	CHECK(rb_select_executable_image(1, get_synthetic_header) == NULL);
	CHECK(g_getter_calls == 1);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_duplicate_executables(void) {
	initialize_header(&g_main_a, MH_EXECUTE, CPU_TYPE_ARM64, MH_MAGIC_64);
	initialize_header(&g_main_b, MH_EXECUTE, CPU_TYPE_ARM64, MH_MAGIC_64);
	reset_synthetic_images(2);
	g_images[0] = (const struct mach_header *)&g_main_a;
	g_images[1] = (const struct mach_header *)&g_main_b;

	CHECK(rb_select_executable_image(2, get_synthetic_header) == NULL);
	CHECK(g_getter_calls == 2);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_null_header_is_skipped(void) {
	initialize_header(&g_main_a, MH_EXECUTE, CPU_TYPE_ARM64, MH_MAGIC_64);
	reset_synthetic_images(2);
	g_images[0] = NULL;
	g_images[1] = (const struct mach_header *)&g_main_a;

	CHECK(rb_select_executable_image(2, get_synthetic_header) == &g_main_a);
	CHECK(g_getter_calls == 2);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_invalid_magic_rejected(void) {
	initialize_header(&g_invalid, MH_EXECUTE, CPU_TYPE_ARM64, 0);
	reset_synthetic_images(1);
	g_images[0] = (const struct mach_header *)&g_invalid;

	CHECK(rb_select_executable_image(1, get_synthetic_header) == NULL);
	CHECK(g_getter_calls == 1);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_wrong_architecture_rejected(void) {
	initialize_header(&g_invalid, MH_EXECUTE, CPU_TYPE_X86_64, MH_MAGIC_64);
	reset_synthetic_images(1);
	g_images[0] = (const struct mach_header *)&g_invalid;

	CHECK(rb_select_executable_image(1, get_synthetic_header) == NULL);
	CHECK(g_getter_calls == 1);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_invalid_filetype_rejected(void) {
	initialize_header(&g_invalid, 0, CPU_TYPE_ARM64, MH_MAGIC_64);
	reset_synthetic_images(1);
	g_images[0] = (const struct mach_header *)&g_invalid;

	CHECK(rb_select_executable_image(1, get_synthetic_header) == NULL);
	CHECK(g_getter_calls == 1);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_oversized_count_rejected_without_getter(void) {
	reset_synthetic_images(RB_ENQUEUE_PROBE_MAX_IMAGES);

	CHECK(rb_select_executable_image(
	          RB_ENQUEUE_PROBE_MAX_IMAGES + 1, get_synthetic_header) == NULL);
	CHECK(g_getter_calls == 0);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_exact_limit_stays_bounded(void) {
	initialize_header(&g_dylib, MH_DYLIB, CPU_TYPE_ARM64, MH_MAGIC_64);
	initialize_header(&g_many[RB_ENQUEUE_PROBE_MAX_IMAGES - 1],
	    MH_EXECUTE, CPU_TYPE_ARM64, MH_MAGIC_64);
	reset_synthetic_images(RB_ENQUEUE_PROBE_MAX_IMAGES);
	for (uint32_t i = 0; i < RB_ENQUEUE_PROBE_MAX_IMAGES; i++) {
		g_images[i] = (const struct mach_header *)&g_dylib;
	}
	g_images[RB_ENQUEUE_PROBE_MAX_IMAGES - 1] =
	    (const struct mach_header *)&g_many[RB_ENQUEUE_PROBE_MAX_IMAGES - 1];

	CHECK(rb_select_executable_image(
	          RB_ENQUEUE_PROBE_MAX_IMAGES, get_synthetic_header) ==
	    &g_many[RB_ENQUEUE_PROBE_MAX_IMAGES - 1]);
	CHECK(g_getter_calls == RB_ENQUEUE_PROBE_MAX_IMAGES);
	CHECK(g_getter_out_of_bounds == 0);
	return 0;
}

static int test_empty_count_and_null_getter(void) {
	reset_synthetic_images(0);
	CHECK(rb_select_executable_image(0, get_synthetic_header) == NULL);
	CHECK(g_getter_calls == 0);
	CHECK(rb_select_executable_image(1, NULL) == NULL);
	CHECK(g_getter_calls == 0);
	return 0;
}

int main(void) {
	if (test_dylib_before_main() != 0 ||
	    test_main_at_index_zero() != 0 ||
	    test_no_executable() != 0 ||
	    test_duplicate_executables() != 0 ||
	    test_null_header_is_skipped() != 0 ||
	    test_invalid_magic_rejected() != 0 ||
	    test_wrong_architecture_rejected() != 0 ||
	    test_invalid_filetype_rejected() != 0 ||
	    test_oversized_count_rejected_without_getter() != 0 ||
	    test_exact_limit_stays_bounded() != 0 ||
	    test_empty_count_and_null_getter() != 0) {
		return 1;
	}
	puts("enqueue_probe_image_test: all selector cases passed");
	return 0;
}
