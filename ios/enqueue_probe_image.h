#ifndef RASPBERRY_ENQUEUE_PROBE_IMAGE_H
#define RASPBERRY_ENQUEUE_PROBE_IMAGE_H

#include <mach-o/loader.h>
#include <mach/machine.h>
#include <stddef.h>
#include <stdint.h>

enum {
	RB_ENQUEUE_PROBE_MAX_IMAGES = 4096,
};

typedef const struct mach_header *(*rb_image_header_getter)(uint32_t);

static inline const struct mach_header_64 *rb_select_executable_image(
    uint32_t image_count, rb_image_header_getter get_header) {
	if (get_header == NULL || image_count == 0 ||
	    image_count > RB_ENQUEUE_PROBE_MAX_IMAGES) {
		return NULL;
	}

	const struct mach_header_64 *selected = NULL;
	for (uint32_t i = 0; i < image_count; i++) {
		const struct mach_header *header = get_header(i);
		if (header == NULL) {
			continue;
		}
		if (((uintptr_t)header % _Alignof(struct mach_header_64)) != 0 ||
		    header->magic != MH_MAGIC_64 ||
		    header->cputype != CPU_TYPE_ARM64 ||
		    header->filetype < MH_OBJECT ||
		    header->filetype > MH_FILESET) {
			return NULL;
		}
		if (header->filetype != MH_EXECUTE) {
			continue;
		}
		if (selected != NULL) {
			return NULL;
		}
		selected = (const struct mach_header_64 *)header;
	}
	return selected;
}

#endif
