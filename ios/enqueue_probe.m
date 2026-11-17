#import <os/log.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <mach/vm_prot.h>
#include "enqueue_probe_image.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
	kProbeTargetRVA = 0x17aa618,
	kProbeThunkRVA = 0x3000,
	kProbeTrampolineRVA = 0x3100,
	kProbeLiteralRVA = 0x30c0,
	kProbeMetadataRVA = 0x3200,
	kProbeDlsymStubRVA = 0x1ac1748,
	kProbeNCommands = 77,
	kProbeSizeOfCommands = 8320,
	kProbeOriginalEntryWord = 0xa9bd57f6,
	kProbeVersion = 1,
	kProbeMetadataSize = 64,
};

static const char kLoaderPath[] =
    "@executable_path/Frameworks/libraspberry.dylib";
static const char kHookName[] = "raspberry_ios_enqueue_probe_v1";
static const uint8_t kMetadataMagic[8] = {
    'R', 'B', 'E', 'N', 'Q', 'P', 'V', '1'};

struct probe_metadata {
	uint8_t magic[8];
	uint32_t fields[14];
};

_Static_assert(sizeof(struct probe_metadata) == kProbeMetadataSize,
    "probe metadata must occupy the fixed 64-byte slot");

static _Atomic(uintptr_t) g_original_trampoline;
static atomic_flag g_marker_emitted = ATOMIC_FLAG_INIT;

static _Noreturn void probe_fail_closed(void) {
	__builtin_trap();
}

static bool has_name(const char field[16], const char *name) {
	size_t length = strlen(name);
	return length < 16 && memcmp(field, name, length) == 0 &&
	    field[length] == '\0';
}

static uint32_t branch_word(uint64_t pc, uint64_t target, bool link) {
	int64_t delta = (int64_t)target - (int64_t)pc;
	if ((pc & 3U) != 0 || (target & 3U) != 0 ||
	    delta < -(INT64_C(1) << 27) ||
	    delta > (INT64_C(1) << 27) - 4) {
		probe_fail_closed();
	}
	uint32_t opcode = link ? UINT32_C(0x94000000) : UINT32_C(0x14000000);
	return opcode | ((uint32_t)(delta >> 2) & UINT32_C(0x03ffffff));
}

static bool segment_matches(const struct segment_command_64 *segment,
    const char *name, uint64_t vmaddr, uint64_t vmsize, uint64_t fileoff,
    uint64_t filesize, int32_t maxprot, int32_t initprot,
    uint32_t nsects) {
	return has_name(segment->segname, name) &&
	    segment->vmaddr == vmaddr && segment->vmsize == vmsize &&
	    segment->fileoff == fileoff && segment->filesize == filesize &&
	    segment->maxprot == maxprot && segment->initprot == initprot &&
	    segment->nsects == nsects;
}

static uintptr_t validate_main_and_cache_trampoline(void) {
	const struct mach_header_64 *header =
	    rb_select_executable_image(_dyld_image_count(),
	        _dyld_get_image_header);
	if (header == NULL || header->magic != MH_MAGIC_64 ||
	    header->cputype != CPU_TYPE_ARM64 || header->filetype != MH_EXECUTE ||
	    header->ncmds != kProbeNCommands ||
	    header->sizeofcmds != kProbeSizeOfCommands) {
		probe_fail_closed();
	}

	const uint8_t *cursor = (const uint8_t *)(header + 1);
	size_t remaining = header->sizeofcmds;
	uint32_t segments = 0;
	uint32_t text_segments = 0;
	uint32_t data_segments = 0;
	uint32_t linkedit_segments = 0;
	uint32_t pagezero_segments = 0;
	uint32_t loader_dependencies = 0;
	bool saw_text = false;

	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (remaining < sizeof(struct load_command)) {
			probe_fail_closed();
		}
		const struct load_command *command =
		    (const struct load_command *)cursor;
		if (command->cmdsize < sizeof(struct load_command) ||
		    command->cmdsize > remaining) {
			probe_fail_closed();
		}

		switch (command->cmd) {
		case LC_SEGMENT_64: {
			if (command->cmdsize < sizeof(struct segment_command_64)) {
				probe_fail_closed();
			}
			const struct segment_command_64 *segment =
			    (const struct segment_command_64 *)command;
			size_t section_bytes =
			    (size_t)segment->nsects * sizeof(struct section_64);
			if (sizeof(*segment) + section_bytes != command->cmdsize ||
			    (segment->vmaddr & UINT64_C(0x3fff)) != 0 ||
			    (segment->vmsize & UINT64_C(0x3fff)) != 0 ||
			    ((segment->initprot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) ==
			        (VM_PROT_WRITE | VM_PROT_EXECUTE))) {
				probe_fail_closed();
			}
			segments++;
			if (has_name(segment->segname, "__PAGEZERO")) {
				pagezero_segments++;
				if (!segment_matches(segment, "__PAGEZERO", 0,
				        UINT64_C(0x100000000), 0, 0, 0, 0, 0)) {
					probe_fail_closed();
				}
			} else if (has_name(segment->segname, "__TEXT")) {
				text_segments++;
				if (!segment_matches(segment, "__TEXT",
				        UINT64_C(0x100000000), UINT64_C(0x1d38000),
				        0, UINT64_C(0x1d38000),
				        VM_PROT_READ | VM_PROT_EXECUTE,
				        VM_PROT_READ | VM_PROT_EXECUTE, 13)) {
					probe_fail_closed();
				}
				const struct section_64 *sections =
				    (const struct section_64 *)(cursor + sizeof(*segment));
				for (uint32_t j = 0; j < segment->nsects; j++) {
					if (has_name(sections[j].sectname, "__text") &&
					    has_name(sections[j].segname, "__TEXT") &&
					    sections[j].addr == UINT64_C(0x10000555c) &&
					    sections[j].offset == UINT32_C(0x555c)) {
						saw_text = true;
					}
				}
			} else if (has_name(segment->segname, "__DATA")) {
				data_segments++;
				if (!segment_matches(segment, "__DATA",
				        UINT64_C(0x101d38000), UINT64_C(0xc94000),
				        UINT64_C(0x1d38000), UINT64_C(0x4e8000),
				        VM_PROT_READ | VM_PROT_WRITE,
				        VM_PROT_READ | VM_PROT_WRITE, 21)) {
					probe_fail_closed();
				}
			} else if (has_name(segment->segname, "__LINKEDIT")) {
				linkedit_segments++;
				if (segment->vmsize == 0 || segment->filesize == 0 ||
				    segment->filesize > segment->vmsize ||
				    segment->filesize > UINT64_MAX - segment->fileoff ||
				    segment->maxprot != VM_PROT_READ ||
				    segment->initprot != VM_PROT_READ ||
				    segment->nsects != 0) {
					probe_fail_closed();
				}
			} else {
				probe_fail_closed();
			}
			break;
		}
		case LC_LOAD_DYLIB: {
			if (command->cmdsize < sizeof(struct dylib_command)) {
				probe_fail_closed();
			}
			const struct dylib_command *dylib =
			    (const struct dylib_command *)command;
			if (dylib->dylib.name.offset < sizeof(*dylib) ||
			    dylib->dylib.name.offset >= command->cmdsize) {
				probe_fail_closed();
			}
			const char *name =
			    (const char *)cursor + dylib->dylib.name.offset;
			size_t available = command->cmdsize - dylib->dylib.name.offset;
			const char *terminator = memchr(name, '\0', available);
			if (terminator == NULL) {
				probe_fail_closed();
			}
			size_t name_length = (size_t)(terminator - name);
			if (name_length == sizeof(kLoaderPath) - 1 &&
			    memcmp(name, kLoaderPath, sizeof(kLoaderPath)) == 0) {
				loader_dependencies++;
			}
			break;
		}
		default:
			break;
		}
		cursor += command->cmdsize;
		remaining -= command->cmdsize;
	}
	if (remaining != 0 || segments != 4 || pagezero_segments != 1 ||
	    text_segments != 1 || data_segments != 1 || linkedit_segments != 1 ||
	    loader_dependencies != 1 || !saw_text) {
		probe_fail_closed();
	}

	const uintptr_t base = (uintptr_t)header;
	const struct probe_metadata *metadata =
	    (const struct probe_metadata *)(base + kProbeMetadataRVA);
	const uint32_t expected_entry =
	    branch_word(kProbeTargetRVA, kProbeThunkRVA, false);
	const uint32_t expected_dlsym =
	    branch_word(kProbeThunkRVA + 9 * 4, kProbeDlsymStubRVA, true);
	const uint32_t expected_return =
	    branch_word(kProbeTrampolineRVA + 4, kProbeTargetRVA + 4, false);
	const uint32_t expected_thunk[21] = {
		UINT32_C(0xd10183ff), // sub sp, sp, #96
		UINT32_C(0xa90007e0), // stp x0, x1, [sp]
		UINT32_C(0xa9010fe2), // stp x2, x3, [sp, #16]
		UINT32_C(0xa90217e4), // stp x4, x5, [sp, #32]
		UINT32_C(0xa9031fe6), // stp x6, x7, [sp, #48]
		UINT32_C(0xa90477e8), // stp x8, x29, [sp, #64]
		UINT32_C(0xf9002bfe), // str x30, [sp, #80]
		UINT32_C(0x92800020), // movn x0, #1 (RTLD_DEFAULT)
		UINT32_C(0x10000501), // adr x1, hook name
		expected_dlsym,       // BL to the main image's _dlsym stub
		UINT32_C(0xaa0003f0), // mov x16, x0
		UINT32_C(0xb5000050), // cbnz x16, restore
		UINT32_C(0xd4200000), // brk #0 if resolution failed
		UINT32_C(0xa94007e0), // ldp x0, x1, [sp]
		UINT32_C(0xa9410fe2), // ldp x2, x3, [sp, #16]
		UINT32_C(0xa94217e4), // ldp x4, x5, [sp, #32]
		UINT32_C(0xa9431fe6), // ldp x6, x7, [sp, #48]
		UINT32_C(0xa94477e8), // ldp x8, x29, [sp, #64]
		UINT32_C(0xf9402bfe), // ldr x30, [sp, #80]
		UINT32_C(0x910183ff), // add sp, sp, #96
		UINT32_C(0xd61f0200), // br x16 (tail branch to exported hook)
	};
	const uint32_t expected_fields[14] = {
		kProbeVersion,
		kProbeMetadataSize,
		kProbeTargetRVA,
		kProbeOriginalEntryWord,
		expected_entry,
		kProbeThunkRVA,
		84,
		kProbeTrampolineRVA,
		8,
		kProbeLiteralRVA,
		sizeof(kHookName),
		kProbeDlsymStubRVA,
		expected_dlsym,
		expected_return,
	};
	if (memcmp(metadata->magic, kMetadataMagic, sizeof(kMetadataMagic)) != 0 ||
	    memcmp(metadata->fields, expected_fields, sizeof(expected_fields)) != 0) {
		probe_fail_closed();
	}

	const uint32_t *target =
	    (const uint32_t *)(base + kProbeTargetRVA);
	const uint32_t *thunk = (const uint32_t *)(base + kProbeThunkRVA);
	const uint32_t *trampoline =
	    (const uint32_t *)(base + kProbeTrampolineRVA);
	const char *hook_name = (const char *)(base + kProbeLiteralRVA);
	if (*target != expected_entry ||
	    memcmp(thunk, expected_thunk, sizeof(expected_thunk)) != 0 ||
	    trampoline[0] != kProbeOriginalEntryWord ||
	    trampoline[1] != expected_return ||
	    memcmp(hook_name, kHookName, sizeof(kHookName)) != 0) {
		probe_fail_closed();
	}
	return base + kProbeTrampolineRVA;
}

__attribute__((constructor))
static void raspberry_ios_enqueue_probe_initialize(void) {
	uintptr_t trampoline = validate_main_and_cache_trampoline();
	atomic_store_explicit(&g_original_trampoline, trampoline,
	    memory_order_release);
}

__attribute__((visibility("hidden")))
void *raspberry_ios_enqueue_probe_prepare(void) {
	uintptr_t trampoline =
	    atomic_load_explicit(&g_original_trampoline, memory_order_acquire);
	if (trampoline == 0) {
		probe_fail_closed();
	}
	if (!atomic_flag_test_and_set_explicit(&g_marker_emitted,
	        memory_order_relaxed)) {
		os_log(OS_LOG_DEFAULT, "raspberry-ios enqueue-probe-hit");
	}
	return (void *)trampoline;
}
