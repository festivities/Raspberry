#ifndef RASPBERRY_RESUME_GUARD_H
#define RASPBERRY_RESUME_GUARD_H

#include <stddef.h>
#include <stdint.h>

#define RB_PT_LOAD 1u
#define RB_PF_X 1u
#define RB_PF_W 2u
#define RB_PF_R 4u

#define RB_PROT_READ 1
#define RB_PROT_WRITE 2
#define RB_PROT_EXEC 4

enum {
    RB_RESUME_OK_RX = 0,
    RB_RESUME_OK_RO_SOURCE = 1,
    RB_RESUME_ERR_INPUT = -1,
    RB_RESUME_ERR_ELF = -2,
    RB_RESUME_ERR_MAP = -3,
    RB_RESUME_ERR_BYTES = -4
};

typedef struct rb_elf_load_seg {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
} rb_elf_load_seg;

typedef struct rb_map_span {
    uintptr_t start;
    uintptr_t end;
    int prot;
} rb_map_span;

/* Strip optional ARMv7 Thumb low-bit tag from a callable RVA to obtain the source RVA. */
uintptr_t rb_resume_strip_tag(uintptr_t tagged_rva, int strip_thumb_bit);

/* Validate ELF executable-source bounds and live-map permissions without reading source bytes.
 * Returns RB_RESUME_OK_RX (R-X), RB_RESUME_OK_RO_SOURCE (R--), or negative RB_RESUME_ERR_*.
 */
int rb_validate_resume_layout(uintptr_t base,
                              const rb_elf_load_seg *segs,
                              size_t seg_count,
                              uintptr_t tagged_rva,
                              int strip_thumb_bit,
                              uint64_t expected_file_off,
                              const rb_map_span *map,
                              size_t expected_len);

/* Full validation: checks layout first, then compares observed_bytes against expected_bytes.
 * Never dereferences observed_bytes if layout validation fails.
 */
int rb_validate_resume_source(uintptr_t base,
                              const rb_elf_load_seg *segs,
                              size_t seg_count,
                              uintptr_t tagged_rva,
                              int strip_thumb_bit,
                              uint64_t expected_file_off,
                              const rb_map_span *map,
                              const uint8_t *observed_bytes,
                              const uint8_t *expected_bytes,
                              size_t expected_len);

#endif
