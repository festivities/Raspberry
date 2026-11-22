#include "resume_guard.h"

#include <string.h>

static int span_inside_u64(uint64_t lo, uint64_t hi, uint64_t addr, uint64_t width) {
    if (width == 0u || lo >= hi || addr < lo) {
        return 0;
    }
    if (width > UINT64_MAX - addr) {
        return 0;
    }
    return (addr + width) <= hi ? 1 : 0;
}

static int span_inside_uptr(uintptr_t lo, uintptr_t hi, uintptr_t addr, uintptr_t width) {
    if (width == 0u || lo >= hi || addr < lo) {
        return 0;
    }
    if (width > UINTPTR_MAX - addr) {
        return 0;
    }
    return (addr + width) <= hi ? 1 : 0;
}

uintptr_t rb_resume_strip_tag(uintptr_t tagged_rva, int strip_thumb_bit) {
    if (strip_thumb_bit) {
        return tagged_rva & ~(uintptr_t)1u;
    }
    return tagged_rva;
}

int rb_validate_resume_layout(uintptr_t base,
                              const rb_elf_load_seg *segs,
                              size_t seg_count,
                              uintptr_t tagged_rva,
                              int strip_thumb_bit,
                              uint64_t expected_file_off,
                              const rb_map_span *map,
                              size_t expected_len) {
    uintptr_t source_rva;
    uintptr_t addr;
    size_t i;
    int elf_ok = 0;

    if (!segs || seg_count == 0u || expected_len == 0u) {
        return RB_RESUME_ERR_INPUT;
    }
    source_rva = rb_resume_strip_tag(tagged_rva, strip_thumb_bit);
    if (source_rva > UINTPTR_MAX - base) {
        return RB_RESUME_ERR_INPUT;
    }
    addr = base + source_rva;
    if ((uintptr_t)expected_len > UINTPTR_MAX - addr) {
        return RB_RESUME_ERR_INPUT;
    }

    for (i = 0; i < seg_count; i++) {
        const rb_elf_load_seg *s = &segs[i];
        uint64_t file_hi;
        uint64_t mem_hi;
        uint64_t delta;
        uint64_t file_off;
        uintptr_t mapped_lo;
        uintptr_t mapped_hi;

        if (s->p_type != RB_PT_LOAD) {
            continue;
        }
        if ((s->p_flags & (RB_PF_R | RB_PF_W | RB_PF_X)) != (RB_PF_R | RB_PF_X)) {
            continue;
        }
        if (s->p_filesz > UINT64_MAX - s->p_vaddr || s->p_memsz > UINT64_MAX - s->p_vaddr) {
            continue;
        }
        file_hi = s->p_vaddr + s->p_filesz;
        mem_hi = s->p_vaddr + s->p_memsz;
        if (!span_inside_u64(s->p_vaddr, file_hi, (uint64_t)source_rva, (uint64_t)expected_len) ||
            !span_inside_u64(s->p_vaddr, mem_hi, (uint64_t)source_rva, (uint64_t)expected_len)) {
            continue;
        }
        delta = (uint64_t)source_rva - s->p_vaddr;
        if (delta > UINT64_MAX - s->p_offset) {
            continue;
        }
        file_off = s->p_offset + delta;
        if (file_off != expected_file_off) {
            continue;
        }
        if (s->p_vaddr > (uint64_t)UINTPTR_MAX || s->p_filesz > (uint64_t)UINTPTR_MAX) {
            continue;
        }
        if ((uintptr_t)s->p_vaddr > UINTPTR_MAX - base) {
            continue;
        }
        mapped_lo = base + (uintptr_t)s->p_vaddr;
        if ((uintptr_t)s->p_filesz > UINTPTR_MAX - mapped_lo) {
            continue;
        }
        mapped_hi = mapped_lo + (uintptr_t)s->p_filesz;
        if (!span_inside_uptr(mapped_lo, mapped_hi, addr, (uintptr_t)expected_len)) {
            continue;
        }
        elf_ok = 1;
        break;
    }

    if (!elf_ok) {
        return RB_RESUME_ERR_ELF;
    }
    if (!map || !span_inside_uptr(map->start, map->end, addr, (uintptr_t)expected_len)) {
        return RB_RESUME_ERR_MAP;
    }
    if ((map->prot & RB_PROT_READ) == 0 || (map->prot & RB_PROT_WRITE) != 0) {
        return RB_RESUME_ERR_MAP;
    }
    if ((map->prot & RB_PROT_EXEC) != 0) {
        return RB_RESUME_OK_RX;
    }
    return RB_RESUME_OK_RO_SOURCE;
}

int rb_validate_resume_source(uintptr_t base,
                              const rb_elf_load_seg *segs,
                              size_t seg_count,
                              uintptr_t tagged_rva,
                              int strip_thumb_bit,
                              uint64_t expected_file_off,
                              const rb_map_span *map,
                              const uint8_t *observed_bytes,
                              const uint8_t *expected_bytes,
                              size_t expected_len) {
    int rc;
    if (!expected_bytes || expected_len == 0u) {
        return RB_RESUME_ERR_INPUT;
    }
    rc = rb_validate_resume_layout(base, segs, seg_count, tagged_rva, strip_thumb_bit,
                                   expected_file_off, map, expected_len);
    if (rc < 0) {
        return rc;
    }
    if (!observed_bytes) {
        return RB_RESUME_ERR_INPUT;
    }
    if (memcmp(observed_bytes, expected_bytes, expected_len) != 0) {
        return RB_RESUME_ERR_BYTES;
    }
    return rc;
}
