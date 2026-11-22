#include "resume_guard.c"

#include <stdio.h>
#include <string.h>

static int g_fails;

static void check(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "fail: %s\n", msg);
        g_fails++;
    }
}

static void test_arm64_native_and_translated(void) {
    const uint8_t req_bytes[8] = {0xfd, 0x7b, 0xb5, 0xa9, 0x1e, 0xbd, 0x8d, 0x17};
    const uint8_t vis_bytes[8] = {0xfd, 0x7b, 0xbb, 0xa9, 0x5e, 0x64, 0x91, 0x17};
    const uintptr_t base = (uintptr_t)0x70000000u;
    const rb_elf_load_seg segs[2] = {
        {RB_PT_LOAD, RB_PF_R | RB_PF_X, 0u, 0u, 0x3850000u, 0x3850000u},
        {RB_PT_LOAD, RB_PF_R | RB_PF_W, 0x3850000u, 0x3851000u, 0x350000u, 0x639600u},
    };
    rb_map_span rx_map = {base, base + 0x3850000u, RB_PROT_READ | RB_PROT_EXEC};
    rb_map_span ro_map = {base, base + 0x3850000u, RB_PROT_READ};

    check(rb_validate_resume_source(base, segs, 2, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, req_bytes, req_bytes, sizeof req_bytes) == RB_RESUME_OK_RX,
          "arm64 req native R-X accepted");
    check(rb_validate_resume_source(base, segs, 2, 0x384fff0u, 0, 0x384fff0u,
                                    &rx_map, vis_bytes, vis_bytes, sizeof vis_bytes) == RB_RESUME_OK_RX,
          "arm64 vis native R-X accepted");
    check(rb_validate_resume_source(base, segs, 2, 0x384ffdcu, 0, 0x384ffdcu,
                                    &ro_map, req_bytes, req_bytes, sizeof req_bytes) == RB_RESUME_OK_RO_SOURCE,
          "arm64 req translated R-- accepted");
    check(rb_validate_resume_source(base, segs, 2, 0x384fff0u, 0, 0x384fff0u,
                                    &ro_map, vis_bytes, vis_bytes, sizeof vis_bytes) == RB_RESUME_OK_RO_SOURCE,
          "arm64 vis translated R-- accepted");
}

static void test_armv7_thumb_tag_and_lengths(void) {
    const uint8_t req_bytes[16] = {
        0x4a, 0xf6, 0xc0, 0x53, 0xc0, 0xf2, 0x02, 0x13,
        0x2d, 0xe9, 0xf0, 0x47, 0x7d, 0xf5, 0x17, 0x91,
    };
    const uint8_t vis_bytes[8] = {
        0x2d, 0xe9, 0xf0, 0x41, 0xe3, 0xf5, 0xe8, 0x95,
    };
    const uintptr_t base = (uintptr_t)0x50000000u;
    const rb_elf_load_seg segs[2] = {
        {RB_PT_LOAD, RB_PF_R | RB_PF_X, 0u, 0u, 0x2080700u, 0x2080700u},
        {RB_PT_LOAD, RB_PF_R | RB_PF_W, 0x2081000u, 0x2082000u, 0x200000u, 0x432400u},
    };
    rb_map_span rx_map = {base, base + 0x2081000u, RB_PROT_READ | RB_PROT_EXEC};
    rb_map_span ro_map = {base, base + 0x2081000u, RB_PROT_READ};

    check(rb_resume_strip_tag(0x20806a0u | 1u, 1) == 0x20806a0u, "strip thumb bit");
    check(rb_resume_strip_tag(0x20806a0u | 1u, 0) == (0x20806a0u | 1u), "preserve bit when strip=0");

    check(rb_validate_resume_source(base, segs, 2, 0x20806a0u | 1u, 1, 0x20806a0u,
                                    &rx_map, req_bytes, req_bytes, sizeof req_bytes) == RB_RESUME_OK_RX,
          "armv7 req R-X with thumb tag");
    check(rb_validate_resume_source(base, segs, 2, 0x2080684u | 1u, 1, 0x2080684u,
                                    &ro_map, vis_bytes, vis_bytes, sizeof vis_bytes) == RB_RESUME_OK_RO_SOURCE,
          "armv7 vis R-- with thumb tag");
    check(rb_validate_resume_source(base, segs, 2, 0x20806a0u | 1u, 0, 0x20806a0u,
                                    &rx_map, req_bytes, req_bytes, sizeof req_bytes) == RB_RESUME_ERR_ELF,
          "unstripped thumb tag fails file-offset binding");
}

static void test_map_permission_and_span_rejections(void) {
    const uint8_t bytes[8] = {0xfd, 0x7b, 0xb5, 0xa9, 0x1e, 0xbd, 0x8d, 0x17};
    const uintptr_t base = (uintptr_t)0x70000000u;
    const rb_elf_load_seg seg = {RB_PT_LOAD, RB_PF_R | RB_PF_X, 0u, 0u, 0x3850000u, 0x3850000u};
    rb_map_span rw_map = {base, base + 0x3850000u, RB_PROT_READ | RB_PROT_WRITE};
    rb_map_span rwx_map = {base, base + 0x3850000u, RB_PROT_READ | RB_PROT_WRITE | RB_PROT_EXEC};
    rb_map_span none_map = {base, base + 0x3850000u, 0};
    rb_map_span xo_map = {base, base + 0x3850000u, RB_PROT_EXEC};
    rb_map_span wo_map = {base, base + 0x3850000u, RB_PROT_WRITE};
    rb_map_span partial_end = {base, base + 0x384ffe0u, RB_PROT_READ | RB_PROT_EXEC};
    rb_map_span partial_start = {base + 0x384ffe0u, base + 0x3850000u, RB_PROT_READ | RB_PROT_EXEC};
    rb_map_span inverted = {base + 0x3850000u, base, RB_PROT_READ | RB_PROT_EXEC};

    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rw_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "RW mapping rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rwx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "RWX mapping rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &none_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "PROT_NONE mapping rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &xo_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "execute-only mapping rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &wo_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "write-only mapping rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    NULL, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "NULL map rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &partial_end, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "partial map ending mid-stub rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &partial_start, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "partial map starting mid-stub rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &inverted, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_MAP,
          "inverted map rejected");
}

static void test_elf_and_memsz_rejections(void) {
    const uint8_t bytes[8] = {0xfd, 0x7b, 0xb5, 0xa9, 0x1e, 0xbd, 0x8d, 0x17};
    const uintptr_t base = (uintptr_t)0x70000000u;
    rb_map_span rx_map = {base, base + 0x3860000u, RB_PROT_READ | RB_PROT_EXEC};

    rb_elf_load_seg not_load = {2u, RB_PF_R | RB_PF_X, 0u, 0u, 0x3850000u, 0x3850000u};
    rb_elf_load_seg rw_seg = {RB_PT_LOAD, RB_PF_R | RB_PF_W, 0u, 0u, 0x3850000u, 0x3850000u};
    rb_elf_load_seg rwx_seg = {RB_PT_LOAD, RB_PF_R | RB_PF_W | RB_PF_X, 0u, 0u, 0x3850000u, 0x3850000u};
    rb_elf_load_seg ro_seg = {RB_PT_LOAD, RB_PF_R, 0u, 0u, 0x3850000u, 0x3850000u};
    rb_elf_load_seg memsz_only = {RB_PT_LOAD, RB_PF_R | RB_PF_X, 0u, 0u, 0x384ffe0u, 0x3850000u};
    rb_elf_load_seg shifted_off = {RB_PT_LOAD, RB_PF_R | RB_PF_X, 0x1000u, 0u, 0x3850000u, 0x3850000u};
    rb_elf_load_seg short_seg = {RB_PT_LOAD, RB_PF_R | RB_PF_X, 0u, 0u, 0x384ffceu, 0x384ffceu};

    check(rb_validate_resume_source(base, &not_load, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_ELF,
          "non-PT_LOAD rejected");
    check(rb_validate_resume_source(base, &rw_seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_ELF,
          "PF_R|PF_W segment rejected");
    check(rb_validate_resume_source(base, &rwx_seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_ELF,
          "PF_R|PF_W|PF_X segment rejected");
    check(rb_validate_resume_source(base, &ro_seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_ELF,
          "PF_R-only segment rejected");
    check(rb_validate_resume_source(base, &memsz_only, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_ELF,
          "memsz-only (beyond p_filesz) rejected");
    check(rb_validate_resume_source(base, &shifted_off, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_ELF,
          "file offset mismatch rejected");
    check(rb_validate_resume_source(base, &short_seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_ERR_ELF,
          "unexpanded stock p_filesz rejected");
    check(rb_validate_resume_source(base, &shifted_off, 1, 0x384ffdcu, 0, 0x3850fdcu,
                                    &rx_map, bytes, bytes, sizeof bytes) == RB_RESUME_OK_RX,
          "non-zero p_offset matching expected_file_off accepted");
}

static void test_byte_mismatch_and_overflow(void) {
    const uint8_t expect[8] = {0xfd, 0x7b, 0xb5, 0xa9, 0x1e, 0xbd, 0x8d, 0x17};
    uint8_t bad_first[8] = {0xfc, 0x7b, 0xb5, 0xa9, 0x1e, 0xbd, 0x8d, 0x17};
    uint8_t bad_last[8] = {0xfd, 0x7b, 0xb5, 0xa9, 0x1e, 0xbd, 0x8d, 0x16};
    const uintptr_t base = (uintptr_t)0x70000000u;
    const rb_elf_load_seg seg = {RB_PT_LOAD, RB_PF_R | RB_PF_X, 0u, 0u, 0x3850000u, 0x3850000u};
    rb_map_span ro_map = {base, base + 0x3850000u, RB_PROT_READ};

    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &ro_map, bad_first, expect, sizeof expect) == RB_RESUME_ERR_BYTES,
          "first-byte mismatch rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &ro_map, bad_last, expect, sizeof expect) == RB_RESUME_ERR_BYTES,
          "last-byte mismatch rejected");

    /* Overflow and invalid inputs */
    check(rb_validate_resume_source(UINTPTR_MAX - 0x10u, &seg, 1, 0x100u, 0, 0x100u,
                                    &ro_map, expect, expect, sizeof expect) == RB_RESUME_ERR_INPUT,
          "base + rva overflow rejected");
    check(rb_validate_resume_source(UINTPTR_MAX - 4u, &seg, 1, 0u, 0, 0u,
                                    &ro_map, expect, expect, sizeof expect) == RB_RESUME_ERR_INPUT,
          "addr + len overflow rejected");
    check(rb_validate_resume_source(base, NULL, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &ro_map, expect, expect, sizeof expect) == RB_RESUME_ERR_INPUT,
          "null segs rejected");
    check(rb_validate_resume_source(base, &seg, 0, 0x384ffdcu, 0, 0x384ffdcu,
                                    &ro_map, expect, expect, sizeof expect) == RB_RESUME_ERR_INPUT,
          "zero seg_count rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &ro_map, expect, NULL, sizeof expect) == RB_RESUME_ERR_INPUT,
          "null expected_bytes rejected");
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    &ro_map, expect, expect, 0) == RB_RESUME_ERR_INPUT,
          "zero expected_len rejected");
    /* Layout failure must never dereference observed_bytes (NULL here). */
    check(rb_validate_resume_source(base, &seg, 1, 0x384ffdcu, 0, 0x384ffdcu,
                                    NULL, NULL, expect, sizeof expect) == RB_RESUME_ERR_MAP,
          "layout error returns before inspecting observed_bytes");
}

int main(void) {
    test_arm64_native_and_translated();
    test_armv7_thumb_tag_and_lengths();
    test_map_permission_and_span_rejections();
    test_elf_and_memsz_rejections();
    test_byte_mismatch_and_overflow();
    if (g_fails) {
        fprintf(stderr, "%d failed\n", g_fails);
        return 1;
    }
    return 0;
}
