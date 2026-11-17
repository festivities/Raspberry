.section __TEXT,__text,regular,pure_instructions
.p2align 2

.globl _raspberry_ios_enqueue_probe_v1
.private_extern _raspberry_ios_enqueue_probe_prepare

_raspberry_ios_enqueue_probe_v1:
.cfi_startproc
.cfi_def_cfa 31, 0
	sub	sp, sp, #96
.cfi_def_cfa_offset 96
	stp	x0, x1, [sp]
.cfi_offset 0, -96
.cfi_offset 1, -88
	stp	x2, x3, [sp, #16]
.cfi_offset 2, -80
.cfi_offset 3, -72
	stp	x4, x5, [sp, #32]
.cfi_offset 4, -64
.cfi_offset 5, -56
	stp	x6, x7, [sp, #48]
.cfi_offset 6, -48
.cfi_offset 7, -40
	stp	x8, x29, [sp, #64]
.cfi_offset 8, -32
.cfi_offset 29, -24
	str	x30, [sp, #80]
.cfi_offset 30, -16

	bl	_raspberry_ios_enqueue_probe_prepare
	mov	x16, x0

	ldp	x0, x1, [sp]
.cfi_restore 0
.cfi_restore 1
	ldp	x2, x3, [sp, #16]
.cfi_restore 2
.cfi_restore 3
	ldp	x4, x5, [sp, #32]
.cfi_restore 4
.cfi_restore 5
	ldp	x6, x7, [sp, #48]
.cfi_restore 6
.cfi_restore 7
	ldp	x8, x29, [sp, #64]
.cfi_restore 8
.cfi_restore 29
	ldr	x30, [sp, #80]
.cfi_restore 30
	add	sp, sp, #96
.cfi_def_cfa_offset 0
	br	x16
.cfi_endproc
