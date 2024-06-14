/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UKARCH_SEV_H__
#define __UKARCH_SEV_H__
#include "stdbool.h"
#include <uk/essentials.h>

/* CPUID Fn800_001F[EBX] bits 5:0 indicate the location of the c-bit in the PTE */
#define X86_AMD64_CPUID_EBX_MEM_ENCRYPTION_MASK		((1UL << 6) - 1)

/* CPUID Fn800_001F[EAX] memory encryption-related bits */
#define X86_AMD64_CPUID_EAX_SEV_ENABLED			(1UL << 1)
#define X86_AMD64_CPUID_EAX_SEV_ES_ENABLED		(1UL << 3)
#define X86_AMD64_CPUID_EAX_SEV_SNP_ENABLED		(1UL << 4)


static inline void vmgexit(void){
	asm volatile("rep;vmmcall;");
}

#define PVALIDATE_OPCODE				".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
#define PVALIDATE_SUCCESS				0
#define PVALIDATE_FAIL_INPUT				1
#define PVALIDATE_FAIL_SIZEMISMATCH			6
#define PVALIDATE_PAGE_SIZE_4K				0
#define PVALIDATE_PAGE_SIZE_2M				1

static inline int pvalidate_noupdate(__u64 vaddr, int page_size)
{
	int rc;
	int rmp_not_updated;
	int validated = 1;

	asm volatile(PVALIDATE_OPCODE
		     : "=a"(rc), "=@ccc"(rmp_not_updated)
		     : "a"(vaddr), "c"(page_size), "d"(validated)
		     : "memory", "cc");

	return rc;
}

static inline int pvalidate(__u64 vaddr, int page_size, int validated)
{
	int rc;
	int rmp_not_updated;

	asm volatile(PVALIDATE_OPCODE
		     : "=a"(rc), "=@ccc"(rmp_not_updated)
		     : "a"(vaddr), "c"(page_size), "d"(validated)
		     : "memory", "cc");

	if (rmp_not_updated) {
		return -1;
	}
	return rc;
}

static inline int rmpadjust(unsigned long vaddr, bool rmp_psize, unsigned long attrs)
{
	int rc;

	/* "rmpadjust" mnemonic support in binutils 2.36 and newer */
	asm volatile(".byte 0xF3,0x0F,0x01,0xFE\n\t"
		     : "=a"(rc)
		     : "a"(vaddr), "c"(rmp_psize), "d"(attrs)
		     : "memory", "cc");

	return rc;
}



struct vmcb_seg {
	__u16 selector;
	__u16 attrib;
	__u32 limit;
	__u64 base;
} __packed;

/* Save area definition for SEV-ES and SEV-SNP guests */
struct sev_es_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	__u64 vmpl0_ssp;
	__u64 vmpl1_ssp;
	__u64 vmpl2_ssp;
	__u64 vmpl3_ssp;
	__u64 u_cet;
	__u8 reserved_0xc8[2];
	__u8 vmpl;
	__u8 cpl;
	__u8 reserved_0xcc[4];
	__u64 efer;
	__u8 reserved_0xd8[104];
	__u64 xss;
	__u64 cr4;
	__u64 cr3;
	__u64 cr0;
	__u64 dr7;
	__u64 dr6;
	__u64 rflags;
	__u64 rip;
	__u64 dr0;
	__u64 dr1;
	__u64 dr2;
	__u64 dr3;
	__u64 dr0_addr_mask;
	__u64 dr1_addr_mask;
	__u64 dr2_addr_mask;
	__u64 dr3_addr_mask;
	__u8 reserved_0x1c0[24];
	__u64 rsp;
	__u64 s_cet;
	__u64 ssp;
	__u64 isst_addr;
	__u64 rax;
	__u64 star;
	__u64 lstar;
	__u64 cstar;
	__u64 sfmask;
	__u64 kernel_gs_base;
	__u64 sysenter_cs;
	__u64 sysenter_esp;
	__u64 sysenter_eip;
	__u64 cr2;
	__u8 reserved_0x248[32];
	__u64 g_pat;
	__u64 dbgctl;
	__u64 br_from;
	__u64 br_to;
	__u64 last_excp_from;
	__u64 last_excp_to;
	__u8 reserved_0x298[80];
	__u32 pkru;
	__u32 tsc_aux;
	__u8 reserved_0x2f0[24];
	__u64 rcx;
	__u64 rdx;
	__u64 rbx;
	__u64 reserved_0x320;	/* rsp already available at 0x01d8 */
	__u64 rbp;
	__u64 rsi;
	__u64 rdi;
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u8 reserved_0x380[16];
	__u64 guest_exit_info_1;
	__u64 guest_exit_info_2;
	__u64 guest_exit_int_info;
	__u64 guest_nrip;
	__u64 sev_features;
	__u64 vintr_ctrl;
	__u64 guest_exit_code;
	__u64 virtual_tom;
	__u64 tlb_id;
	__u64 pcpu_id;
	__u64 event_inj;
	__u64 xcr0;
	__u8 reserved_0x3f0[16];

	/* Floating point area */
	__u64 x87_dp;
	__u32 mxcsr;
	__u16 x87_ftw;
	__u16 x87_fsw;
	__u16 x87_fcw;
	__u16 x87_fop;
	__u16 x87_ds;
	__u16 x87_cs;
	__u64 x87_rip;
	__u8 fpreg_x87[80];
	__u8 fpreg_xmm[256];
	__u8 fpreg_ymm[256];
} __packed __attribute__ ((aligned (4096)));



#endif /* __UKARCH_SEV_H__ */
