/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include "../../vmem.h"

#include <uk/assert.h>
#include <uk/arch/traps.h>
#include <uk/arch/types.h>
#include <uk/print.h>
#include <uk/config.h>


#if CONFIG_OBLIVIUM
#include <oblivium/breakpoint.h>
#endif


#if CONFIG_OBLIVIUM_PROFILE_PF
#include <oblivium/oblivium.h>
static inline unsigned long rdtsc(void)
{
	unsigned long l, h;

	__asm__ __volatile__("rdtsc" : "=a"(l), "=d"(h));
	return (h << 32) | l;
}
#endif

static int vmem_arch_pagefault(void *data)
{

	#if CONFIG_OBLIVIUM_PROFILE_PF
	int timer = rdtsc();
	#endif
	struct ukarch_trap_ctx *ctx = (struct ukarch_trap_ctx *)data;
	__vaddr_t vaddr = (__vaddr_t)ctx->fault_address;
	const char *faultstr[] __maybe_unused = {
		"read", "write", "exec"
	};
	unsigned int faulttype;
	int rc;

	if (ctx->error_code & X86_PF_EC_WR)
		faulttype = UK_VMA_FAULT_WRITE;
	else if (ctx->error_code & X86_PF_EC_ID)
		faulttype = UK_VMA_FAULT_EXEC;
	else
		faulttype = UK_VMA_FAULT_READ;

	if (!(ctx->error_code & X86_PF_EC_P))
		faulttype |= UK_VMA_FAULT_NONPRESENT;
	else if (ctx->error_code & X86_PF_EC_RSVD)
		faulttype |= UK_VMA_FAULT_MISCONFIG;

	rc = vmem_pagefault(vaddr, faulttype, ctx->regs);
	#if CONFIG_OBLIVIUM_PROFILE_PF
	timer = rdtsc() - timer;
	oblivium_get_global_stats()->total_fault_time += timer;
	#endif
	if (unlikely(rc < 0)) {
		uk_pr_debug("Cannot handle %s page fault at 0x%"__PRIvaddr
			    " (ec: 0x%x): %d\n",
			    faultstr[faulttype & UK_VMA_FAULT_ACCESSTYPE],
			    vaddr, ctx->error_code, rc);

		return UK_EVENT_NOT_HANDLED;
	}

	return UK_EVENT_HANDLED;
}

UK_EVENT_HANDLER_PRIO(UKARCH_TRAP_PAGE_FAULT, vmem_arch_pagefault,
		      CONFIG_LIBUKVMEM_PAGEFAULT_HANDLER_PRIO);

#if CONFIG_OBLIVIUM
int handle_debug(void *data)
{
	return handle_sw_breakpoint(data);
}

UK_EVENT_HANDLER_PRIO(UKARCH_TRAP_DEBUG, handle_debug, 0);
#endif
