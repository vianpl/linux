/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CONTEXT_TRACKING_WORK_H
#define _LINUX_CONTEXT_TRACKING_WORK_H
#include <asm/sync_core.h>
#include <asm/tlbflush.h>

#include <linux/bitops.h>

enum {
	CONTEXT_WORK_SYNC_OFFSET,
	CONTEXT_WORK_TLBI_OFFSET,
	CONTEXT_WORK_MAX_OFFSET
};

enum ct_work {
	CONTEXT_WORK_SYNC = BIT(CONTEXT_WORK_SYNC_OFFSET),
	CONTEXT_WORK_TLBI = BIT(CONTEXT_WORK_TLBI_OFFSET),
	CONTEXT_WORK_MAX = BIT(CONTEXT_WORK_MAX_OFFSET)
};

static __always_inline void arch_context_tracking_work(int work)
{
	switch(work) {
	case CONTEXT_WORK_SYNC:
		sync_core();
		break;
	case CONTEXT_WORK_TLBI:
		/*
		 * When in NMI context we can't trust 'cpu_tlbstate.cr4' to be
		 * correct as we might be racing with another TLB flush. So get
		 * the value directly from the register. With this approach we
		 * should be able to nest as many times as necessary.
		 *
		 * XXX: Should this be moved into x86/mm/tlb.c?
		 */
		if (!static_cpu_has(X86_FEATURE_INVPCID) && in_nmi()) {
			__native_tlb_flush_global(native_read_cr4());
			break;
		}

		__flush_tlb_all();
		break;
	}
}

#endif
