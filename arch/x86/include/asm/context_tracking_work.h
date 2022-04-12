/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CONTEXT_TRACKING_WORK_H
#define _LINUX_CONTEXT_TRACKING_WORK_H
#include <asm/sync_core.h>

#include <linux/bitops.h>

enum {
	CONTEXT_WORK_SYNC_OFFSET,
	CONTEXT_WORK_MAX_OFFSET
};

enum ct_work {
	CONTEXT_WORK_SYNC = BIT(CONTEXT_WORK_SYNC_OFFSET),
	CONTEXT_WORK_MAX = BIT(CONTEXT_WORK_MAX_OFFSET)
};

static __always_inline void arch_context_tracking_work(int work)
{
	switch(work) {
	case CONTEXT_WORK_SYNC:
		sync_core();
		break;
	}
}

#endif
