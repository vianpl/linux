/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CONTEXT_TRACKING_WORK_H
#define _LINUX_CONTEXT_TRACKING_WORK_H

#include <linux/bitops.h>

enum {
	CONTEXT_WORK_n_OFFSET,
	CONTEXT_WORK_MAX_OFFSET
};

enum ct_work {
	CONTEXT_WORK_n = BIT(CONTEXT_WORK_n_OFFSET),
	CONTEXT_WORK_MAX = BIT(CONTEXT_WORK_MAX_OFFSET)
};

static __always_inline void arch_context_tracking_work(int work)
{
	switch(work) {
	case CONTEXT_WORK_n:
		// Do work...
		break;
	}
}

#endif
