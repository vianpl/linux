/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVM_PARA_H
#define _UAPI__LINUX_KVM_PARA_H

#include <linux/types.h>

/*
 * This header file provides a method for making a hypercall to the host
 * Architectures should define:
 * - kvm_hypercall0, kvm_hypercall1...
 * - kvm_arch_para_features
 * - kvm_para_available
 */

/* Return values for hypercalls */
#define KVM_ENOSYS		1000
#define KVM_EFAULT		EFAULT
#define KVM_EINVAL		EINVAL
#define KVM_E2BIG		E2BIG
#define KVM_EPERM		EPERM
#define KVM_EOPNOTSUPP		95

#define KVM_HC_VAPIC_POLL_IRQ		1
#define KVM_HC_MMU_OP			2
#define KVM_HC_FEATURES			3
#define KVM_HC_PPC_MAP_MAGIC_PAGE	4
#define KVM_HC_KICK_CPU			5
#define KVM_HC_MIPS_GET_CLOCK_FREQ	6
#define KVM_HC_MIPS_EXIT_VM		7
#define KVM_HC_MIPS_CONSOLE_OUTPUT	8
#define KVM_HC_CLOCK_PAIRING		9
#define KVM_HC_SEND_IPI		10
#define KVM_HC_SCHED_YIELD		11
#define KVM_HC_MAP_GPA_RANGE		12
#define KVM_HC_GUEST_HINT		13

/*
 * KVM_HC_GUEST_HINT: guest -> hypervisor scheduling/configuration hints.
 *
 * Arguments:
 *   a0: hint type (KVM_HINT_*)
 *   a1: guest physical address of payload (page-aligned)
 *   a2: payload length in bytes (1..PAGE_SIZE)
 *   a3: reserved, must be 0
 *
 * Discovery: presence of KVM_FEATURE_GUEST_HINTS in CPUID indicates the
 * hypercall is available. To enumerate the hint types userspace will accept,
 * the guest issues the hypercall with type=KVM_HINT_QUERY and a buffer for
 * struct kvm_hint_query_response. Userspace fills the bitmap with one bit per
 * supported type id; bit KVM_HINT_QUERY itself is always set.
 *
 * For all other (non-query) types, KVM forwards to userspace via
 * KVM_EXIT_HYPERCALL. Per-type payload format and validation live in
 * userspace.
 */
#define KVM_HINT_QUERY			0
#define KVM_HINT_LOW_LATENCY_VCPU	1

/*
 * Response payload for KVM_HINT_QUERY. @bitmap is sized in 64-bit words and
 * indexed by hint type id; bit N set means type N is supported.
 */
struct kvm_hint_query_response {
	__u32 flags;
	__u32 nr_types;
	__u64 bitmap[];
};

/*
 * Payload for KVM_HINT_LOW_LATENCY_VCPU. Bit N set in @bitmap means vCPU N
 * is latency-sensitive ("isolated"); cleared means it's available for
 * housekeeping work.
 */
struct kvm_hint_low_latency_vcpu {
	__u32 flags;
	__u32 nr_vcpus;
	__u64 bitmap[];
};

/*
 * hypercalls use architecture specific
 */
#include <asm/kvm_para.h>

#endif /* _UAPI__LINUX_KVM_PARA_H */
