// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test for KVM_HC_GUEST_HINT hypercall.
 *
 * Two subtests, both via the same VM lifecycle:
 *
 *   1. Discovery + low-latency-vCPU happy path: guest checks the single
 *      KVM_FEATURE_GUEST_HINTS CPUID bit, then issues KVM_HC_GUEST_HINT
 *      with type=KVM_HINT_QUERY to enumerate which hint types userspace
 *      supports. After verifying KVM_HINT_LOW_LATENCY_VCPU is advertised,
 *      the guest builds a kvm_hint_low_latency_vcpu payload and issues the
 *      hint. Userspace reads the page back and asserts contents.
 *
 *   2. Invalid hint type: guest passes a bogus type. KVM forwards to
 *      userspace per the design (type semantics are userspace-owned); the
 *      test loop returns -KVM_EINVAL via run->hypercall.ret and the guest
 *      verifies rax matches.
 */
#include <asm/kvm_para.h>
#include <linux/kvm_para.h>
#include <stdint.h>
#include <string.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

#define HINT_NR_VCPUS		4
#define HINT_FLAGS		0
#define LL_BITMAP_WORDS		DIV_ROUND_UP(HINT_NR_VCPUS, 64)
#define LL_BITMAP_PATTERN	0xaUL	/* vCPUs 1 and 3 are isolated */
#define HINT_BAD_TYPE		0xdeadbeefUL

/* Mirror struct kvm_hint_query_response with a small fixed bitmap. */
struct query_payload {
	__u32 flags;
	__u32 nr_types;
	__u64 bitmap[1];
};

/* Mirror struct kvm_hint_low_latency_vcpu with a fixed-size bitmap. */
struct ll_payload {
	__u32 flags;
	__u32 nr_vcpus;
	__u64 bitmap[LL_BITMAP_WORDS];
};

static bool guest_run_invalid_type;

static void guest_code(gva_t query_gva, gpa_t query_gpa, gva_t ll_gva,
		       gpa_t ll_gpa)
{
	struct query_payload *q = (struct query_payload *)query_gva;
	struct ll_payload *p = (struct ll_payload *)ll_gva;
	long ret;
	int i;

	GUEST_ASSERT(this_cpu_has(X86_FEATURE_KVM_GUEST_HINTS));

	memset(q, 0, sizeof(*q));
	q->nr_types = 64;
	ret = kvm_hypercall(KVM_HC_GUEST_HINT, KVM_HINT_QUERY,
			    query_gpa, sizeof(*q), 0);
	GUEST_ASSERT_EQ(ret, 0);
	GUEST_ASSERT(q->bitmap[0] & BIT(KVM_HINT_QUERY));
	GUEST_ASSERT(q->bitmap[0] & BIT(KVM_HINT_LOW_LATENCY_VCPU));

	memset(p, 0, sizeof(*p));
	p->flags = HINT_FLAGS;
	p->nr_vcpus = HINT_NR_VCPUS;
	for (i = 0; i < LL_BITMAP_WORDS; i++)
		p->bitmap[i] = LL_BITMAP_PATTERN;

	ret = kvm_hypercall(KVM_HC_GUEST_HINT, KVM_HINT_LOW_LATENCY_VCPU,
			    ll_gpa, sizeof(*p), 0);
	GUEST_ASSERT_EQ(ret, 0);

	if (guest_run_invalid_type) {
		ret = kvm_hypercall(KVM_HC_GUEST_HINT, HINT_BAD_TYPE,
				    ll_gpa, sizeof(*p), 0);
		GUEST_ASSERT_EQ(ret, -KVM_EINVAL);
	}

	GUEST_DONE();
}

static void fill_query_response(struct kvm_vm *vm, gva_t query_gva)
{
	struct kvm_hint_query_response *resp = addr_gva2hva(vm, query_gva);

	TEST_ASSERT(resp->nr_types >= 64,
		    "Guest query buffer too small: nr_types=%u", resp->nr_types);
	resp->flags = 0;
	resp->bitmap[0] = BIT(KVM_HINT_QUERY) | BIT(KVM_HINT_LOW_LATENCY_VCPU);
}

static void verify_low_latency_payload(struct kvm_vm *vm, gva_t ll_gva)
{
	struct kvm_hint_low_latency_vcpu *hint = addr_gva2hva(vm, ll_gva);
	int i;

	TEST_ASSERT(hint->flags == HINT_FLAGS,
		    "Expected flags 0x%x, got 0x%x",
		    HINT_FLAGS, hint->flags);
	TEST_ASSERT(hint->nr_vcpus == HINT_NR_VCPUS,
		    "Expected nr_vcpus %u, got %u",
		    HINT_NR_VCPUS, hint->nr_vcpus);
	for (i = 0; i < LL_BITMAP_WORDS; i++)
		TEST_ASSERT(hint->bitmap[i] == LL_BITMAP_PATTERN,
			    "bitmap[%d]: expected 0x%lx, got 0x%llx",
			    i, LL_BITMAP_PATTERN,
			    (unsigned long long)hint->bitmap[i]);
}

static void handle_hint_exit(struct kvm_vcpu *vcpu, gva_t query_gva,
			     gpa_t query_gpa, gva_t ll_gva, gpa_t ll_gpa)
{
	struct kvm_run *run = vcpu->run;
	__u64 type = run->hypercall.args[0];
	__u64 gpa = run->hypercall.args[1];

	TEST_ASSERT(run->hypercall.nr == KVM_HC_GUEST_HINT,
		    "Expected hypercall nr %u, got %llu",
		    KVM_HC_GUEST_HINT, run->hypercall.nr);

	switch (type) {
	case KVM_HINT_QUERY:
		TEST_ASSERT(gpa == query_gpa,
			    "Query gpa: expected 0x%lx, got 0x%llx",
			    query_gpa, gpa);
		fill_query_response(vcpu->vm, query_gva);
		run->hypercall.ret = 0;
		break;
	case KVM_HINT_LOW_LATENCY_VCPU:
		TEST_ASSERT(gpa == ll_gpa,
			    "Low-latency gpa: expected 0x%lx, got 0x%llx",
			    ll_gpa, gpa);
		verify_low_latency_payload(vcpu->vm, ll_gva);
		run->hypercall.ret = 0;
		break;
	default:
		run->hypercall.ret = -KVM_EINVAL;
		break;
	}
}

static void run_to_completion(struct kvm_vcpu *vcpu, gva_t query_gva,
			      gpa_t query_gpa, gva_t ll_gva, gpa_t ll_gpa)
{
	struct kvm_run *run = vcpu->run;
	struct ucall uc;

	for (;;) {
		vcpu_run(vcpu);

		if (run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_hint_exit(vcpu, query_gva, query_gpa,
					 ll_gva, ll_gpa);
			continue;
		}

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_DONE:
			return;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		default:
			TEST_FAIL("Unexpected ucall %lu (exit_reason=%u: %s)",
				  uc.cmd, run->exit_reason,
				  exit_reason_str(run->exit_reason));
		}
	}
}

static void test_hint(bool invalid_type)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t query_gva, ll_gva;
	gpa_t query_gpa, ll_gpa;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL,
		      BIT(KVM_HC_GUEST_HINT));

	guest_run_invalid_type = invalid_type;
	sync_global_to_guest(vm, guest_run_invalid_type);

	query_gva = vm_alloc_page(vm);
	query_gpa = addr_gva2gpa(vm, query_gva);
	ll_gva = vm_alloc_page(vm);
	ll_gpa = addr_gva2gpa(vm, ll_gva);

	vcpu_args_set(vcpu, 4, query_gva, query_gpa, ll_gva, ll_gpa);

	run_to_completion(vcpu, query_gva, query_gpa, ll_gva, ll_gpa);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_EXIT_HYPERCALL) &
		     BIT(KVM_HC_GUEST_HINT));
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_KVM_GUEST_HINTS));

	pr_info("Subtest: discovery via query + low-latency-vCPU happy path\n");
	test_hint(false);

	pr_info("Subtest: invalid hint type rejected by userspace\n");
	test_hint(true);

	return 0;
}
