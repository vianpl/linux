// SPDX-License-Identifier: GPL-2.0
/*
 * Test for KVM's emulation of Hyper-V's TlbFlushInhibit bit
 *
 * Copyright © 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */
#include <pthread.h>
#include <time.h>

#include "apic.h"
#include "hyperv.h"

struct timespec abstime;

struct test_data {
	bool entered;
	bool hypercall_done;
	vm_paddr_t hcall_gpa;
};

void guest_main(vm_vaddr_t test_data)
{
	struct test_data *data = (struct test_data *)test_data;

	wrmsr(HV_X64_MSR_GUEST_OS_ID, HYPERV_LINUX_OS_ID);
	wrmsr(HV_X64_MSR_HYPERCALL, data->hcall_gpa);

	WRITE_ONCE(data->entered, true);

	/* Aligned for loading into XMM registers */
	__aligned(16) u64 processor_mask = BIT(0) | BIT(1) | BIT(2);

	/* Setup fast hyper-call */
	hyperv_write_xmm_input(&processor_mask, 1);
	hyperv_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE |
				 HV_HYPERCALL_FAST_BIT,
			 0x0, HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES);
	data->hypercall_done = true;

	GUEST_DONE();
}

struct test_data *test_data_init(struct kvm_vcpu *vcpu)
{
	vm_vaddr_t test_data_page;

	test_data_page = vm_vaddr_alloc_page(vcpu->vm);

	vcpu_args_set(vcpu, 1, test_data_page);

	return (struct test_data *)addr_gva2hva(vcpu->vm, test_data_page);
}

static void *vcpu_thread(void *arg)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)arg;
	struct ucall uc;

	while (1) {
		vcpu_run(vcpu);

		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_PRINTF:
			REPORT_GUEST_PRINTF(uc);
			break;
		default:
			TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);
			return NULL;
		}
	}
}

/* Test one vCPU being inhibited while another tries to flush its TLB */
void test_single(struct kvm_vm *vm, struct kvm_vcpu *inhibitor,
		 struct kvm_vcpu *flusher)
{
	struct kvm_hyperv_tlb_flush_inhibit set;
	struct test_data *data;
	unsigned int to_sleep;
	pthread_t thread;

	printf("%s ...\t", __func__);

	vcpu_arch_set_entry_point(flusher, guest_main);

	data = test_data_init(flusher);

	data->entered = false;
	data->hypercall_done = false;
	data->hcall_gpa = addr_gva2gpa(vm, vm_vaddr_alloc_pages(vm, 1));

	set.inhibit = true;
	vcpu_ioctl(inhibitor, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);

	pthread_create(&thread, NULL, vcpu_thread, flusher);

	/* Waiting on the guest to fully enter */
	while (READ_ONCE(data->entered) == false)
		asm volatile ("nop");

	/* Give the guest some time to attempt the hyper-call */
	to_sleep = 2;
	while ((to_sleep = sleep(to_sleep)))
		asm volatile ("nop");

	TEST_ASSERT_EQ(data->hypercall_done, false);
	TEST_ASSERT(pthread_tryjoin_np(thread, NULL) != 0, "thread finished early");

	set.inhibit = false;
	vcpu_ioctl(inhibitor, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);

	clock_gettime(CLOCK_REALTIME, &abstime);
	abstime.tv_sec += 5;
	TEST_ASSERT(pthread_timedjoin_np(thread, NULL, &abstime) == 0,
		    "couldn't join thread");

	TEST_ASSERT_EQ(data->hypercall_done, true);

	printf("[ok]\n");
}

/* Test one vCPU being inhibited while two others try to flush its TLB */
void test_multi_flusher(struct kvm_vm *vm, struct kvm_vcpu *inhibitor,
			struct kvm_vcpu *flusher1, struct kvm_vcpu *flusher2)
{
	struct kvm_hyperv_tlb_flush_inhibit set;
	struct test_data *data1, *data2;
	pthread_t thread1, thread2;
	unsigned int to_sleep;

	printf("%s ...\t", __func__);

	vcpu_arch_set_entry_point(flusher1, guest_main);
	vcpu_arch_set_entry_point(flusher2, guest_main);

	data1 = test_data_init(flusher1);
	data2 = test_data_init(flusher2);

	data1->entered = false;
	data1->hypercall_done = false;
	data1->hcall_gpa = addr_gva2gpa(vm, vm_vaddr_alloc_pages(vm, 1));
	data2->entered = false;
	data2->hypercall_done = false;
	data2->hcall_gpa = addr_gva2gpa(vm, vm_vaddr_alloc_pages(vm, 1));

	set.inhibit = true;
	vcpu_ioctl(inhibitor, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);

	pthread_create(&thread1, NULL, vcpu_thread, flusher1);
	pthread_create(&thread2, NULL, vcpu_thread, flusher2);

	/* Waiting on the guests to fully enter */
	while (READ_ONCE(data1->entered) == false)
		asm volatile("nop");
	while (READ_ONCE(data2->entered) == false)
		asm volatile("nop");

	/* Give the guests some time to attempt the hyper-call */
	to_sleep = 2;
	while ((to_sleep = sleep(to_sleep)))
		asm volatile("nop");

	TEST_ASSERT_EQ(data1->hypercall_done, false);
	TEST_ASSERT_EQ(data2->hypercall_done, false);

	TEST_ASSERT(pthread_tryjoin_np(thread1, NULL) != 0,
		    "thread 1 finished early");
	TEST_ASSERT(pthread_tryjoin_np(thread2, NULL) != 0,
		    "thread 2 finished early");

	set.inhibit = false;
	vcpu_ioctl(inhibitor, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);

	clock_gettime(CLOCK_REALTIME, &abstime);
	abstime.tv_sec += 5;
	TEST_ASSERT(pthread_timedjoin_np(thread1, NULL, &abstime) == 0,
		    "couldn't join thread1");

	clock_gettime(CLOCK_REALTIME, &abstime);
	abstime.tv_sec += 5;
	TEST_ASSERT(pthread_timedjoin_np(thread2, NULL, &abstime) == 0,
		    "couldn't join thread2");

	TEST_ASSERT_EQ(data1->hypercall_done, true);
	TEST_ASSERT_EQ(data2->hypercall_done, true);

	printf("[ok]\n");
}

/* Test two vCPUs being inhibited while another tries to flush their TLBs */
void test_multi_inhibitor(struct kvm_vm *vm, struct kvm_vcpu *inhibitor1,
			  struct kvm_vcpu *inhibitor2, struct kvm_vcpu *flusher)
{
	struct kvm_hyperv_tlb_flush_inhibit set;
	struct test_data *data;
	unsigned int to_sleep;
	pthread_t thread;

	printf("%s ...\t", __func__);

	vcpu_arch_set_entry_point(flusher, guest_main);

	data = test_data_init(flusher);

	data->entered = false;
	data->hypercall_done = false;
	data->hcall_gpa = addr_gva2gpa(vm, vm_vaddr_alloc_pages(vm, 1));

	set.inhibit = true;
	vcpu_ioctl(inhibitor1, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);
	vcpu_ioctl(inhibitor2, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);

	pthread_create(&thread, NULL, vcpu_thread, flusher);

	/* Waiting on the guest to fully enter */
	while (READ_ONCE(data->entered) == false)
		asm volatile ("nop");

	/* Give the guest some time to attempt the hyper-call */
	to_sleep = 2;
	while ((to_sleep = sleep(to_sleep)))
		asm volatile ("nop");

	TEST_ASSERT_EQ(data->hypercall_done, false);
	TEST_ASSERT(pthread_tryjoin_np(thread, NULL) != 0, "thread finished early");

	set.inhibit = false;
	vcpu_ioctl(inhibitor1, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);

	to_sleep = 1;
	while ((to_sleep = sleep(to_sleep)))
		asm volatile ("nop");

	TEST_ASSERT_EQ(data->hypercall_done, false);
	TEST_ASSERT(pthread_tryjoin_np(thread, NULL) != 0, "thread finished early");

	set.inhibit = false;
	vcpu_ioctl(inhibitor2, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);

	clock_gettime(CLOCK_REALTIME, &abstime);
	abstime.tv_sec += 5;
	TEST_ASSERT(pthread_timedjoin_np(thread, NULL, &abstime) == 0,
		    "couldn't join thread");

	TEST_ASSERT_EQ(data->entered, true);
	TEST_ASSERT_EQ(data->hypercall_done, true);

	printf("[ok]\n");
}

int main(int argc, char *argv[])
{
	struct kvm_vcpu *vcpu[3];
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_HYPERV_TLBFLUSH));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_HYPERV_TLB_FLUSH_INHIBIT));

	vm = vm_create_with_vcpus(3, guest_main, vcpu);

	vcpu_set_hv_cpuid(vcpu[0]);
	vcpu_set_hv_cpuid(vcpu[1]);
	vcpu_set_hv_cpuid(vcpu[2]);

	test_single(vm, vcpu[1], vcpu[0]);
	test_multi_flusher(vm, vcpu[1], vcpu[0], vcpu[2]);
	test_multi_inhibitor(vm, vcpu[1], vcpu[2], vcpu[0]);

	kvm_vm_free(vm);

	return 0;
}
