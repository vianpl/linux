// SPDX-License-Identifier: GPL-2.0
/*
 * Test for KVM's emulation of Hyper-V's TlbFlushInhibit bit
 *
 * Copyright © 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */

#include "processor.h"

void set_dr0(uint64_t value) {
	__asm__ __volatile__ ("movq %0, %%rax; movq %%rax, %%dr0" :: "g" (value) : "%rax");
}

static inline void set_gdt(struct desc_ptr gdt)
{
	__asm__ __volatile__("lgdt %[gdt]"
			     :: /* input */ [gdt]"m"(gdt));
}

void guest_main(void)
{
	set_gdt(get_gdt());
	u64 cr0 = get_cr0();
	cr0 |= X86_CR0_WP;
	set_cr0(cr0);
	set_dr0((uint64_t) guest_main);
	xsetbv(0, xgetbv(0));

	GUEST_FAIL("xsetbv not caught");
}

void vcpu_run_expect_reg_filter(struct kvm_vcpu *vcpu, __u64 reg_id) {
	struct ucall ucall;

	vcpu_run(vcpu);

	if (vcpu->run->exit_reason == KVM_EXIT_IO &&
	    get_ucall(vcpu, &ucall) == UCALL_ABORT) {
		TEST_FAIL("%s", ucall.buffer);
	}

	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_WRITE_REG);
	TEST_ASSERT_EQ(vcpu->run->reg.reason, KVM_REG_EXIT_REASON_FILTER);
	TEST_ASSERT_EQ(vcpu->run->reg.reg, reg_id);
}

int main(int argc, char *argv[])
{
	struct kvm_register_filter filter = {};
	struct kvm_sregs sregs;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	__u64 reg_ids[] = {
		KVM_X86_REG_GDT,
		KVM_X86_REG_CR(0),
		KVM_X86_REG_DR(0),
		KVM_X86_REG_XCR(0),
	};

	printf("register_filter ...\t");

	filter.mask = KVM_REG_WRITE;
	filter.nmregs = ARRAY_SIZE(reg_ids);
	filter.regs = reg_ids;

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);

	vcpu_ioctl(vcpu, KVM_GET_SREGS, &sregs);
	sregs.cr4 |= (1 << 18);
	vcpu_ioctl(vcpu, KVM_SET_SREGS, &sregs);

	vm_ioctl(vm, KVM_SET_REGISTER_FILTER, &filter);

	for (size_t i = 0; i < ARRAY_SIZE(reg_ids); i++) {
		vcpu_run_expect_reg_filter(vcpu, reg_ids[i]);
	}

	printf("[ok]\n");

	kvm_vm_free(vm);

	return 0;
}
