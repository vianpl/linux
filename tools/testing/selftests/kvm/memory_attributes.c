// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Amazon.com, Inc. or its affiliates. All Rights Reserved
 *
 * Test for KVM_MEMORY_ATTRIBUTES
 */
#include <pthread.h>
#include <signal.h>

#include "test_util.h"
#include "ucall_common.h"
#include "kvm_util.h"
#include "processor.h"
#include "hyperv.h"
#include "apic.h"
#include "asm/pvclock-abi.h"

#define KVM_MEMORY_ATTRIBUTE_NO_ACCESS                       \
	(KVM_MEMORY_ATTRIBUTE_NR | KVM_MEMORY_ATTRIBUTE_NW | \
	 KVM_MEMORY_ATTRIBUTE_NX)

#define MMIO_GPA	0x700000000
#define MMIO_GVA	MMIO_GPA

enum {
	TEST_OP_NOP,
	TEST_OP_READ,
	TEST_OP_WRITE,
	TEST_OP_EXEC,
	TEST_OP_EXIT,
};

const char *test_op_names[] =
{
	[TEST_OP_READ] = "Read",
	[TEST_OP_WRITE] = "Write",
	[TEST_OP_EXEC] = "Exec",
	[TEST_OP_EXIT] = "Exit",
};

struct test_data {
	uint8_t op;
	int stage;
	vm_vaddr_t vaddr;

	struct kvm_vcpu *vcpu;
};

static struct test_data *test_data;

/* Arch-specific implementation mandatory */
__weak uint64_t arch_controlled_read(vm_vaddr_t addr)
{
	return 0;
}
__weak void arch_controlled_write(vm_vaddr_t addr) { }
__weak void arch_controlled_exec(vm_vaddr_t addr) { }
__weak void arch_write_return_insn(struct kvm_vm *vm, vm_vaddr_t addr) { }

static void guest_code(void *data)
{
	struct test_data *test_data = data;
	int stage = 1;
	uint32_t val;

	while (true) {
		vm_vaddr_t vaddr = READ_ONCE(test_data->vaddr);

		switch(READ_ONCE(test_data->op)) {
		case TEST_OP_READ:
			val = arch_controlled_read(vaddr);
			GUEST_SYNC(stage++);
			break;
		case TEST_OP_WRITE:
			arch_controlled_write(vaddr);
			GUEST_SYNC(stage++);
			break;
		case TEST_OP_EXEC:
			arch_controlled_exec(vaddr);
			GUEST_SYNC(stage++);
			break;
		default:
			goto exit;
		};
	}

exit:
	GUEST_DONE();
}

static void vcpu_run_and_inc_stage(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	vcpu_run(vcpu);

	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		TEST_ASSERT(uc.args[1] == test_data->stage,
			    "Unexpected stage: %ld (%d expected)",
			    uc.args[1], test_data->stage);
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		/* NOT REACHED */
	default:
		TEST_FAIL("Unknown ucall %lu", uc.cmd);
	}

	test_data->stage++;
}

static void test_page_restricted(struct kvm_vcpu *vcpu, int op,
				 vm_vaddr_t vaddr, vm_paddr_t fault_paddr,
				 uint64_t fault_reason)
{
	struct kvm_vm *vm = vcpu->vm;
	int rc;

	test_data->op = op;
	test_data->vaddr = vaddr;

	rc = _vcpu_run(vcpu);
	TEST_ASSERT(rc == -1 && errno == EFAULT,
		    "KVM_RUN IOCTL didn't return EFAULT on %s, rc %d, errno %d",
		    test_op_names[op], rc, errno);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MEMORY_FAULT);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.gpa, fault_paddr);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.flags, fault_reason);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.size, vm->page_size);
}

static void test_page_accessible(struct kvm_vcpu *vcpu, int op, vm_vaddr_t vaddr)
{
	test_data->op = op;
	test_data->vaddr = vaddr;
	vcpu_run_and_inc_stage(vcpu);
}

/*
 * We want to test the following cases:
 * - Sucessful access to GPAs backed by memory attributes (for ex. read access
 *   on an read-only page).
 * - First fault after setting memory attributes, with unpopulated SPTEs/EPTS.
 * - Fault caused by an SPTE/EPT reflecting the memory attributes.
 *
 * The list of ops below tests the 3 situations for each memory attribute
 * combination.
 */
const struct memory_access {
	uint64_t attrs;
	int ops[5];
} access_array[] = {
	{ 0, { TEST_OP_READ, TEST_OP_WRITE, TEST_OP_EXEC } },
	{ KVM_MEMORY_ATTRIBUTE_NW,
	  { TEST_OP_WRITE, TEST_OP_READ, TEST_OP_EXEC, TEST_OP_WRITE } },
	{ KVM_MEMORY_ATTRIBUTE_NX,
	  { TEST_OP_EXEC, TEST_OP_READ, TEST_OP_WRITE, TEST_OP_EXEC } },
	{ KVM_MEMORY_ATTRIBUTE_NW | KVM_MEMORY_ATTRIBUTE_NX,
	  { TEST_OP_EXEC, TEST_OP_WRITE, TEST_OP_READ, TEST_OP_WRITE,
	    TEST_OP_EXEC } },
	{ KVM_MEMORY_ATTRIBUTE_NO_ACCESS,
	  { TEST_OP_READ, TEST_OP_WRITE, TEST_OP_EXEC } },
	/* Verify everything is back to normal */
	{ 0, { TEST_OP_READ, TEST_OP_WRITE, TEST_OP_EXEC } },
};

static void test_page_access(struct kvm_vcpu *vcpu, vm_vaddr_t vaddr,
			     uint64_t attrs, const int ops[])
{
	struct kvm_vm *vm = vcpu->vm;
	vm_paddr_t paddr = addr_gva2gpa(vm, vaddr);

	for (int i = 0; i < ARRAY_SIZE(access_array[0].ops); i++) {
		int op = ops[i];

		if (op == TEST_OP_NOP)
			continue;

		/*
		 * We're about to have the guest jump into 'vaddr', make it a
		 * 'ret' instruction so it returns right away.
		 */
		if (op == TEST_OP_EXEC)
			arch_write_return_insn(vm, vaddr);

		vm_set_memory_attributes(vm, paddr, vm->page_size, attrs);

		/*
		 * Attributes are negated, a match means the operation should
		 * fail.
		 */
		if (attrs & BIT_ULL(op - 1)) {
			test_page_restricted(vcpu, op, vaddr, paddr, BIT(op - 1));
			vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
		}

		test_page_accessible(vcpu, op, vaddr);
	}

}

static void test_memory_access(struct kvm_vcpu *vcpu, vm_vaddr_t test_vm_vaddr,
			       size_t size)
{
	struct kvm_vm *vm = vcpu->vm;

	for (size_t i = 0; i < ARRAY_SIZE(access_array); i++) {
		uint64_t attrs = access_array[i].attrs;

		vm_set_memory_attributes(vm, addr_gva2gpa(vm, test_vm_vaddr),
					 size, attrs);

		for (vm_vaddr_t vaddr = test_vm_vaddr;
		     vaddr < test_vm_vaddr + size; vaddr += vm->page_size)
			test_page_access(vcpu, vaddr, attrs, access_array[i].ops);
	}
}

static void test_memattrs_ignore_mmio(struct kvm_vcpu *vcpu)
{
	struct kvm_vm *vm = vcpu->vm;

	vm_set_memory_attributes(vm, MMIO_GPA, vm->page_size,
				 KVM_MEMORY_ATTRIBUTE_NO_ACCESS);

	test_data->op = TEST_OP_READ;
	test_data->vaddr = MMIO_GVA;
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(vcpu->run->mmio.phys_addr, MMIO_GPA);
	TEST_ASSERT_EQ(vcpu->run->mmio.is_write, 0);
	TEST_ASSERT_EQ(vcpu->run->mmio.len, 8);
	vcpu_run_and_inc_stage(vcpu);

	test_data->op = TEST_OP_WRITE;
	test_data->vaddr = MMIO_GVA;
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(vcpu->run->mmio.phys_addr, MMIO_GPA);
	TEST_ASSERT_EQ(vcpu->run->mmio.is_write, 1);
	TEST_ASSERT_EQ(vcpu->run->mmio.len, 8);
	vcpu_run_and_inc_stage(vcpu);

	vm_set_memory_attributes(vm, MMIO_GPA, vm->page_size, 0);
}

static void test_input_validation(struct kvm_vm *vm)
{
	uint64_t flags, gpa = 0, size = 0, attrs = 0;
	int rc;

	/* 'flags' is unsupported */
	flags = BIT(0);
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);

	/* 'size' can't be 0 */
	flags = 0;
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);

	/* 'gpa' shouldn't overflow */
	gpa = 0ULL - vm->page_size;
	size = vm->page_size;
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);

	/* 'gpa' should be page aligned */
	gpa = 1;
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);

	/* 'size' should be page aligned */
	gpa = 0;
	size = 1;
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);

	/* exec mappings require read access */
	size = vm->page_size;
	attrs = KVM_MEMORY_ATTRIBUTE_NR | KVM_MEMORY_ATTRIBUTE_NW;
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);

	/* write mappings require read access */
	size = vm->page_size;
	attrs = KVM_MEMORY_ATTRIBUTE_NR | KVM_MEMORY_ATTRIBUTE_NX;
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);

	/* private mappings are incompatible with access restrictions */
	attrs = KVM_MEMORY_ATTRIBUTE_NW | KVM_MEMORY_ATTRIBUTE_PRIVATE;
	rc = __vm_set_memory_attributes(vm, gpa, size, attrs, flags);
	TEST_ASSERT_VM_VCPU_IOCTL(rc == -1 && errno == EINVAL,
				  KVM_SET_MEMORY_ATTRIBUTES, rc, vm);
}

static void test_finalize(struct kvm_vcpu *vcpu)
{
	test_data->op = TEST_OP_EXIT;
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);
}

static struct test_data *init_test_data(struct kvm_vcpu *vcpu)
{
	struct kvm_vm *vm = vcpu->vm;
	vm_vaddr_t test_data_vm_vaddr;

	test_data_vm_vaddr = vm_vaddr_alloc_page(vm);
	vcpu_args_set(vcpu, 1, test_data_vm_vaddr);

	test_data = addr_gva2hva(vm, test_data_vm_vaddr);
	test_data->stage = 1;
	test_data->vcpu = vcpu;

	return test_data;
}

int main(int argc, char *argv[])
{
	uint32_t guest_page_size = vm_guest_mode_params[VM_MODE_DEFAULT].page_size;
	unsigned int ptes_per_page = guest_page_size / 8;
	size_t size = guest_page_size * ptes_per_page * 2; /* 2 huge-pages */
	struct kvm_vcpu *vcpu;
	vm_vaddr_t test_mem;
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_MEMORY_ATTRIBUTES) &
		     KVM_MEMORY_ATTRIBUTE_NO_ACCESS);

	vm = __vm_create_with_one_vcpu(&vcpu, size, guest_code);
	test_mem = vm_vaddr_alloc(vm, size, KVM_UTIL_MIN_VADDR);
	virt_map(vcpu->vm, MMIO_GVA, MMIO_GPA, 1);
	test_data = init_test_data(vcpu);

	test_input_validation(vm);
	test_memory_access(vcpu, test_mem, size);
	test_memattrs_ignore_mmio(vcpu);
	test_finalize(vcpu);

	kvm_vm_free(vm);
	return 0;
}
