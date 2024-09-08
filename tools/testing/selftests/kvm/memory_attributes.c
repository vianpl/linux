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

#define HV_STATUS_INVALID_HYPERCALL_INPUT	3

#define MMIO_GPA	0x700000000
#define MMIO_GVA	MMIO_GPA

#define PT_WRITABLE_MASK	BIT_ULL(1)
#define PT_ACCESSED_MASK	BIT_ULL(5)
#define PTE_VADDR		0x1000000000

static volatile uint64_t ipis_rcvd;

static pthread_t vcpu_thread;

struct hv_vpset {
	u64 format;
	u64 valid_bank_mask;
	u64 bank_contents[2];
};

enum HV_GENERIC_SET_FORMAT {
	HV_GENERIC_SET_SPARSE_4K,
	HV_GENERIC_SET_ALL,
};

struct hv_send_ipi_ex {
	u32 vector;
	u32 reserved;
	struct hv_vpset vp_set;
};

enum {
	TEST_OP_NOP,
	TEST_OP_READ,
	TEST_OP_WRITE,
	TEST_OP_EXEC,
	TEST_OP_INVPLG,
	TEST_OP_HYPERV_HYPERCALL_INPUT,
	TEST_OP_MONITOR_ADDRESS,
	TEST_OP_EXIT,
};

const char *test_op_names[] =
{
	[TEST_OP_READ] = "Read",
	[TEST_OP_WRITE] = "Write",
	[TEST_OP_EXEC] = "Exec",
	[TEST_OP_INVPLG] = "Invplg",
	[TEST_OP_HYPERV_HYPERCALL_INPUT] = "HvHcall input",
	[TEST_OP_MONITOR_ADDRESS] = "Monitor address",
	[TEST_OP_EXIT] = "Exit",
};

struct test_data {
	uint8_t op;
	int stage;
	vm_vaddr_t vaddr;
	vm_paddr_t paddr;
	uint8_t confirm_read;
	uint64_t expected_val;

	struct kvm_vcpu *vcpu;
};

static struct test_data *test_data;

/* Arch-specific implementation mandatory */
__weak uint64_t arch_controlled_read(vm_vaddr_t addr)
{
	return 0;
}
__weak void arch_controlled_write(vm_vaddr_t addr, uint64_t val) { }
__weak void arch_controlled_exec(vm_vaddr_t addr) { }
__weak void arch_write_return_insn(struct kvm_vm *vm, vm_vaddr_t addr) { }

/* Arch-specific implementation optional */
__weak void arch_guest_init(void) { }

static void guest_code(void *data)
{
	struct test_data *test_data = data;
	int stage = 1;
	uint32_t val;

	arch_guest_init();

	while (true) {
		uint64_t expected_val = READ_ONCE(test_data->expected_val);
		bool confirm_read = READ_ONCE(test_data->confirm_read);
		vm_vaddr_t vaddr = READ_ONCE(test_data->vaddr);
		vm_paddr_t paddr = READ_ONCE(test_data->paddr);

		switch(READ_ONCE(test_data->op)) {
		case TEST_OP_READ:
			val = arch_controlled_read(vaddr);
			if (confirm_read)
				GUEST_ASSERT_EQ(expected_val, val);
			GUEST_SYNC(stage++);
			break;
		case TEST_OP_WRITE:
			arch_controlled_write(vaddr, expected_val);
			GUEST_SYNC(stage++);
			break;
		case TEST_OP_EXEC:
			arch_controlled_exec(vaddr);
			GUEST_SYNC(stage++);
			break;
#ifdef __x86_64__
		case TEST_OP_INVPLG:
			asm volatile("invlpg (%0)"
				     :: "b" (vaddr): "memory");
			GUEST_SYNC(stage++);
			break;
		case TEST_OP_HYPERV_HYPERCALL_INPUT: {
			uint64_t hv_status;
			uint8_t vector;

			vector = __hyperv_hypercall(HVCALL_SEND_IPI_EX,
						    paddr, 0, &hv_status);
			GUEST_ASSERT_EQ(vector, 0);
			GUEST_ASSERT_EQ(hv_status, HV_STATUS_INVALID_HYPERCALL_INPUT);
			GUEST_SYNC(stage++);

			hyperv_hypercall(HVCALL_SEND_IPI_EX, paddr, 0);
			asm volatile ("sti; hlt; cli;");
			GUEST_ASSERT_EQ(ipis_rcvd, 1);
			GUEST_SYNC(stage++);
			break;
		}
		case TEST_OP_MONITOR_ADDRESS: {
			uint64_t *pval = (uint64_t *)vaddr;
			uint64_t val = READ_ONCE(*pval);

			while (READ_ONCE(*pval) == val &&
			       /* So host can force the op out of the loop */
			       READ_ONCE(test_data->op) == TEST_OP_MONITOR_ADDRESS)
				asm volatile("nop");

			GUEST_SYNC(stage++);
			break;
		}
#endif
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

static int test_page(struct kvm_vcpu *vcpu, int op, vm_vaddr_t vaddr)
{
	int rc;

	test_data->op = op;
	test_data->vaddr = vaddr;

	rc = _vcpu_run(vcpu);

	if (rc >= 0)
		test_data->stage++;

	return rc < 0 ? -errno : rc;
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
	if (fault_reason)
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

#ifdef __x86_64__
/*
 * This test validates that, during a page walk, if the page a PTE is placed in
 * is read-only the accesss and dirty bits will not be written. Note There's a
 * slight variation in behaviour between TDP and non-TDP VMs:
 *  - With TDP enabled, KVM issues a fault exit upon observing the non-writable
 *  page.
 *  - With non-TDP, the access bit is not set, but the walk succeeds.
 *
 *  This is aligned with read-only memslots' behaviour.
 */
static void test_memory_access_pte_ro(struct kvm_vcpu *vcpu, vm_vaddr_t vaddr)
{
	struct kvm_vm *vm = vcpu->vm;
	int level = PG_LEVEL_4K;
	vm_paddr_t paddr;
	uint64_t *pte;

	pte = __vm_get_page_table_entry(vm, vaddr, &level);
	TEST_ASSERT_EQ(level, PG_LEVEL_4K);
	paddr = addr_hva2gpa(vm, pte) & GENMASK(61, vm->page_shift);

	*pte &= ~PTE_ACCESSED_MASK;
	vm_set_memory_attributes(vm, paddr, vm->page_size, KVM_MEMORY_ATTRIBUTE_NW);
	if (test_page(vcpu, TEST_OP_READ, vaddr) < 0) {
		test_page_restricted(vcpu, TEST_OP_READ, vaddr, paddr,
				     /* write PTE's accessed bit */
				     KVM_MEMORY_EXIT_FLAG_WRITE);

		vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
		test_page_accessible(vcpu, TEST_OP_READ, vaddr);
		TEST_ASSERT_EQ(*pte & PTE_ACCESSED_MASK, PTE_ACCESSED_MASK);

		/* Re-run the test, now vaddr is backed by an EPT. */
		*pte &= ~PTE_ACCESSED_MASK;
		vm_set_memory_attributes(vm, paddr, vm->page_size,
					 KVM_MEMORY_ATTRIBUTE_NW);
		test_page_restricted(vcpu, TEST_OP_READ, vaddr, paddr,
				     /* write PTE's accessed bit */
				     KVM_MEMORY_EXIT_FLAG_WRITE);
		vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
		test_page_accessible(vcpu, TEST_OP_READ, vaddr);
	} else {
		TEST_ASSERT_EQ(*pte & PTE_ACCESSED_MASK, 0);
		vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
	}
}

/*
 * This test validates that, during a page walk, if the page a PTE is placed in
 * is maked as non-accesible, KVM issues a fault exit.
 */
static void test_memory_access_pte_nr(struct kvm_vcpu *vcpu, vm_vaddr_t vaddr)
{
	struct kvm_vm *vm = vcpu->vm;
	int level = PG_LEVEL_4K;
	vm_paddr_t paddr;
	uint64_t *pte;

	pte = __vm_get_page_table_entry(vm, vaddr, &level);
	TEST_ASSERT_EQ(level, PG_LEVEL_4K);
	paddr = addr_hva2gpa(vm, pte) & GENMASK(61, vm->page_shift);

	vm_set_memory_attributes(vm, paddr, vm->page_size,
				 KVM_MEMORY_ATTRIBUTE_NO_ACCESS);

	test_page_restricted(vcpu, TEST_OP_READ, vaddr, paddr, 0);

	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
	test_page_accessible(vcpu, TEST_OP_READ, vaddr);

	/* Re-run the test, now vaddr is backed by an SPTE. */
	vm_set_memory_attributes(vm, paddr, vm->page_size,
				 KVM_MEMORY_ATTRIBUTE_NO_ACCESS);
	test_page_restricted(vcpu, TEST_OP_READ, vaddr, paddr, 0);
	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
	test_page_accessible(vcpu, TEST_OP_READ, vaddr);
}

static void test_memory_access_sync_spte(struct kvm_vcpu *vcpu, vm_vaddr_t vaddr)
{
	struct kvm_vm *vm = vcpu->vm;
	vm_paddr_t paddr = addr_gva2gpa(vm, vaddr);
	uint64_t *pte, old_pte, new_pte;
	int level = PG_LEVEL_4K;

	pte = __vm_get_page_table_entry(vm, vaddr, &level);
	TEST_ASSERT_EQ(level, PG_LEVEL_4K);
	vm_paddr_t pte_paddr = addr_hva2gpa(vm, pte);
	vm_paddr_t pte_page_paddr = pte_paddr & GENMASK(61, vm->page_shift);
	int pte_offset = pte_paddr - pte_page_paddr;
	virt_pg_map(vm, PTE_VADDR, pte_page_paddr);
	old_pte = *pte;

	/* Set vmaddr as non-executable */
	vm_set_memory_attributes(vm, paddr, vm->page_size, KVM_MEMORY_ATTRIBUTE_NX);
	printf("paddr %lx, vaddr %lx, pteaddr%lx\n", paddr, vaddr, pte_paddr);

	/*
	 * Make sure SPTEs are populated as previous op might have destroyed
	 * them. We new have a non-executable SPTE.
	 */
	test_page_accessible(vcpu, TEST_OP_READ, vaddr);

	/*
	 * Update PTE, make it non-writable and flush TLBs to make sure we go
	 * through the sync_spte path. This should update the SPTE and make it
	 * read-only.
	 */
	new_pte = (old_pte & ~PT_WRITABLE_MASK) | PT_ACCESSED_MASK;
	test_data->expected_val = new_pte;
	test_page_accessible(vcpu, TEST_OP_WRITE, PTE_VADDR + pte_offset);
	TEST_ASSERT_EQ(*pte, new_pte);
	test_page_accessible(vcpu, TEST_OP_INVPLG, vaddr);

	/* The not executable attrs remain valid */
	arch_write_return_insn(vm, vaddr);
	test_page_restricted(vcpu, TEST_OP_EXEC, vaddr, paddr,
			     KVM_MEMORY_EXIT_FLAG_EXEC);

	/* Cleanup */
	*pte = old_pte;
	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
	test_page_accessible(vcpu, TEST_OP_EXEC, vaddr);
}

static void test_memory_access_pte(struct kvm_vcpu *vcpu, vm_vaddr_t vaddr)
{
	test_memory_access_pte_nr(vcpu, vaddr);
	test_memory_access_pte_ro(vcpu, vaddr);
	test_memory_access_sync_spte(vcpu, vaddr);
}

#define IPI_VECTOR	 0xfe

static void guest_ipi_handler_hv(struct ex_regs *regs)
{
	ipis_rcvd++;
	wrmsr(HV_X64_MSR_EOI, 1);
}

/*
 * This test verifies that the Hyper-V hypercall exit handler takes memory
 * attributes into account before accessing input data. It coordinates with the
 * guest through the 'TEST_OP_HYPERV_HYPERCALL_INPUT' operation and instructs
 * the guest to issue two PV IPIs. The first PV IPI fails because the input
 * data is held in read-protected memory. Subsequently, the memory protection
 * is lifted, and the second PV IPI succeeds.
 */
static void test_side_channel_hyperv_hypercall_inputs(struct kvm_vcpu *vcpu,
						      vm_vaddr_t test_vm_addr,
						      size_t size)
{
	struct hv_send_ipi_ex *ipi_ex = addr_gva2hva(vcpu->vm, test_vm_addr);
	struct kvm_vm *vm = vcpu->vm;
	vm_paddr_t paddr;

	if (!kvm_has_cap(KVM_CAP_HYPERV_SEND_IPI))
		return;

	ipis_rcvd = 0;
	vm_install_exception_handler(vm, IPI_VECTOR, guest_ipi_handler_hv);
	vcpu_set_msr(vcpu, HV_X64_MSR_GUEST_OS_ID, HYPERV_LINUX_OS_ID);

	test_data->op = TEST_OP_HYPERV_HYPERCALL_INPUT;
	test_data->vaddr = test_vm_addr;
	paddr = addr_gva2gpa(vm, test_data->vaddr);
	test_data->paddr = paddr;
	ipi_ex->vector = IPI_VECTOR;
	ipi_ex->vp_set.format = HV_GENERIC_SET_ALL;
	vm_set_memory_attributes(vm, paddr, vm->page_size, KVM_MEMORY_ATTRIBUTE_NO_ACCESS);
	vcpu_run_and_inc_stage(vcpu);
	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
	vcpu_run_and_inc_stage(vcpu);
}

/*
 * Verifies that the guest page table walker fails the walk if it encounters a
 * page table entry address read-protected by a memory attribute.
 */
static void test_side_channel_emul_page_walks(struct kvm_vcpu *vcpu,
					      vm_vaddr_t test_vm_addr,
					      size_t size)
{
	const uint64_t pte_addr_mask = GENMASK(51, 12);
	struct kvm_vm *vm = vcpu->vm;
	struct kvm_translation tr;
	int level = PG_LEVEL_1G;
	vm_paddr_t paddr;
	uint64_t *pte;

	pte = __vm_get_page_table_entry(vm, test_vm_addr, &level);
	TEST_ASSERT_EQ(level, PG_LEVEL_1G);
	paddr = *pte & pte_addr_mask;

	tr = vcpu_translate(vcpu, test_vm_addr);
	TEST_ASSERT_EQ(tr.valid, true);
	TEST_ASSERT_EQ(tr.physical_address, addr_gva2gpa(vm, test_vm_addr));

	vm_set_memory_attributes(vm, paddr, vm->page_size, KVM_MEMORY_ATTRIBUTE_NO_ACCESS);
	tr = vcpu_translate(vcpu, test_vm_addr);
	TEST_ASSERT_EQ(tr.valid, false);

	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
}

static void vm_set_vapic_addr(struct kvm_vcpu *vcpu, uint64_t addr)
{
	struct kvm_vapic_addr va;

	va.vapic_addr = addr;
	vcpu_ioctl(vcpu, KVM_SET_VAPIC_ADDR, &va);
}

/*
 * Perform a dummy regs update to issue a KVM_REQ_EVENT. This forces
 * vapic to be synced before entering the guest.
 */
static void vcpu_force_vapic_update(struct kvm_vcpu *vcpu)
{
	struct kvm_regs regs;

	vcpu_regs_get(vcpu, &regs);
	vcpu_regs_set(vcpu, &regs);
}

/*
 * Setup the vapic address on a GPA that is write-protected. Force an vapic
 * update and validate its contents were not changes. Then, lift the write
 * restriction and validate the page's contents are updated.
 */
static void test_side_channel_vapic_addr(struct kvm_vcpu *vcpu)
{
	struct kvm_vm *vm = vcpu->vm;
	vm_vaddr_t vaddr = vm_vaddr_alloc_page(vm);
	vm_paddr_t paddr = addr_gva2gpa(vm, vaddr);

	vm_set_vapic_addr(vcpu, paddr);
	test_data->op = TEST_OP_READ;
	test_data->vaddr = vaddr;
	test_data->confirm_read = 1;
	test_data->expected_val = ~0ULL >> 32;
	memset(addr_gva2hva(vm, vaddr), 0xff, sizeof(uint32_t));
	vm_set_memory_attributes(vm, paddr, vm->page_size, KVM_MEMORY_ATTRIBUTE_NW);
	vcpu_run_and_inc_stage(vcpu);

	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
	vcpu_force_vapic_update(vcpu);
	test_data->expected_val = 0ULL;
	vcpu_run_and_inc_stage(vcpu);

	vm_set_vapic_addr(vcpu, 0);
	test_data->confirm_read = 0;
}

static void *vcpu_worker(void *data)
{
	struct test_data *test_data = data;
	struct kvm_vcpu *vcpu = test_data->vcpu;

	vcpu_run_and_inc_stage(vcpu);

	return NULL;
}

/*
 * Set up the pvclock page and validate that KVM periodically updates the
 * 'tsc_timestamp' field. Subsequently, make the pvclock page non-writable and
 * verify that the 'tsc_timestamp' field is no longer updated.
 */
static void test_side_channel_pvclock(struct kvm_vcpu *vcpu)
{
	struct kvm_vm *vm = vcpu->vm;
	vm_vaddr_t vaddr = vm_vaddr_alloc_page(vm);
	vm_paddr_t paddr = addr_gva2gpa(vm, vaddr);
	vcpu_set_msr(vcpu, MSR_KVM_SYSTEM_TIME_NEW, paddr | 0x1);

	test_data->op = TEST_OP_MONITOR_ADDRESS;
	test_data->vaddr = vaddr + offsetof(struct pvclock_vcpu_time_info, tsc_timestamp);

	pthread_create(&vcpu_thread, NULL, vcpu_worker, test_data);
	usleep(msecs_to_usecs(1000));
	TEST_ASSERT_EQ(pthread_tryjoin_np(vcpu_thread, NULL), 0);

	vm_set_memory_attributes(vm, paddr, vm->page_size, KVM_MEMORY_ATTRIBUTE_NW);
	pthread_create(&vcpu_thread, NULL, vcpu_worker, test_data);
	usleep(msecs_to_usecs(1000));
	TEST_ASSERT_EQ(pthread_tryjoin_np(vcpu_thread, NULL), EBUSY);

	/* Force the 'monitor_address' guest operation to finish */
	test_data->op = TEST_OP_NOP;
	TEST_ASSERT_EQ(pthread_join(vcpu_thread, NULL), 0);
	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
	vcpu_set_msr(vcpu, MSR_KVM_SYSTEM_TIME_NEW, 0);
}

/*
 * Write to MSR_KVM_WALL_CLOCK_NEW and verify that the struct's 'version' field
 * is updated. Subsequently, make the target guest physical address
 * non-writable, and verify the 'version' field isn't updated anymore.
 */
static void test_side_channel_wallclock(struct kvm_vcpu *vcpu)
{
	struct kvm_vm *vm = vcpu->vm;
	vm_vaddr_t vaddr = vm_vaddr_alloc_page(vm);
	vm_paddr_t paddr = addr_gva2gpa(vm, vaddr);
	struct pvclock_wall_clock *wc = addr_gva2hva(vm, vaddr);

	wc->version = 0x0;
	vcpu_set_msr(vcpu, MSR_KVM_WALL_CLOCK_NEW, paddr);
	TEST_ASSERT_EQ(wc->version, 2);

	vm_set_memory_attributes(vm, paddr, vm->page_size, KVM_MEMORY_ATTRIBUTE_NW);
	vcpu_set_msr(vcpu, MSR_KVM_WALL_CLOCK_NEW, paddr);
	TEST_ASSERT_EQ(wc->version, 2);

	vm_set_memory_attributes(vm, paddr, vm->page_size, 0);
}

/*
 * Memory attributes are vulnerable to side-channel attacks. This means that
 * any KVM operation initiated by the guest that requires guest memory access
 * (which is the case for most pv-interfaces) needs to consider memory
 * attributes.
 *
 * The following tests validate that this requirement is upheld for a variety
 * of use-cases. These test cases were selected to exercise specific approaches
 * to accessing guest memory, including:
 *
 *  - kvm_read/write_guest()
 *  - gfn_to_hva_cache
 *  - gfn_to_pfn_cache
 *  - Guest page walker
 */
static void test_side_channels(struct kvm_vcpu *vcpu, vm_vaddr_t test_vm_addr,
			       size_t size)
{
	test_side_channel_hyperv_hypercall_inputs(vcpu, test_vm_addr, size);
	test_side_channel_emul_page_walks(vcpu, test_vm_addr, size);
	test_side_channel_vapic_addr(vcpu);
	test_side_channel_pvclock(vcpu);
	test_side_channel_wallclock(vcpu);
}
#endif

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
#ifdef __x86_64__
	vcpu_set_hv_cpuid(vcpu);
#endif

	test_input_validation(vm);
	test_memory_access(vcpu, test_mem, size);
	test_memattrs_ignore_mmio(vcpu);
#ifdef __x86_64__
	test_memory_access_pte(vcpu, test_mem);
	test_side_channels(vcpu, test_mem, size);
#endif
	test_finalize(vcpu);

	kvm_vm_free(vm);
	return 0;
}
