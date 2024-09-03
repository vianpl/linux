// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Amazon.com, Inc. or its affiliates. All Rights Reserved
 *
 * Test for KVM_MEMORY_ATTRIBUTES
 */
#include "kvm_util.h"
#include "apic.h"

uint64_t arch_controlled_read(vm_vaddr_t addr)
{
	uint64_t val;

	asm volatile("mov %[addr], %%rax \n\r"
		     "mov (%%rax), %[val] \n\r"
		     : [val] "=r" (val)
		     : [addr] "m"(addr)
		     : "memory", "rax");

	return val;
}

void arch_controlled_write(vm_vaddr_t addr)
{
	asm volatile("mov %[addr], %%rax \n\r"
		     "mov %%rax, (%%rax) \n\r"
		     :: [addr] "m"(addr)
		     : "memory", "rax");
}

void arch_controlled_exec(vm_vaddr_t addr)
{
	asm volatile("mov %[addr], %%rax \n\r"
		     "call *%%rax \n\t"
		     :: [addr] "m"(addr)
		     : "memory", "rax");
}

void arch_write_return_insn(struct kvm_vm *vm, vm_paddr_t vaddr)
{
	memset(addr_gva2hva(vm, vaddr), 0xc3, 1);
}
