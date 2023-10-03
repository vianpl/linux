// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Microsoft Hyper-V VSM emulation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


#include <linux/kvm_host.h>

#include "mmu/mmu_internal.h"
#include "hyperv.h"
#include "mmu.h"

#define KVM_HV_VTL_ATTRS                                         \
	(KVM_MEMORY_ATTRIBUTE_READ | KVM_MEMORY_ATTRIBUTE_WRITE | \
		KVM_MEMORY_ATTRIBUTE_EXECUTE)

struct kvm_hv_vtl_dev {
	int vtl;
	struct xarray mem_attrs;
};

static struct xarray *kvm_hv_vsm_get_memprots(struct kvm_vcpu *vcpu);

static int kvm_hv_faultin_exit(struct kvm_vcpu *vcpu,
			       struct kvm_page_fault *fault,
			       unsigned long prot)
{
	u64 flags;

	if (!prot)
		flags = KVM_MEMORY_EXIT_NO_ACCESS;
	else if (fault->write & !(prot & KVM_MEMORY_ATTRIBUTE_WRITE))
		flags = KVM_MEMORY_EXIT_FLAG_NW;
	else if (fault->exec & !(prot & KVM_MEMORY_ATTRIBUTE_EXECUTE))
		flags = KVM_MEMORY_EXIT_FLAG_NX;
	else {
		fault->map_executable = prot & KVM_MEMORY_ATTRIBUTE_EXECUTE;
		fault->map_writable = prot & KVM_MEMORY_ATTRIBUTE_WRITE;
		return RET_PF_CONTINUE;
	}

	vcpu->run->exit_reason = KVM_EXIT_MEMORY_FAULT;
	vcpu->run->memory.gpa = fault->gfn << PAGE_SHIFT;
	vcpu->run->memory.size = PAGE_SIZE;
	vcpu->run->memory.flags = flags;

	return RET_PF_USER;
}

int kvm_hv_faultin_pfn(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct xarray *prots = kvm_hv_vsm_get_memprots(vcpu);
	void *entry;

	if (!prots)
		return RET_PF_CONTINUE;

	entry = xa_load(prots, fault->gfn);
	if (!xa_is_value(entry))
		return RET_PF_CONTINUE;

	return kvm_hv_faultin_exit(vcpu, fault, xa_to_value(entry));
}

static int kvm_hv_vtl_get_attr(struct kvm_device *dev,
			       struct kvm_device_attr *attr)
{
	struct kvm_hv_vtl_dev *vtl_dev = dev->private;

	switch (attr->group) {
	case KVM_DEV_HV_VTL_GROUP:
	switch (attr->attr){
	case KVM_DEV_HV_VTL_GROUP_VTLNUM:
		return put_user(vtl_dev->vtl, (u32 __user *)attr->addr);
	}
	}

	return -EINVAL;
}

static void kvm_hv_vtl_release(struct kvm_device *dev)
{
	struct kvm_hv_vtl_dev *vtl_dev = dev->private;

	xa_destroy(&vtl_dev->mem_attrs);
	kfree(vtl_dev);
	kfree(dev); /* alloc by kvm_ioctl_create_device, free by .release */
}

static long kvm_hv_vtl_ioctl(struct kvm_device *dev, unsigned int ioctl,
			     unsigned long arg)
{
	switch (ioctl) {
	case KVM_SET_MEMORY_ATTRIBUTES: {
		struct kvm_hv_vtl_dev *vtl_dev = dev->private;
		struct kvm_memory_attributes attrs;
		int r;

		if (copy_from_user(&attrs, (void __user *)arg, sizeof(attrs)))
			return -EFAULT;

		r = kvm_set_mem_attributes(dev->kvm, &vtl_dev->mem_attrs,
					   &attrs, KVM_HV_VTL_ATTRS);
		if (r)
			return r;

		if (copy_to_user((void __user *)arg, &attrs, sizeof(attrs)))
			return -EFAULT;
		break;
	}
	default:
		return -ENOTTY;
	}

	return 0;
}

static int kvm_hv_vtl_create(struct kvm_device *dev, u32 type);

static struct kvm_device_ops kvm_hv_vtl_ops = {
	.name = "kvm-hv-vtl",
	.create = kvm_hv_vtl_create,
	.release = kvm_hv_vtl_release,
	.ioctl = kvm_hv_vtl_ioctl,
	.get_attr = kvm_hv_vtl_get_attr,
};

static struct xarray *kvm_hv_vsm_get_memprots(struct kvm_vcpu *vcpu)
{
	struct kvm_hv_vtl_dev *vtl_dev;
	struct kvm_device *tmp;

	list_for_each_entry(tmp, &vcpu->kvm->devices, vm_node)
		if (tmp->ops == &kvm_hv_vtl_ops) {
			vtl_dev = tmp->private;
			if (vtl_dev->vtl == get_active_vtl(vcpu))
				return &vtl_dev->mem_attrs;
		}

	return NULL;
}

static int kvm_hv_vtl_create(struct kvm_device *dev, u32 type)
{
	struct kvm_hv_vtl_dev *vtl_dev;
	struct kvm_device *tmp;
	int vtl = 0;

	vtl_dev = kzalloc(sizeof(*vtl_dev), GFP_KERNEL_ACCOUNT);
	if (!vtl_dev)
		return -ENOMEM;

	/* Device creation is protected by kvm->lock */
	list_for_each_entry(tmp, &dev->kvm->devices, vm_node)
		if (tmp->ops == &kvm_hv_vtl_ops)
			vtl++;

	vtl_dev->vtl = vtl;
	xa_init(&vtl_dev->mem_attrs);
	dev->private = vtl_dev;

	return 0;
}

int kvm_hv_vtl_dev_register(void)
{
	return kvm_register_device_ops(&kvm_hv_vtl_ops, KVM_DEV_TYPE_HV_VSM_VTL);
}

void kvm_hv_vtl_dev_unregister(void)
{
	kvm_unregister_device_ops(KVM_DEV_TYPE_HV_VSM_VTL);
}
