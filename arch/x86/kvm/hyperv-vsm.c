// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Microsoft Hyper-V VSM emulation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "hyperv.h"

#include <linux/kvm_host.h>

#define KVM_HV_VTL_ATTRS                                         \
	KVM_MEMORY_ATTRIBUTE_READ | KVM_MEMORY_ATTRIBUTE_WRITE | \
		KVM_MEMORY_ATTRIBUTE_EXECUTE

struct kvm_hv_vtl_dev {
	int vtl;
	struct xarray mem_attrs;
};

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

static int kvm_hv_vtl_create(struct kvm_device *dev, u32 type);

static int kvm_hv_vtl_set_mem_attributes(struct kvm_hv_vtl_dev *vtl_dev,
					 struct kvm_memory_attributes *attrs)
{
	u64 supported_attrs = KVM_HV_VTL_ATTRS;
	gfn_t start, end;
	unsigned long i;
	void *entry;

	/* flags is currently not used. */
	if (attrs->flags)
		return -EINVAL;
	if (attrs->attributes & ~supported_attrs)
		return -EINVAL;
	if (attrs->size == 0 || attrs->address + attrs->size < attrs->address)
		return -EINVAL;
	if (!PAGE_ALIGNED(attrs->address) || !PAGE_ALIGNED(attrs->size))
		return -EINVAL;

	start = attrs->address >> PAGE_SHIFT;
	end = (attrs->address + attrs->size - 1 + PAGE_SIZE) >> PAGE_SHIFT;

	entry = attrs->attributes ? xa_mk_value(attrs->attributes) : NULL;

	for (i = start; i < end; i++)
		if (xa_err(xa_store(&vtl_dev->mem_attrs, i, entry,
				    GFP_KERNEL_ACCOUNT)))
			break;

	attrs->address = i << PAGE_SHIFT;
	attrs->size = (end - i) << PAGE_SHIFT;

	return 0;
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

		r = kvm_hv_vtl_set_mem_attributes(vtl_dev, &attrs);
		if (!r && copy_to_user((void __user *)arg, &attrs, sizeof(attrs)))
			return -EFAULT;
		break;
	}
	default:
		return -ENOTTY;
	}

	return 0;
}

static struct kvm_device_ops kvm_hv_vtl_ops = {
	.name = "kvm-hv-vtl",
	.create = kvm_hv_vtl_create,
	.release = kvm_hv_vtl_release,
	.ioctl = kvm_hv_vtl_ioctl,
	.get_attr = kvm_hv_vtl_get_attr,
};

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
