// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Microsoft Hyper-V VSM emulation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "hyperv.h"

#include <linux/kvm_host.h>

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

static struct kvm_device_ops kvm_hv_vtl_ops = {
	.name = "kvm-hv-vtl",
	.create = kvm_hv_vtl_create,
	.release = kvm_hv_vtl_release,
	/* .ioctl = kvm_hv_vtl_ioctl, */
	/* .set_attr = kvm_hv_vtl_set_attr, */
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
