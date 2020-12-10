// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2020 Nicolas Saenz Julienne <nsaenzjulienne@suse.de>
 */

#include <linux/io.h>
#include <linux/module.h>
#include <linux/nvmem-provider.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>

struct rmem {
	struct device *dev;
	struct nvmem_device *nvmem;
	struct reserved_mem *rmem;

	const void *base;
	phys_addr_t size;
};

static int rmem_read(void *context, unsigned int offset,
		     void *val, size_t bytes)
{
	struct rmem *priv = context;
	loff_t off = offset;

	return memory_read_from_buffer(val, bytes, &off, priv->base, priv->size);
}

static int rmem_probe(struct platform_device *pdev)
{
	struct nvmem_config config = { };
	struct device *dev = &pdev->dev;
	struct device_node *rmem_np;
	struct reserved_mem *rmem;
	struct rmem *priv;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->dev = dev;

	rmem_np = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!rmem_np) {
		dev_err(dev, "Failed to lookup reserved memory phandle\n");
		return -EINVAL;
	}

	rmem = of_reserved_mem_lookup(rmem_np);
	of_node_put(rmem_np);
	if (!rmem) {
		dev_err(dev, "Failed to lookup reserved memory\n");
		return -EINVAL;
	}

	priv->rmem = rmem;
	priv->size = rmem->size;

	priv->base = devm_memremap(dev, rmem->base, rmem->size, MEMREMAP_WB);
	if (IS_ERR(priv->base)) {
		dev_err(dev, "Failed to remap memory region\n");
		return PTR_ERR(priv->base);
	}

	config.dev = dev;
	config.priv = priv;
	config.name = "rmem";
	config.size = priv->size;
	config.reg_read = rmem_read;

	priv->nvmem = devm_nvmem_register(dev, &config);
	return PTR_ERR_OR_ZERO(priv->nvmem);
}

static const struct of_device_id rmem_match[] = {
	{ .compatible = "nvmem-rmem", },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, rmem_match);

static struct platform_driver rmem_driver = {
	.probe = rmem_probe,
	.driver = {
		.name = "rmem",
		.of_match_table = rmem_match,
	},
};
module_platform_driver(rmem_driver);

MODULE_AUTHOR("Nicolas Saenz Julienne <nsaenzjulienne@suse.de>");
MODULE_DESCRIPTION("Reserved Memory Based nvmem Driver");
MODULE_LICENSE("GPL");
