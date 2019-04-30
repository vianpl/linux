// SPDX-License-Identifier: GPL-2.0
/*
 * Raspberry Pi firmware based cpufreq driver
 *
 * Copyright (C) 2019, Nicolas Saenz Julienne <nsaenzjulienne@suse.de>
 */
#include <linux/cpufreq.h>
#include <linux/clk.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_opp.h>

#include <soc/bcm2835/raspberrypi-firmware.h>

#define VCMSG_ID_ARM_CLOCK	0x000000003
#define VCMSG_ID_VPU_CLOCK	0x000000004

struct raspberrypi_cpufreq {
	struct platform_device *pdev;
	struct rpi_firmware *fw;
	struct clk *plla_clk;
	struct clk *pllb_clk;
	struct clk *pllc_clk;
	struct clk *vpu_clk;

	struct cpufreq_frequency_table *freq_table;
	bool turbo_mode;
	int vpu_min;
	int vpu_max;
};

struct prop {
       u32 id;			/* the ID of the clock/voltage to get or set */
       u32 val;			/* the value (e.g. rate (in Hz)) to set */
} __packed;

static int raspberrypi_clock_property(struct rpi_firmware *fw, u32 tag,
				      u32 clk, u32 *val)
{
	int ret;
	struct prop msg = {
		.id = clk,
		.val = *val,
	};

	ret = rpi_firmware_property(fw, tag, &msg, sizeof(msg));
	if (ret)
		return ret;

	*val = msg.val;

	return 0;
}

static int raspberrypi_cpufreq_set_target(struct cpufreq_policy *policy,
				          unsigned int index)
{
	struct raspberrypi_cpufreq *rpi = cpufreq_get_driver_data();
	unsigned long rate = rpi->freq_table[index].frequency;
	u32 new_rate = rate * 1000;
	bool rising = !!index;
	int ret;

	if (rpi->turbo_mode) {
		ret = clk_notify(rpi->vpu_clk, PRE_RATE_CHANGE,
				 rising ? rpi->vpu_min : rpi->vpu_max,
				 rising ? rpi->vpu_max : rpi->vpu_min);
		if (ret & NOTIFY_STOP_MASK) {
			clk_notify(rpi->vpu_clk, ABORT_RATE_CHANGE,
				   rising ? rpi->vpu_min : rpi->vpu_max,
				   rising ? rpi->vpu_max : rpi->vpu_min);
			dev_err(&rpi->pdev->dev,
					"Devices failed to ack freq change\n");
			return -EINVAL;
		}
	}

	ret = raspberrypi_clock_property(rpi->fw, RPI_FIRMWARE_SET_CLOCK_RATE,
					 VCMSG_ID_ARM_CLOCK, &new_rate);
	if (ret) {
		dev_err(&rpi->pdev->dev, "Failed to change CPU frequency: %d", ret);
		return ret;
	}

	/* Force to recalculate all rates */
	clk_get_rate(rpi->plla_clk);
	clk_get_rate(rpi->pllb_clk);
	clk_get_rate(rpi->pllc_clk);

	if (rpi->turbo_mode)
		clk_notify(rpi->vpu_clk, POST_RATE_CHANGE,
			   rising ? rpi->vpu_min : rpi->vpu_max,
			   rising ? rpi->vpu_max : rpi->vpu_min);

	return 0;
}

static unsigned int raspberrypi_cpufreq_get(unsigned int cpu)
{
	struct raspberrypi_cpufreq *rpi = cpufreq_get_driver_data();
	u32 rate = 0;
	int ret;

	ret = raspberrypi_clock_property(rpi->fw, RPI_FIRMWARE_GET_CLOCK_RATE,
					 VCMSG_ID_ARM_CLOCK, &rate);
	return rate / 1000;
}

static int raspberrypi_cpufreq_init(struct cpufreq_policy *policy)
{
	struct raspberrypi_cpufreq *rpi = cpufreq_get_driver_data();
	int ret;

	ret = cpufreq_generic_init(policy, rpi->freq_table, 355000);
	if (ret)
		return ret;

	return 0;
}

static struct cpufreq_driver raspberrypi_cpufreq_driver = {
	.name = "raspberrypi",
	.flags = CPUFREQ_NEED_INITIAL_FREQ_CHECK | CPUFREQ_IS_COOLING_DEV,
	.verify = cpufreq_generic_frequency_table_verify,
	.target_index = raspberrypi_cpufreq_set_target,
	.get = raspberrypi_cpufreq_get,
	.init = raspberrypi_cpufreq_init,
	.attr = cpufreq_generic_attr,
};

static int raspberrypi_get_fw_configuration(struct raspberrypi_cpufreq *rpi)
{
	u32 cpu_min = 0, cpu_max = 0;
	int ret;

	ret = raspberrypi_clock_property(rpi->fw, RPI_FIRMWARE_GET_MIN_CLOCK_RATE,
					 VCMSG_ID_ARM_CLOCK, &cpu_min);
	if (ret) {
		dev_err(&rpi->pdev->dev, "Failed to get cpu min freq: %d\n", ret);
		return ret;
	}

	ret = raspberrypi_clock_property(rpi->fw, RPI_FIRMWARE_GET_MAX_CLOCK_RATE,
					 VCMSG_ID_ARM_CLOCK, &cpu_max);
	if (ret) {
		dev_err(&rpi->pdev->dev, "Failed to get cpu max freq: %d\n", ret);
		return ret;
	}

	ret = raspberrypi_clock_property(rpi->fw, RPI_FIRMWARE_GET_MIN_CLOCK_RATE,
					 VCMSG_ID_VPU_CLOCK, &rpi->vpu_min);
	if (ret) {
		dev_err(&rpi->pdev->dev, "Failed to get vpu min freq: %d\n", ret);
		return ret;
	}

	ret = raspberrypi_clock_property(rpi->fw, RPI_FIRMWARE_GET_MAX_CLOCK_RATE,
					 VCMSG_ID_VPU_CLOCK, &rpi->vpu_max);
	if (ret) {
		dev_err(&rpi->pdev->dev, "Failed to get vpu max freq: %d\n", ret);
		return ret;
	}

	rpi->vpu_min /= 1000;
	rpi->vpu_max /= 1000;

	if (rpi->vpu_max > rpi->vpu_min)
		rpi->turbo_mode = true;

	rpi->freq_table = devm_kcalloc(&rpi->pdev->dev, 3,
				       sizeof(*rpi->freq_table), GFP_KERNEL);
	if (!rpi->freq_table) {
		dev_err(&rpi->pdev->dev, "Failed to allocate freq_table\n");
		return -ENOMEM;
	}

	rpi->freq_table[0].frequency = cpu_min / 1000;
	rpi->freq_table[1].frequency = cpu_max / 1000;
	rpi->freq_table[2].frequency = CPUFREQ_TABLE_END;

	dev_info(&rpi->pdev->dev,
		 "firmware freqs: cpu_min %d, cpu_max %d, vpu_min %d, vpu_max %d\n",
		 cpu_min, cpu_max, rpi->vpu_min, rpi->vpu_max);

	return 0;
}

static int raspberrypi_cpufreq_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct raspberrypi_cpufreq *rpi;
	struct device_node *fw_node;
	struct rpi_firmware *fw;
	int ret;

	fw_node = of_get_parent(np);
	if (!fw_node) {
		dev_err(dev, "Missing firmware node\n");
		return -ENOENT;
	}

	fw = rpi_firmware_get(fw_node);
	of_node_put(fw_node);
	if (!fw)
		return -EPROBE_DEFER;

	rpi = devm_kzalloc(dev, sizeof(*rpi), GFP_KERNEL);
	if (!rpi)
		return -ENOMEM;

	platform_set_drvdata(pdev, rpi);
	rpi->pdev = pdev;
	rpi->fw = fw;

	rpi->plla_clk = devm_clk_get(dev, "plla");
	if (IS_ERR(rpi->plla_clk)) {
		ret = PTR_ERR(rpi->plla_clk);
		if (ret != -EPROBE_DEFER)
			dev_err(&pdev->dev, "Failed to get plla_clk: %d\n", ret);
		return ret;
	}

	rpi->pllb_clk = devm_clk_get(dev, "pllb");
	if (IS_ERR(rpi->pllb_clk)) {
		ret = PTR_ERR(rpi->pllb_clk);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "Failed to get pllb_clk: %d\n", ret);
		return ret;
	}

	rpi->pllc_clk = devm_clk_get(dev, "pllc");
	if (IS_ERR(rpi->pllc_clk)) {
		ret = PTR_ERR(rpi->pllc_clk);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "Failed to get pllc_clk: %d\n", ret);
		return ret;
	}

	rpi->vpu_clk = devm_clk_get(dev, "vpu");
	if (IS_ERR(rpi->vpu_clk)) {
		ret = PTR_ERR(rpi->vpu_clk);
		if (ret != -EPROBE_DEFER)
			dev_err(&pdev->dev, "Failed to get vpu_clk: %d\n", ret);
		return ret;
	}

	ret = raspberrypi_get_fw_configuration(rpi);
	if (ret)
		return ret;

	raspberrypi_cpufreq_driver.driver_data = rpi;

	return cpufreq_register_driver(&raspberrypi_cpufreq_driver);
}

static int raspberrypi_cpufreq_remove(struct platform_device *pdev)
{
	cpufreq_unregister_driver(&raspberrypi_cpufreq_driver);

	return 0;
}

static const struct of_device_id raspberrypi_cpufreq_of_match[] = {
	{ .compatible = "raspberrypi,cpufreq", },
	{ }
};
MODULE_DEVICE_TABLE(of, raspberrypi_cpufreq_of_match);

static struct platform_driver raspberrypi_cpufreq_platform_driver = {
	.driver = {
		.name = "raspberrypi-cpufreq",
		.of_match_table = raspberrypi_cpufreq_of_match,
	},
	.probe = raspberrypi_cpufreq_probe,
	.remove = raspberrypi_cpufreq_remove,
};
module_platform_driver(raspberrypi_cpufreq_platform_driver);

MODULE_AUTHOR("Nicolas Saenz Julienne <nsaenzjulienne@suse.de");
MODULE_DESCRIPTION("Raspberry Pi cpufreq driver");
MODULE_LICENSE("GPL v2");
