/*
 * Raspberry Pi 3 firmware based touchscreen driver
 *
 * Copyright (C) 2015, 2017 Raspberry Pi
 * Copyright (C) 2018 Nicolas Saenz Julienne <nsaenzjulienne@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/io.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/input/touchscreen.h>
#include <soc/bcm2835/raspberrypi-firmware.h>

#define RPI_TS_DEFAULT_WIDTH	800
#define RPI_TS_DEFAULT_HEIGHT	480

#define RPI_TS_MAX_SUPPORTED_POINTS	10

#define RPI_TS_FTS_TOUCH_DOWN		0
#define RPI_TS_FTS_TOUCH_CONTACT	2

struct rpi_ts {
	struct input_dev *input;
	struct touchscreen_properties prop;

	void __iomem *ts_base;
	dma_addr_t bus_addr;

	struct delayed_work work;
	int known_ids;
};

struct rpi_ts_regs {
	uint8_t device_mode;
	uint8_t gesture_id;
	uint8_t num_points;
	struct rpi_ts_touch {
		uint8_t xh;
		uint8_t xl;
		uint8_t yh;
		uint8_t yl;
		uint8_t pressure; /* Not supported */
		uint8_t area;     /* Not supported */
	} point[RPI_TS_MAX_SUPPORTED_POINTS];
};

/*
 * This process polls the memory based register copy of the touch screen chip
 * registers using the number of points register to know whether the copy has
 * been updated (we write 99 to the memory copy, the GPU will write between 0 -
 * 10 points)
 */
static void rpi_ts_work(struct work_struct *work)
{
	struct rpi_ts *ts = container_of(work, struct rpi_ts, work.work);
	struct input_dev *input = ts->input;
	struct rpi_ts_regs regs;
	int modified_ids = 0;
	int released_ids;
	int event_type;
	int touchid;
	int x, y;
	int i;

	memcpy_fromio(&regs, ts->ts_base, sizeof(struct rpi_ts_regs));
	iowrite8(99, ts->ts_base + offsetof(struct rpi_ts_regs, num_points));

	if (regs.num_points == 99 ||
	    (regs.num_points == 0 && ts->known_ids == 0))
	    goto out;

	for (i = 0; i < regs.num_points; i++) {
		x = (((int)regs.point[i].xh & 0xf) << 8) + regs.point[i].xl;
		y = (((int)regs.point[i].yh & 0xf) << 8) + regs.point[i].yl;
		touchid = (regs.point[i].yh >> 4) & 0xf;
		event_type = (regs.point[i].xh >> 6) & 0x03;

		modified_ids |= BIT(touchid);

		if (event_type == RPI_TS_FTS_TOUCH_DOWN ||
		    event_type == RPI_TS_FTS_TOUCH_CONTACT) {
			input_mt_slot(input, touchid);
			input_mt_report_slot_state(input, MT_TOOL_FINGER, 1);
			touchscreen_report_pos(input, &ts->prop, x, y, true);
		}
	}

	released_ids = ts->known_ids & ~modified_ids;
	for (i = 0; released_ids && i < RPI_TS_MAX_SUPPORTED_POINTS; i++) {
		if (released_ids & BIT(i)) {
			input_mt_slot(input, i);
			input_mt_report_slot_state(input, MT_TOOL_FINGER, 0);
			modified_ids &= ~(BIT(i));
		}
	}
	ts->known_ids = modified_ids;

	input_mt_report_pointer_emulation(ts->input, true);
	input_sync(ts->input);

out:
	schedule_delayed_work(&ts->work, msecs_to_jiffies(17)); /* 60 fps */
}

static int rpi_ts_open(struct input_dev *dev)
{
	struct rpi_ts *ts = input_get_drvdata(dev);

	schedule_delayed_work(&ts->work, 0);

	return 0;
}

static void rpi_ts_close(struct input_dev *dev)
{
	struct rpi_ts *ts = input_get_drvdata(dev);

	cancel_delayed_work_sync(&ts->work);
}

static int rpi_ts_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct device_node *fw_node;
	struct input_dev *input;
	struct rpi_firmware *fw;
	struct rpi_ts *ts;
	u32 touchbuf;
	int err = 0;

	fw_node = of_get_parent(np);
	if (!fw_node) {
		dev_err(dev, "Missing firmware node\n");
		return -ENOENT;
	}

	fw = rpi_firmware_get(fw_node);
	if (!fw)
		return -EPROBE_DEFER;

	ts = devm_kzalloc(dev, sizeof(struct rpi_ts), GFP_KERNEL);
	if (!ts) {
		dev_err(dev, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	input = input_allocate_device();
	if (!input) {
		dev_err(dev, "Failed to allocate input device\n");
		return -ENOMEM;
	}
	ts->input = input;

	ts->ts_base = dma_zalloc_coherent(dev, PAGE_SIZE, &ts->bus_addr,
					  GFP_KERNEL);
	if (!ts->ts_base) {
		dev_err(dev, "failed to dma_alloc_coherent\n");
		err = -ENOMEM;
		goto undegister_input_device;
	}

	touchbuf = (u32)ts->bus_addr;
	err = rpi_firmware_property(fw, RPI_FIRMWARE_FRAMEBUFFER_SET_TOUCHBUF,
				    &touchbuf, sizeof(touchbuf));

	if (err || touchbuf != 0) {
		dev_warn(dev, "Failed to set touchbuf, trying to get err:%x\n",
			 err);
		goto clean_dma_buf;
	}

	INIT_DELAYED_WORK(&ts->work, rpi_ts_work);
	platform_set_drvdata(pdev, ts);

	input->name = "raspberrypi-ts";
	input->id.bustype = BUS_HOST;
	input->open = rpi_ts_open;
	input->close = rpi_ts_close;
	input->dev.parent = &pdev->dev;

	__set_bit(EV_KEY, input->evbit);
	__set_bit(EV_SYN, input->evbit);
	__set_bit(EV_ABS, input->evbit);

	input_set_abs_params(input, ABS_MT_POSITION_X, 0,
			     RPI_TS_DEFAULT_WIDTH, 0, 0);
	input_set_abs_params(input, ABS_MT_POSITION_Y, 0,
			     RPI_TS_DEFAULT_HEIGHT, 0, 0);
	touchscreen_parse_properties(input, true, &ts->prop);

	input_mt_init_slots(input, RPI_TS_MAX_SUPPORTED_POINTS,
			    INPUT_MT_DIRECT);

	input_set_drvdata(input, ts);

	err = input_register_device(input);
	if (err) {
		dev_err(dev, "could not register input device, %d\n",
			err);
		goto clean_dma_buf;
	}
	return 0;

clean_dma_buf:
	dma_free_coherent(dev, PAGE_SIZE, ts->ts_base, ts->bus_addr);
undegister_input_device:
	input_unregister_device(ts->input);

	return err;
}

static int rpi_ts_remove(struct platform_device *pdev)
{
	struct rpi_ts *ts = (struct rpi_ts *)platform_get_drvdata(pdev);

	input_unregister_device(ts->input);
	dma_free_coherent(&pdev->dev, PAGE_SIZE, ts->ts_base, ts->bus_addr);
	return 0;
}

static const struct of_device_id rpi_ts_match[] = {
	{ .compatible = "raspberrypi,firmware-ts", },
	{},
};
MODULE_DEVICE_TABLE(of, rpi_ts_match);

static struct platform_driver rpi_ts_driver = {
	.driver = {
		.name   = "raspberrypi-ts",
		.owner  = THIS_MODULE,
		.of_match_table = rpi_ts_match,
	},
	.probe          = rpi_ts_probe,
	.remove         = rpi_ts_remove,
};

module_platform_driver(rpi_ts_driver);

MODULE_AUTHOR("Gordon Hollingworth");
MODULE_AUTHOR("Nicolas Saenz Julienne <nsaenzjulienne@suse.de>");
MODULE_DESCRIPTION("Raspberry Pi 3 firmware based touchscreen driver");
MODULE_LICENSE("GPL");
