// SPDX-License-Identifier: GPL-2.0
/*
 * Serial port driver for BCM2835AUX UART
 *
 * Copyright (C) 2016 Martin Sperl <kernel@martin.sperl.org>
 *
 * Based on 8250_lpc18xx.c:
 * Copyright (C) 2015 Joachim Eastwood <manabian@gmail.com>
 */

#include <linux/clk.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#include "8250.h"

#define UART_BCM2835AUX_CNTL	8

struct bcm2835aux_data {
	struct uart_8250_port uart;
	struct clk *clk;
	struct notifier_block clk_notifier;
	int line;
};

static int bcm2835aux_clk_notifier_cb(struct notifier_block *nb,
				      unsigned long event, void *priv)
{
	struct bcm2835aux_data *data = container_of(nb, struct bcm2835aux_data,
						    clk_notifier);
	struct uart_8250_port *uart = serial8250_get_port(data->line);
	struct uart_port *up = &uart->port;
	unsigned long flags;

	if (up->suspended)
		return NOTIFY_OK;

	switch (event) {
	case PRE_RATE_CHANGE:
		console_lock();
		serial8250_rpm_get(uart);
		spin_lock_irqsave(&up->lock, flags);
		/* Stop UART */
		serial_out(uart, UART_BCM2835AUX_CNTL, 0);
		spin_unlock_irqrestore(&up->lock, flags);
		serial8250_rpm_put(uart);

		return NOTIFY_OK;
	case POST_RATE_CHANGE:
	{
		struct clk_notifier_data *ndata = priv;
		struct ktermios termios;
		unsigned int quot, baud;

		up->uartclk = ndata->new_rate * 2 * 1000;
		termios.c_cflag = up->cons->cflag;
		if (up->state->port.tty && termios.c_cflag == 0)
			termios.c_cflag = up->state->port.tty->termios.c_cflag;
		baud = uart_get_baud_rate(up, &termios, NULL,
					  up->uartclk / 16 / UART_DIV_MAX,
					  up->uartclk);
		quot = uart_get_divisor(up, baud);

		serial8250_rpm_get(uart);
		spin_lock_irqsave(&up->lock, flags);
		/* Update divisor*/
		serial8250_do_set_divisor(up, baud, quot, 0);
		/* Recover LCR state */
		serial_out(uart, UART_LCR, uart->lcr);
		/* Enable UART */
		serial_out(uart, UART_BCM2835AUX_CNTL, 0x3);
		spin_unlock_irqrestore(&up->lock, flags);
		serial8250_rpm_put(uart);
		console_unlock();

		return NOTIFY_OK;
	}
	case ABORT_RATE_CHANGE:
		serial8250_rpm_get(uart);
		spin_lock_irqsave(&up->lock, flags);
		/* Start UART */
		serial_out(uart, UART_BCM2835AUX_CNTL, 0x3);
		spin_unlock_irqrestore(&up->lock, flags);
		serial8250_rpm_put(uart);
		console_unlock();

		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}

	return 0;
}

static int bcm2835aux_serial_probe(struct platform_device *pdev)
{
	struct bcm2835aux_data *data;
	struct resource *res;
	int ret;

	/* allocate the custom structure */
	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* initialize data */
	spin_lock_init(&data->uart.port.lock);
	data->uart.capabilities = UART_CAP_FIFO | UART_CAP_MINI;
	data->uart.port.dev = &pdev->dev;
	data->uart.port.regshift = 2;
	data->uart.port.type = PORT_16550;
	data->uart.port.iotype = UPIO_MEM;
	data->uart.port.fifosize = 8;
	data->uart.port.flags = UPF_SHARE_IRQ |
				UPF_FIXED_PORT |
				UPF_FIXED_TYPE |
				UPF_SKIP_TEST;

	/* get the clock - this also enables the HW */
	data->clk = devm_clk_get(&pdev->dev, NULL);
	ret = PTR_ERR_OR_ZERO(data->clk);
	if (ret) {
		dev_err(&pdev->dev, "could not get clk: %d\n", ret);
		return ret;
	}

	/* get the interrupt */
	ret = platform_get_irq(pdev, 0);
	if (ret < 0) {
		dev_err(&pdev->dev, "irq not found - %i", ret);
		return ret;
	}
	data->uart.port.irq = ret;

	/* map the main registers */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "memory resource not found");
		return -EINVAL;
	}
	data->uart.port.membase = devm_ioremap_resource(&pdev->dev, res);
	ret = PTR_ERR_OR_ZERO(data->uart.port.membase);
	if (ret)
		return ret;

	/* Check for a fixed line number */
	ret = of_alias_get_id(pdev->dev.of_node, "serial");
	if (ret >= 0)
		data->uart.port.line = ret;

	/* enable the clock as a last step */
	ret = clk_prepare_enable(data->clk);
	if (ret) {
		dev_err(&pdev->dev, "unable to enable uart clock - %d\n",
			ret);
		return ret;
	}

	/* the HW-clock divider for bcm2835aux is 8,
	 * but 8250 expects a divider of 16,
	 * so we have to multiply the actual clock by 2
	 * to get identical baudrates.
	 */
	data->uart.port.uartclk = clk_get_rate(data->clk) * 2;

	/* register the port */
	ret = serial8250_register_8250_port(&data->uart);
	if (ret < 0) {
		dev_err(&pdev->dev, "unable to register 8250 port - %d\n",
			ret);
		goto dis_clk;
	}
	data->line = ret;

	data->clk_notifier.notifier_call = bcm2835aux_clk_notifier_cb;
	ret = clk_notifier_register(data->clk, &data->clk_notifier);
	if (ret) {
		dev_err(&pdev->dev, "unable to register clk notifier - %d\n",
			ret);
		goto dis_clk;
	}

	platform_set_drvdata(pdev, data);

	return 0;

dis_clk:
	clk_disable_unprepare(data->clk);
	return ret;
}

static int bcm2835aux_serial_remove(struct platform_device *pdev)
{
	struct bcm2835aux_data *data = platform_get_drvdata(pdev);

	serial8250_unregister_port(data->uart.port.line);
	clk_notifier_unregister(data->clk, &data->clk_notifier);
	clk_disable_unprepare(data->clk);

	return 0;
}

static const struct of_device_id bcm2835aux_serial_match[] = {
	{ .compatible = "brcm,bcm2835-aux-uart" },
	{ },
};
MODULE_DEVICE_TABLE(of, bcm2835aux_serial_match);

static struct platform_driver bcm2835aux_serial_driver = {
	.driver = {
		.name = "bcm2835-aux-uart",
		.of_match_table = bcm2835aux_serial_match,
	},
	.probe  = bcm2835aux_serial_probe,
	.remove = bcm2835aux_serial_remove,
};
module_platform_driver(bcm2835aux_serial_driver);

MODULE_DESCRIPTION("BCM2835 auxiliar UART driver");
MODULE_AUTHOR("Martin Sperl <kernel@martin.sperl.org>");
MODULE_LICENSE("GPL v2");
