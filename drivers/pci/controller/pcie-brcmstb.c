// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009 - 2018 Broadcom
 * Copyright (C) 2019 - Nicolas Saenz Julienne <nsaenzjulienne@suse.de>
 */

#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "../pci.h"

/* BRCM_PCIE_CAP_REGS - Offset for the mandatory capability config regs */
#define BRCM_PCIE_CAP_REGS				0x00ac

/*
 * Broadcom Settop Box PCIe Register Offsets. The names are from
 * the chip's RDB and we use them here so that a script can correlate
 * this code and the RDB to prevent discrepancies.
 */
#define PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1		0x0188
#define PCIE_RC_CFG_PRIV1_ID_VAL3			0x043c
#define PCIE_RC_DL_MDIO_ADDR				0x1100
#define PCIE_RC_DL_MDIO_WR_DATA				0x1104
#define PCIE_RC_DL_MDIO_RD_DATA				0x1108
#define PCIE_MISC_MISC_CTRL				0x4008
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LO		0x400c
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_HI		0x4010
#define PCIE_MISC_RC_BAR1_CONFIG_LO			0x402c
#define PCIE_MISC_RC_BAR2_CONFIG_LO			0x4034
#define PCIE_MISC_RC_BAR2_CONFIG_HI			0x4038
#define PCIE_MISC_RC_BAR3_CONFIG_LO			0x403c
#define PCIE_MISC_PCIE_CTRL				0x4064
#define PCIE_MISC_PCIE_STATUS				0x4068
#define PCIE_MISC_REVISION				0x406c
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT	0x4070
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI		0x4080
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI		0x4084
#define PCIE_MISC_HARD_PCIE_HARD_DEBUG			0x4204
#define PCIE_INTR2_CPU_BASE				0x4300

/*
 * Broadcom Settop Box PCIe Register Field shift and mask info. The
 * names are from the chip's RDB and we use them here so that a script
 * can correlate this code and the RDB to prevent discrepancies.
 */
#define PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1_ENDIAN_MODE_BAR2_MASK	0xc
#define PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1_ENDIAN_MODE_BAR2_SHIFT	0x2
#define PCIE_RC_CFG_PRIV1_ID_VAL3_CLASS_CODE_MASK		0xffffff
#define PCIE_RC_CFG_PRIV1_ID_VAL3_CLASS_CODE_SHIFT		0x0
#define PCIE_MISC_MISC_CTRL_SCB_ACCESS_EN_MASK			0x1000
#define PCIE_MISC_MISC_CTRL_SCB_ACCESS_EN_SHIFT			0xc
#define PCIE_MISC_MISC_CTRL_CFG_READ_UR_MODE_MASK		0x2000
#define PCIE_MISC_MISC_CTRL_CFG_READ_UR_MODE_SHIFT		0xd
#define PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_MASK			0x300000
#define PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_SHIFT		0x14
#define PCIE_MISC_MISC_CTRL_SCB0_SIZE_MASK			0xf8000000
#define PCIE_MISC_MISC_CTRL_SCB0_SIZE_SHIFT			0x1b
#define PCIE_MISC_MISC_CTRL_SCB1_SIZE_MASK			0x7c00000
#define PCIE_MISC_MISC_CTRL_SCB1_SIZE_SHIFT			0x16
#define PCIE_MISC_MISC_CTRL_SCB2_SIZE_MASK			0x1f
#define PCIE_MISC_MISC_CTRL_SCB2_SIZE_SHIFT			0x0
#define PCIE_MISC_RC_BAR1_CONFIG_LO_SIZE_MASK			0x1f
#define PCIE_MISC_RC_BAR1_CONFIG_LO_SIZE_SHIFT			0x0
#define PCIE_MISC_RC_BAR2_CONFIG_LO_SIZE_MASK			0x1f
#define PCIE_MISC_RC_BAR2_CONFIG_LO_SIZE_SHIFT			0x0
#define PCIE_MISC_RC_BAR3_CONFIG_LO_SIZE_MASK			0x1f
#define PCIE_MISC_RC_BAR3_CONFIG_LO_SIZE_SHIFT			0x0
#define PCIE_MISC_PCIE_CTRL_PCIE_PERSTB_MASK			0x4
#define PCIE_MISC_PCIE_CTRL_PCIE_PERSTB_SHIFT			0x2
#define PCIE_MISC_PCIE_CTRL_PCIE_L23_REQUEST_MASK		0x1
#define PCIE_MISC_PCIE_CTRL_PCIE_L23_REQUEST_SHIFT		0x0
#define PCIE_MISC_PCIE_STATUS_PCIE_PORT_MASK			0x80
#define PCIE_MISC_PCIE_STATUS_PCIE_PORT_SHIFT			0x7
#define PCIE_MISC_PCIE_STATUS_PCIE_DL_ACTIVE_MASK		0x20
#define PCIE_MISC_PCIE_STATUS_PCIE_DL_ACTIVE_SHIFT		0x5
#define PCIE_MISC_PCIE_STATUS_PCIE_PHYLINKUP_MASK		0x10
#define PCIE_MISC_PCIE_STATUS_PCIE_PHYLINKUP_SHIFT		0x4
#define PCIE_MISC_PCIE_STATUS_PCIE_LINK_IN_L23_MASK		0x40
#define PCIE_MISC_PCIE_STATUS_PCIE_LINK_IN_L23_SHIFT		0x6
#define PCIE_MISC_REVISION_MAJMIN_MASK				0xffff
#define PCIE_MISC_REVISION_MAJMIN_SHIFT				0
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT_LIMIT_MASK	0xfff00000
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT_LIMIT_SHIFT	0x14
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT_BASE_MASK	0xfff0
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT_BASE_SHIFT	0x4
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT_NUM_MASK_BITS	0xc
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI_BASE_MASK		0xff
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI_BASE_SHIFT	0x0
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI_LIMIT_MASK	0xff
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI_LIMIT_SHIFT	0x0
#define PCIE_MISC_HARD_PCIE_HARD_DEBUG_CLKREQ_DEBUG_ENABLE_MASK	0x2
#define PCIE_MISC_HARD_PCIE_HARD_DEBUG_CLKREQ_DEBUG_ENABLE_SHIFT 0x1
#define PCIE_MISC_HARD_PCIE_HARD_DEBUG_SERDES_IDDQ_MASK		0x08000000
#define PCIE_MISC_HARD_PCIE_HARD_DEBUG_SERDES_IDDQ_SHIFT	0x1b
#define PCIE_RGR1_SW_INIT_1_PERST_MASK				0x1
#define PCIE_RGR1_SW_INIT_1_PERST_SHIFT				0x0

#define BRCM_NUM_PCIE_OUT_WINS		0x4
#define BRCM_MAX_SCB			0x4

#define BRCM_MSI_TARGET_ADDR_LT_4GB	0x0fffffffcULL
#define BRCM_MSI_TARGET_ADDR_GT_4GB	0xffffffffcULL

#define BURST_SIZE_128			0
#define BURST_SIZE_256			1
#define BURST_SIZE_512			2

/* Offsets from PCIE_INTR2_CPU_BASE */
#define STATUS				0x0
#define SET				0x4
#define CLR				0x8
#define MASK_STATUS			0xc
#define MASK_SET			0x10
#define MASK_CLR			0x14

#define PCIE_BUSNUM_SHIFT		20
#define PCIE_SLOT_SHIFT			15
#define PCIE_FUNC_SHIFT			12

#if defined(__BIG_ENDIAN)
#define	DATA_ENDIAN			2	/* PCIe->DDR inbound traffic */
#define MMIO_ENDIAN			2	/* CPU->PCIe outbound traffic */
#else
#define	DATA_ENDIAN			0
#define MMIO_ENDIAN			0
#endif

#define MDIO_PORT0			0x0
#define MDIO_DATA_MASK			0x7fffffff
#define MDIO_DATA_SHIFT			0x0
#define MDIO_PORT_MASK			0xf0000
#define MDIO_PORT_SHIFT			0x16
#define MDIO_REGAD_MASK			0xffff
#define MDIO_REGAD_SHIFT		0x0
#define MDIO_CMD_MASK			0xfff00000
#define MDIO_CMD_SHIFT			0x14
#define MDIO_CMD_READ			0x1
#define MDIO_CMD_WRITE			0x0
#define MDIO_DATA_DONE_MASK		0x80000000
#define MDIO_RD_DONE(x)			(((x) & MDIO_DATA_DONE_MASK) ? 1 : 0)
#define MDIO_WT_DONE(x)			(((x) & MDIO_DATA_DONE_MASK) ? 0 : 1)

#define IDX_ADDR(pcie)	\
	((pcie)->reg_offsets[EXT_CFG_INDEX])
#define DATA_ADDR(pcie)	\
	((pcie)->reg_offsets[EXT_CFG_DATA])
#define PCIE_RGR1_SW_INIT_1(pcie) \
	((pcie)->reg_offsets[RGR1_SW_INIT_1])

enum {
	RGR1_SW_INIT_1,
	EXT_CFG_INDEX,
	EXT_CFG_DATA,
};

enum {
	RGR1_SW_INIT_1_INIT_MASK,
	RGR1_SW_INIT_1_INIT_SHIFT,
	RGR1_SW_INIT_1_PERST_MASK,
	RGR1_SW_INIT_1_PERST_SHIFT,
};

struct brcm_window {
	dma_addr_t pcie_addr;
	phys_addr_t cpu_addr;
	dma_addr_t size;
};

/* Internal PCIe Host Controller Information.*/
struct brcm_pcie {
	struct device		*dev;
	void __iomem		*base;
	struct list_head	resources;
	int			irq;
	struct pci_bus		*root_bus;
	struct device_node	*np;
	int			id;
	bool			suspended;
	int			num_out_wins;
	int			gen;
	struct brcm_window	out_wins[BRCM_NUM_PCIE_OUT_WINS];
	unsigned int		rev;
	const int		*reg_offsets;
	const int		*reg_field_info;
};

static const int pcie_reg_field_info[] = {
	[RGR1_SW_INIT_1_INIT_MASK] = 0x2,
	[RGR1_SW_INIT_1_INIT_SHIFT] = 0x1,
};

static const int pcie_offsets[] = {
	[RGR1_SW_INIT_1] = 0x9210,
	[EXT_CFG_INDEX]  = 0x9000,
	[EXT_CFG_DATA]   = 0x8000,
};

static void __iomem *brcm_pcie_map_conf(struct pci_bus *bus, unsigned int devfn,
					int where);

static struct pci_ops brcm_pcie_ops = {
	.map_bus = brcm_pcie_map_conf,
	.read = pci_generic_config_read,
	.write = pci_generic_config_write,
};

#if defined(CONFIG_MIPS)
/* Broadcom MIPs HW implicitly does the swapping if necessary */
#define bcm_readl(a)		__raw_readl(a)
#define bcm_writel(d, a)	__raw_writel(d, a)
#define bcm_readw(a)		__raw_readw(a)
#define bcm_writew(d, a)	__raw_writew(d, a)
#else
#define bcm_readl(a)		readl(a)
#define bcm_writel(d, a)	writel(d, a)
#define bcm_readw(a)		readw(a)
#define bcm_writew(d, a)	writew(d, a)
#endif

/* These macros extract/insert fields to host controller's register set. */
#define RD_FLD(base, reg, field) \
	rd_fld((base) + reg, reg##_##field##_MASK, reg##_##field##_SHIFT)
#define WR_FLD(base, reg, field, val) \
	wr_fld((base) + reg, reg##_##field##_MASK, reg##_##field##_SHIFT, val)
#define WR_FLD_RB(base, reg, field, val) \
	wr_fld_rb((base) + reg, reg##_##field##_MASK, \
		reg##_##field##_SHIFT, val)
#define WR_FLD_WITH_OFFSET(base, off, reg, field, val) \
	wr_fld((base) + reg + (off), reg##_##field##_MASK, \
	       reg##_##field##_SHIFT, val)
#define EXTRACT_FIELD(val, reg, field) \
	(((val) & reg##_##field##_MASK) >> reg##_##field##_SHIFT)
#define INSERT_FIELD(val, reg, field, field_val) \
	(((val) & ~reg##_##field##_MASK) | \
	 (reg##_##field##_MASK & (field_val << reg##_##field##_SHIFT)))

static u32 rd_fld(void __iomem *p, u32 mask, int shift)
{
	return (bcm_readl(p) & mask) >> shift;
}

static void wr_fld(void __iomem *p, u32 mask, int shift, u32 val)
{
	u32 reg = bcm_readl(p);

	reg = (reg & ~mask) | ((val << shift) & mask);
	bcm_writel(reg, p);
}

static void wr_fld_rb(void __iomem *p, u32 mask, int shift, u32 val)
{
	wr_fld(p, mask, shift, val);
	(void)bcm_readl(p);
}

static const char *link_speed_to_str(int s)
{
	switch (s) {
	case 1:
		return "2.5";
	case 2:
		return "5.0";
	case 3:
		return "8.0";
	default:
		break;
	}
	return "???";
}

/*
 * The roundup_pow_of_two() from log2.h invokes
 * __roundup_pow_of_two(unsigned long), but we really need a
 * such a function to take a native u64 since unsigned long
 * is 32 bits on some configurations.  So we provide this helper
 * function below.
 */
static u64 roundup_pow_of_two_64(u64 n)
{
	return 1ULL << fls64(n - 1);
}

/*
 * This is to convert the size of the inbound "BAR" region to the
 * non-linear values of PCIE_X_MISC_RC_BAR[123]_CONFIG_LO.SIZE
 */
int encode_ibar_size(u64 size)
{
	int log2_in = ilog2(size);

	if (log2_in >= 12 && log2_in <= 15)
		/* Covers 4KB to 32KB (inclusive) */
		return (log2_in - 12) + 0x1c;
	else if (log2_in >= 16 && log2_in <= 37)
		/* Covers 64KB to 32GB, (inclusive) */
		return log2_in - 15;
	/* Something is awry so disable */
	return 0;
}

/* Limits operation to a specific generation (1, 2, or 3) */
static void set_gen(void __iomem *base, int gen)
{
	u32 lnkcap = bcm_readl(base + BRCM_PCIE_CAP_REGS + PCI_EXP_LNKCAP);
	u16 lnkctl2 = bcm_readw(base + BRCM_PCIE_CAP_REGS + PCI_EXP_LNKCTL2);

	lnkcap = (lnkcap & ~PCI_EXP_LNKCAP_SLS) | gen;
	bcm_writel(lnkcap, base + BRCM_PCIE_CAP_REGS + PCI_EXP_LNKCAP);

	lnkctl2 = (lnkctl2 & ~0xf) | gen;
	bcm_writew(lnkctl2, base + BRCM_PCIE_CAP_REGS + PCI_EXP_LNKCTL2);
}

static void brcm_pcie_set_outbound_win(struct brcm_pcie *pcie,
				       unsigned int win, phys_addr_t cpu_addr,
				       dma_addr_t pcie_addr, dma_addr_t size)
{
	void __iomem *base = pcie->base;
	phys_addr_t cpu_addr_mb, limit_addr_mb;
	u32 tmp;

	/* Set the base of the pcie_addr window */
	bcm_writel(lower_32_bits(pcie_addr) + MMIO_ENDIAN,
		   base + PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LO + (win * 8));
	bcm_writel(upper_32_bits(pcie_addr),
		   base + PCIE_MISC_CPU_2_PCIE_MEM_WIN0_HI + (win * 8));

	cpu_addr_mb = cpu_addr >> 20;
	limit_addr_mb = (cpu_addr + size - 1) >> 20;

	/* Write the addr base low register */
	WR_FLD_WITH_OFFSET(base, (win * 4),
			   PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT,
			   BASE, cpu_addr_mb);
	/* Write the addr limit low register */
	WR_FLD_WITH_OFFSET(base, (win * 4),
			   PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT,
			   LIMIT, limit_addr_mb);

	/* Write the cpu addr high register */
	tmp = (u32)(cpu_addr_mb >>
		PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT_NUM_MASK_BITS);
	WR_FLD_WITH_OFFSET(base, (win * 8),
			   PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI,
			   BASE, tmp);
	/* Write the cpu limit high register */
	tmp = (u32)(limit_addr_mb >>
		PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT_NUM_MASK_BITS);
	WR_FLD_WITH_OFFSET(base, (win * 8),
			   PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI,
			   LIMIT, tmp);
}

/* Configuration space read/write support */
static int cfg_index(int busnr, int devfn, int reg)
{
	return ((PCI_SLOT(devfn) & 0x1f) << PCIE_SLOT_SHIFT)
		| ((PCI_FUNC(devfn) & 0x07) << PCIE_FUNC_SHIFT)
		| (busnr << PCIE_BUSNUM_SHIFT)
		| (reg & ~3);
}

/* The controller is capable of serving in both RC and EP roles */
static bool brcm_pcie_rc_mode(struct brcm_pcie *pcie)
{
	void __iomem *base = pcie->base;
	u32 val = bcm_readl(base + PCIE_MISC_PCIE_STATUS);

	return !!EXTRACT_FIELD(val, PCIE_MISC_PCIE_STATUS, PCIE_PORT);
}

static bool brcm_pcie_link_up(struct brcm_pcie *pcie)
{
	void __iomem *base = pcie->base;
	u32 val = bcm_readl(base + PCIE_MISC_PCIE_STATUS);
	u32 dla = EXTRACT_FIELD(val, PCIE_MISC_PCIE_STATUS, PCIE_DL_ACTIVE);
	u32 plu = EXTRACT_FIELD(val, PCIE_MISC_PCIE_STATUS, PCIE_PHYLINKUP);

	return  (dla && plu) ? true : false;
}

static void __iomem *brcm_pcie_map_conf(struct pci_bus *bus, unsigned int devfn,
					int where)
{
	struct brcm_pcie *pcie = bus->sysdata;
	void __iomem *base = pcie->base;
	int idx;

	/* Accesses to the RC go right to the RC registers if slot==0 */
	if (pci_is_root_bus(bus))
		return PCI_SLOT(devfn) ? NULL : base + where;

	/* For devices, write to the config space index register */
	idx = cfg_index(bus->number, devfn, 0);
	bcm_writel(idx, pcie->base + IDX_ADDR(pcie));
	return base + DATA_ADDR(pcie) + where;
}

static inline void brcm_pcie_bridge_sw_init_set(struct brcm_pcie *pcie,
						unsigned int val)
{
	unsigned int shift = pcie->reg_field_info[RGR1_SW_INIT_1_INIT_SHIFT];
	u32 mask =  pcie->reg_field_info[RGR1_SW_INIT_1_INIT_MASK];

	wr_fld_rb(pcie->base + PCIE_RGR1_SW_INIT_1(pcie), mask, shift, val);
}

static inline void brcm_pcie_perst_set(struct brcm_pcie *pcie,
				       unsigned int val)
{
	wr_fld_rb(pcie->base + PCIE_RGR1_SW_INIT_1(pcie),
		  PCIE_RGR1_SW_INIT_1_PERST_MASK,
		  PCIE_RGR1_SW_INIT_1_PERST_SHIFT, val);
}

static int brcm_pcie_set_inbound_viewport(struct brcm_pcie *pcie)
{
	struct of_pci_range_parser parser;
	u64 rc_bar2_offset, rc_bar2_size;
 	void __iomem *base = pcie->base;
	unsigned int scb_size_val;
	struct of_pci_range range;
	int index = 0;
	u32 tmp;

	if (of_pci_dma_range_parser_init(&parser, pcie->np)) {
		dev_err(pcie->dev, "missing dma-ranges property\n");
		return -EINVAL;
	}

	/*
	 * Set up inbound memory view for the EP (called RC_BAR2, not to be
	 * confused with the BARs that are advertised by the EP).
	 *
	 * The PCIe host controller by design must set the inbound viewport to
	 * be a contiguous arrangement of all of the system's memory.  In
	 * addition, its size mut be a power of two.  To further complicate
	 * matters, the viewport must start on a pcie-address that is aligned
	 * on a multiple of its size.  If a portion of the viewport does not
	 * represent system memory -- e.g. 3GB of memory requires a 4GB
	 * viewport -- we can map the outbound memory in or after 3GB and even
	 * though the viewport will overlap the outbound memory the controller
	 * will know to send outbound memory downstream and everything else
	 * upstream.
	 */
	for_each_of_pci_range(&parser, &range) {
		if (index)
			return -EINVAL;

		rc_bar2_offset = range.pci_addr;
		rc_bar2_size = roundup_pow_of_two_64(range.size);

		/* Verify the alignment is correct */
		if (rc_bar2_offset & (rc_bar2_size - 1)) {
			dev_err(pcie->dev, "inbound window is misaligned\n");
			return -EINVAL;
		}

		tmp = lower_32_bits(rc_bar2_offset);
		tmp = INSERT_FIELD(tmp, PCIE_MISC_RC_BAR2_CONFIG_LO, SIZE,
				   encode_ibar_size(rc_bar2_size));
		bcm_writel(tmp, base + PCIE_MISC_RC_BAR2_CONFIG_LO);
		bcm_writel(upper_32_bits(rc_bar2_offset),
			   base + PCIE_MISC_RC_BAR2_CONFIG_HI);

		scb_size_val = ilog2(range.size) - 15;
		WR_FLD(base, PCIE_MISC_MISC_CTRL, SCB0_SIZE, scb_size_val);

		index++;
	}

	return 0;
}

static int brcm_pcie_parse_request_of_pci_ranges(struct brcm_pcie *pcie)
{
	struct resource_entry *win;
	int ret;

	ret = devm_of_pci_get_host_bridge_resources(pcie->dev, 0, 0xff,
						    &pcie->resources, NULL);
	if (ret) {
		dev_err(pcie->dev, "failed to get host resources\n");
		return ret;
	}

	resource_list_for_each_entry(win, &pcie->resources) {
		struct resource *res = win->res;
		dma_addr_t offset = (dma_addr_t)win->offset;

		if (resource_type(res) != IORESOURCE_MEM)
			continue;

		if (pcie->num_out_wins >= BRCM_NUM_PCIE_OUT_WINS) {
			dev_err(pcie->dev, "too many outbound wins\n");
			return -EINVAL;
		}
		pcie->out_wins[pcie->num_out_wins].cpu_addr =
			(phys_addr_t)res->start;
		pcie->out_wins[pcie->num_out_wins].pcie_addr =
			(dma_addr_t)(res->start - (phys_addr_t)offset);
		pcie->out_wins[pcie->num_out_wins].size =
			(dma_addr_t)(res->end - res->start + 1);
		pcie->num_out_wins++;
	}

	ret = devm_request_pci_bus_resources(pcie->dev, &pcie->resources);
	if (ret)
		dev_err(pcie->dev, "failed to request pci resources\n");
	return ret;
}

static int brcm_pcie_setup(struct brcm_pcie *pcie)
{
	void __iomem *base = pcie->base;
	struct device *dev = pcie->dev;
	int i, j, ret, limit;
	u16 nlw, cls, lnksta;
	u32 tmp;

	/* Reset the bridge */
	brcm_pcie_bridge_sw_init_set(pcie, 1);

	/* Ensure that the fundamental reset is asserted */
	brcm_pcie_perst_set(pcie, 1);

	usleep_range(100, 200);

	/* Take the bridge out of reset */
	brcm_pcie_bridge_sw_init_set(pcie, 0);

	WR_FLD_RB(base, PCIE_MISC_HARD_PCIE_HARD_DEBUG, SERDES_IDDQ, 0);
	/* Wait for SerDes to be stable */
	usleep_range(100, 200);

	/* Grab the PCIe hw revision number */
	tmp = bcm_readl(base + PCIE_MISC_REVISION);
	pcie->rev = EXTRACT_FIELD(tmp, PCIE_MISC_REVISION, MAJMIN);

	/* Set SCB_MAX_BURST_SIZE, CFG_READ_UR_MODE, SCB_ACCESS_EN */
	tmp = INSERT_FIELD(0, PCIE_MISC_MISC_CTRL, SCB_ACCESS_EN, 1);
	tmp = INSERT_FIELD(tmp, PCIE_MISC_MISC_CTRL, CFG_READ_UR_MODE, 1);
	tmp = INSERT_FIELD(tmp, PCIE_MISC_MISC_CTRL, MAX_BURST_SIZE, BURST_SIZE_128);
	bcm_writel(tmp, base + PCIE_MISC_MISC_CTRL);

	ret = brcm_pcie_set_inbound_viewport(pcie);
	if (ret)
		return ret;

	/* disable the PCIe->GISB memory window (RC_BAR1) */
	WR_FLD(base, PCIE_MISC_RC_BAR1_CONFIG_LO, SIZE, 0);

	/* disable the PCIe->SCB memory window (RC_BAR3) */
	WR_FLD(base, PCIE_MISC_RC_BAR3_CONFIG_LO, SIZE, 0);

	if (!pcie->suspended) {
		/* clear any interrupts we find on boot */
		bcm_writel(0xffffffff, base + PCIE_INTR2_CPU_BASE + CLR);
		(void)bcm_readl(base + PCIE_INTR2_CPU_BASE + CLR);
	}

	/* Mask all interrupts since we are not handling any yet */
	bcm_writel(0xffffffff, base + PCIE_INTR2_CPU_BASE + MASK_SET);
	(void)bcm_readl(base + PCIE_INTR2_CPU_BASE + MASK_SET);

	if (pcie->gen)
		set_gen(base, pcie->gen);

	/* Unassert the fundamental reset */
	brcm_pcie_perst_set(pcie, 0);

	/*
	 * Give the RC/EP time to wake up, before trying to configure RC.
	 * Intermittently check status for link-up, up to a total of 100ms
	 * when we don't know if the device is there, and up to 1000ms if
	 * we do know the device is there.
	 */
	limit = pcie->suspended ? 1000 : 100;
	for (i = 1, j = 0; j < limit && !brcm_pcie_link_up(pcie);
	     j += i, i = i * 2)
		msleep(i + j > limit ? limit - j : i);

	if (!brcm_pcie_link_up(pcie)) {
		dev_info(dev, "link down\n");
		return -ENODEV;
	}

	if (!brcm_pcie_rc_mode(pcie)) {
		dev_err(dev, "PCIe misconfigured; is in EP mode\n");
		return -EINVAL;
	}

	for (i = 0; i < pcie->num_out_wins; i++)
		brcm_pcie_set_outbound_win(pcie, i, pcie->out_wins[i].cpu_addr,
					   pcie->out_wins[i].pcie_addr,
					   pcie->out_wins[i].size);

	/*
	 * For config space accesses on the RC, show the right class for
	 * a PCIe-PCIe bridge (the default setting is to be EP mode).
	 */
	WR_FLD_RB(base, PCIE_RC_CFG_PRIV1_ID_VAL3, CLASS_CODE, 0x060400);

	lnksta = bcm_readw(base + BRCM_PCIE_CAP_REGS + PCI_EXP_LNKSTA);
	cls = lnksta & PCI_EXP_LNKSTA_CLS;
	nlw = (lnksta & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	dev_info(dev, "link up, %s Gbps x%u\n", link_speed_to_str(cls), nlw);

	/* PCIe->SCB endian mode for BAR */
	/* field ENDIAN_MODE_BAR2 = DATA_ENDIAN */
	WR_FLD_RB(base, PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1,
		  ENDIAN_MODE_BAR2, DATA_ENDIAN);

	/*
	 * Refclk from RC should be gated with CLKREQ# input when ASPM L0s,L1
	 * is enabled =>  setting the CLKREQ_DEBUG_ENABLE field to 1.
	 */
	WR_FLD_RB(base, PCIE_MISC_HARD_PCIE_HARD_DEBUG, CLKREQ_DEBUG_ENABLE, 1);

	return 0;
}

/* L23 is a low-power PCIe link state */
static void enter_l23(struct brcm_pcie *pcie)
{
	void __iomem *base = pcie->base;
	int l23, i;

	/* assert request for L23 */
	WR_FLD_RB(base, PCIE_MISC_PCIE_CTRL, PCIE_L23_REQUEST, 1);

	/* Wait up to 30 msec for L23 */
	l23 = RD_FLD(base, PCIE_MISC_PCIE_STATUS, PCIE_LINK_IN_L23);
	for (i = 0; i < 15 && !l23; i++) {
		usleep_range(2000, 2400);
		l23 = RD_FLD(base, PCIE_MISC_PCIE_STATUS, PCIE_LINK_IN_L23);
	}

	if (!l23)
		dev_err(pcie->dev, "failed to enter L23\n");
}

static void turn_off(struct brcm_pcie *pcie)
{
	void __iomem *base = pcie->base;

	if (brcm_pcie_link_up(pcie))
		enter_l23(pcie);
	/* Assert fundamental reset */
	brcm_pcie_perst_set(pcie, 1);
	/* Deassert request for L23 in case it was asserted */
	WR_FLD_RB(base, PCIE_MISC_PCIE_CTRL, PCIE_L23_REQUEST, 0);
	/* Turn off SerDes */
	WR_FLD_RB(base, PCIE_MISC_HARD_PCIE_HARD_DEBUG, SERDES_IDDQ, 1);
	/* Shutdown PCIe bridge */
	brcm_pcie_bridge_sw_init_set(pcie, 1);
}

static int brcm_pcie_suspend(struct device *dev)
{
	struct brcm_pcie *pcie = dev_get_drvdata(dev);

	turn_off(pcie);
	pcie->suspended = true;

	return 0;
}

static int brcm_pcie_resume(struct device *dev)
{
	struct brcm_pcie *pcie = dev_get_drvdata(dev);
	void __iomem *base;
	int ret;

	base = pcie->base;

	/* Take bridge out of reset so we can access the SerDes reg */
	brcm_pcie_bridge_sw_init_set(pcie, 0);

	/* Turn on SerDes */
	WR_FLD_RB(base, PCIE_MISC_HARD_PCIE_HARD_DEBUG, SERDES_IDDQ, 0);
	/* Wait for SerDes to be stable */
	usleep_range(100, 200);

	ret = brcm_pcie_setup(pcie);
	if (ret)
		return ret;

	pcie->suspended = false;

	return 0;
}

static void _brcm_pcie_remove(struct brcm_pcie *pcie)
{
	turn_off(pcie);
	pci_free_resource_list(&pcie->resources);
}

static int brcm_pcie_remove(struct platform_device *pdev)
{
	struct brcm_pcie *pcie = platform_get_drvdata(pdev);

	pci_stop_root_bus(pcie->root_bus);
	pci_remove_root_bus(pcie->root_bus);
	_brcm_pcie_remove(pcie);

	return 0;
}

static const struct of_device_id brcm_pcie_match[] = {
	{ .compatible = "brcm,bcm2711-pcie" },
	{},
};
MODULE_DEVICE_TABLE(of, brcm_pcie_match);

static int brcm_pcie_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	const struct of_device_id *of_id;
	struct pci_host_bridge *bridge;
	struct brcm_pcie *pcie;
	struct pci_bus *child;
	struct resource *res;
	void __iomem *base;
	int ret;

	bridge = devm_pci_alloc_host_bridge(&pdev->dev, sizeof(*pcie));
	if (!bridge)
		return -ENOMEM;

	pcie = pci_host_bridge_priv(bridge);
	INIT_LIST_HEAD(&pcie->resources);

	of_id = of_match_node(brcm_pcie_match, np);
	if (!of_id) {
		dev_err(&pdev->dev, "failed to look up compatible string\n");
		return -EINVAL;
	}

	pcie->reg_offsets = pcie_offsets;
	pcie->reg_field_info = pcie_reg_field_info;
	pcie->np = np;
	pcie->dev = &pdev->dev;

	/* We use the domain number as our controller number */
	pcie->id = of_get_pci_domain_nr(np);
	if (pcie->id < 0)
		return pcie->id;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -EINVAL;

	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	pcie->base = base;

	ret = of_pci_get_max_link_speed(np);
	pcie->gen = (ret < 0) ? 0 : ret;

	ret = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (ret == 0)
		/* keep going, as we don't use this intr yet */
		dev_warn(pcie->dev, "cannot get PCIe interrupt\n");
	else
		pcie->irq = ret;

	ret = brcm_pcie_parse_request_of_pci_ranges(pcie);
	if (ret)
		return ret;

	ret = brcm_pcie_setup(pcie);
	if (ret)
		goto fail;

	list_splice_init(&pcie->resources, &bridge->windows);
	bridge->dev.parent = &pdev->dev;
	bridge->busnr = 0;
	bridge->ops = &brcm_pcie_ops;
	bridge->sysdata = pcie;
	bridge->map_irq = of_irq_parse_and_map_pci;
	bridge->swizzle_irq = pci_common_swizzle;

	ret = pci_scan_root_bus_bridge(bridge);
	if (ret < 0) {
		dev_err(pcie->dev, "Scanning root bridge failed\n");
		goto fail;
	}

	pci_assign_unassigned_bus_resources(bridge->bus);
	list_for_each_entry(child, &bridge->bus->children, node)
		pcie_bus_configure_settings(child);
	pci_bus_add_devices(bridge->bus);
	platform_set_drvdata(pdev, pcie);
	pcie->root_bus = bridge->bus;

	return 0;

fail:
	_brcm_pcie_remove(pcie);
	return ret;
}

static const struct dev_pm_ops brcm_pcie_pm_ops = {
	.suspend_noirq = brcm_pcie_suspend,
	.resume_noirq = brcm_pcie_resume,
};

static struct platform_driver brcm_pcie_driver = {
	.probe = brcm_pcie_probe,
	.remove = brcm_pcie_remove,
	.driver = {
		.name = "brcm-pcie",
		.of_match_table = brcm_pcie_match,
		.pm = &brcm_pcie_pm_ops,
	},
};

module_platform_driver(brcm_pcie_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Broadcom STB PCIe RC driver");
MODULE_AUTHOR("Broadcom");
MODULE_AUTHOR("Nicolas Saenz Julienne <nsaenzjulienne@suse.de>");
