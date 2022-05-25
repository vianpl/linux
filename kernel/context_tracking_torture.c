// SPDX-License-Identifier: GPL-2.0-only
/*
 * Context Tracking debugfs, torture tests for the ct work deferral features
 * Copyright (C) 2022 Red Hat, Inc., Nicolas Saenz Julienne <nsaenzju@redhat.com>
 *
 * TODO:
 *  - review naming
 *  - think better error reporting
 *  - add tracepoints?
 */

#include <linux/cpumask.h>
#include <linux/context_tracking_state.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/torture.h>
#include <linux/vmalloc.h>

#include <asm/apic.h>
#include <asm/nmi.h>
#include <asm/tlbflush.h>

#include "../mm/internal.h"

#define NMI_PERIOD_US		1000
#define IRQ_PERIOD_US		500
#define VMAP_PERIOD_US		3000
#define STATIC_KEY_PERIOD_US	3000
#define ERROR_INJECTION_US	0
#define STAT_PERIOD_S		60
#define SHUFFLE_INTERVAL	3
#define SHUTDOWN_SECS		0
#define STUTTER			5
#define ONOFF_INTERVAL		0
#define ONOFF_HOLDOFF		0

#define POISON			0xBADBAD
#define UNPOISON		0xACEACE

DEFINE_STATIC_KEY_FALSE(ct_torture_sync_stress_key);

static char *torture_type = "context-tracking";
static bool verbose = true;

struct ct_work_percpu_data {
	unsigned long nmi_entry_count;
	unsigned long irq_entry_count;
	unsigned long syscall_entry_count;
	unsigned long idle_entry_count;
	unsigned long guest_entry_count;
	unsigned long error_injection_count;
};

struct ct_work_debugfs {
	unsigned int nmi_period_us;
	unsigned int irq_period_us;
	unsigned int vmap_period_us;
	unsigned int static_key_period_us;
	unsigned int error_injection_us;
	unsigned int stat_period_s;
	unsigned int shuffle_interval;
	unsigned int shutdown_secs;
	unsigned int stutter;
	unsigned int onoff_interval;
	unsigned int onoff_holdoff;

	struct mutex lock;
	struct task_struct *ipi_thread;
	struct task_struct *nmi_thread;
	struct task_struct *vmap_thread;
	struct task_struct *static_key_thread;
	struct task_struct *error_thread;
	struct task_struct *stat_thread;
	struct ct_work_percpu_data __percpu *percpu;
	bool running;

	struct dentry *root_dir;

	/* tlb/vmap torture */
	atomic_t vmap_busy;
	int *vaddr;
	struct vm_struct *area;
	struct page *pages[2];
	unsigned long vmap_count;
};

struct ct_work_debugfs *ct_torture;

static __always_inline bool ct_torture_try_set_busy(atomic_t *val)
{
	return !arch_atomic_cmpxchg_acquire(val, 0, 1);
}

static __always_inline void ct_torture_set_busy(atomic_t *val)
{
	do { } while(atomic_cmpxchg_acquire(val, 0, 1));
}

static __always_inline void ct_torture_clear_busy(atomic_t *val)
{
	arch_atomic_set_release(val, 0);
}


static __always_inline void ct_report_vmap_error(int seq)
{
	trace_printk("%s: cpu %d: ct 0x%x: Wrong content out of virtual addr, TLB flush missed!\n",
	       __func__, raw_smp_processor_id(), seq);
	trace_dump_stack(0);

	pr_err("%s: cpu %d: ct 0x%x: Wrong content out of virtual addr, TLB flush missed!\n",
	       __func__, raw_smp_processor_id(), seq);
	dump_stack();
}

static __always_inline bool ct_work_torture_vmap_entry(struct ct_work_debugfs *dfs,
						       int seq)
{
	if (!ct_torture_try_set_busy(&dfs->vmap_busy))
		return -EBUSY;

	if (*dfs->vaddr != UNPOISON)
		ct_report_vmap_error(seq);

	ct_torture_clear_busy(&dfs->vmap_busy);

	return 0;
}

static __always_inline void ct_report_static_key_error(int seq, int key_enabled)
{
	trace_printk("%s: cpu %d: ct 0x%x: Wrong static key branch taken, key_enabled %d!\n",
	             __func__, raw_smp_processor_id(), seq, key_enabled);
	trace_dump_stack(0);

	pr_err("%s: cpu %d: ct 0x%x: Wrong static key branch taken, key_enabled %d!\n",
	       __func__, raw_smp_processor_id(), seq, key_enabled);
	dump_stack();
}

static __always_inline bool ct_work_torture_static_key_entry(struct ct_work_debugfs *dfs,
							     int seq)
{

	if (static_branch_unlikely(&ct_torture_sync_stress_key))
		nop();

	return 0;
}

static __always_inline void ct_work_torture_stats_entry(struct ct_work_debugfs *dfs,
							int seq)
{
	struct ct_work_percpu_data *pcp = this_cpu_ptr(dfs->percpu);

	if (in_nmi()) {
		pcp->nmi_entry_count++;
		return;
	}

	//TODO fix this, there is no way to know we're entering from
	// interrupt context at this stage...
	/* else if (ct->dynticks_nmi_nesting) */
		/* pcp->irq_entry_count++; */

	switch (seq & CT_STATE_MASK) {
	case CONTEXT_USER:
		pcp->syscall_entry_count++;
		break;
	case CONTEXT_IDLE:
		pcp->idle_entry_count++;
		break;
	case CONTEXT_GUEST:
		pcp->guest_entry_count++;
		break;
	default:
		WARN(1, "Reached %s from wrong context: 0x%x\n",
		     __func__, seq);
		break;
	}
}

/*
 * This check has to happen as soon as possible so as to make sure TLB still
 * has stale entries.
 */
void noinstr ct_work_torture(int seq)
{
	struct ct_work_debugfs *dfs = ct_torture;

	ct_work_torture_static_key_entry(dfs, seq);
	ct_work_torture_vmap_entry(dfs, seq);
	ct_work_torture_stats_entry(dfs, seq);
}

static void torture_update_vmaps(struct ct_work_debugfs *dfs)
{
	unsigned long addr = (unsigned long)dfs->vaddr;
	unsigned long end = addr + PAGE_SIZE;
	struct page *page;

	*dfs->vaddr = POISON;

	/* Unmap memory */
	vunmap_range(addr, end);

	/* Map new memory */
	page = dfs->pages[dfs->vmap_count++ % 2];
	vmap_pages_range_noflush(addr, end, pgprot_nx(PAGE_KERNEL), &page, PAGE_SHIFT);
	flush_cache_vmap(addr, end);

	*dfs->vaddr = UNPOISON;
}

static int torture_vmap_work(void *data)
{
	static DEFINE_TORTURE_RANDOM(rand);
	struct ct_work_debugfs *dfs = data;

	do {
		ct_torture_set_busy(&dfs->vmap_busy);
		torture_update_vmaps(dfs);
		ct_torture_clear_busy(&dfs->vmap_busy);

		torture_hrtimeout_us(dfs->vmap_period_us,
				     dfs->vmap_period_us * NSEC_PER_USEC, &rand);
	} while (!torture_must_stop());
	torture_kthread_stopping("torture_vmap_work");

	return 0;
}

static void torture_update_static_key(struct ct_work_debugfs *dfs)
{
	if (static_key_enabled(&ct_torture_sync_stress_key))
		static_branch_disable(&ct_torture_sync_stress_key);
	else
		static_branch_enable(&ct_torture_sync_stress_key);
}

static int torture_static_key_work(void *data)
{
	static DEFINE_TORTURE_RANDOM(rand);
	struct ct_work_debugfs *dfs = data;

	do {
		torture_update_static_key(dfs);

		torture_hrtimeout_us(dfs->static_key_period_us,
				     dfs->static_key_period_us * NSEC_PER_USEC,
				     &rand);
	} while (!torture_must_stop());
	torture_kthread_stopping("torture_static_key_work");

	return 0;
}

static int torture_error_injection_work(void *data)
{
	static DEFINE_TORTURE_RANDOM(rand);
	struct ct_work_debugfs *dfs = data;
	unsigned int cpu = 0;

	VERBOSE_TOROUT_STRING("torture_error_injection task started");
	do {
		arch_atomic_andnot(CT_WORK_PENDING,
				   per_cpu_ptr(&context_tracking.state, cpu));

		torture_hrtimeout_us(dfs->error_injection_us,
				     dfs->error_injection_us * NSEC_PER_USEC, &rand);

		cpu = cpumask_next(cpu, cpu_online_mask);
		if (cpu >= nr_cpu_ids)
			cpu = 0;
	} while (!torture_must_stop());
	torture_kthread_stopping("torture_error_injection_work");

	return 0;
}

static int torture_stat_work(void *data)
{
	struct ct_work_debugfs *dfs = data;
	int cpu;

	VERBOSE_TOROUT_STRING("torture_stat task started");
	do {
		unsigned long syscall_entry_count = 0;
		unsigned long guest_entry_count = 0;
		unsigned long idle_entry_count = 0;
		unsigned long nmi_entry_count = 0;
		unsigned long irq_entry_count = 0;
		unsigned long vmap_count = 0;

		schedule_timeout_interruptible(dfs->stat_period_s * HZ);

		for_each_online_cpu(cpu) {
			struct ct_work_percpu_data *pcp = per_cpu_ptr(dfs->percpu, cpu);

			nmi_entry_count += pcp->nmi_entry_count;
			irq_entry_count += pcp->irq_entry_count;
			syscall_entry_count += pcp->syscall_entry_count;
			idle_entry_count += pcp->idle_entry_count;
			guest_entry_count += pcp->guest_entry_count;
			vmap_count += dfs->vmap_count;
		}

		pr_alert("ct-torture nmi %lu, irq %lu, ",
			 nmi_entry_count, irq_entry_count);
		pr_cont("syscall %lu, idle %lu, guest %lu, vmap %lu\n",
			syscall_entry_count, idle_entry_count,
			guest_entry_count, vmap_count);

	} while (!torture_must_stop());
	torture_kthread_stopping("torture_stat_work");

	return 0;
}

static int torture_nmi_handler(unsigned int val, struct pt_regs *regs)
{
	/*
	 * Nothing to do here, magic happens during nmi entry in
	 * ct_work_torture().
	 */
	return NMI_HANDLED;
}

static int torture_nmi_work(void *data)
{
	static DEFINE_TORTURE_RANDOM(rand);
	struct ct_work_debugfs *dfs = data;
	int ret;

	ret = register_nmi_handler(NMI_UNKNOWN, torture_nmi_handler, 0,
				   "ct-torture");

	VERBOSE_TOROUT_STRING("torture_nmi task started");
	if (ret) {
		pr_err("%s: Failed to register nmi handler, %d\n", __func__, ret);
		return ret;
	}

	do {
		apic->send_IPI_all(NMI_VECTOR);

		torture_hrtimeout_us(dfs->nmi_period_us,
				     dfs->nmi_period_us * NSEC_PER_USEC, &rand);
	} while (!torture_must_stop());

	unregister_nmi_handler(NMI_UNKNOWN, "ct-torture");
	torture_kthread_stopping("torture_nmi_work");

	return 0;
}

static void torture_ipi(void *info)
{
	/*
	 * Most of the implementation happens in ct_work_torture(), called
	 * during irq entry.
	 */
}

static int torture_irq_work(void *data)
{
	static DEFINE_TORTURE_RANDOM(rand);
	struct ct_work_debugfs *dfs = data;

	VERBOSE_TOROUT_STRING("torture_irq task started");
	do {
		on_each_cpu(torture_ipi, dfs, 1);

		torture_hrtimeout_us(dfs->irq_period_us,
				     dfs->irq_period_us * NSEC_PER_USEC, &rand);
	} while (!torture_must_stop());
	torture_kthread_stopping("torture_irq_work");

	return 0;
}

static void torture_init_vmap(struct ct_work_debugfs *dfs)
{
	unsigned long addr;
	unsigned long end;
	struct page *page;

	dfs->area = get_vm_area(PAGE_SIZE, VM_MAP);
	dfs->vaddr = dfs->area->addr;
	dfs->pages[0] = alloc_page(GFP_KERNEL);
	dfs->pages[1] = alloc_page(GFP_KERNEL);

	page = dfs->pages[dfs->vmap_count++ % 2];
	addr = (unsigned long)dfs->vaddr;
	end = addr + PAGE_SIZE;
	vmap_pages_range_noflush(addr, end, pgprot_nx(PAGE_KERNEL), &page, PAGE_SHIFT);
	flush_cache_vmap(addr, end);
	*dfs->vaddr = UNPOISON;
}

static void torture_unregister_cpu(struct ct_work_percpu_data *pcp)
{
	pcp->irq_entry_count = 0;
	pcp->nmi_entry_count = 0;
	pcp->syscall_entry_count = 0;
	pcp->idle_entry_count = 0;
	pcp->guest_entry_count = 0;
	pcp->error_injection_count = 0;
}

static void torture_unregister_vmap(struct ct_work_debugfs *dfs)
{
	unsigned long addr = (unsigned long)dfs->vaddr;
	unsigned long end = addr + PAGE_SIZE;

	vunmap_range(addr, end);
	__free_page(dfs->pages[0]);
	__free_page(dfs->pages[1]);
	remove_vm_area(dfs->vaddr);
	dfs->vmap_count = 0;
}

static int torture_start(struct ct_work_debugfs *dfs)
{
	int ret;
	int cpu;

	torture_init_begin("context-tracking", verbose);

	torture_init_vmap(dfs);

	if (dfs->irq_period_us) {
		ret = torture_create_kthread(torture_irq_work, dfs, dfs->ipi_thread);
		if (ret)
			goto error;
	}

	if (dfs->nmi_period_us) {
		ret = torture_create_kthread(torture_nmi_work, dfs, dfs->nmi_thread);
		if (ret)
			goto error;
	}

	if (dfs->stat_period_s) {
		ret = torture_create_kthread(torture_stat_work, dfs, dfs->stat_thread);
		if (ret)
			goto error;
	}

	if (dfs->vmap_period_us) {
		ret = torture_create_kthread(torture_vmap_work, dfs, dfs->vmap_thread);
		if (ret)
			goto error;
	}

	if (dfs->static_key_period_us) {
		ret = torture_create_kthread(torture_static_key_work, dfs, dfs->static_key_thread);
		if (ret)
			goto error;
	}

	if (dfs->error_injection_us) {
		pr_alert("context-tracking-torture: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		pr_alert("context-tracking-torture: !!! Error injection enabled, the system might become unstable, data will be lost !!!\n");
		pr_alert("context-tracking-torture: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

		ret = torture_create_kthread(torture_error_injection_work, dfs,
					     dfs->error_thread);
		if (ret)
			goto error;
	}

	if (dfs->shuffle_interval) {
		ret = torture_shuffle_init(dfs->shuffle_interval);
		if (ret)
			goto error;
	}

	if (dfs->shutdown_secs) {
		ret = torture_shutdown_init(dfs->shutdown_secs, NULL);
		if (ret)
			goto error;
	}

	if (dfs->stutter) {
		ret = torture_stutter_init(dfs->stutter, dfs->stutter);
		if (ret)
			goto error;
	}

	if (dfs->onoff_interval > 0) {
		ret = torture_onoff_init(dfs->onoff_holdoff * HZ,
					      dfs->onoff_interval * HZ, NULL);
		if (ret)
			goto error;
	}

	static_branch_inc(&context_tracking_torture_key);

	dfs->running = true;

	torture_init_end();

	return 0;

error:
	torture_init_end();
	torture_stop_kthread(torture_vmap_work, dfs->vmap_thread);
	torture_stop_kthread(torture_static_key_work, dfs->static_key_thread);
	torture_stop_kthread(torture_nmi_work, dfs->nmi_thread);
	torture_stop_kthread(torture_irq_work, dfs->ipi_thread);
	torture_stop_kthread(torture_error_injection_work, dfs->error_thread);
	torture_stop_kthread(torture_stat_work, dfs->stat_thread);

	for_each_online_cpu(cpu)
		torture_unregister_cpu(per_cpu_ptr(dfs->percpu, cpu));
	torture_unregister_vmap(dfs);

	return ret;
}

static int torture_stop(struct ct_work_debugfs *dfs)
{
	int cpu;

	torture_cleanup_begin();

	static_branch_dec(&context_tracking_torture_key);

	torture_stop_kthread(torture_vmap_work, dfs->vmap_thread);
	torture_stop_kthread(torture_static_key_work, dfs->static_key_thread);
	torture_stop_kthread(torture_nmi_work, dfs->nmi_thread);
	torture_stop_kthread(torture_irq_work, dfs->ipi_thread);
	torture_stop_kthread(torture_error_injection_work, dfs->error_thread);
	torture_stop_kthread(torture_stat_work, dfs->stat_thread);

	for_each_online_cpu(cpu)
		torture_unregister_cpu(per_cpu_ptr(dfs->percpu, cpu));
	torture_unregister_vmap(dfs);

	dfs->running = false;

	torture_cleanup_end();

	return 0;
}

static ssize_t torture_write(struct file *filp, const char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	struct seq_file *seq = filp->private_data;
	struct ct_work_debugfs *dfs = seq->private;
	char buf[2] = { };
	ssize_t ret = -EINVAL;

	ret = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, ubuf, count);
	if (ret < 0)
		return ret;
	if (!ret)
		return -EINVAL;

	mutex_lock(&dfs->lock);
	if (!dfs->running && buf[0] == '1')
		ret = torture_start(dfs);
	else if (dfs->running && buf[0] == '0')
		ret = torture_stop(dfs);
	mutex_unlock(&dfs->lock);

	return ret ? : count;
}

static int torture_show(struct seq_file *file, void *v)
{
	struct ct_work_debugfs *dfs = file->private;

	seq_printf(file, "%d\n", dfs->running ? 1 : 0);

	return 0;
}

static int torture_open(struct inode *inode, struct file *file)
{
	return single_open(file, torture_show, inode->i_private);
}

static const struct file_operations torture_fops = {
	.open		= torture_open,
	.read		= seq_read,
	.write		= torture_write,
	.llseek		= generic_file_llseek,
};

static int __init ct_work_torture_init(void)
{
	struct ct_work_debugfs *dfs;

	dfs = kzalloc(sizeof(*dfs), GFP_KERNEL);
	if (!dfs)
		return -ENOMEM;

	mutex_init(&dfs->lock);
	dfs->irq_period_us = IRQ_PERIOD_US;
	dfs->vmap_period_us = VMAP_PERIOD_US;
	dfs->static_key_period_us = STATIC_KEY_PERIOD_US;
	dfs->error_injection_us = ERROR_INJECTION_US;
	dfs->nmi_period_us = NMI_PERIOD_US;
	dfs->stat_period_s = STAT_PERIOD_S;
	dfs->shuffle_interval = SHUFFLE_INTERVAL;
	dfs->shutdown_secs = SHUTDOWN_SECS;
	dfs->stutter = STUTTER;
	dfs->onoff_interval = ONOFF_INTERVAL;
	dfs->onoff_holdoff = ONOFF_HOLDOFF;
	dfs->percpu = alloc_percpu(struct ct_work_percpu_data);

	dfs->root_dir = debugfs_create_dir("context_tracking", NULL);
	if (!dfs->root_dir)
		return 0;

	debugfs_create_file("torture", 0644, dfs->root_dir, dfs, &torture_fops);
	debugfs_create_u32("nmi_period_us", 0644, dfs->root_dir, &dfs->nmi_period_us);
	debugfs_create_u32("irq_period_us", 0644, dfs->root_dir, &dfs->irq_period_us);
	debugfs_create_u32("vmap_period_us", 0644, dfs->root_dir, &dfs->vmap_period_us);
	debugfs_create_u32("static_key_period_us", 0644, dfs->root_dir, &dfs->static_key_period_us);
	debugfs_create_u32("error_injection_us", 0644, dfs->root_dir, &dfs->error_injection_us);
	debugfs_create_u32("stat_period_s", 0644, dfs->root_dir, &dfs->stat_period_s);
	debugfs_create_u32("shuffle_interval", 0644, dfs->root_dir, &dfs->shuffle_interval);
	debugfs_create_u32("shutdown_secs", 0644, dfs->root_dir, &dfs->shutdown_secs);
	debugfs_create_u32("stutter", 0644, dfs->root_dir, &dfs->stutter);
	debugfs_create_u32("onoff_interval", 0644, dfs->root_dir, &dfs->onoff_interval);
	debugfs_create_u32("onoff_holdoff", 0644, dfs->root_dir, &dfs->onoff_holdoff);
	debugfs_create_bool("verbose", 0644, dfs->root_dir, &verbose);

	ct_torture = dfs; /* for ct_work_torture() */

	pr_info("Context tracking work deferral torture module loaded!\n");
	return 0;
}

late_initcall(ct_work_torture_init);
