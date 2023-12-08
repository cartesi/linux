////// SPDX-License-Identifier: GPL-2.0
/*
 * Cartesi cmio device.
 * Copyright (C) 2023 Cartesi Machine reference unit
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <asm/sbi.h>
#include <uapi/linux/cartesi/cmio.h>

#define DEVICE_NAME "cmio"
#define MODULE_DESC "Cartesi Machine " DEVICE_NAME " device"

#define SBI_YIELD 9

struct cmio_device {
	struct platform_device *pdev;
	struct miscdevice mdev;
	struct cmio_setup bufs;
	atomic_t single_user_lock;
};

static struct cmio_device *to_cmio_device(struct file *file)
{
	struct miscdevice *dev = file->private_data;
	return container_of(dev, struct cmio_device, mdev);
}

static long cmio_ioctl_setup(struct cmio_device *me, unsigned long arg)
{
	if (copy_to_user((void __user *)arg, &me->bufs, sizeof me->bufs))
		return -EFAULT;

	return 0;
}

static long cmio_ioctl_yield(struct cmio_device *me, unsigned long arg)
{
	__u64 req = 0,
	      rep = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof req))
		return -EFAULT;

	rep = sbi_ecall(SBI_YIELD, 0, req, 0, 0, 0, 0, 0).value;

	if (copy_to_user((void __user *)arg, &rep, sizeof rep))
		return -EFAULT;

	return 0;
}

/*
 * We enforce only one user at a time here with the open/release.
 */
static int cmio_open(struct inode *inode, struct file *file)
{
	struct cmio_device *cmio = to_cmio_device(file);
	if (!cmio)
		return -EBADF;

	if (!atomic_inc_and_test(&cmio->single_user_lock)) {
		atomic_dec(&cmio->single_user_lock);
		return -EBUSY;
	}
	return 0;
}

static int cmio_release(struct inode *inode, struct file *file)
{
	struct cmio_device *cmio = to_cmio_device(file);
	if (!cmio)
		return -EBADF;

	atomic_dec(&cmio->single_user_lock);
	return 0;
}

static long cmio_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cmio_device *cmio = to_cmio_device(file);
	if (!cmio)
		return -EBADF;

	switch (cmd) {
	case IOCTL_CMIO_SETUP:
		return cmio_ioctl_setup(cmio, arg);
	case IOCTL_CMIO_YIELD:
		return cmio_ioctl_yield(cmio, arg);
	}
	return -ENOIOCTLCMD;
}

static int cmio_mmap(struct file *file, struct vm_area_struct *vma)
{
	__u64 vma_size;
	struct cmio_device *cmio = to_cmio_device(file);
	if (!cmio)
		return -EBADF;

	vma_size = vma->vm_end - vma->vm_start;
	if (!((vma->vm_start == cmio->bufs.tx.data && vma_size == cmio->bufs.tx.length)
	||    (vma->vm_start == cmio->bufs.rx.data && vma_size == cmio->bufs.rx.length)))
		return -EINVAL;

	return remap_pfn_range(vma,
	                       vma->vm_start,
	                       vma->vm_start >> PAGE_SHIFT,
	                       vma_size,
	                       vma->vm_page_prot);
}

static const struct file_operations cmio_fileops = {
	.open           = cmio_open,
	.release        = cmio_release,
	.unlocked_ioctl = cmio_ioctl,
	.mmap           = cmio_mmap,
	.owner          = THIS_MODULE,
};

static int setup_buffer(struct device_node *parent, const char *name, struct cmio_buffer *buf)
{
	u64 xs[2];
	int rc = -EIO;
	struct device_node *node = NULL;

	if (!(node = of_find_node_by_name(parent, name)))
		goto leave;
	if (of_property_read_u64_array(node, "reg", xs, 2))
		goto leave;
	if (!(buf->data = xs[0]))
		goto leave;
	if (!(buf->length = xs[1]))
		goto leave;
	rc = 0;
leave:
	of_node_put(node);
	return rc;
}

static int check_yield_automatic_and_manual(struct device_node *node)
{
	return !(of_property_read_bool(node, "automatic")
	&&       of_property_read_bool(node, "manual"));
}

static int setup_io(struct cmio_device *cmio)
{
	int rc = -EIO;
	struct device_node *cmio_node = NULL,
	                   *yield_node = NULL;

	if (!(cmio_node = of_find_node_by_path("/cmio"))
	||  setup_buffer(cmio_node, "tx_buffer", &cmio->bufs.tx)
	||  setup_buffer(cmio_node, "rx_buffer", &cmio->bufs.rx))
		goto leave;

	if (!(yield_node = of_find_node_by_path("/yield"))
	||    check_yield_automatic_and_manual(yield_node))
		goto leave;
	rc = 0;
leave:
	of_node_put(yield_node);
	of_node_put(cmio_node);
	return rc;
}

static int cmio_driver_probe(struct platform_device *pdev)
{
	int rc;
	struct cmio_device *cmio;

	cmio = devm_kzalloc(&pdev->dev, sizeof(*cmio), GFP_KERNEL);
	if (!cmio)
		return -ENOMEM;

	atomic_set(&cmio->single_user_lock, -1);
	cmio->mdev.minor = MISC_DYNAMIC_MINOR;
	cmio->mdev.name  = DEVICE_NAME;
	cmio->mdev.fops  = &cmio_fileops;
	rc = misc_register(&cmio->mdev);
	if (rc) {
		dev_err(&pdev->dev, "failed to register miscdevice\n");
		goto leave;
	}

	rc = setup_io(cmio);
	if (rc) {
		dev_err(&pdev->dev, "failed to parse device tree\n");
		goto deregister;
	}

	platform_set_drvdata(pdev, cmio);
	cmio->pdev = pdev;

	pr_info(MODULE_DESC ": Module loaded\n");
	return 0;

deregister:
	misc_deregister(&cmio->mdev);
leave:
	return rc;
}

static int cmio_driver_remove(struct platform_device *pdev)
{
	struct cmio_device *cmio = platform_get_drvdata(pdev);
	misc_deregister(&cmio->mdev);
	dev_info(&pdev->dev, "unregistered\n");
	return 0;
}

static const struct of_device_id cmio_match[] = {
	{.compatible = "ctsi-cmio",}, {},
};
MODULE_DEVICE_TABLE(of, cmio_match);

static struct platform_driver cmio_driver = {
	.driver = {
		.name = DEVICE_NAME,
		.of_match_table = cmio_match,
	},
	.probe = cmio_driver_probe,
	.remove = cmio_driver_remove,
};

module_platform_driver(cmio_driver);

MODULE_DESCRIPTION(MODULE_DESC);
MODULE_LICENSE("GPL");
