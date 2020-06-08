// SPDX-License-Identifier: GPL-2.0
/*
 * Cartesi yield device.
 * Copyright (C) 2020 Cartesi Pte. Ltd.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <asm/sbi.h>

#include <uapi/linux/cartesi/yield.h>

#define DEVICE_NAME "yield"
#define MODULE_DESC "Cartesi Machine " DEVICE_NAME " device"

#define SBI_YIELD 9

static long yield_drv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct yield_request request;
    uint64_t yield_cmd, sbi_cmd;
    int ret;

    if (cmd != IOCTL_YIELD)
        return -ENOIOCTLCMD;

    if ((ret = copy_from_user(&request, (void __user*)arg, sizeof(request))))
        return ret;

    sbi_cmd = request.tohost << 8 >> 8;
    yield_cmd = sbi_cmd << 8 >> 56;

    if (yield_cmd != HTIF_YIELD_PROGRESS && yield_cmd != HTIF_YIELD_ROLLUP)
        return -EINVAL;

    request.fromhost = SBI_CALL_1(SBI_YIELD, sbi_cmd);

    if ((ret = copy_to_user((void __user *)arg, &request, sizeof(request))))
        return ret;

    return 0;
}

static const struct file_operations fileops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = yield_drv_ioctl
};

static struct miscdevice yield_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &fileops
};

static int __init yield_dev_init(void)
{
    int ret = misc_register(&yield_dev);
    if (ret) {
        pr_err(MODULE_DESC ": Registration failed with error %d\n", ret);
        return ret;
    }

    pr_info(MODULE_DESC ": Module loaded\n");
    return 0;
}

static void __exit yield_dev_exit(void)
{
    misc_deregister(&yield_dev);
    pr_info(MODULE_DESC ": Module unloaded\n");
}

module_init(yield_dev_init);
module_exit(yield_dev_exit);

MODULE_DESCRIPTION(MODULE_DESC);
MODULE_LICENSE("GPL");
