// SPDX-License-Identifier: GPL-2.0
/*
 * Cartesi yield device.
 * Copyright (C) 2020-2021 Cartesi Pte. Ltd.
 */

#include <linux/kernel.h>
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
#include "libyield.h"
#include <uapi/linux/cartesi/yield.h>

#define DEVICE_NAME "yield"
#define FDT_YIELD_PATH "/yield"
#define MODULE_DESC "Cartesi Machine " DEVICE_NAME " device"

static const char *available_cmds[] = {
    [HTIF_YIELD_AUTOMATIC] = "automatic",
    [HTIF_YIELD_MANUAL]    = "manual",
};
struct yield_device {
    struct miscdevice mdev;
    u64 enabled_cmds;
};

static struct yield_device *to_yield_device(struct file *file)
{
    struct miscdevice *dev = file->private_data;
    return container_of(dev, struct yield_device, mdev);
}

static int retrieve_enabled_cmds(struct yield_device *yield)
{
    int i, enabled_cmds_count = 0;
    struct device_node *node = of_find_node_by_path(FDT_YIELD_PATH);

    for (i=0; i<ARRAY_SIZE(available_cmds); ++i) {
        bool p = of_property_read_bool(node, available_cmds[i]);
        yield->enabled_cmds |= (u64)p << i;
        enabled_cmds_count += p;
    }
    return enabled_cmds_count;
}

static long yield_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret;
    struct yield_device *yield;
    struct yield_request req, rep;

    if ((yield = to_yield_device(file)) == NULL)
        return -EBADF;

    if (cmd != IOCTL_YIELD)
        return -ENOIOCTLCMD;

    if ((ret = copy_from_user(&req, (void __user*)arg, sizeof(req))) ||
        (ret = cartesi_yield_validate(&req)) ||
        (ret = yield->enabled_cmds & (1ul << req.cmd)? 0 : -EIO) ||
        (ret = cartesi_yield(req.cmd, req.reason, req.data, &rep)) ||
        (ret = copy_to_user((void __user*)arg, &rep, sizeof(rep))))
        return ret;

    return 0;
}

static const struct file_operations yield_fileops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = yield_ioctl
};

static int yield_device_probe(struct platform_device *pdev)
{
    int ret;
    struct yield_device *yield;

    yield = (struct yield_device*) kzalloc(sizeof(struct yield_device), GFP_KERNEL);
    if (!yield) {
        dev_err(&pdev->dev, "failed to allocate memory\n");
        return -ENOMEM;
    }

    /* this should only happen on a malformed FDT in which there is an empty
     * `yield` entry, that is, with no bits enabled */
    if (retrieve_enabled_cmds(yield) == 0) {
        ret = -ENODEV;
        dev_err(&pdev->dev, "failed to retrieve enabled yield commands\n");
        goto free_yield;
    }

    yield->mdev.minor = MISC_DYNAMIC_MINOR;
    yield->mdev.name  = DEVICE_NAME;
    yield->mdev.fops  = &yield_fileops;
    if ((ret = misc_register(&yield->mdev)) != 0) {
        dev_err(&pdev->dev, "failed to register miscdevice\n");
        goto free_yield;
    }
    pr_info(MODULE_DESC ": Module loaded\n");
    return 0;

free_yield:
    kfree(yield);
    return ret;
}

static int yield_device_remove(struct platform_device *pdev)
{
    struct yield_device *yield = platform_get_drvdata(pdev);
    misc_deregister(&yield->mdev);
    kfree(yield);
    dev_info(&pdev->dev, "unregistered\n");
    return 0;
}

static const struct of_device_id cartesi_yield_match[] = {
    {.compatible = "ctsi-yield",}, {},
};
MODULE_DEVICE_TABLE(of, cartesi_yield_match);

static struct platform_driver yield_device = {
    .driver = {
        .name = DEVICE_NAME,
        .of_match_table = cartesi_yield_match,
    },
    .probe = yield_device_probe,
    .remove = yield_device_remove,
};

module_platform_driver(yield_device);

MODULE_DESCRIPTION(MODULE_DESC);
MODULE_LICENSE("GPL");
