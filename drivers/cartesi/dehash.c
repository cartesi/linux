////// SPDX-License-Identifier: GPL-2.0
/*
 * Cartesi dehash device.
 * Copyright (C) 2020 Cartesi Pte. Ltd.
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
#include <linux/mutex.h>

#include <uapi/linux/cartesi/dehash.h>

#define DEVICE_NAME "dehash"
#define MODULE_DESC "Cartesi Machine " DEVICE_NAME " device"

// DHD registers
#define DHD_IDX_RESERVED  0
#define DHD_IDX_TSTART    1
#define DHD_IDX_TLENGTH   2
#define DHD_IDX_DLENGTH   3
#define DHD_IDX_HLENGTH   4
#define DHD_IDX_H0        5
#define DHD_H_REG_COUNT   4

struct dehash_device {
    /* device lock */
    struct mutex lock;
    /* mmapped address of DHD registers */
    uint64_t *registers;
    /* mmapped address to DHD target data */
    unsigned char *target;
    /* platform_device pointer */
    struct platform_device *pdev;
    /* Misc device struct that set file_operations */
    struct miscdevice mdev;
};

static inline struct dehash_device *to_dehash_device(struct file *file)
{
    struct miscdevice *dev = file->private_data;
    return container_of(dev, struct dehash_device, mdev);
}

static long dehash_exec_query(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret, i;
    uint64_t data_length, *hash;
    struct dehash_query query;
    struct dehash_device *dhd;

    if ((dhd = to_dehash_device(file)) == NULL)
        return -ENXIO;

    if ((ret = copy_from_user(&query, (void __user*)arg, sizeof(struct dehash_query))))
        return ret;

    if (!query.hash_length || query.hash_length > sizeof(uint64_t) * DHD_H_REG_COUNT)
        return -EINVAL;

    if (mutex_lock_interruptible(&dhd->lock))
        return -ERESTARTSYS;

    dhd->registers[DHD_IDX_DLENGTH] = query.data_length;
    hash = (uint64_t*) &query.hash;
    for (i = 0; i < DHD_H_REG_COUNT; i++)
        dhd->registers[DHD_IDX_H0+i] = hash[i];

    dhd->registers[DHD_IDX_HLENGTH] = query.hash_length;
    data_length = dhd->registers[DHD_IDX_DLENGTH];

    if (data_length == CARTESI_HASH_NOT_FOUND) {
        query.data_length = data_length;
    } else {
        query.data_length = min(data_length, query.data_length);
        if ((ret = copy_to_user((void __user*)query.data, dhd->target, query.data_length)))
            goto unlock;
    }
    ret = copy_to_user((void __user*)arg, &query, sizeof(query));

unlock:
    mutex_unlock(&dhd->lock);
    return ret;
}

static long dehash_get_info(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret, i;
    uint64_t *hash;
    struct dehash_info info;
    struct dehash_device *dhd;
    struct resource *res;

    if ((dhd = to_dehash_device(file)) == NULL)
        return -ENXIO;

    if ((res = platform_get_resource(dhd->pdev, IORESOURCE_MEM, 0)) == NULL)
        return -ENXIO;

    if (mutex_lock_interruptible(&dhd->lock))
        return -ERESTARTSYS;

    info.device_address = res->start;
    info.device_length = resource_size(res);
    info.target_address = dhd->registers[DHD_IDX_TSTART];
    info.target_length = dhd->registers[DHD_IDX_TLENGTH];

    ret = copy_to_user((void __user*)arg, &info, sizeof(info));

    mutex_unlock(&dhd->lock);
    return ret;
}

static long dehash_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (cmd == IOCTL_DEHASH_QUERY)
        return dehash_exec_query(file, cmd, arg);
    else if (cmd == IOCTL_DEHASH_INFO)
        return dehash_get_info(file, cmd, arg);

    return -ENOIOCTLCMD;
}

static const struct file_operations dehash_fileops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = dehash_ioctl
};

static int dehash_driver_probe(struct platform_device *pdev)
{
    uint64_t tstart, tlength;
    struct resource *res;
    struct dehash_device *dhd;
    int ret = -ENXIO;

    dhd = (struct dehash_device*) kzalloc(sizeof(struct dehash_device), GFP_KERNEL);
    if (!dhd) {
        dev_err(&pdev->dev, "failed to allocate memory\n");
        return -ENOMEM;
    }

    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if (!res) {
        dev_err(&pdev->dev, "could not get DHD IO memory");
        goto error;
    }
    dhd->registers = (uint64_t*) devm_ioremap_resource(&pdev->dev, res);
    if (IS_ERR((void*) dhd->registers)) {
        dev_err(&pdev->dev, "failed to map DHD memory range");
        goto error;
    }

    tstart = dhd->registers[DHD_IDX_TSTART];
    tlength = dhd->registers[DHD_IDX_TLENGTH];
    if (!tlength) {
        dev_err(&pdev->dev, "DHD is not present (tlength == 0)");
        goto error;
    }
    if (!request_mem_region(tstart, tlength, res->name)) {
        dev_err(&pdev->dev, "DHD target memory request failed");
        goto error;
    }
    dhd->target = ioremap(tstart, tlength);
    if (!dhd->target) {
        dev_err(&pdev->dev, "failed to map DHD target memory range");
        goto error;
    }

    mutex_init(&dhd->lock);
    dhd->mdev.minor = MISC_DYNAMIC_MINOR;
    dhd->mdev.name  = DEVICE_NAME;
    dhd->mdev.fops  = &dehash_fileops;

    if ((ret = misc_register(&dhd->mdev)) != 0) {
        dev_err(&pdev->dev, "failed to register miscdevice\n");
        goto error;
    }

    platform_set_drvdata(pdev, dhd);
    dhd->pdev = pdev;

    pr_info(MODULE_DESC ": Module loaded\n");
    return 0;

error:
    kfree(dhd);
    return ret;
}

static int dehash_driver_remove(struct platform_device *pdev)
{
    struct dehash_device *dhd = platform_get_drvdata(pdev);
    misc_deregister(&dhd->mdev);
    dhd->pdev = NULL;
    kfree(dhd);
    dev_info(&pdev->dev, "unregistered\n");
    return 0;
}

// device_id is used to match this device to device entries like:
// dehash@40030000 {
//   compatible = "ctsi-dhd";
//   ...
static const struct of_device_id cartesi_dehash_match[] = {
    {.compatible = "ctsi-dhd",}, {},
};
MODULE_DEVICE_TABLE(of, cartesi_dehash_match);

static struct platform_driver dehash_driver = {
    .driver = {
        .name = DEVICE_NAME,
        .of_match_table = cartesi_dehash_match,
    },
    .probe = dehash_driver_probe,
    .remove = dehash_driver_remove,
};

module_platform_driver(dehash_driver);

MODULE_DESCRIPTION(MODULE_DESC);
MODULE_LICENSE("GPL");
