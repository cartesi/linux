////// SPDX-License-Identifier: GPL-2.0
/*
 * Cartesi rollup device.
 * Copyright (C) 2021 Cartesi Pte. Ltd.
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
#include <crypto/hash.h>
#include "libstream256.h"
#include "libyield.h"
#include <uapi/linux/cartesi/rollup.h>

#define DEVICE_NAME "rollup"
#define FDT_ROLLUP_PATH "/rollup"
#define MODULE_DESC "Cartesi Machine " DEVICE_NAME " device"

#define CARTESI_ROLLUP_INITIAL_STATE (-1)

/* NOTE: keep in sync with node_paths */
#define TX_BUFFER_INDEX      0
#define RX_BUFFER_INDEX      1
#define INPUT_METADATA_INDEX 2
#define VOUCHER_HASHES_INDEX 3
#define NOTICE_HASHES_INDEX  4

static const char *node_paths[] = {
    "tx_buffer",
    "rx_buffer",
    "input_metadata",
    "voucher_hashes",
    "notice_hashes",
};

static atomic_t rollup_probe_once = ATOMIC_INIT(1);

struct rollup_device {
    struct platform_device *pdev;
    struct miscdevice mdev;
    struct shash_desc *keccak;
    struct mutex lock;
    atomic_t rollup_status;
    int next_request_type;
    struct stream256 buffers[ARRAY_SIZE(node_paths)];
};

struct rx_header {
    union be256 offset;
    union be256 length;
};

struct input_metadata_header {
    uint8_t padding[sizeof(union be256) - CARTESI_ROLLUP_ADDRESS_SIZE];
    uint8_t msg_sender[CARTESI_ROLLUP_ADDRESS_SIZE];
    union be256 blocknumber;
    union be256 timestamp;
    union be256 epoch_number;
    union be256 input_number;
};

static struct rollup_device *to_rollup_device(struct file *file)
{
    struct miscdevice *dev = file->private_data;
    return container_of(dev, struct rollup_device, mdev);
}

static long rollup_ioctl_finish(struct rollup_device *rollup, unsigned long arg)
{
    long i, ret;
    u64 rx_length, reason;
    struct rollup_finish finish;
    struct stream256 *rx = &rollup->buffers[RX_BUFFER_INDEX];
    struct yield_request rep;

    // NOTE: pointer is known to be aligned
    struct rx_header *rx_header = (void *)rx->data;

    if ((ret = copy_from_user(&finish, (void __user*)arg, sizeof(finish)))) {
        return -EFAULT;
    }

    reason = finish.accept_previous_request?
        HTIF_YIELD_REASON_RX_ACCEPTED:
        HTIF_YIELD_REASON_RX_REJECTED;

    if (mutex_lock_interruptible(&rollup->lock))
        return -ERESTARTSYS;

    if ((ret = cartesi_yield(HTIF_YIELD_MANUAL, reason, 0, &rep))) {
        ret = -EIO;
        goto unlock;
    }

    if (rep.data != CARTESI_ROLLUP_ADVANCE_STATE &&
        rep.data != CARTESI_ROLLUP_INSPECT_STATE) {
        ret = -EOPNOTSUPP;
        goto unlock;
    }
    rollup->next_request_type = rep.data;
    finish.next_request_type = rep.data;

    if ((ret = be256_to_u64(&rx_header->length, &rx_length)))
        goto unlock;

    for (i = 0; i < ARRAY_SIZE(node_paths); ++i)
        stream256_reset(&rollup->buffers[i]);

    mutex_unlock(&rollup->lock);

    finish.next_request_payload_length = rx_length;
    if ((ret = copy_to_user((void __user*)arg, &finish, sizeof(finish))))
        return -EFAULT;

    return 0;
unlock:
    mutex_unlock(&rollup->lock);
    return ret;
}

static long copy_rx(struct rollup_device *rollup, struct rollup_bytes *payload)
{
    long ret;
    struct stream256 *rx = &rollup->buffers[RX_BUFFER_INDEX];
    struct rx_header *rxh = (void *)rx->data;
    u64 data_length, data_bytes_to_copy;

    if ((ret = be256_to_u64(&rxh->length, &data_length)))
        return ret;

    // length we received in `rxh` must fit into `rx`
    if (data_length > rx->length - sizeof(*rxh))
        return -EIO;

    // it must also fit into the buffer the user provided
    if (data_length > payload->length)
        return -ENOBUFS;

    data_bytes_to_copy = min(data_length, payload->length);
    return copy_to_user((void __user*)payload->data, rxh + 1, data_bytes_to_copy);
}

static long rollup_ioctl_read_advance(struct rollup_device *rollup, unsigned long arg)
{
    long ret;
    struct stream256 *im = &rollup->buffers[INPUT_METADATA_INDEX];
    struct input_metadata_header *imh = (void *)im->data;
    struct rollup_advance_state advance;

    if (rollup->next_request_type != CARTESI_ROLLUP_ADVANCE_STATE)
        return -EOPNOTSUPP;

    if ((ret = copy_from_user(&advance, (void __user*)arg, sizeof(advance))))
        return -EFAULT;

    if (mutex_lock_interruptible(&rollup->lock))
        return -ERESTARTSYS;

    if ((ret = copy_rx(rollup, &advance.payload))) {
        ret = -EFAULT;
        goto unlock;
    }

    memcpy(advance.metadata.msg_sender, &imh->msg_sender, sizeof(advance.metadata.msg_sender));
    if ((ret = be256_to_u64(&imh->blocknumber, &advance.metadata.block_number)) ||
        (ret = be256_to_u64(&imh->timestamp, &advance.metadata.timestamp)) ||
        (ret = be256_to_u64(&imh->epoch_number, &advance.metadata.epoch_index)) ||
        (ret = be256_to_u64(&imh->input_number, &advance.metadata.input_index))) {
        goto unlock;
    }
    mutex_unlock(&rollup->lock);

    if ((ret = copy_to_user((void __user*)arg, &advance, sizeof(advance))))
        return -EFAULT;

    return 0;
unlock:
    mutex_unlock(&rollup->lock);
    return ret;
}

static long rollup_ioctl_read_inspect(struct rollup_device *rollup, unsigned long arg)
{
    long ret = 0;
    struct rollup_inspect_state inspect;

    if (rollup->next_request_type != CARTESI_ROLLUP_INSPECT_STATE)
        return -EOPNOTSUPP;

    if ((ret = copy_from_user(&inspect, (void __user*)arg, sizeof(inspect))))
        return -EFAULT;

    if (mutex_lock_interruptible(&rollup->lock))
        return -ERESTARTSYS;

    if ((ret = copy_rx(rollup, &inspect.payload))) {
        ret = -EFAULT;
        goto unlock;
    }

    /* fall-through */
unlock:
    mutex_unlock(&rollup->lock);
    return ret;
}

static long rollup_ioctl_voucher(struct rollup_device *rollup, unsigned long arg)
{
    long ret = 0;
    struct rollup_voucher voucher;
    struct stream256 *tx = &rollup->buffers[TX_BUFFER_INDEX],
                         *vh = &rollup->buffers[VOUCHER_HASHES_INDEX];
    struct yield_request rep;

    if (rollup->next_request_type == CARTESI_ROLLUP_INSPECT_STATE) {
        dev_warn(&rollup->pdev->dev, "trying to emit a voucher during a inspect\n");
        return -EOPNOTSUPP;
    }

    if ((ret = copy_from_user(&voucher, (void __user*)arg, sizeof(voucher)))) {
        dev_warn(&rollup->pdev->dev, "failed to read voucher struct\n");
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&rollup->lock))
        return -ERESTARTSYS;

    stream256_reset(tx);
    if ((ret = stream256_encode_address(tx, voucher.address, sizeof(voucher.address))) ||
        (ret = stream256_encode_u64(tx, 0x40)) ||
        (ret = stream256_encode_u64(tx, voucher.payload.length)) ||
        (ret = stream256_encode_ubuf(tx, voucher.payload.data, voucher.payload.length)) ||
        (ret = stream256_encode_keccak(rollup->keccak, tx, vh, &voucher.index))) {
        goto unlock;
    }

    if ((ret = cartesi_yield(HTIF_YIELD_AUTOMATIC, HTIF_YIELD_REASON_TX_VOUCHER, 0, &rep))) {
        ret = -EIO;
        goto unlock;
    }

    if ((ret = copy_to_user((void __user*)arg, &voucher, sizeof(voucher)))) {
        ret = -EFAULT;
        goto unlock;
    }

    /* fall-through */
unlock:
    mutex_unlock(&rollup->lock);
    return ret;
}

static long rollup_ioctl_notice(struct rollup_device *rollup, unsigned long arg)
{
    long ret = 0;
    struct rollup_notice notice;
    struct stream256 *tx = &rollup->buffers[TX_BUFFER_INDEX],
                     *nh = &rollup->buffers[NOTICE_HASHES_INDEX];

    struct yield_request rep;

    if (rollup->next_request_type == CARTESI_ROLLUP_INSPECT_STATE) {
        dev_warn(&rollup->pdev->dev, "trying to emit a notice during a inspect\n");
        return -EOPNOTSUPP;
    }

    if ((ret = copy_from_user(&notice, (void __user*)arg, sizeof(notice)))) {
        dev_warn(&rollup->pdev->dev, "failed to read notice struct\n");
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&rollup->lock))
        return -ERESTARTSYS;

    stream256_reset(tx);
    if ((ret = stream256_encode_u64(tx, 0x20)) ||
        (ret = stream256_encode_u64(tx, notice.payload.length)) ||
        (ret = stream256_encode_ubuf(tx, notice.payload.data, notice.payload.length)) ||
        (ret = stream256_encode_keccak(rollup->keccak, tx, nh, &notice.index))) {
        goto unlock;
    }

    if ((ret = cartesi_yield(HTIF_YIELD_AUTOMATIC, HTIF_YIELD_REASON_TX_NOTICE, 0, &rep))) {
        ret = -EIO;
        goto unlock;
    }

    if ((ret = copy_to_user((void __user*)arg, &notice, sizeof(notice)))) {
        ret = -EFAULT;
        goto unlock;
    }

    /* fall-through */
unlock:
    mutex_unlock(&rollup->lock);
    return ret;
}

static long yield_simple_payload(stream256_encode_buf_t enc, struct stream256 *tx, struct rollup_bytes *payload, u64 cmd, u64 reason)
{
    long ret;
    struct yield_request rep;

    stream256_reset(tx);
    if ((ret = stream256_encode_u64(tx, 0x20)) ||
        (ret = stream256_encode_u64(tx, payload->length)) ||
        (ret = enc(tx, payload->data, payload->length))) {
        return ret;
    }

    if ((ret = cartesi_yield(cmd, reason, 0, &rep))) {
        return -EIO;
    }
    return 0;
}

static long rollup_ioctl_report(struct rollup_device *rollup, unsigned long arg)
{
    long ret = 0;
    struct rollup_report report;
    struct stream256 *tx = &rollup->buffers[TX_BUFFER_INDEX];

    if ((ret = copy_from_user(&report, (void __user*)arg, sizeof(report)))) {
        dev_warn(&rollup->pdev->dev, "failed to read report struct\n");
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&rollup->lock))
        return -ERESTARTSYS;

    ret = yield_simple_payload(stream256_encode_ubuf, tx, &report.payload,
            HTIF_YIELD_AUTOMATIC, HTIF_YIELD_REASON_TX_REPORT);

    mutex_unlock(&rollup->lock);
    return ret;
}

static long rollup_ioctl_exception(struct rollup_device *rollup, unsigned long arg)
{
    long ret = 0;
    struct rollup_exception exception;
    struct stream256 *tx = &rollup->buffers[TX_BUFFER_INDEX];

    if ((ret = copy_from_user(&exception, (void __user*)arg, sizeof(exception)))) {
        dev_warn(&rollup->pdev->dev, "failed to read exception struct\n");
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&rollup->lock))
        return -ERESTARTSYS;

    ret = yield_simple_payload(stream256_encode_ubuf, tx, &exception.payload,
            HTIF_YIELD_MANUAL, HTIF_YIELD_REASON_TX_EXCEPTION);

    mutex_unlock(&rollup->lock);
    return ret;
}

/*
 * We enforce only one user at a time here with the open/close.
 */
static int rollup_open(struct inode *inode, struct file *file)
{
    struct rollup_device *rollup;
    if ((rollup = to_rollup_device(file)) == NULL)
        return -EBADF;

    if (!atomic_dec_and_test(&rollup->rollup_status)) {
        atomic_inc(&rollup->rollup_status);
        return -EBUSY;
    }
    return 0;
}

static int rollup_release(struct inode *inode, struct file *file)
{
    struct rollup_device *rollup;
    if ((rollup = to_rollup_device(file)) == NULL)
        return -EBADF;

    atomic_inc(&rollup->rollup_status);
    return 0;
}

static long rollup_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct rollup_device *rollup;

    if ((rollup = to_rollup_device(file)) == NULL)
        return -EBADF;
    if ((rollup->next_request_type == CARTESI_ROLLUP_INITIAL_STATE) && !(
            (cmd == IOCTL_ROLLUP_FINISH) ||
            (cmd == IOCTL_ROLLUP_THROW_EXCEPTION))) {

        int ret;
        struct stream256 *tx = &rollup->buffers[TX_BUFFER_INDEX];
        unsigned char msg[] = "first ioctl must be either `finish' or `throw_exception'";
        struct rollup_bytes bytes = {msg, sizeof(msg)-1};
        dev_warn(&rollup->pdev->dev, msg);
        if (mutex_lock_interruptible(&rollup->lock))
            return -ERESTARTSYS;

        ret = yield_simple_payload(stream256_encode_buf, tx, &bytes,
                HTIF_YIELD_MANUAL, HTIF_YIELD_REASON_TX_EXCEPTION);

        mutex_unlock(&rollup->lock);
        return -EBADE;
    }

    switch (cmd) {
    case IOCTL_ROLLUP_FINISH:
        return rollup_ioctl_finish(rollup, arg);
    case IOCTL_ROLLUP_READ_ADVANCE_STATE:
        return rollup_ioctl_read_advance(rollup, arg);
    case IOCTL_ROLLUP_READ_INSPECT_STATE:
        return rollup_ioctl_read_inspect(rollup, arg);
    case IOCTL_ROLLUP_WRITE_NOTICE:
        return rollup_ioctl_notice(rollup, arg);
    case IOCTL_ROLLUP_WRITE_REPORT:
        return rollup_ioctl_report(rollup, arg);
    case IOCTL_ROLLUP_WRITE_VOUCHER:
        return rollup_ioctl_voucher(rollup, arg);
    case IOCTL_ROLLUP_THROW_EXCEPTION:
        return rollup_ioctl_exception(rollup, arg);
    }
    return -ENOIOCTLCMD;
}

static const struct file_operations rollup_fileops = {
    .open           = rollup_open,
    .release        = rollup_release,
    .owner          = THIS_MODULE,
    .unlocked_ioctl = rollup_ioctl
};

static int find_memory_regions(struct rollup_device *rollup)
{
    int i, j, err = 0;
    struct device_node *node = of_find_node_by_path(FDT_ROLLUP_PATH);

    for (i = 0; !err && i < ARRAY_SIZE(node_paths); ++i) {
        u64 xs[2];
        struct stream256 *bi = &rollup->buffers[i];
        struct device_node *buffer = of_find_node_by_name(node, node_paths[i]);
        err = of_property_read_u64_array(buffer, "reg", xs, 2);

        if (xs[0] == 0)
            return -ENODEV;
        if (xs[1] == 0)
            return -EIO;

        if ((bi->data = devm_ioremap(rollup->mdev.this_device, xs[0], xs[1])) == NULL)
            return -ENODEV;
        bi->length = xs[1];
        bi->offset = 0;

        /* do buffers intersect => malformed IO */
        for (j = 0; j < i; ++j) {
            struct stream256 *bj = &rollup->buffers[j];
            if ((bi->data <= bj->data && bj->data < bi->data + bi->length) ||
                (bj->data <= bi->data && bi->data < bj->data + bj->length))
                return -EIO;
        }
    }

    return err;
}

static int rollup_driver_probe(struct platform_device *pdev)
{
    struct rollup_device *rollup;
    struct crypto_shash *alg;
    int ret = -ENXIO;

    if (!atomic_dec_and_test(&rollup_probe_once)) {
        atomic_inc(&rollup_probe_once);
        return -EBUSY;
    }

    rollup = (struct rollup_device*) kzalloc(sizeof(struct rollup_device), GFP_KERNEL);
    if (!rollup) {
        dev_err(&pdev->dev, "failed to allocate memory\n");
        return -ENOMEM;
    }

    atomic_set(&rollup->rollup_status, 1);
    rollup->mdev.minor = MISC_DYNAMIC_MINOR;
    rollup->mdev.name  = DEVICE_NAME;
    rollup->mdev.fops  = &rollup_fileops;
    if ((ret = misc_register(&rollup->mdev)) != 0) {
        dev_err(&pdev->dev, "failed to register miscdevice\n");
        goto free_rollup;
    }

    if ((ret = find_memory_regions(rollup)) != 0) {
        dev_err(&pdev->dev, "failed to parse device tree\n");
        goto free_miscdevice;
    }

    alg = crypto_alloc_shash("keccak-256-generic", CRYPTO_ALG_TYPE_SHASH, 0);
    if (IS_ERR(alg)) {
        dev_err(&pdev->dev, "failed to create keccak-256\n");
        goto free_miscdevice;
    }

    rollup->keccak = kmalloc(sizeof(rollup->keccak) + crypto_shash_descsize(alg), GFP_KERNEL);
    if (!rollup->keccak) {
        dev_err(&pdev->dev, "failed to allocate memory\n");
        goto free_digest;
    }
    rollup->keccak->tfm = alg;

    platform_set_drvdata(pdev, rollup);
    rollup->pdev = pdev;
    rollup->next_request_type = CARTESI_ROLLUP_INITIAL_STATE;

    mutex_init(&rollup->lock);
    pr_info(MODULE_DESC ": Module loaded\n");
    return 0;

free_digest:
    crypto_free_shash(alg);
free_miscdevice:
    misc_deregister(&rollup->mdev);
free_rollup:
    kfree(rollup);
    return ret;
}

static int rollup_driver_remove(struct platform_device *pdev)
{
    struct rollup_device *rollup = platform_get_drvdata(pdev);
    crypto_free_shash(rollup->keccak->tfm);
    kfree(rollup->keccak);
    misc_deregister(&rollup->mdev);
    kfree(rollup);
    dev_info(&pdev->dev, "unregistered\n");
    return 0;
}

static const struct of_device_id cartesi_rollup_match[] = {
    {.compatible = "ctsi-rollup",}, {},
};
MODULE_DEVICE_TABLE(of, cartesi_rollup_match);

static struct platform_driver rollup_driver = {
    .driver = {
        .name = DEVICE_NAME,
        .of_match_table = cartesi_rollup_match,
    },
    .probe = rollup_driver_probe,
    .remove = rollup_driver_remove,
};

module_platform_driver(rollup_driver);

MODULE_DESCRIPTION(MODULE_DESC);
MODULE_LICENSE("GPL");
