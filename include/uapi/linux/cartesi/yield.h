/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Cartesi yield device.
 * Copyright (C) 2020-2021 Cartesi Pte. Ltd.
 */

#ifndef _UAPI_LINUX_CARTESI_YIELD_H
#define _UAPI_LINUX_CARTESI_YIELD_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct yield_request {
    __u8 dev;
    __u8 cmd;
    __u16 reason;
    __u32 data;
};

#define HTIF_DEVICE_YIELD   2

#define HTIF_YIELD_AUTOMATIC  0
#define HTIF_YIELD_MANUAL    1

#define HTIF_YIELD_REASON_PROGRESS 0
#define HTIF_YIELD_REASON_RX_ACCEPTED 1
#define HTIF_YIELD_REASON_RX_REJECTED 2
#define HTIF_YIELD_REASON_TX_VOUCHER 3
#define HTIF_YIELD_REASON_TX_NOTICE 4
#define HTIF_YIELD_REASON_TX_REPORT 5
#define HTIF_YIELD_REASON_TX_EXCEPTION 6

#define IOCTL_YIELD   _IOWR(0xd1, 0, struct yield_request)

#endif /* _UAPI_LINUX_CARTESI_YIELD_H */
