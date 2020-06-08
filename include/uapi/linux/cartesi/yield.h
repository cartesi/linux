/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Cartesi yield device.
 * Copyright (C) 2020 Cartesi Pte. Ltd.
 */

#ifndef _UAPI_LINUX_CARTESI_YIELD_H
#define _UAPI_LINUX_CARTESI_YIELD_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct yield_request {
    uint64_t tohost;
    uint64_t fromhost;
};

#define HTIF_YIELD_PROGRESS 0
#define HTIF_YIELD_ROLLUP   1

#define IOCTL_YIELD   _IOWR(0xd1, 0, struct yield_request)

#endif
