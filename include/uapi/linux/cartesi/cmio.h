/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Cartesi cmio device.
 * Copyright (C) 2023-2024 Cartesi Machine reference unit
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef _UAPI_LINUX_CARTESI_CMIO_H
#define _UAPI_LINUX_CARTESI_CMIO_H
#include <linux/types.h>
#include <linux/ioctl.h>

struct cmio_buffer {
	__u64 data;
	__u64 length;
};

struct cmio_setup {
	struct cmio_buffer tx, rx;
};

/** Return a @p cmio_setup structure filled with tx and rx buffer details. Use
 * these values to mmap them into the user-space.
 *
 * @return
 *  0 on success.
 * -1 on error and errno is set. */
#define IOCTL_CMIO_SETUP _IOR  (0xd3, 0, struct cmio_setup)

/** Yield the machine execution and transfer control back to the emulator.
 *
 * @return
 *  0 on success.
 * -1 on error and errno is set. */
#define IOCTL_CMIO_YIELD _IOWR (0xd3, 1, __u64)

#endif
