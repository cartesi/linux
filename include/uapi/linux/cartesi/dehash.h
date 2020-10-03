/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Cartesi dehash device.
 * Copyright (C) 2020 Cartesi Pte. Ltd.
 */

#ifndef _UAPI_LINUX_CARTESI_DEHASH_H
#define _UAPI_LINUX_CARTESI_DEHASH_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define CARTESI_HASH_SIZE      32
#define CARTESI_HASH_NOT_FOUND ((uint64_t)~0ULL)

struct dehash_query {
    /* Block hash in binary */
    unsigned char hash[CARTESI_HASH_SIZE];

    /* Length of hash (max is CARTESI_HASH_SIZE) */
    uint64_t hash_length;

    /* On input: length of the buffer pointed by "data"
     * On output: length of hashed data, or CARTESI_HASH_NOT_FOUND */
    uint64_t data_length;

    /* Resulting block data */
    unsigned char *data;
};

struct dehash_info {
    /* Dehash device start address */
    uint64_t device_address;

    /* Dehash device length */
    uint64_t device_length;

    /* Dehash device target start address */
    uint64_t target_address;

    /* Dehash device target length */
    uint64_t target_length;
};

#define IOCTL_DEHASH_QUERY _IOWR(0xd2, 0, struct dehash_query)
#define IOCTL_DEHASH_INFO  _IOWR(0xd2, 1, struct dehash_info)

#endif
