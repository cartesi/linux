// SPDX-License-Identifier: GPL-2.0
/*
 * Cartesi yield device.
 * Copyright (C) 2020-2021 Cartesi Pte. Ltd.
 */
#ifndef LIBYIELD_H
#define LIBYIELD_H
#include <uapi/linux/cartesi/yield.h>

struct cartesi_yield_unpacked {
    u8 dev;
    u8 cmd;
    u8 reason;
    u32 data;
};

int cartesi_yield(u64 mode, u64 reason, u64 data, struct cartesi_yield_unpacked *reply);

#endif /* LIBYIELD_H */
