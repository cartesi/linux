// SPDX-License-Identifier: GPL-2.0
/*
 * Cartesi yield device.
 * Copyright (C) 2020-2021 Cartesi Pte. Ltd.
 */
#ifndef LIBYIELD_H
#define LIBYIELD_H
#include <uapi/linux/cartesi/yield.h>

int cartesi_yield_validate(struct yield_request *rep);
int cartesi_yield(u64 mode, u64 reason, u64 data, struct yield_request *reply);

#endif /* LIBYIELD_H */
