#include <linux/module.h>
#include <asm/sbi.h>
#include "libyield.h"

#define SBI_YIELD 9

static int _yield_validate(u64 dev, u64 cmd, u64 reason)
{
    if (dev != HTIF_DEVICE_YIELD) {
        return -EINVAL;
    }

    if (cmd != HTIF_YIELD_MANUAL &&
        cmd != HTIF_YIELD_AUTOMATIC) {
        return -EINVAL;
    }

    if (reason != HTIF_YIELD_REASON_PROGRESS &&
        reason != HTIF_YIELD_REASON_RX_ACCEPTED &&
        reason != HTIF_YIELD_REASON_RX_REJECTED &&
        reason != HTIF_YIELD_REASON_TX_VOUCHER &&
        reason != HTIF_YIELD_REASON_TX_NOTICE &&
        reason != HTIF_YIELD_REASON_TX_REPORT &&
        reason != HTIF_YIELD_REASON_TX_EXCEPTION) {
        return -EINVAL;
    }

    return 0;
}

static u64 _yield_pack(u64 cmd, u64 reason, u64 data)
{
    return ((u64)HTIF_DEVICE_YIELD << 56)
        |  ((u64)cmd               << 56 >> 8)
        |  ((u64)reason            << 48 >> 16)
        |  ((u64)data              << 32 >> 32)
        ;
}

static struct yield_request _yield_unpack(u64 packed)
{
    struct yield_request out = {
        (u64)packed >> 56,
        (u64)packed <<  8 >> 56,
        (u64)packed << 16 >> 48,
        (u64)packed << 32 >> 32,
    };
    return out;
}

int cartesi_yield_validate(struct yield_request *req)
{
    return req->dev != HTIF_DEVICE_YIELD? -EINVAL:
        _yield_validate(req->dev, req->cmd, req->reason);
}

int cartesi_yield(u64 cmd, u64 reason, u64 data, struct yield_request *rep)
{
    int ret;
    u64 tohost, fromhost;

    if ((ret = _yield_validate(HTIF_DEVICE_YIELD, cmd, reason)))
        return ret;

    tohost = _yield_pack(cmd, reason, data);
    fromhost = SBI_CALL_1(SBI_YIELD, tohost);
    *rep = _yield_unpack(fromhost);
    return _yield_validate(rep->dev, rep->cmd, rep->reason);
}
