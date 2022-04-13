#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include "libstream256.h"

static bool in_bounds(const struct stream256 *me, size_t bytes)
{
    return me->length - me->offset >= bytes;
}

static size_t align256(size_t n)
{
    return PTR_ALIGN(n, sizeof(union be256));
}

static void pad(struct stream256 *me, size_t n)
{
    size_t misaligned = align256(n) - n;

    if (misaligned) {
        memset(me->data + me->offset, 0, misaligned);
        me->offset += misaligned;
    }
}

void stream256_reset(struct stream256 *me)
{
    me->offset = 0;
}

int stream256_encode_u64(struct stream256 *me, uint64_t x)
{
    union be256 u;

    be256_from_u64(&u, x);
    if (!in_bounds(me, sizeof(u)))
        return -ENOBUFS;
    memcpy(me->data + me->offset, u.data, sizeof(u));
    me->offset += sizeof(u);

    return 0;
}

int stream256_encode_address(struct stream256 *me, uint8_t *p, size_t n)
{
    if (!in_bounds(me, align256(n)))
        return -ENOBUFS;
    pad(me, n);
    memcpy(me->data + me->offset, p, n);
    me->offset += n;

    return 0;
}

int stream256_encode_buf(struct stream256 *me, uint8_t *p, size_t n)
{
    if (!in_bounds(me, align256(n)))
        return -ENOBUFS;
    memcpy(me->data + me->offset, p, n);
    me->offset += n;
    pad(me, n);

    return 0;
}

int stream256_encode_ubuf(struct stream256 *me, uint8_t *p, size_t n)
{
    int ret;

    if (!in_bounds(me, align256(n)))
        return -ENOBUFS;
    if ((ret = copy_from_user(me->data + me->offset, p, n)))
        return ret;
    me->offset += n;
    pad(me, n);

    return 0;
}

int stream256_encode_keccak(struct shash_desc *keccak,
        const struct stream256 *me, struct stream256 *hash, uint64_t *index)
{
    if (!in_bounds(hash, align256(sizeof(union be256))))
        return -ENOBUFS;
    crypto_shash_init(keccak);
    crypto_shash_update(keccak, me->data, me->offset);
    crypto_shash_final(keccak, hash->data + hash->offset);
    if (index)
        *index = hash->offset / sizeof(union be256);
    hash->offset += sizeof(union be256);
    return 0;
}

void be256_from_u64(union be256 *me, uint64_t x)
{
    me->be64[0] = 0;
    me->be64[1] = 0;
    me->be64[2] = 0;
    me->be64[3] = cpu_to_be64(x);
}

int be256_to_u64(union be256 *me, uint64_t *x)
{
    if (me->be64[0] || me->be64[1] || me->be64[2])
        return -EDOM;
    *x = be64_to_cpu(me->be64[3]);
    return 0;
}
