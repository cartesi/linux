#ifndef LIBSTREAM_H
#define LIBSTREAM_H
#include <linux/kernel.h>
#include <crypto/hash.h>

struct stream256 {
    u8 *data;
    u64 offset, length;
};

union be256 {
    __be64 be64[4];
    __be32 be32[8];
    __be16 be16[16];
    u8     data[32];
};

typedef int (*stream256_encode_buf_t)(struct stream256 *me, u8 *p, size_t n);

void stream256_reset      (struct stream256 *me);
int  stream256_encode_u64 (struct stream256 *me, u64 x);
int  stream256_encode_address(struct stream256 *me, u8 *p, size_t n);
int  stream256_encode_buf (struct stream256 *me, u8 *p, size_t n);
int  stream256_encode_ubuf(struct stream256 *me, u8 *p, size_t n);
int stream256_encode_keccak(struct shash_desc *keccak,
        const struct stream256 *me, struct stream256 *hash, uint64_t*index);

void be256_from_u64(union be256 *me, uint64_t x);
int be256_to_u64(union be256 *me, uint64_t *x);

#endif /* LIBSTREAM_H */
