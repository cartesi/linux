#ifndef _UAPI_LINUX_CARTESI_ROLLUP_H
#define _UAPI_LINUX_CARTESI_ROLLUP_H

#define CARTESI_ROLLUP_ADVANCE_STATE 0
#define CARTESI_ROLLUP_INSPECT_STATE 1

#define CARTESI_ROLLUP_ADDRESS_SIZE 20

#include <linux/ioctl.h>
#include <linux/types.h>

struct rollup_bytes {
    __u8 *data;
    __u64 length;
};

struct rollup_input_metadata {
    __u8 msg_sender[CARTESI_ROLLUP_ADDRESS_SIZE];
    __u64 block_number;
    __u64 timestamp;
    __u64 epoch_index;
    __u64 input_index;
};

struct rollup_advance_state {
    struct rollup_input_metadata metadata;
    struct rollup_bytes payload;
};

struct rollup_inspect_state {
    struct rollup_bytes payload;
};

struct rollup_finish {
    /* True if previous request should be accepted */
    /* False if previous request should be rejected */
    _Bool accept_previous_request;

    int next_request_type; /* either CARTESI_ROLLUP_ADVANCE or CARTESI_ROLLUP_INSPECT */
    int next_request_payload_length;
};

struct rollup_voucher {
    __u8 destination[CARTESI_ROLLUP_ADDRESS_SIZE];
    struct rollup_bytes payload;
    __u64 index;
};

struct rollup_notice {
    struct rollup_bytes payload;
    __u64 index;
};

struct rollup_report {
    struct rollup_bytes payload;
};

struct rollup_exception {
    struct rollup_bytes payload;
};

/* Finishes processing of current advance or inspect.
 * Returns only when next advance input or inspect query is ready.
 * How:
 *   Yields manual with rx-accepted if accept is true and yields manual with rx-rejected if accept is false.
 *   Once yield returns, checks the data field in fromhost to decide if next request is advance or inspect.
 *   Returns type and payload length of next request in struct
 * on success:
 *   Returns 0
 * on failure:
 *   EFAULT in case of invalid arguments
 *   ERESTARTSYS in case of an internal lock error
 *   EIO in case of yield device error
 *   EOPNOTSUPP in case of an invalid next_request_type */
#define IOCTL_ROLLUP_FINISH  _IOWR(0xd3, 0, struct rollup_finish)

/* Obtains arguments to advance state
 * How:
 *   Reads from input metadat memory range and convert data.
 *   Reads from rx buffer and copy to payload
 * on success:
 *   Returns 0
 * on failure:
 *   EOPNOTSUPP in case the driver is not currently processing an advance state
 *   EFAULT in case of invalid arguments
 *   ERESTARTSYS in case of an internal lock error
 *   EDOM in case of an integer larger than 64bits is received */
#define IOCTL_ROLLUP_READ_ADVANCE_STATE _IOWR(0xd3, 0, struct rollup_advance_state)

/* Obtains arguments to inspect state
 * How:
 *   Reads from rx buffer and copy to payload
 * on success:
 *   Returns 0
 * on failure:
 *   EOPNOTSUPP in case the driver is not currently processing an inspect state
 *   EFAULT in case of invalid arguments
 *   ERESTARTSYS in case of an internal lock error */
#define IOCTL_ROLLUP_READ_INSPECT_STATE _IOWR(0xd3, 0, struct rollup_inspect_state)

/* Outputs a new voucher.
 * How: Computes the Keccak-256 hash of address+payload and then, atomically:
 *  - Copies the (address+be32(0x40)+be32(payload_length)+payload) to the tx buffer
 *  - Copies the hash to the next available slot in the voucher-hashes memory range
 *  - Yields automatic with tx-voucher
 *  - Fills in the index field with the corresponding slot from voucher-hashes
 * on success:
 *   Returns 0
 * on failure:
 *   EOPNOTSUPP in case the driver is currently processing an inspect state
 *   EFAULT in case of invalid arguments
 *   ERESTARTSYS in case of an internal lock error
 *   EDOM in case of an integer larger than 64bits is received
 *   EIO in case of yield device error */
#define IOCTL_ROLLUP_WRITE_VOUCHER _IOWR(0xd3, 1, struct rollup_voucher)

/* Outputs a new notice.
 * How: Computes the Keccak-256 hash of payload and then, atomically:
 *  - Copies the (be32(0x20)+be32(payload_length)+payload) to the tx buffer
 *  - Copies the hash to the next available slot in the notice-hashes memory range
 *  - Yields automatic with tx-notice
 *  - Fills in the index field with the corresponding slot from notice-hashes
 * on success:
 *   Returns 0
 * on failure:
 *   EOPNOTSUPP in case the driver is currently processing an inspect state
 *   EFAULT in case of invalid arguments
 *   ERESTARTSYS in case of an internal lock error
 *   EDOM in case of an integer larger than 64bits is received
 *   EIO in case of yield device error */
#define IOCTL_ROLLUP_WRITE_NOTICE  _IOWR(0xd3, 2, struct rollup_notice)

/* Outputs a new report.
 *  - Copies the (be32(0x20)+be32(payload_length)+payload) to the tx buffer
 *  - Yields automatic with tx-report
 * on success:
 *   Returns 0
 * on failure:
 *   EFAULT in case of invalid arguments
 *   ERESTARTSYS in case of an internal lock error
 *   EIO in case of yield device error */
#define IOCTL_ROLLUP_WRITE_REPORT  _IOWR(0xd3, 3, struct rollup_report)

/* Throws an exeption.
 *  - Copies the (be32(0x20)+be32(payload_length)+payload) to the tx buffer
 *  - Yields manual with tx-exception
 * on success:
 *   Returns 0
 * on failure:
 *   EFAULT in case of invalid arguments
 *   ERESTARTSYS in case of an internal lock error
 *   EIO in case of yield device error */
#define IOCTL_ROLLUP_THROW_EXCEPTION  _IOWR(0xd3, 4, struct rollup_exception)
#endif
