// SPDX-License-Identifier: GPL-2.0
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/cartesi/cmio.h>
#include "../../kselftest_harness.h"

#define DEVICE_NAME "/dev/cmio"

/* HTIF yield encoding, as in the emulator's cm.h */
#define HTIF_DEV_SHIFT 56
#define HTIF_CMD_SHIFT 48
#define HTIF_REASON_SHIFT 32
#define HTIF_DEV_YIELD 2
#define HTIF_YIELD_CMD_AUTOMATIC 0
#define HTIF_YIELD_AUTOMATIC_REASON_PROGRESS 1

FIXTURE(cmio) {
	int fd;
};
FIXTURE_SETUP(cmio) {
	self->fd = open(DEVICE_NAME, O_RDWR);
	ASSERT_GE(self->fd, 0) {
		TH_LOG("fixture error: %s\n", strerror(errno));
	}
}
FIXTURE_TEARDOWN(cmio) {
	close(self->fd);
}

TEST_F(cmio, echo) {
	const int tx_prot = PROT_READ | PROT_WRITE,
	          rx_prot = PROT_READ;

	struct cmio_setup setup;

	ASSERT_EQ(ioctl(self->fd, IOCTL_CMIO_SETUP, (unsigned long) &setup), 0);
	uint8_t *tx = mmap((void *)setup.tx.data, setup.tx.length, tx_prot, MAP_SHARED, self->fd, 0);
	uint8_t *rx = mmap((void *)setup.rx.data, setup.rx.length, rx_prot, MAP_SHARED, self->fd, 0);

	ASSERT_NE(tx, MAP_FAILED);
	ASSERT_NE(rx, MAP_FAILED);
	uint64_t length =
		setup.rx.length < setup.tx.length?
		setup.rx.length : setup.tx.length;
	memcpy(tx, rx, length);
}

TEST_F(cmio, yield_automatic) {
	__u64 req = ((__u64) HTIF_DEV_YIELD << HTIF_DEV_SHIFT)
	          | ((__u64) HTIF_YIELD_CMD_AUTOMATIC << HTIF_CMD_SHIFT)
	          | ((__u64) HTIF_YIELD_AUTOMATIC_REASON_PROGRESS << HTIF_REASON_SHIFT);

	/* the emulator acknowledges an automatic yield with the device and command, and resumes */
	ASSERT_EQ(ioctl(self->fd, IOCTL_CMIO_YIELD, (unsigned long) &req), 0);
	ASSERT_EQ(req, ((__u64) HTIF_DEV_YIELD << HTIF_DEV_SHIFT)
	             | ((__u64) HTIF_YIELD_CMD_AUTOMATIC << HTIF_CMD_SHIFT));
}

TEST_HARNESS_MAIN
