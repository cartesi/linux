#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/cartesi/cmio.h>
#include "../../kselftest_harness.h"

#define DEVICE_NAME "/dev/cmio"

FIXTURE(cmio) {
	int fd;
};
FIXTURE_SETUP(cmio) {
	self->fd = open(DEVICE_NAME, O_RDWR);
	ASSERT_GT(self->fd, 0) {
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

TEST_HARNESS_MAIN
