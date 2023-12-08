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

TEST_F(cmio, open_again) {
	ASSERT_LT(open(DEVICE_NAME, O_RDWR), 0);
}

TEST_HARNESS_MAIN

