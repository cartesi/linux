#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/cartesi/rollup.h>
#include "../../kselftest_harness.h"

#define ROLLUP_DEVICE_NAME "/dev/rollup"

FIXTURE(rollup) {
	int fd;
};
FIXTURE_SETUP(rollup) {
	self->fd = open(ROLLUP_DEVICE_NAME, O_RDWR);
	ASSERT_GT(self->fd, 0) {
		TH_LOG("fixture error: %s\n", strerror(self->fd));
	}
}
FIXTURE_TEARDOWN(rollup) {
	close(self->fd);
}
TEST_F(rollup, exception) {
	int ret;
	const char msg[] = "exception";

	struct rollup_finish finish = {
		.accept_previous_request = true,
	};
	struct rollup_exception exception = {
		.payload = {
			.data = msg,
			.length = sizeof(msg)-1,
		},
	};

	if ((ret = ioctl(self->fd, IOCTL_ROLLUP_FINISH, (unsigned long) &finish)) ||
	    (ret = ioctl(self->fd, IOCTL_ROLLUP_THROW_EXCEPTION, (unsigned long) &exception)))
		return ret;

	return 0;
}

TEST_HARNESS_MAIN
