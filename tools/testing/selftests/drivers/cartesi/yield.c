#include "../../kselftest_harness.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/cartesi/yield.h>

#define YIELD_DEVICE_NAME "/dev/yield"

FIXTURE(yield) {
	int fd;
};
FIXTURE_SETUP(yield) {
	self->fd = open(YIELD_DEVICE_NAME, O_RDWR);
	ASSERT_GT(self->fd, 0) {
		TH_LOG("fixture error: %s\n", strerror(self->fd));
	}
}
FIXTURE_TEARDOWN(yield) {
	close(self->fd);
}
TEST_F(yield, do_a_automatic_yield) {
    int cmds[] = {HTIF_YIELD_AUTOMATIC, HTIF_YIELD_MANUAL};
    int reasons[] = {
        HTIF_YIELD_REASON_PROGRESS,    HTIF_YIELD_REASON_RX_ACCEPTED,
        HTIF_YIELD_REASON_RX_REJECTED, HTIF_YIELD_REASON_TX_VOUCHER,
        HTIF_YIELD_REASON_TX_NOTICE,   HTIF_YIELD_REASON_TX_REPORT,
        HTIF_YIELD_REASON_TX_EXCEPTION,
    };

    for (int cmd=0; cmd < ARRAY_SIZE(cmds); ++cmd) {
        for (int reason=0; reason < ARRAY_SIZE(reasons); ++reason) {
            struct yield_request req = {
                .dev    = HTIF_DEVICE_YIELD,
                .cmd    = cmd,
                .reason = reason,
                .data   = (cmd * ARRAY_SIZE(reasons)) + reason,
            };
            ASSERT_EQ(ioctl(self->fd, IOCTL_YIELD, (unsigned long)&req), 0);
        }
    }
}

TEST_HARNESS_MAIN
