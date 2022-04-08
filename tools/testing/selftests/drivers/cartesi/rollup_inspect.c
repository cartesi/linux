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
TEST_F(rollup, voucher_and_notice_must_fail_on_inspect) {
    int ret = 0;

    struct rollup_finish finish = {
        .accept_previous_request = true,
    };
    uint8_t msg[] = "payload";
    struct rollup_voucher voucher = {
        .payload = {msg, sizeof(msg)-1},
    };
    struct rollup_notice notice = {
        .payload = {msg, sizeof(msg)-1},
    };
    struct rollup_report report = {
        .payload = {msg, sizeof(msg)-1},
    };

    /* fail to emit a voucher before the first finish */
    ASSERT_EQ(ioctl(self->fd, IOCTL_ROLLUP_WRITE_VOUCHER, (unsigned long) &voucher), -1);
    ASSERT_EQ(errno, EBADE);

    /* fail to emit a notice before the first finish */
    ASSERT_EQ(ioctl(self->fd, IOCTL_ROLLUP_WRITE_NOTICE, (unsigned long) &notice), -1);
    ASSERT_EQ(errno, EBADE);

    /* fail to emit a report before the first finish */
    ASSERT_EQ(ioctl(self->fd, IOCTL_ROLLUP_WRITE_REPORT, (unsigned long) &report), -1);
    ASSERT_EQ(errno, EBADE);

    ASSERT_EQ(
        (ret = ioctl(self->fd, IOCTL_ROLLUP_FINISH, (unsigned long) &finish)) ||
        (ret = (finish.next_request_type == CARTESI_ROLLUP_INSPECT_STATE? 0 : EIO)), 0);

    /* fail to emit a voucher during a inspect */
    ASSERT_EQ(ioctl(self->fd, IOCTL_ROLLUP_WRITE_VOUCHER, (unsigned long) &voucher), -1);
    ASSERT_EQ(errno, EOPNOTSUPP);

    /* fail to emit a notice during a inspect */
    ASSERT_EQ(ioctl(self->fd, IOCTL_ROLLUP_WRITE_NOTICE, (unsigned long) &notice), -1);
    ASSERT_EQ(errno, EOPNOTSUPP);

    /* succeed to emit a report during a inspect */
    ASSERT_EQ(ioctl(self->fd, IOCTL_ROLLUP_WRITE_REPORT, (unsigned long) &report), 0);
}

TEST_HARNESS_MAIN
