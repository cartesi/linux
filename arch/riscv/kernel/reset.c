// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/kernel.h>
#include <linux/reboot.h>
#include <linux/pm.h>
#include <asm/sbi.h>

static void default_power_off(void)
{
	while (1)
		wait_for_interrupt();
}

void (*pm_power_off)(void) = NULL;
EXPORT_SYMBOL(pm_power_off);

void machine_restart(char *cmd)
{
	int32_t type   = 0,
		reason = 0;

	if (kstrtoint(cmd, 10, &reason) != 0)
		type = 1;
	do_kernel_restart(cmd);
	sbi_ecall(SBI_EXT_0_1_SHUTDOWN, 0, type, reason, 0, 0, 0, 0);
}

void machine_halt(void)
{
	do_kernel_power_off();
	default_power_off();
}

void machine_power_off(void)
{
	do_kernel_power_off();
	default_power_off();
}
