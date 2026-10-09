# SPDX-License-Identifier: GPL-2.0
#
# Build the Cartesi Machine kernel artifacts:
#
#   make -f cartesi.mk          # all artifacts into artifacts/
#   make -f cartesi.mk env      # print artifact names
#   make -f cartesi.mk run-selftest
#
# Requires a riscv64-linux-gnu cross toolchain and wget. Outside a git
# checkout, set SOURCE_DATE_EPOCH to the commit date.

TOOLCHAIN_PREFIX    ?= riscv64-linux-gnu

WORK_DIR            := .work

OPENSBI_VERSION     ?= 1.3.1-ctsi-2
OPENSBI_SHA256      ?= 35082380131117aa8424d1b81ca9e6e0280baa9bffbcf3f46080a652e4cb4385
OPENSBI_URL         := https://github.com/cartesi/opensbi/archive/refs/tags/v$(OPENSBI_VERSION).tar.gz
OPENSBI_TARGZ       := $(WORK_DIR)/opensbi-$(OPENSBI_VERSION).tar.gz
OPENSBI_DIR         := $(WORK_DIR)/opensbi-$(OPENSBI_VERSION)
OPENSBI_BUILD_DIR   := $(OPENSBI_DIR)/build

LINUX_TEST_DIR      := tools/testing/selftests

JOBS                ?= -j$(shell nproc)

KERNEL_VERSION      := $(shell $(MAKE) -s --no-print-directory -f Makefile kernelversion)
SOURCE_DATE_EPOCH   ?= $(shell git log -1 --format=%ct)
ifeq ($(strip $(SOURCE_DATE_EPOCH)),)
$(error Cannot get the commit date from git. Set SOURCE_DATE_EPOCH)
endif
KERNEL_TIMESTAMP    := $(shell date -Rud @$(SOURCE_DATE_EPOCH))
HEADERS             := artifacts/linux-headers-$(KERNEL_VERSION).tar.xz
IMAGE               := artifacts/linux-$(KERNEL_VERSION)-no-opensbi.bin
LINUX               := artifacts/linux-$(KERNEL_VERSION).bin
LINUX_ELF           := artifacts/linux-$(KERNEL_VERSION).elf
SELFTEST            := artifacts/linux-selftest-$(KERNEL_VERSION).tar.xz
ARTIFACTS           := $(HEADERS) $(IMAGE) $(LINUX) $(LINUX_ELF) $(SELFTEST)

CARTESI_MACHINE     ?= cartesi-machine
SELFTEST_CMD        ?= /mnt/selftest/run_kselftest.sh

all: $(ARTIFACTS)

env:
	@echo KBUILD_BUILD_TIMESTAMP=\""$(KERNEL_TIMESTAMP)"\"
	@echo KBUILD_BUILD_USER=dapp
	@echo KBUILD_BUILD_HOST=cartesi

	@echo HEADERS="$(HEADERS)"
	@echo IMAGE="$(IMAGE)"
	@echo LINUX="$(LINUX)"
	@echo LINUX_ELF="$(LINUX_ELF)"
	@echo SELFTEST="$(SELFTEST)"

# build linux
# ------------------------------------------------------------------------------
LINUX_OPTS=$(JOBS) ARCH=riscv CROSS_COMPILE=$(TOOLCHAIN_PREFIX)- KBUILD_BUILD_TIMESTAMP="$(KERNEL_TIMESTAMP)" KBUILD_BUILD_USER=dapp KBUILD_BUILD_HOST=cartesi LOCALVERSION=
vmlinux $(IMAGE) $(LINUX_ELF) $(HEADERS) &: .config
	mkdir -p artifacts
	$(MAKE) -r $(LINUX_OPTS) olddefconfig
	$(MAKE) -r $(LINUX_OPTS) vmlinux Image
	$(MAKE) -r $(LINUX_OPTS) headers_install \
		INSTALL_HDR_PATH=$(abspath $(WORK_DIR)/linux-headers)
	tar --sort=name --mtime="$(KERNEL_TIMESTAMP)" --owner=1000 --group=1000 --numeric-owner -cJf $(HEADERS) -C $(abspath $(WORK_DIR)/linux-headers) .
	cp arch/riscv/boot/Image $(IMAGE)
	cp vmlinux $(LINUX_ELF)

.config:
	$(MAKE) -r $(LINUX_OPTS) cartesi_defconfig

# build linux w/ opensbi
# ------------------------------------------------------------------------------
OPENSBI_OPTS=$(JOBS) FW_PAYLOAD_PATH=$(abspath $(IMAGE)) FW_PAYLOAD=y FW_OPTIONS=0x01 PLATFORM=cartesi CROSS_COMPILE=$(TOOLCHAIN_PREFIX)-
$(LINUX): $(IMAGE) | $(OPENSBI_DIR)/Makefile
	@mkdir -p artifacts
	$(MAKE) -rC $(OPENSBI_DIR) $(OPENSBI_OPTS)
	@cp $(OPENSBI_BUILD_DIR)/platform/cartesi/firmware/fw_payload.bin $@

$(OPENSBI_DIR)/Makefile:
	mkdir -p $(WORK_DIR)
	wget -q -O $(OPENSBI_TARGZ) $(OPENSBI_URL)
	printf '%s  %s\n' '$(OPENSBI_SHA256)' '$(OPENSBI_TARGZ)' | shasum -a 256 -c -
	tar -xzf $(OPENSBI_TARGZ) -C $(WORK_DIR)

# build linux tests
# ------------------------------------------------------------------------------
$(SELFTEST): vmlinux
	mkdir -p artifacts
	$(MAKE) -r $(LINUX_OPTS) headers
	$(MAKE) -rC $(LINUX_TEST_DIR) $(LINUX_OPTS) \
		TARGETS=drivers/cartesi install
	chmod -R go=u-w $(LINUX_TEST_DIR)/kselftest_install
	tar --sort=name --mtime="$(KERNEL_TIMESTAMP)" --owner=1000 --group=1000 --numeric-owner -cJf $@ -C $(LINUX_TEST_DIR)/kselftest_install .

run-selftest:
	$(CARTESI_MACHINE) \
		--ram-image=$(abspath $(LINUX)) \
		--volume=host_directory:$(abspath $(LINUX_TEST_DIR)/kselftest_install),guest_directory:/mnt/selftest \
		-- $(SELFTEST_CMD)

clean:
	$(MAKE) -r $(LINUX_OPTS) clean
	rm -rf artifacts $(WORK_DIR)

.PHONY: all env run-selftest clean vmlinux $(ARTIFACTS)
