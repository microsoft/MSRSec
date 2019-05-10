BINARY= 53bab89c-b864-4d7e-acbc-33c07a9c1b8d

O ?= ../out/fTPM
SUBMODULE_ROOT := ../../../external
WOLF_ROOT := $(SUBMODULE_ROOT)/wolfssl
OSSL_ROOT := $(SUBMODULE_ROOT)/ossl
TPM_ROOT := $(SUBMODULE_ROOT)/ms-tpm-20-ref/TPMCmd

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(CFG_ARM64_ta_arm64),y)
# include libgcc.a for __udivti3
ldargs-$(binary).elf += $(libgcc$(sm))
endif

CPPFLAGS +=  -fshort-wchar

clean: clean_stripped_file
.PHONY: clean_stripped_file
clean_stripped_file:
	rm -f $(BINARY).stripped.elf

