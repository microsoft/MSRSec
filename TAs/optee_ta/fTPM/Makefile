BINARY= bc50d971-d4c9-42c4-82cb-343fb7f37896

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

