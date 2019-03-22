BINARY=2d57c0f7-bddf-48ea-832f-d84a1a219301

O ?= ../out/AuthVars
WOLF_ROOT := ../../../../external/wolfssl/

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

CPPFLAGS +=  -fshort-wchar

clean: clean_stripped_file
.PHONY: clean_stripped_file
clean_stripped_file:
	rm -f $(BINARY).stripped.elf

