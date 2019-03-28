#
# For the purposes of this command the current working directory is the makefile root (/fTPM) folder,
# but the symlink will be created relative to THIS directory so the source requires an extra '../../'.
#
./lib/wolf/wolf_symlink: remove_wolf_symlink download_wolf
	@echo Checking symlink to the WolfSSL folder: $(abspath $(WOLF_ROOT))
	@if [ -L ./lib/wolf/wolf_symlink ] ; \
	then \
	echo Symlink already established ; \
	else \
	echo Establishing symlink. ; \
	ln -s ../../$(WOLF_ROOT) ./lib/wolf/wolf_symlink; \
	fi

.PHONY: remove_wolf_symlink
remove_wolf_symlink:
	@echo Clearing symlink to the Wolf folder: $(abspath $(WOLF_ROOT))
	unlink ./lib/wolf/wolf_symlink || true

.PHONY: download_wolf
download_wolf: $(WOLF_ROOT)/README

$(WOLF_ROOT)/README:
	( cd $(SUBMODULE_ROOT); git submodule update --init wolfssl)

global-incdirs-y += wolf_symlink

wolf_crypt_files = \
 wolf_symlink/wolfcrypt/src/aes.c \
 wolf_symlink/wolfcrypt/src/asn.c \
 wolf_symlink/wolfcrypt/src/des3.c \
 wolf_symlink/wolfcrypt/src/ecc.c \
 wolf_symlink/wolfcrypt/src/integer.c \
 wolf_symlink/wolfcrypt/src/memory.c \
 wolf_symlink/wolfcrypt/src/random.c \
 wolf_symlink/wolfcrypt/src/sha.c \
 wolf_symlink/wolfcrypt/src/sha256.c \
 wolf_symlink/wolfcrypt/src/sha512.c \
 wolf_symlink/wolfcrypt/src/tfm.c \
 wolf_symlink/wolfcrypt/src/wolfmath.c \

srcs-y = $(foreach wcfile, $(wolf_crypt_files), $(wcfile) )
$(foreach wcfile, $(wolf_crypt_files), $(eval  cflags-$(wcfile)-y += $(WOLF_SSL_FLAGS) $(INCLUDE_OVERWRITES) $(WOLF_WARNING_SUPPRESS)))
$(foreach wcfile, $(wolf_crypt_files), $(eval  incdirs-$(wcfile)-y += ../tpm/tpm_symlink/tpm/include))