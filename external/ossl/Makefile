TARGET=linux-generic32
PREFIX=/opt/openssl

INCLUDES = -I$(PREFIX)/include

LDFLAGS += -L$(PREFIX)/lib
LDFLAGS += -Wl,-whole-archive
LDFLAGS += -nodefaultlibs
TA_CROSS_COMPILE ?= /home/damcilva/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-

CC= $(TA_CROSS_COMPILE)gcc
CC+=-I$(CURDIR)/include
CC+=-fno-builtin
CC+=-ffreestanding
CC+=-nostdinc
CC+=-mno-unaligned-access
CC+=-fshort-wchar
CC+=-DOPENSSL_IMPLEMENTS_strncasecmp
CC+=-DOPENSSL_NO_SOCK
CC+=-DNO_SYSLOG
CC+=-DOPENSSL_NO_DEPRECATED
CC+=-DOPENSSL_NO_DGRAM
CC+=-DOPENSSL_NO_UI_CONSOLE
CC+=-DOPENSSL_NO_SOCK
CC+=-DOPENSSL_NO_HW
CC+=-DOPENSSL_NO_STDIO
CC+=-DNO_CHMOD
CC+=-DOPENSSL_NO_POSIX_IO
CC+=-DRAND_DRBG_GET_RANDOM_NONCE
CC+=-fPIC
CC+=-fPIE
CC+=-Os
CC+=-Werror
CC+=$(OPENSSL_FLAGS)
CC+=$(OPENSSL_EXFLAGS)

OPENSSL_CONFIG = \
--with-rand-seed=getrandom \
no-asm \
no-async \
no-autoalginit \
no-deprecated \
no-engine \
no-posix-io \
no-rdrand \
no-shared \
no-stdio \
no-threads \
 \
no-dso \
no-hw \
no-zlib \
no-pinshared \
-static \
--static \
-g \
-Os \


OPENSSL=openssl
PREFIX=/opt/openssl

all: build

.PHONY: download
download: $(OPENSSL)/README

# If the OSSL readme is not pressent, update the submodule
$(OPENSSL)/README:
	git submodule update --init openssl

.PHONY: configure
configure: download $(OPENSSL)/Makefile

.PHONY: $(OPENSSL)/Makefile
$(OPENSSL)/Makefile:
	( cd $(OPENSSL); ./Configure $(OPENSSL_CONFIG) $(TARGET) --prefix=$(PREFIX) --openssldir=$(PREFIX) )

build: configure
	( cd $(OPENSSL); $(MAKE) CC="$(CC)" build_generated libcrypto.a )

clean:
	( cd $(OPENSSL); $(MAKE) clean; git clean -fdx )

distclean:
	rm -rf $(OPENSSL)
	mkdir $(OPENSSL)
