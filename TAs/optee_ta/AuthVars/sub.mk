WARNS ?= 1
NOWERROR ?= 1
CFG_TA_DEBUG ?= n
CFG_TEE_TA_LOG_LEVEL ?= 1

AUTHVAR_FLAGS = -DGCC

CFG_FTPM_USE_WOLF ?= n

ifeq ($(CFG_AUTHVARS_USE_WOLF),y)
CPPFLAGS += -DUSE_WOLFCRYPT
WOLF_SSL_FLAGS = -DSINGLE_THREADED -DNO_FILESYSTEM -DNO_WOLFSSL_CLIENT -DNO_WOLFSSL_SERVER -DOPENSSL_EXTRA -DWOLFSSL_USER_SETTINGS -DTIME_OVERRIDES -DSTRING_USER -DCTYPE_USER -DHAVE_PKCS7 -DHAVE_AES_KEYWRAP -DHAVE_X963_KDF -DNO_WRITEV -DNO_ASN_TIME -DHAVE_TIME_T_TYPE -DWOLFCRYPT_ONLY
WOLF_WARNING_SUPPRESS = -Wno-unused-function -Wno-switch-default

WOLF_INCLUDES = -include ./src/include/user_settings.h
INCLUDE_OVERWRITES = $(WOLF_INCLUDES)
endif

CPPFLAGS += -DTHIRTY_TWO_BIT -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -D_ARM_ -w -Wno-strict-prototypes -mcpu=$(TA_CPU) -fstack-protector -Wstack-protector

ifeq ($(CFG_ARM64_ta_arm64),y)
CPPFLAGS += -mstrict-align
CPPFLAGS += -DfTPMARM64=1
else
CPPFLAGS += -mno-unaligned-access
CPPFLAGS += -DfTPMARM32=1
endif

ifeq ($(CFG_TA_DEBUG),y)
CPPFLAGS += -DDBG=1
CPPFLAGS += -O0
CPPFLAGS += -DDEBUG
CPPFLAGS += -DAUTHVAR_DEBUG=1
else
CPPFLAGS += -Os
CPPFLAGS += -DNDEBUG
endif

#
# Link the required external code into the libraries folder. OP-TEE build
# does not work well when accessing anything below the root directory. Use
# symlinks to trick it.
#
all: create_lib_symlinks
clean: clean_lib_symlinks

subdirs-y += lib

global-incdirs-y += src/include

cflags-y += $(AUTHVAR_FLAGS) $(WOLF_SSL_FLAGS) $(INCLUDE_OVERWRITES)

srcs-y += src/varops.c
srcs-y += src/varauth.c
srcs-y += src/varmgmt.c
srcs-y += src/RuntimeSupport.c

srcs-y += AuthVars.c
