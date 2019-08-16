WARNS ?= 1
NOWERROR ?= 1
CFG_TA_DEBUG ?= n
CFG_TEE_TA_LOG_LEVEL ?= 1

CFG_FTPM_USE_WOLF ?= n

FTPM_FLAGS = -DGCC -DSIMULATION=NO -DUSE_PLATFORM_EPS -DVTPM
FTPM_DEBUG =  -DCOMPILER_CHECKS=YES -DfTPMDebug -DRUNTIME_SIZE_CHECKS -DLIBRARY_COMPATIBILITY_CHECK -DFAIL_TRACE
FTPM_RELEASE = -DCOMPILER_CHECKS=NO -DRUNTIME_SIZE_CHECKS=NO -DLIBRARY_COMPATIBILITY_CHECK=NO
FTPM_WARNING_SUPPRESS = -Wno-cast-align -Wno-switch-default -Wno-suggest-attribute=noreturn -Wno-missing-braces -Wno-sign-compare

ifeq ($(CFG_FTPM_USE_WOLF),y)
FTPM_FLAGS += -DUSE_WOLFCRYPT
WOLF_SSL_FLAGS += -DUSE_WOLFCRYPT
WOLF_SSL_FLAGS += -DSINGLE_THREADED -DNO_WOLFSSL_CLIENT -DNO_WOLFSSL_SERVER -DOPENSSL_EXTRA -DNO_FILESYSTEM -DWOLFSSL_USER_SETTINGS -DTIME_OVERRIDES -DSTRING_USER -DCTYPE_USER
WOLF_WARNING_SUPPRESS += -Wno-unused-function -Wno-switch-default
endif

CPPFLAGS += -DTHIRTY_TWO_BIT -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -D_ARM_ -w -Wno-strict-prototypes -mcpu=$(TA_CPU) -fstack-protector -Wstack-protector

ifeq ($(CFG_ARM64_ta_arm64),y)
CPPFLAGS += -mstrict-align
CPPFLAGS += -DfTPMARM64=1
CPPFLAGS += -D_M_ARM64
else
CPPFLAGS += -mno-unaligned-access
CPPFLAGS += -DfTPMARM32=1
endif

ifeq ($(CFG_TA_DEBUG),y)
CPPFLAGS += -DDBG=1
CPPFLAGS += -O0
CPPFLAGS += -DDEBUG
CPPFLAGS += -DfTPMDebug=1
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

#
# Order is important here since we override a few headers from the reference implementation
#
global-incdirs-y += include
global-incdirs-y += reference/include
global-incdirs-y += platform/include
global-incdirs-y += lib/tpm/tpm_symlink/tpm/include
global-incdirs-y += lib/tpm/tpm_symlink/tpm/include/prototypes

ifeq ($(CFG_FTPM_USE_WOLF),y)
global-incdirs-y += lib/tpm/tpm_symlink/tpm/include/Wolf
WOLF_SSL_FLAGS += -include ./reference/include/RuntimeSupport.h
endif

PLATFORM_SOURCES =  \
 platform/AdminPPI.c \
 platform/Cancel.c \
 platform/Clock.c \
 platform/DebugHelpers.c \
 platform/Entropy.c \
 platform/LocalityPlat.c \
 platform/NvAdmin.c \
 platform/NVMem.c \
 platform/PowerPlat.c \
 platform/PlatformData.c \
 platform/PPPlat.c \
 platform/RunCommand.c \
 platform/Unique.c \
 platform/EPS.c \
 reference/RuntimeSupport.c \

srcs-y += fTPM.c

srcs-y += $(foreach platfile, $(PLATFORM_SOURCES), $(platfile) )
$(foreach platfile, $(PLATFORM_SOURCES), $(eval  cflags-$(platfile)-y += $(FTPM_FLAGS) $(WOLF_SSL_FLAGS) $(FTPM_WARNING_SUPPRESS)))