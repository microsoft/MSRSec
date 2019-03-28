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

#
# The fTPM needs to overwrite some of the header files used in the reference implementation. The search order GCC
# uses is dependent on the order the '-I/include/path' arguments are passed in. This is depended on the optee_os build
# system which makes it brittle. Force including these files here will make sure the correct files are used first.
#
FTPM_INCLUDES = -include ./reference/include/VendorString.h -include ./reference/include/Implementation.h
WOLF_INCLUDES = 
INCLUDE_OVERWRITES = $(FTPM_INCLUDES) $(WOLF_INCLUDES)

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

global-incdirs-y += include
global-incdirs-y += reference/include
global-incdirs-y += platform/include

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
$(foreach platfile, $(PLATFORM_SOURCES), $(eval  cflags-$(platfile)-y += $(FTPM_FLAGS) $(WOLF_SSL_FLAGS) $(INCLUDE_OVERWRITES) $(FTPM_WARNING_SUPPRESS)))
$(foreach platfile, $(PLATFORM_SOURCES), $(eval  incdirs-$(platfile)-y += lib/tpm/tpm_symlink/tpm/include lib/tpm/tpm_symlink/tpm/include/prototypes ))
