Stand Alone OpenSSL Crypto
==========================
This folder contains the necessary infrastructure to compile `libcrypto.a` for use as a statically linked library. Traditionally OpenSSL relies on an underlying operating system to supply some of its functionality (stdlib, random number generation, time, etc.).

This is not feasible for OP-TEE since many of functions used by OpenSSL are not available, and there is no Unix like set of system calls. OP-TEE only implements a limited subset of the standard library (no `strcat()` for example, only `strncat()`).

## Building libcrypto.a
A makefile is provided which automatically configures and builds `libcrypto.a` from OpenSSL version 1.1.1.

`OSSL_CROSS_COMPILE` should be the same compiler used to compile the final application.
```bash
# Download, configure, and build OpenSSL's libcrypto.a
make OSSL_CROSS_COMPILE=~/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-

# Removes all compiled artifacts, and clean the submodule
make clean

# Fully removes the contents of the submodule (make will re-download as needed)
# Helpful for fixing issues with the submodule.
make distclean
```



## Understanding Stand Alone OpenSSL

### Compiling OpenSSL with no Operating System
For this repo (Firmware TPM and Authenticated Variables) a very limited subset of OpenSSL features are needed, so most options are turned off using the OpenSSL config tool:
```
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
```

More areas are disabled by passing additional flags to the compiler at build time:
```
CC = $(OSSL_CROSS_COMPILE)gcc \
 -I$(CURDIR)/include \
 -fno-builtin \
 -ffreestanding \
 -nostdinc \
 -mno-unaligned-access \
 -fshort-wchar \
 -DOPENSSL_IMPLEMENTS_strncasecmp \
 -DOPENSSL_NO_SOCK \
 -DNO_SYSLOG \
 -DOPENSSL_NO_DEPRECATED \
 -DOPENSSL_NO_DGRAM \
 -DOPENSSL_NO_UI_CONSOLE \
 -DOPENSSL_NO_SOCK \
 -DOPENSSL_NO_HW \
 -DOPENSSL_NO_STDIO \
 -DNO_CHMOD \
 -DOPENSSL_NO_POSIX_IO \
 -DRAND_DRBG_GET_RANDOM_NONCE \
 -fPIC \
 -fPIE \
 -Os \
 -Werror \
 $(OPENSSL_FLAGS) \
 $(OPENSSL_EXFLAGS) \
```

#### Remapping Stdlib Functions
Note the `-fno-builtin` switch which disables the built-in library headers/implementations for standard functions. The expected header files are instead included in `/ossl/include/`. These headers do not implement any of these functions, they instead redirect the calls to an external implementation.

##### From /ossl/include/string.h:
```C
static inline char *strcat(char *dest, const char *src)
{
    extern char *sassl_strcat(char *dest, const char *src);
    return sassl_strcat(dest, src);
}
```

### Implementing the Remapped Functions
The remapped `sassl_*()` functions must be defined in the binary which the crypto library is to be linked with. In the case of the OP-TEE TAs `/ossl/optee_lib/optee_stdlib.c` implements the `sassl_*()` functions. If `optee_stdlib.c` is included as part of the TA then `libcrypto.a` should link successfully.

The implementations either directly map the calls to functions provided by OP-TEE, provide a basic implementation, or are stubbed out and generate an error. For example OP-TEE provides an implementation of `memcpy()` so it is sufficient to simply pass the call along. `strcasecmp()` is not currently implemented by OP-TEE so a basic implementation is provided here, and `closedir()` is not required for any of the TA code so it is stubbed out.
```C
// Remap:
void *sassl_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, n);
}
// Implement:
int sassl_strcasecmp(const char *s1, const char *s2) {
    size_t i = 0;
    for(i = 0; s1[i] && s2[i]; i++)
    {
        char delta = tolower(s1[i]) - tolower(s2[i]);
        if (delta != 0)
        {
            return delta;
        }
    }
    return 0;
}
// Stub:
int sassl_closedir(void *dirp) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}
```
#### Discovering Missing Implementations
Gcc will list all undefined references once libcrypto.a is linked into the final binary. To quickly get a list of `sassl_*()` functions which need to be added run:
```bash
make <your target here> | grep "undefined reference" | sed "s/.*\`//g" | sed "s/'.*//g" | sort | uniq
```
For each line, look up the corresponding function in the standard library and add the sassl_* version to the application's sassl .c file (`optee_stdlib.c` in this case):
```C
int sassl_MyUnimplementedFunction(int MyArgument) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}
```
Unfortunately, there is no way to determine if the function is required other than searching the OpenSSL codebase or comprehensive testing at runtime. In the above example an error message is printed to the serial port and the TA will panic if the function is called.

### OpenSSL Random Number Generation
OpenSSL uses a pseudo random number generation system called the Deterministic Random Bit Generator (DRBG). The DRBG is initialized once with a random seed and a nonce, then additional entropy is added as needed. The nonce is usually comprised of information provided by the OS which is not applicable here. Instead the `RAND_DRBG_GET_RANDOM_NONCE` flag is passed when OpenSSL is built which instead uses additional pure entropy to seed the generator.

This entropy is usually gathered via Linux system calls or other mechanisms (`/dev/random` etc), many of which are not available here. The `--with-rand-seed=getrandom` configuration option is used to have OpenSSL use the
```c
extern int getentropy(void *buffer, size_t length)
```
function which can be implemented by the application. In the case of OP-TEE:
```C
int getentropy(void *buffer, size_t length) {
    TEE_GenerateRandom(buffer, (uint32_t)length);
    return 0;
}
```
The DRBG attempts to add additional entropy by calling `gettimeofday()` when the pool runs low. OP-TEE can only provide time to the nearest millisecond, and additionally this is not a secure source of time. However, since `gettimeofday()` ideally returns times accurate to the nearest microsecond there are unused digits. To add better (and secure) entropy the OP-TEE implementation fills out the microsecond portion of the time with true hardware entropy.
