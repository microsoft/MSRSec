UEFI Authenticated Variable Store
===========

This variable store implements section 8.2 of the [UEFI Spec 2.7](https://uefi.org/sites/default/files/resources/UEFI%20Spec%202_7_B.pdf).


## Design

### Crypto

The AuthVars TA relies on external crypto libraries for PKCS7 signing using either OpenSSL or WolfSSL. See repo [README.md](../../../README.md#3-crypto-options) for more details.

### Non-Volatile Storage

The AuthVars TA's memory is backed by the OP-TEE file system. See [OP-TEE's documentation](https://optee.readthedocs.io/architecture/secure_storage.html) for details. Each variable is stored as a seperate OP-TEE storage object.

When the TA is first loaded it enumerates and loads all of its existing variables into memory. OP-TEE's filesystem guarantees atomicity of I/O operations, which is a requirement of the UEFI spec.

This storage is currently encrypted by OP-TEE using a TA Storage Key (TSK) encryption key which is based on the device's unique hardware ID and the TPM's UUID.

### Authenticated Variables

The UEFI spec describes an authenticated variable store for use with Secure Boot. T

## Debugging AuthVars

### Clearing Storage

During development of OP-TEE, if the key derivation functions change, the non-volatile memory will become inaccessible. OP-TEE offers a flag which clears RPMB storage on every boot which can be used to reset all TA storage: `CFG_RPMB_RESET_FAT=y`. Note: This does not reset the RPMB key used to encrypt the backing storage, use `CFG_RPMB_TESTKEY=y` during development.

### Debug Output

Increase the debugging level using `CFG_TEE_TA_LOG_LEVEL=4` when compiling the TA. Additional development only debug information can be enabled by using `CFG_TA_DEBUG=y`. Turning this on will print information about each transaction which occurs. This option will significantly degrade performance.

### External Code Debuging

*WolfSSL* sources are compiled directly, so adding `#include <trace.h>` is sufficient to gain access to the full set of OP-TEE tracing functions (`DMSG(), etc`).

Since *OpenSSL* is compiled seperately and then linked this will not work. The stdlib shim layer implements `sassl_print( char *c )`, a basic print command which can be added to the OpenSSL codebase if needed.