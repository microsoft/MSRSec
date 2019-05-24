Firmware Trusted Platform Module (fTPM)
===========

This TPM implementation is based on the [TPM reference implementation](https://github.com/Microsoft/ms-tpm-20-ref) provided by Microsoft Research.

## Design

### Platform

The TPM reference implementation defines a platform API (`ms-tpm-20-ref/TPMCmd/Platform`) which can be swapped out depending on where the TPM code is running. In the case of the fTPM the OP-TEE API is used to implement this platform.

### Crypto

The reference implementation includes a cryptographic abstraction layer which currently supports LibTomCrypt, WolfSSL, and OpenSSL. LibTomCrypt does not support Pkcs7 which is required for the AuthVars TA, so only OpenSSL and WolfSSL are supported by this build system. The TPM relies on the external crypto libraries for bignum operations, but implements actual crypto algorithms internally. See repo [README.md](../../../README.md#3-crypto-options) for more details on selecting a crypto package.

### Endorsement Primary Seed (EPS)

The EPS is the root of trust for all TPM functions. The fTPM has two options for deriving an EPS. The first (and best) option is to request one from the OP-TEE kernel. The kernel implements a vendor property `"com.microsoft.ta.endorsementSeed"` which returns a hashed value derived from the unique hardware ID, the hardware die ID, and the UUID of the fTPM TA. This means that if the non-volatile storage on the device is reset the TPM will still re-derive the same EPS and existing certificates and connections will continue to work.

If this property is not available, the TPM will generate a random EPS and store it in non-volatile memory. In the event the memory is cleared the TPM will generate a new EPS. Any certificates or connections based on the endorsement certificate will no longer be valid.

#### Security Considerations

The UUID is not secret. The security of the EPS (and TA storage in general) relies on the key used to sign the TAs being kept secure. If the TPM binary is replaced with a malicious TA claiming the same UUID then the TPM's secure memory (containing its EPS among other things) can be leaked. This means that the TA signing key should be kept very secure, or destroyed, after use.

### Non-Volatile Storage

The TPM's memory is backed by the OP-TEE file system. See [OP-TEE's documentation](https://optee.readthedocs.io/architecture/secure_storage.html) for details. The memory is stored as a byte array spread across multiple blocks, each backed by a separate OP-TEE file.

This storage is currently encrypted by OP-TEE using a TA Storage Key (TSK) encryption key which is based on the device's unique hardware ID and the TPM's UUID.

## Debugging the fTPM

### Clearing Storage

During development of OP-TEE, if the key derivation functions change, the non-volatile memory will become inaccessible. OP-TEE offers a flag which clears RPMB storage on every boot which can be used to reset all TA storage. Recompile OP-TEE with `CFG_RPMB_RESET_FAT=y`. Note: This does not reset the RPMB key used to encrypt the backing storage, use `CFG_RPMB_TESTKEY=y` during development.

### Debug Output

Increase the debugging level using `CFG_TEE_TA_LOG_LEVEL=4` when compiling the TA. Additional development only debug information can be enabled by using `CFG_TA_DEBUG=y`. This option will dump buffers which may contain sensitive information, use only during development. This flag also turns on extra runtime and compile time checking.

### External Code Debugging

*WolfSSL* and *ms-tpm-20-ref* sources are compiled directly, so adding `#include <trace.h>` is sufficient to gain access to the full set of OP-TEE tracing functions (`DMSG(), etc`).

Since *OpenSSL* is compiled separately and then linked this will not work. The stdlib shim layer implements `sassl_print( char *c )`, a basic print command which can be added to the OpenSSL codebase if needed.
