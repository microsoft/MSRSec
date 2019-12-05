Microsoft Research Security TAs
===========
## Trusted firmware for 32-bit and 64-bit ARM SoC's

This repository contains [OP-TEE](https://github.com/OP-TEE/optee_os) Trusted Applications (TAs) which implement a firmware Trusted Platform Module (TPM), and a UEFI authenticated variable store.

## Further Reading

See [Authvars README.md](TAs/optee_ta/AuthVars/README.md) and [fTPM README.md](TAs/optee_ta/fTPM/README.md) for details about each TA.

See [External Libraries README.md](external/README.md) for details about how the external code is linked into the TAs.

See [IoT Core build-firmware.md](https://github.com/ms-iot/imx-iotcore/blob/public_preview/Documentation/build-firmware.md) for details on using these TAs in a full firmware stack.

# Crypto Options

Each TA can link against either OpenSSL or WolfSSL crypto libraries. 

## Stand Alone OpenSSL

OpenSSL is provided as the default crypto option. OpenSSL's `libcrypto.a` is compiled and statically linked with each TA. Work was required to stub out many standard library functions which the OP-TEE environment does not provide. See the [SASSL README.md](external/ossl/README.md) for details.

## WolfSSL

Please be aware of licensing considerations when using WolfSSL. To enable WolfSSL set the `CFG_AUTHVARS_USE_WOLF=y` and `CFG_FTPM_USE_WOLF=y` flags when building the TAs.

# Building

## Extra Installation Steps

The secure firmware utilizes the OP-TEE implementation of the Global Platform specifications. The OP-TEE project is
not duplicated in this repository but is obtained directly from the public release (however some features of the fTPM will only work with the Microsoft [fork of OP-TEE](https://github.com/ms-iot/optee_os)).

OP-TEE builds natively on Linux, however the following installation steps allow OP-TEE to be built under Windows using the Windows Subsystem for Linux (WSL). Only the optee_os repository is relevant for building the trusted firmware - the optee_client & optee_linuxdriver repositories are integration components for Linux and can serve as a reference for the Windows equivalent components. Note that optee_linuxdriver is GPL.

OP-TEE generates a build environment for trusted applications which is based on Make (See TA_DEV_KIT_DIR in the build directions).
This build environment places several constraints on how the code is organized, which are explained in the relevant makefiles, and in the [external library README.md](external/README.md). See the [optee_os documentation](https://optee.readthedocs.io/building/index.html) for details about how OP-TEE build works.

#### 1. Enable Windows Subsystem for Linux if needed
See instructions [here](https://docs.microsoft.com/en-us/windows/wsl/install-win10).

The build has also been validated on Ubuntu 16.04.

#### 2. Launch Bash
Search for "bash" in the start menu, OR press Windows key + 'R', then type bash.  
Update if needed.

In WSL:
```sh
sudo apt-get update
```

#### 3. Install the ARM tool chain
Install the ARM toolchain to a directory of your choice.
```sh
cd ~
wget https://releases.linaro.org/components/toolchain/binaries/6.4-2017.11/arm-linux-gnueabihf/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz
tar xf gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz
rm gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz
```

#### 4. Clone the OP-TEE source code
If you do not already have a version of the OP-TEE OS repo cloned on your machine you may run:
```sh
cd ~
git clone https://github.com/ms-iot/optee_os.git
```
Additional information on the Microsoft IoT fork of OP-TEE OS can be found [here](https://github.com/ms-iot/optee_os).

#### 5. Build OP-TEE OS for the target platform

`CROSS_COMPILE` should point to the ARM toolchain installed in [step 3](#3-install-the-arm-tool-chain).

```sh
cd ~/optee_os
CROSS_COMPILE=~/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf- make PLATFORM=imx-mx6qhmbedge CFG_TEE_CORE_LOG_LEVEL=4 CFG_REE_FS=n CFG_RPMB_FS=y CFG_RPMB_TESTKEY=y CFG_RPMB_WRITE_KEY=y -j20
```

#### 6. Clone the MSRSec source code
```sh
cd ~
git clone https://github.com/Microsoft/MSRSec.git
```

#### 7. (Optional) Initialize the git submodules
The build system will determine which submodules are required at build time, but you can manually download them now. This will download the MSR TPM reference implementation, OpenSSL, and WolfSSL.
```sh
cd ~/MSRSec
git submodule update --init
```

---

## Building the TAs

`TA_CROSS_COMPILE` should point to the ARM toolchain installed in [step 3](#3-install-the-arm-tool-chain).

`TA_DEV_KIT_DIR` should point to the directory the optee_os TA devkit was compiled to in [step 5](#5-build-op-tee-os-for-the-target-platform).

`-j` increases the parallelism of the build process.

```sh
cd ~/MSRSec/TAs/optee_ta
TA_CPU=cortex-a9 TA_CROSS_COMPILE=~/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf- TA_DEV_KIT_DIR=~/optee_os/out/arm-plat-imx/export-ta_arm32 CFG_TEE_TA_LOG_LEVEL=2 make -j20
```
Debugging options you may want to add:

`CFG_TEE_TA_LOG_LEVEL=3` 1 is fatal errors only, other values increase debug tracing output.

`CFG_TA_DEBUG=y` Turns on debug output from the TAs, and enables extra correctness checks in the fTPM TA.

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
