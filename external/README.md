TA Libraries
============
This folder contains shared libraries used by the TAs. The OP-TEE build system does not work well with relative paths which go below the root directory for a TA (i.e. `~/repo_root/TAs/ta_root/lib/../../../../external/my_lib` => `~/repo_root/external/my_lib`). When building, the library files will be placed outside the expected build folder (i.e. `~/misc_dir/build_folder/out/lib/../../../../external` => `~/external/my_lib`).

Each TA may also need to utilize the library in a slightly different manner, so each TA needs a separate `sub.mk` file. To achieve this each library's `sub.mk` is responsible for either copying the required files locally, or setting up a symlink to the external folder.

## Using the Libraries
The following lines in the TA root `sub.mk` file make sure that the libraries are correctly setup before they are referenced.
```makefile
all: create_lib_symlinks
clean: clean_lib_symlinks
subdirs-y += lib
```
Inside `lib/sub.mk` each library is added depending on the needs of the TA.
```makefile
.PHONY: create_lib_symlinks clean_lib_symlinks
# You can start with empty targets if you have only optional libraries
create_lib_symlinks:
clean_lib_symlinks:

# This library just copies files
subdirs-y += copy_lib

# Always use this library:
subdirs-y += required_lib
create_lib_symlinks: ./lib/required_lib/required_lib_symlink
clean_lib_symlinks: remove_required_lib_symlink

# Optionally use another library
ifeq ($(CFG_MY_TA_USE_OPTIONAL),y)
subdirs-y += optional_lib
create_lib_symlinks: ./lib/optional_lib/optional_lib_symlink
clean_lib_symlinks: remove_optional_lib_symlink
endif

```
## Types of Libraries
### Symlinks
The `lib/my_lib/sub.mk` file should automatically create the symlinks when needed. Currently all libraries are backed by submodules which are also automatically initialized and downloaded if they are not already present.
```makefile
./lib/my_lib/my_lib_symlink: remove_my_lib_symlink download_my_lib
    ...

.PHONY: remove_my_lib_symlink
remove_my_lib_symlink:
    ...

.PHONY: download_my_lib
download_my_lib: $(MY_LIB_ROOT)/README

$(MY_LIB_ROOT)/README:
	( cd $(SUBMODULE_ROOT); git submodule update --init my_lib_repo)
```

### Copying Files
In some cases it is easier to just copy a few files as needed (ie OpenSSL's libcrypto.a and supporting files). In this case symlinks are not needed, instead the files are simply copied locally. The OpenSSL library calls the makefile in `external/ossl` to create a copy of `libcrypto.a` which is then copied locally. The OpenSSL makefile (see /external/ossl/README.md for details) configures and builds a custom libcrypto.a when called. The library makefile then copies over the required supporting files, headers, and libcrypto.a.
