.PHONY: clone_wolf clone_tpm
clone_wolf: clone_tpm
	@echo Verifying WolfSSL repo is available.
	cd $(TPM_ROOT) && git submodule init && git submodule update

clone_tpm:
	@echo Verifying TPM repo is available.
	git submodule init && git submodule update

.PHONY: create_lib_symlinks
create_lib_symlinks: ./lib/tpm/tpm_symlink

.PHONY: clean_lib_symlinks
clean_lib_symlinks: remove_tpm_symlink

ifeq ($(CFG_FTPM_USE_WOLF),y)
subdirs-y += wolf
create_lib_symlinks: ./lib/wolf/wolf_symlink
clean_lib_symlinks: remove_wolf_symlink
else
subdirs-y += libssl
endif

subdirs-y += tpm
