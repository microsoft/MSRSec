.PHONY: create_lib_symlinks
create_lib_symlinks: ./lib/tpm/tpm_symlink

.PHONY: clean_lib_symlinks
clean_lib_symlinks: remove_tpm_symlink

ifeq ($(CFG_FTPM_USE_WOLF),y)
subdirs-y += wolf
create_lib_symlinks: ./lib/wolf/wolf_symlink
clean_lib_symlinks: remove_wolf_symlink
else
subdirs-y += ossl
endif

subdirs-y += tpm
