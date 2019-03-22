.PHONY: create_lib_symlinks
create_lib_symlinks: ./lib/wolf/wolf_symlink

.PHONY: clean_lib_symlinks
clean_lib_symlinks: remove_wolf_symlink

subdirs-y += wolf