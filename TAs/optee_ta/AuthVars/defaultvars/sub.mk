CFG_DEFAULT_VARS_JSON ?= $(sub-dir)/defaultvars_example.json

DEFAULT_VARS_PATHS := $(shell find $(sub-dir) -name '*.bin')

srcs-y += defaultvars.c
global-incdirs-y += ./

# Make can have trouble tracking updates to binary files outside the tree.
# It is very fast to rebuild the encoding, so just do that every time.
.PHONY: always_rebuild_defaultvars

gensrcs-y += default_vars
produce-default_vars = defaultvars_encoding.c
depends-default_vars = always_rebuild_defaultvars
recipe-default_vars = python $(sub-dir)/defaultvars.py $(CFG_DEFAULT_VARS_JSON) $(sub-dir-out)/defaultvars_encoding.c
cleanfiles += $(sub-dir-out)/defaultvars_encoding.c