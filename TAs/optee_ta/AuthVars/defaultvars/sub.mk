DEFAULT_VARS_PATHS := $(shell find $(sub-dir) -name '*.bin')
DEFAULT_VARS_JSON ?= $(sub-dir)/default_vars.json
#DEFAULT_VAR_PATHS = $(foreach file,$(DEFAULT_VAR_BINS),$(sub-dir)/$(file))

srcs-y += default_vars.c
global-incdirs-y += ./

gensrcs-y += default_vars
produce-default_vars = default_vars_encoding.c
depends-default_vars = $(DEFAULT_VARS_PATHS) $(sub-dir)/default_vars.py $(DEFAULT_VARS_JSON)
recipe-default_vars = python3 $(sub-dir)default_vars.py $(DEFAULT_VARS_JSON) $(sub-dir-out)/default_vars_encoding.c
cleanfiles += $(sub-dir-out)/default_vars_encoding.c