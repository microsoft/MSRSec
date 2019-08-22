DEFAULT_VARS_PATHS := $(shell find $(sub-dir) -name '*.bin')
DEFAULT_VARS_JSON ?= $(sub-dir)/defaultvars_example.json

srcs-y += defaultvars.c
global-incdirs-y += ./

gensrcs-y += default_vars
produce-default_vars = defaultvars_encoding.c
depends-default_vars = $(DEFAULT_VARS_PATHS) $(sub-dir)/defaultvars.py $(DEFAULT_VARS_JSON)
recipe-default_vars = python3 $(sub-dir)/defaultvars.py $(DEFAULT_VARS_JSON) $(sub-dir-out)/defaultvars_encoding.c
cleanfiles += $(sub-dir-out)/defaultvars_encoding.c