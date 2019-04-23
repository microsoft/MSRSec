
export V?=0

.PHONY: all ftpm authvars
all: ftpm authvars
ftpm:
	$(MAKE) -C fTPM CROSS_COMPILE=$(TA_CROSS_COMPILE)
authvars:
	$(MAKE) -C AuthVars CROSS_COMPILE=$(TA_CROSS_COMPILE)

.PHONY: clean
clean:
	$(MAKE) -C fTPM clean
	$(MAKE) -C AuthVars clean
