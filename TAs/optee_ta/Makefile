
export V?=0

.PHONY: all fTPM authvars
all: fTPM authvars
fTPM:
#	$(MAKE) -C fTPM CROSS_COMPILE=$(TA_CROSS_COMPILE)
authvars:
	$(MAKE) -C AuthVars CROSS_COMPILE=$(TA_CROSS_COMPILE)

.PHONY: clean
clean:
#	$(MAKE) -C fTPM clean
	$(MAKE) -C AuthVars clean