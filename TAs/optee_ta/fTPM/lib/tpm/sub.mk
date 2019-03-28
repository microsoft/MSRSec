ifeq ($(CFG_TA_DEBUG),y)
FTPM_FLAGS += $(FTPM_DEBUG)
else
FTPM_FLAGS += $(FTPM_RELEASE)
endif

#
# For the purposes of this command the current working directory is the makefile root (/fTPM) folder,
# but the symlink will be created relative to THIS directory so the source requires an extra '../../'.
#
# Symlinks are needed since all build output is placed relative to the root. External libraries would result in
# binaries located outside the ouptut folder.
#
./lib/tpm/tpm_symlink: remove_tpm_symlink download_tpm
	@echo Checking symlink to the TPM folder: $(abspath $(TPM_ROOT))
	@if [ -L ./lib/tpm/tpm_symlink ] ; \
	then \
	echo Symlink already established ; \
	else \
	echo Establishing symlink. ; \
	ln -s ../../$(TPM_ROOT) ./lib/tpm/tpm_symlink; \
	fi

.PHONY: remove_tpm_symlink
remove_tpm_symlink:
	@echo Clearing symlink to the TPM folder: $(abspath $(TPM_ROOT))
	unlink ./lib/tpm/tpm_symlink || true

.PHONY: download_tpm
download_tpm: $(TPM_ROOT)/README.md

$(TPM_ROOT)/README.md:
	( cd $(SUBMODULE_ROOT); git submodule update --init ms-tpm-20-ref)

TPM_INCLUDES = \
 tpm_symlink/tpm/include \
 tpm_symlink/tpm/include/ltc \
 tpm_symlink/tpm/include/prototypes \

ifeq ($(CFG_FTPM_USE_WOLF),y)
global-incdirs-y += tpm_symlink/tpm/include/wolf
else
# Don't bother with tpm_symlink/OsslInclude/ as listed in ms-tpm-20-ref readme,
# just map in the OSSL folders directly (see OSSL lib directory)
endif

#
# Generated in WSL using:
# pushd ms-tpm-20-ref/TPMCmd/tpm/src/; find -name *.c | while read line; do echo XXXX$line \\; done | sed -e 's#XXXX.\/# tpm_symlink/tpm/src/#g'; popd
# This may need to be updated if there are any changes to the reference implementation.
#

TPM_SOURCES = \
 tpm_symlink/tpm/src/command/Asymmetric/ECC_Parameters.c \
 tpm_symlink/tpm/src/command/Asymmetric/ECDH_KeyGen.c \
 tpm_symlink/tpm/src/command/Asymmetric/ECDH_ZGen.c \
 tpm_symlink/tpm/src/command/Asymmetric/EC_Ephemeral.c \
 tpm_symlink/tpm/src/command/Asymmetric/RSA_Decrypt.c \
 tpm_symlink/tpm/src/command/Asymmetric/RSA_Encrypt.c \
 tpm_symlink/tpm/src/command/Asymmetric/ZGen_2Phase.c \
 tpm_symlink/tpm/src/command/AttachedComponent/AC_GetCapability.c \
 tpm_symlink/tpm/src/command/AttachedComponent/AC_Send.c \
 tpm_symlink/tpm/src/command/AttachedComponent/AC_spt.c \
 tpm_symlink/tpm/src/command/AttachedComponent/Policy_AC_SendSelect.c \
 tpm_symlink/tpm/src/command/Attestation/Attest_spt.c \
 tpm_symlink/tpm/src/command/Attestation/Certify.c \
 tpm_symlink/tpm/src/command/Attestation/CertifyCreation.c \
 tpm_symlink/tpm/src/command/Attestation/CertifyX509.c \
 tpm_symlink/tpm/src/command/Attestation/GetCommandAuditDigest.c \
 tpm_symlink/tpm/src/command/Attestation/GetSessionAuditDigest.c \
 tpm_symlink/tpm/src/command/Attestation/GetTime.c \
 tpm_symlink/tpm/src/command/Attestation/Quote.c \
 tpm_symlink/tpm/src/command/Capability/GetCapability.c \
 tpm_symlink/tpm/src/command/Capability/TestParms.c \
 tpm_symlink/tpm/src/command/ClockTimer/ClockRateAdjust.c \
 tpm_symlink/tpm/src/command/ClockTimer/ClockSet.c \
 tpm_symlink/tpm/src/command/ClockTimer/ReadClock.c \
 tpm_symlink/tpm/src/command/CommandAudit/SetCommandCodeAuditStatus.c \
 tpm_symlink/tpm/src/command/Context/ContextLoad.c \
 tpm_symlink/tpm/src/command/Context/ContextSave.c \
 tpm_symlink/tpm/src/command/Context/Context_spt.c \
 tpm_symlink/tpm/src/command/Context/EvictControl.c \
 tpm_symlink/tpm/src/command/Context/FlushContext.c \
 tpm_symlink/tpm/src/command/DA/DictionaryAttackLockReset.c \
 tpm_symlink/tpm/src/command/DA/DictionaryAttackParameters.c \
 tpm_symlink/tpm/src/command/Duplication/Duplicate.c \
 tpm_symlink/tpm/src/command/Duplication/Import.c \
 tpm_symlink/tpm/src/command/Duplication/Rewrap.c \
 tpm_symlink/tpm/src/command/EA/PolicyAuthorize.c \
 tpm_symlink/tpm/src/command/EA/PolicyAuthorizeNV.c \
 tpm_symlink/tpm/src/command/EA/PolicyAuthValue.c \
 tpm_symlink/tpm/src/command/EA/PolicyCommandCode.c \
 tpm_symlink/tpm/src/command/EA/PolicyCounterTimer.c \
 tpm_symlink/tpm/src/command/EA/PolicyCpHash.c \
 tpm_symlink/tpm/src/command/EA/PolicyDuplicationSelect.c \
 tpm_symlink/tpm/src/command/EA/PolicyGetDigest.c \
 tpm_symlink/tpm/src/command/EA/PolicyLocality.c \
 tpm_symlink/tpm/src/command/EA/PolicyNameHash.c \
 tpm_symlink/tpm/src/command/EA/PolicyNV.c \
 tpm_symlink/tpm/src/command/EA/PolicyNvWritten.c \
 tpm_symlink/tpm/src/command/EA/PolicyOR.c \
 tpm_symlink/tpm/src/command/EA/PolicyPassword.c \
 tpm_symlink/tpm/src/command/EA/PolicyPCR.c \
 tpm_symlink/tpm/src/command/EA/PolicyPhysicalPresence.c \
 tpm_symlink/tpm/src/command/EA/PolicySecret.c \
 tpm_symlink/tpm/src/command/EA/PolicySigned.c \
 tpm_symlink/tpm/src/command/EA/PolicyTemplate.c \
 tpm_symlink/tpm/src/command/EA/PolicyTicket.c \
 tpm_symlink/tpm/src/command/EA/Policy_spt.c \
 tpm_symlink/tpm/src/command/Ecdaa/Commit.c \
 tpm_symlink/tpm/src/command/FieldUpgrade/FieldUpgradeData.c \
 tpm_symlink/tpm/src/command/FieldUpgrade/FieldUpgradeStart.c \
 tpm_symlink/tpm/src/command/FieldUpgrade/FirmwareRead.c \
 tpm_symlink/tpm/src/command/HashHMAC/EventSequenceComplete.c \
 tpm_symlink/tpm/src/command/HashHMAC/HashSequenceStart.c \
 tpm_symlink/tpm/src/command/HashHMAC/HMAC_Start.c \
 tpm_symlink/tpm/src/command/HashHMAC/MAC_Start.c \
 tpm_symlink/tpm/src/command/HashHMAC/SequenceComplete.c \
 tpm_symlink/tpm/src/command/HashHMAC/SequenceUpdate.c \
 tpm_symlink/tpm/src/command/Hierarchy/ChangeEPS.c \
 tpm_symlink/tpm/src/command/Hierarchy/ChangePPS.c \
 tpm_symlink/tpm/src/command/Hierarchy/Clear.c \
 tpm_symlink/tpm/src/command/Hierarchy/ClearControl.c \
 tpm_symlink/tpm/src/command/Hierarchy/CreatePrimary.c \
 tpm_symlink/tpm/src/command/Hierarchy/HierarchyChangeAuth.c \
 tpm_symlink/tpm/src/command/Hierarchy/HierarchyControl.c \
 tpm_symlink/tpm/src/command/Hierarchy/SetPrimaryPolicy.c \
 tpm_symlink/tpm/src/command/Misc/PP_Commands.c \
 tpm_symlink/tpm/src/command/Misc/SetAlgorithmSet.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_Certify.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_ChangeAuth.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_DefineSpace.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_Extend.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_GlobalWriteLock.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_Increment.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_Read.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_ReadLock.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_ReadPublic.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_SetBits.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_spt.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_UndefineSpace.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_UndefineSpaceSpecial.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_Write.c \
 tpm_symlink/tpm/src/command/NVStorage/NV_WriteLock.c \
 tpm_symlink/tpm/src/command/Object/ActivateCredential.c \
 tpm_symlink/tpm/src/command/Object/Create.c \
 tpm_symlink/tpm/src/command/Object/CreateLoaded.c \
 tpm_symlink/tpm/src/command/Object/Load.c \
 tpm_symlink/tpm/src/command/Object/LoadExternal.c \
 tpm_symlink/tpm/src/command/Object/MakeCredential.c \
 tpm_symlink/tpm/src/command/Object/ObjectChangeAuth.c \
 tpm_symlink/tpm/src/command/Object/Object_spt.c \
 tpm_symlink/tpm/src/command/Object/ReadPublic.c \
 tpm_symlink/tpm/src/command/Object/Unseal.c \
 tpm_symlink/tpm/src/command/PCR/PCR_Allocate.c \
 tpm_symlink/tpm/src/command/PCR/PCR_Event.c \
 tpm_symlink/tpm/src/command/PCR/PCR_Extend.c \
 tpm_symlink/tpm/src/command/PCR/PCR_Read.c \
 tpm_symlink/tpm/src/command/PCR/PCR_Reset.c \
 tpm_symlink/tpm/src/command/PCR/PCR_SetAuthPolicy.c \
 tpm_symlink/tpm/src/command/PCR/PCR_SetAuthValue.c \
 tpm_symlink/tpm/src/command/Random/GetRandom.c \
 tpm_symlink/tpm/src/command/Random/StirRandom.c \
 tpm_symlink/tpm/src/command/Session/PolicyRestart.c \
 tpm_symlink/tpm/src/command/Session/StartAuthSession.c \
 tpm_symlink/tpm/src/command/Signature/Sign.c \
 tpm_symlink/tpm/src/command/Signature/VerifySignature.c \
 tpm_symlink/tpm/src/command/Startup/Shutdown.c \
 tpm_symlink/tpm/src/command/Startup/Startup.c \
 tpm_symlink/tpm/src/command/Symmetric/EncryptDecrypt.c \
 tpm_symlink/tpm/src/command/Symmetric/EncryptDecrypt2.c \
 tpm_symlink/tpm/src/command/Symmetric/EncryptDecrypt_spt.c \
 tpm_symlink/tpm/src/command/Symmetric/Hash.c \
 tpm_symlink/tpm/src/command/Symmetric/HMAC.c \
 tpm_symlink/tpm/src/command/Symmetric/MAC.c \
 tpm_symlink/tpm/src/command/Testing/GetTestResult.c \
 tpm_symlink/tpm/src/command/Testing/IncrementalSelfTest.c \
 tpm_symlink/tpm/src/command/Testing/SelfTest.c \
 tpm_symlink/tpm/src/command/Vendor/Vendor_TCG_Test.c \
 tpm_symlink/tpm/src/crypt/AlgorithmTests.c \
 tpm_symlink/tpm/src/crypt/BnConvert.c \
 tpm_symlink/tpm/src/crypt/BnMath.c \
 tpm_symlink/tpm/src/crypt/BnMemory.c \
 tpm_symlink/tpm/src/crypt/CryptCmac.c \
 tpm_symlink/tpm/src/crypt/CryptDes.c \
 tpm_symlink/tpm/src/crypt/CryptEccData.c \
 tpm_symlink/tpm/src/crypt/CryptEccKeyExchange.c \
 tpm_symlink/tpm/src/crypt/CryptEccMain.c \
 tpm_symlink/tpm/src/crypt/CryptEccSignature.c \
 tpm_symlink/tpm/src/crypt/CryptHash.c \
 tpm_symlink/tpm/src/crypt/CryptPrime.c \
 tpm_symlink/tpm/src/crypt/CryptPrimeSieve.c \
 tpm_symlink/tpm/src/crypt/CryptRand.c \
 tpm_symlink/tpm/src/crypt/CryptRsa.c \
 tpm_symlink/tpm/src/crypt/CryptSelfTest.c \
 tpm_symlink/tpm/src/crypt/CryptSmac.c \
 tpm_symlink/tpm/src/crypt/CryptSym.c \
 tpm_symlink/tpm/src/crypt/CryptUtil.c \
 tpm_symlink/tpm/src/crypt/ltc/TpmToLtcDesSupport.c \
 tpm_symlink/tpm/src/crypt/ltc/TpmToLtcMath.c \
 tpm_symlink/tpm/src/crypt/ltc/TpmToLtcSupport.c \
 tpm_symlink/tpm/src/crypt/ossl/TpmToOsslDesSupport.c \
 tpm_symlink/tpm/src/crypt/ossl/TpmToOsslMath.c \
 tpm_symlink/tpm/src/crypt/ossl/TpmToOsslSupport.c \
 tpm_symlink/tpm/src/crypt/PrimeData.c \
 tpm_symlink/tpm/src/crypt/RsaKeyCache.c \
 tpm_symlink/tpm/src/crypt/Ticket.c \
 tpm_symlink/tpm/src/crypt/wolf/TpmToWolfDesSupport.c \
 tpm_symlink/tpm/src/crypt/wolf/TpmToWolfMath.c \
 tpm_symlink/tpm/src/crypt/wolf/TpmToWolfSupport.c \
 tpm_symlink/tpm/src/events/_TPM_Hash_Data.c \
 tpm_symlink/tpm/src/events/_TPM_Hash_End.c \
 tpm_symlink/tpm/src/events/_TPM_Hash_Start.c \
 tpm_symlink/tpm/src/events/_TPM_Init.c \
 tpm_symlink/tpm/src/main/CommandDispatcher.c \
 tpm_symlink/tpm/src/main/ExecCommand.c \
 tpm_symlink/tpm/src/main/SessionProcess.c \
 tpm_symlink/tpm/src/subsystem/CommandAudit.c \
 tpm_symlink/tpm/src/subsystem/DA.c \
 tpm_symlink/tpm/src/subsystem/Hierarchy.c \
 tpm_symlink/tpm/src/subsystem/NvDynamic.c \
 tpm_symlink/tpm/src/subsystem/NvReserved.c \
 tpm_symlink/tpm/src/subsystem/Object.c \
 tpm_symlink/tpm/src/subsystem/PCR.c \
 tpm_symlink/tpm/src/subsystem/PP.c \
 tpm_symlink/tpm/src/subsystem/Session.c \
 tpm_symlink/tpm/src/subsystem/Time.c \
 tpm_symlink/tpm/src/support/AlgorithmCap.c \
 tpm_symlink/tpm/src/support/Bits.c \
 tpm_symlink/tpm/src/support/CommandCodeAttributes.c \
 tpm_symlink/tpm/src/support/Entity.c \
 tpm_symlink/tpm/src/support/Global.c \
 tpm_symlink/tpm/src/support/Handle.c \
 tpm_symlink/tpm/src/support/IoBuffers.c \
 tpm_symlink/tpm/src/support/Locality.c \
 tpm_symlink/tpm/src/support/Manufacture.c \
 tpm_symlink/tpm/src/support/Marshal.c \
 tpm_symlink/tpm/src/support/MathOnByteBuffers.c \
 tpm_symlink/tpm/src/support/Memory.c \
 tpm_symlink/tpm/src/support/Power.c \
 tpm_symlink/tpm/src/support/PropertyCap.c \
 tpm_symlink/tpm/src/support/Response.c \
 tpm_symlink/tpm/src/support/ResponseCodeProcessing.c \
 tpm_symlink/tpm/src/support/TpmFail.c \
 tpm_symlink/tpm/src/support/TpmSizeChecks.c \
 tpm_symlink/tpm/src/X509/TpmASN1.c \
 tpm_symlink/tpm/src/X509/X509_ECC.c \
 tpm_symlink/tpm/src/X509/X509_RSA.c \
 tpm_symlink/tpm/src/X509/X509_spt.c \

ifeq ($(CFG_FTPM_USE_WOLF),y)
 TPM_ACTIVE_SOURCES = $(filter-out tpm_symlink/tpm/src/crypt/wolf/TpmToOssl%,$(TPM_SOURCES))
else
 TPM_ACTIVE_SOURCES = $(filter-out tpm_symlink/tpm/src/crypt/wolf/TpmToWolf%,$(TPM_SOURCES))
endif

srcs-y = $(foreach tpmfile, $(TPM_ACTIVE_SOURCES), $(tpmfile) )
$(foreach tpmfile, $(TPM_ACTIVE_SOURCES), $(eval  cflags-$(tpmfile)-y += $(FTPM_FLAGS) $(WOLF_SSL_FLAGS) $(INCLUDE_OVERWRITES) $(FTPM_WARNING_SUPPRESS)))
$(foreach tpmfile, $(TPM_ACTIVE_SOURCES), $(eval  incdirs-$(tpmfile)-y += $(TPM_INCLUDES) $(OSSL_INCLUDES)))
