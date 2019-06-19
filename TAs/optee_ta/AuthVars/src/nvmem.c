/*  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <nvmem.h>

//
// Globals to track storage usage
//
UINT32                          s_VolatileSize = 0;
UINT32                          s_NonVolatileSize = 0;

UINT64                          VersionObjectID = 0;
AUTHVAR_META                    VarList[MAX_AUTHVAR_ENTRIES] = { 0 };
USHORT                          NextFreeIdx = 0;

//
// Auth Var storage (de-)init functions
//
TEE_Result
AuthVarValidateVersion(
    VOID
)
/*++

    Routine Description:

        Attempt to load the TA's versioning information object and validate that the current version
        is supported.

    Arguments:

        None

    Returns:

        TEE_Result

--*/
{
    
    UINT64 qHash[TEE_DIGEST_QWORDS];
    TEE_OperationHandle opHandle = TEE_HANDLE_NULL;
    TEE_ObjectHandle objHandle = TEE_HANDLE_NULL;
    TEE_ObjectEnumHandle enumHandle = TEE_HANDLE_NULL;
    UINT32 hashLength, dataSize;
    TEE_Result status;
    CHAR versioningName[] = "Authvar Versioning Information";
    AUTHVAR_VERSIONING versionInformation = {0};

    // Calculate the version object's ID, if we haven't already.
    if(VersionObjectID == 0)
    {
        // Init for hash operation
        opHandle = TEE_HANDLE_NULL;
        hashLength = TEE_SHA256_HASH_SIZE;

        // Generate a unique ObjectID for this object based.
        status = TEE_AllocateOperation(&opHandle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
        if (status != TEE_SUCCESS)
        {
            DMSG("Failed to allocate digest operation");
            goto Cleanup;
        }

        status = TEE_DigestDoFinal(opHandle, versioningName, sizeof(versioningName), (PVOID)qHash, &hashLength);
        if (status != TEE_SUCCESS)
        {
            DMSG("Failed to finalize digest operation");
            goto Cleanup;
        }

        // Assumes TEE_OBJECT_ID_MAX_LEN == 64!
        VersionObjectID = qHash[0];
    }

    status = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                        &(VersionObjectID),
                                        sizeof(VersionObjectID),
                                        TA_STORAGE_FLAGS,
                                        &objHandle);
    if (status == TEE_ERROR_ITEM_NOT_FOUND)
    {
        // This is fine if the TA is un-initialized, verify there are no other storage objects
        DMSG("No Authvars version object found");
        status = TEE_AllocatePersistentObjectEnumerator(&enumHandle);
        if (status != TEE_SUCCESS)
        {
            EMSG("Enumerator failed");
            goto Cleanup;
        }
        status = TEE_StartPersistentObjectEnumerator(enumHandle, TEE_STORAGE_PRIVATE);

        if (status != TEE_ERROR_ITEM_NOT_FOUND)
        {
            // The only valid return result is TEE_ERROR_ITEM_NOT_FOUND
            status = TEE_ERROR_BAD_STATE;
        }

        // Return TEE_ERROR_ITEM_NOT_FOUND so a new versioning object is created.
        goto Cleanup;
    }
    else if (status != TEE_SUCCESS)
    {
        EMSG("Failed to open version object (0x%x)", status);
        goto Cleanup;
    }

    // Validate an existing versioning object.
    status = TEE_ReadObjectData(objHandle,
                                (PVOID)&versionInformation,
                                sizeof(versionInformation),
                                &dataSize);
    if (status != TEE_SUCCESS)
    {
        EMSG("Failed to read version object (0x%x)", status);
        goto Cleanup;
    }

    if (dataSize < sizeof(versionInformation) || 
        versionInformation.Magic != AUTHVARS_MAGIC)
    {
        EMSG("Versioning information for Authvars TA is invalid");
        EMSG("Data size = 0x%x, expected = 0x%x", dataSize, sizeof(versionInformation));
        EMSG("Magic: 0x%x, expected: 0x%x", versionInformation.Magic, AUTHVARS_MAGIC);
        status = TEE_ERROR_CORRUPT_OBJECT;
        goto Cleanup;
    }

    if (versionInformation.MajorVersion != AUTHVARS_NV_MAJOR_VERSION ||
        versionInformation.MinorVersion != AUTHVARS_NV_MINOR_VERSION)
    {
        EMSG("Authvars TA is incompatible with this version");
        EMSG("TA version %d.%d attempting to load data version %d.%d",
                AUTHVARS_NV_MAJOR_VERSION,AUTHVARS_NV_MINOR_VERSION,
                versionInformation.MajorVersion, versionInformation.MinorVersion);
        status = TEE_ERROR_NOT_SUPPORTED;
        goto Cleanup;
    }

    // Success, return
    status = TEE_SUCCESS;

Cleanup:
    if(IS_VALID(objHandle))
    {
        TEE_CloseObject(objHandle);
    }

    if(IS_VALID(opHandle))
    {
        TEE_FreeOperation(opHandle);
    }

    if(IS_VALID(enumHandle))
    {
        TEE_FreePersistentObjectEnumerator(enumHandle);
    }

    return status;
}

TEE_Result
AuthVarStoreVersion(
    VOID
)
/*++

    Routine Description:

        Generate a new versioning information object and store it.

    Arguments:

        None

    Returns:

        TEE_Result

--*/
{
    TEE_Result status;
    TEE_ObjectHandle objHandle = TEE_HANDLE_NULL;
    AUTHVAR_VERSIONING versionInformation = {0};

    versionInformation.Magic = AUTHVARS_MAGIC;
    versionInformation.MajorVersion = AUTHVARS_NV_MAJOR_VERSION;
    versionInformation.MinorVersion = AUTHVARS_NV_MINOR_VERSION - 1;

    IMSG("Storing Authvars versioning information");
    IMSG("TA version: %d.%d",
        AUTHVARS_NV_MAJOR_VERSION,AUTHVARS_NV_MINOR_VERSION);

    if (VersionObjectID == 0 )
    {
        EMSG("Attempted to access uninitialized Authvars version information");
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // Attempt to create an object to store the version information
    status = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                        (PVOID)&VersionObjectID,
                                        sizeof(VersionObjectID),
                                        TA_STORAGE_FLAGS, NULL,
                                        (PVOID)&versionInformation, sizeof(versionInformation),
                                        &objHandle);
    // Successful creation?
    if (status != TEE_SUCCESS)
    {
        // Other unexpected error
        EMSG("Failed to create versioning object with error 0x%x", status);
        goto Cleanup;
    }

    // Write out this variable
    status = TEE_WriteObjectData(objHandle, (PVOID)&versionInformation, sizeof(versionInformation));
    if (status != TEE_SUCCESS)
    {
        EMSG("Failed to write object 0x%x", status);
        goto Cleanup;
    }

    // Success, return
    status = TEE_SUCCESS;

Cleanup:
    if(IS_VALID(objHandle))
    {
        TEE_CloseObject(objHandle);
    }
    return status;
}

TEE_Result
WipeMemory(
    VOID
)
/*++

    Routine Description:

        Clears all persistent objects

    Arguments:

        None

    Returns:

        TEE_SUCCESS if the memory was successfully wiped.


--*/
{
    TEE_Result              status;
    TEE_ObjectInfo          objInfo;
    TEE_ObjectHandle        objHandle;
    TEE_ObjectEnumHandle    enumHandle = TEE_HANDLE_NULL;
    UINT64                  objID;
    UINT32                  objIDLen;
    VARTYPE                 varType;
    UINT32                  i;

    EMSG("Wiping Authvars memory!");
    
    status = TEE_AllocatePersistentObjectEnumerator(&enumHandle);
    if (status != TEE_SUCCESS)
    {
        EMSG("Failed to create enumerator: 0x%x", status);
        goto Cleanup;
    }

    do
    {
        // It is possible deleting objects will break the current enumerator, restart it each time.
        DMSG("Starting enumerator");
        status = TEE_StartPersistentObjectEnumerator(enumHandle, TEE_STORAGE_PRIVATE);
        if (status == TEE_ERROR_ITEM_NOT_FOUND)
        {
            break;
        }
        if (status != TEE_SUCCESS)
        {
            EMSG("Authvars storage wipe failed 0x%x", status);
            goto Cleanup;
        }

        status = TEE_GetNextPersistentObject(enumHandle,
                                    &objInfo,
                                    &objID,
                                    &objIDLen);
        if (status != TEE_SUCCESS)
        {
            EMSG("Authvars storage wipe failed to get next object");
            goto Cleanup;
        }

        status =  TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                    &objID,
                                    objIDLen,
                                    TA_STORAGE_FLAGS,
                                    &objHandle);

        if (status != TEE_SUCCESS)
        {
            EMSG("Authvars storage wipe failed to open object for deletion");
            goto Cleanup;
        }

        DMSG("Deleting object");
        TEE_CloseAndDeletePersistentObject1(objHandle);
        objHandle = TEE_HANDLE_NULL;

        //TEE_ResetPersistentObjectEnumerator(enumHandle);

    } while( status == TEE_SUCCESS );

    if (status == TEE_ERROR_ITEM_NOT_FOUND)
    {
        // This is the expected result, once the enumerator is done.
        status = TEE_SUCCESS;
    }

    // In the event are recovering from a corrupted variable object we will
    // need to clear out any previous variables which are cached in memory.
    for (i = 0; i < MAX_AUTHVAR_ENTRIES; i++)
    {
        if (VarList[i].Var != NULL)
        {
            DMSG("Clearing stored variable");
            TEE_Free(VarList[i].Var);
            memset(&(VarList[i]), 0, sizeof(AUTHVAR_META));
        }
    }

    // Reset the lists.
    for (varType = 0; varType < VTYPE_END; varType++)
    {
        InitializeListHead(&VarInfo[varType].Head);
    }

Cleanup:
    if(IS_VALID(enumHandle))
    {
        TEE_FreePersistentObjectEnumerator(enumHandle);
    }

    if (status != TEE_SUCCESS)
    {
        EMSG("Failed to reset Authvars storage 0x%x", status);
        return status;
    }
    
    return status;
}

VOID
RecoverStorage(
    TEE_Result versioningStatus
)
/*++

    Routine Description:

        Decides which options should be attempted to recover memory.

    Arguments:

        None

    Returns:

        VOID

--*/
{
#ifdef AUTHVAR_DEBUG
    EMSG("Authvars has detected its storage is invalid, run OP-TEE with CFG_RPMB_FAT_RESET=y to clear.");
#endif
#ifdef AUTHVARS_UPGRADE_MEMORY
    if (versioningStatus = TEE_ERROR_NOT_SUPPORTED) {
        EMSG("Version upgrade not supported");
        TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
    }
#else
#endif
#ifdef AUTHVARS_WIPE_MEMORY_ON_CORRUPTION
    if (WipeMemory() == TEE_SUCCESS)
    {
        return;
    }
#endif
    EMSG("Authvars: Failed to recover storage.");
    TEE_Panic(TEE_ERROR_SECURITY);
}

TEE_Result
AuthVarInitStorage(
    VOID
)
/*++

    Routine Description:

        Gather persistent objects (i.e., variables) from storage

    Arguments:

        None

    Returns:

    TEE_Result

--*/
{
    TEE_ObjectInfo  objInfo;
    TEE_ObjectEnumHandle enumHandle = TEE_HANDLE_NULL;
    PUEFI_VARIABLE  pVar;
    PWCHAR          name;
    PCGUID          guid;
    ATTRIBUTES      attrib;
    UINT32          size;
    UINT32          objIDLen;
    VARTYPE         varType;
    TEE_Result      status;
    USHORT          i;
    TEE_Result      versioningStatus;

    // Initialize variable lists
    for(varType = 0; varType < VTYPE_END; varType++ )
    {
        DMSG("Initializing list %d", varType);
        InitializeListHead(&VarInfo[varType].Head);
    }

    // Check for versioning information
    versioningStatus = AuthVarValidateVersion();

    // Check for validation failures. TEE_ERROR_ITEM_NOT_FOUND means we have empty
    // storage which needs to be initialzied, handle during cleanup.
    if ((versioningStatus != TEE_SUCCESS) &&
        (versioningStatus != TEE_ERROR_ITEM_NOT_FOUND))
    {
        EMSG("Versioning check failed!");
        status = TEE_ERROR_BAD_STATE;
        goto Cleanup;
    }

    // Allocate object enumerator
    status = TEE_AllocatePersistentObjectEnumerator(&enumHandle);
    if (status != TEE_SUCCESS)
    {
        DMSG("Failed to create enumerator: 0x%x", status);
        goto Cleanup;
    }

    // Start object enumerator
    status = TEE_StartPersistentObjectEnumerator(enumHandle, TEE_STORAGE_PRIVATE);
    if (status != TEE_SUCCESS)
    {
        DMSG("Failed to start enumerator: 0x%x", status);
        // On first run there will be no objects in storage, this is expected.
        if (status == TEE_ERROR_ITEM_NOT_FOUND)
        {
            DMSG("No stored variables found");
            status = TEE_SUCCESS;
        }
        goto Cleanup;
    }

    // Init index
    i = 0;

    // Iterate over persistent objects
    status = TEE_GetNextPersistentObject(enumHandle,
                                         &objInfo,
                                         &(VarList[i].ObjectID),
                                         &objIDLen);
    // Gather all available objects
    while ((status == TEE_SUCCESS) && (i < MAX_AUTHVAR_ENTRIES))
    {
        if (VarList[i].ObjectID == VersionObjectID) {
            DMSG("Skipping version id object");
            status = TEE_GetNextPersistentObject(enumHandle,
                                        &objInfo,
                                        &(VarList[i].ObjectID),
                                        &objIDLen);
            continue;
        }

        if (objInfo.dataSize < sizeof(UEFI_VARIABLE)) {
            EMSG("Failed AuthVarInit: Object too small");
            status = TEE_ERROR_BAD_STATE;
            goto Cleanup;
        }

        // Allocate space for this var
        if (!(pVar = TEE_Malloc(objInfo.dataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Failed alloc AuthVarInit");
            goto Cleanup;
        }

        if(s_NonVolatileSize + objInfo.dataSize > MAX_NV_STORAGE)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Failed AuthVarInit: Exceeds non-volatile variable max allocation.");
            goto Cleanup;
        }

        s_NonVolatileSize += objInfo.dataSize;

        status = NvOpenVariable(&VarList[i]);
        if (status != TEE_SUCCESS) {
            EMSG("Failed to open NV handle");
            goto Cleanup;
        }

        // Read object
        status = TEE_ReadObjectData(VarList[i].ObjectHandle,
                                    (PVOID)pVar,
                                    objInfo.dataSize,
                                    &size);
        if (status != TEE_SUCCESS) {
            EMSG("Failed to read object");
            goto Cleanup;
        }

        NvCloseVariable(&VarList[i]);

        // Sanity check size
        if (objInfo.dataSize != size)
        {
            status = TEE_ERROR_BAD_STATE;
            goto Cleanup;
        }

        // Init UEFI_VARIABLE fields and pick up pointers
        VarList[i].Var = pVar;
        pVar->BaseAddress = (UINT_PTR)pVar;
        pVar->MetaIndex = i;
        name = (PWCHAR)(pVar->BaseAddress + pVar->NameOffset);
        guid = &pVar->VendorGuid;
        attrib.Flags = pVar->Attributes.Flags;

        // Get var type and add to appropriate list
        GetVariableType(name, guid, attrib, &varType);
        InsertTailList(&VarInfo[varType].Head, &pVar->List);

        // Done, bump index
        i++;

        // Attempt to get another object
        status = TEE_GetNextPersistentObject(enumHandle,
                                             &objInfo,
                                             &(VarList[i].ObjectID),
                                             &objIDLen);
    }

    // Validate status from TEE_GetNextPersistentObject
    if (status != TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("Authvars: Initialization failure! (0x%x)", status);
        goto Cleanup;
    }

    // Ensure we don't exceed max object count
    if (i >= MAX_AUTHVAR_ENTRIES)
    {
        EMSG("Authvars: Initialization found too many objects");
        status = TEE_ERROR_BAD_STATE;
        goto Cleanup;
    }

    // Done, populate next free index
    NextFreeIdx = i;
    status = TEE_SUCCESS;

Cleanup:

    if (status != TEE_SUCCESS) {
        // RecoverStorage() will call TEE_Panic() if it is not able to recover.
        RecoverStorage(versioningStatus);
        versioningStatus = TEE_ERROR_ITEM_NOT_FOUND;
        status = TEE_SUCCESS;
    }

    if (versioningStatus == TEE_ERROR_ITEM_NOT_FOUND) {
        versioningStatus = AuthVarStoreVersion();
        if (versioningStatus != TEE_SUCCESS) {
            EMSG("Failed to store Authvars versioning information! 0x%x", versioningStatus);
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }
    }

    // Free enumerator, if necessary
    if (IS_VALID(enumHandle))
    {
        TEE_FreePersistentObjectEnumerator(enumHandle);
    }

    return status;
}

TEE_Result
AuthVarCloseStorage(
    VOID
)
/*++

    Routine Description:

        Close out persistent object handles for NV variables

    Arguments:

        None

    Returns:

        TEE_Result

--*/
{
    // TODO: This
    return TEE_SUCCESS;
}

TEE_Result
NvOpenVariable(
    AUTHVAR_META *VarMeta
)
/*++

    Routine Description:

        Open a handle for updating a non-volatile variable

    Arguments:

        Address of the variable meta data

    Returns:

        TEE_Result

--*/
{
    // Open object
    FMSG("Opening NV handle");
    return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                        &(VarMeta->ObjectID),
                                        sizeof(VarMeta->ObjectID),
                                        TA_STORAGE_FLAGS,
                                        &(VarMeta->ObjectHandle));
}

VOID
NvCloseVariable(
    AUTHVAR_META *VarMeta
)
/*++

    Routine Description:

        Close a handle after updating a non-volatile variable

    Arguments:

        Address of the variable meta data

    Returns:

        None

--*/
{
    FMSG("Closing NV handle");
    TEE_CloseObject(VarMeta->ObjectHandle);
}
