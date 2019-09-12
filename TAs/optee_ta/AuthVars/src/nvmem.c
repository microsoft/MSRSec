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

#include <varmgmt.h>

// 
// Auth Var in-memory storage layout
//
extern VTYPE_INFO VarInfo[];

//
// Non-Volatile Metadata (runtime only) 
//
extern AUTHVAR_META VarList[];

//
// Object enumerator and next free meta index value
//
static TEE_ObjectEnumHandle    AuthVarEnum = NULL;
static USHORT                  NextFreeIdx = 0;

//
// Global used to track non-volatile storage usage
//
extern UINT32 s_NonVolatileSize;

//
// AuthVars version object
//
#define AUTHVAR_VEROBJ              0x4175746856617273ULL  // 'AuthVars'
#define AUTHVAR_NV_MAJOR_VERSION    0x01UL
#define AUTHVAR_NV_MINOR_VERSION    0x02UL
typedef struct _AUTHVAR_VERSION
{
    UINT64  Magic;
    UINT32  MajorVersion;
    UINT32  MinorVersion;
} AUTHVAR_VERSION, *PAUTHVAR_VERSION;


//
// Prototypes
//

TEE_Result
NvCreateVariable(
    PUEFI_VARIABLE  Var     // IN
);

TEE_Result
NvUpdateVariable(
    PUEFI_VARIABLE  Var     // IN
);

TEE_Result
NvDeleteVariable(
    PUEFI_VARIABLE  Var     // IN
);

static
TEE_Result
NvOpenVariable(
    AUTHVAR_META *VarMeta
);

static
VOID
NvCloseVariable(
    AUTHVAR_META *VarMeta
);

//
// Functions
//

static
TEE_Result
AuthVarVersionSet(
    VOID
)
{
    AUTHVAR_VERSION versionInfo = { 0 };
    UINT64 versionObjectID = AUTHVAR_VEROBJ;
    TEE_ObjectHandle objHandle = TEE_HANDLE_NULL;
    TEE_Result status;

    // Init version information
    versionInfo.Magic = AUTHVAR_VEROBJ;
    versionInfo.MajorVersion = AUTHVAR_NV_MAJOR_VERSION;
    versionInfo.MinorVersion = AUTHVAR_NV_MINOR_VERSION;

    // Attempt to create version information object
    status = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                        (PVOID)&versionObjectID,
                                        sizeof(versionObjectID),
                                        TA_STORAGE_FLAGS,
                                        NULL,
                                        (PVOID)&versionInfo,
                                        sizeof(AUTHVAR_VERSION),
                                        &objHandle);
    // Success?    
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to create version object (0x%x)", status);
        goto Cleanup;
    }

    // Write out version object
    status = TEE_WriteObjectData(objHandle, (PVOID)&versionInfo, sizeof(AUTHVAR_VERSION));
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to write object 0x%x", status);
        goto Cleanup;
    }

    // Success
    status = TEE_SUCCESS;

Cleanup:
    if(IS_VALID(objHandle))
    {
        TEE_CloseObject(objHandle);
    }

    return status;
}


static
TEE_Result
AuthVarVersionCheck(
    VOID
)
{
    AUTHVAR_VERSION versionInfo;
    UINT64 versionObjectID;
    UINT32 dataSize;
    TEE_ObjectHandle objHandle;
    TEE_ObjectEnumHandle enumHandle;
    TEE_Result status;

    // Read version object from storage
    versionObjectID = AUTHVAR_VEROBJ;
    status = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                      &(versionObjectID),
                                      sizeof(versionObjectID),
                                      TA_STORAGE_FLAGS,
                                      &objHandle);

    // We may not encounter a version object.
    // Make sure it is because storage has not been initialized yet.
    if (status == TEE_ERROR_ITEM_NOT_FOUND)
    {
        VAR_MSG("No Authvars version object found");
        status = TEE_AllocatePersistentObjectEnumerator(&enumHandle);
        if (status != TEE_SUCCESS)
        {
            VAR_MSG("Failed to allocate object enumerator");
            goto Cleanup;
        }

        status = TEE_StartPersistentObjectEnumerator(enumHandle, TEE_STORAGE_PRIVATE);
        if (status != TEE_ERROR_ITEM_NOT_FOUND)
        {
            // Even if our status is success (especially if it is success) we
            // have a problem. If we found no version object then we must not
            // also find or read any storage objects.
            status = TEE_ERROR_BAD_STATE;
            goto Cleanup;
        }

        // No version object is present but our storage is clean, so close out
        // the object enumerator and create our version object.
        if (IS_VALID(enumHandle))
        {
            TEE_FreePersistentObjectEnumerator(enumHandle);
        }

        // Create version object
        status = AuthVarVersionSet();
        if(status != TEE_SUCCESS)
        {
            VAR_MSG("Failed to create version object (0x%x)", status);
        }

        goto Cleanup;
    }

    // Deal with potential failure status from object open
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to open version object (0x%x)", status);
        goto Cleanup;
    }

    // Validate existing versioning object
    status = TEE_ReadObjectData(objHandle,
                                (PVOID)&versionInfo,
                                sizeof(AUTHVAR_VERSION),
                                &dataSize);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to read version object (0x%x)", status);
        goto Cleanup;
    }

    // Validate version object
    if ((dataSize != sizeof(AUTHVAR_VERSION)) || (versionInfo.Magic != AUTHVAR_VEROBJ))
    {
        VAR_MSG("Failed version check");
        status = TEE_ERROR_CORRUPT_OBJECT;
        goto Cleanup;
    }

    // Validate version information
    if ((versionInfo.MajorVersion != AUTHVAR_NV_MAJOR_VERSION) ||
        (versionInfo.MinorVersion != AUTHVAR_NV_MINOR_VERSION))
    {
        VAR_MSG("TA version %d.%d attempting to load data version %d.%d",
                AUTHVAR_NV_MAJOR_VERSION, AUTHVAR_NV_MINOR_VERSION,
                versionInfo.MajorVersion, versionInfo.MinorVersion);

        // We do not support rolling major version (right now)
        if (versionInfo.MajorVersion != AUTHVAR_NV_MAJOR_VERSION)
        {
            status = TEE_ERROR_NOT_SUPPORTED;
            goto Cleanup;
        }
#ifdef AUTHVAR_ALLOW_UPGRADE
        // We're ok with picking up older minor versions
        if (versionInfo.MinorVersion < AUTHVAR_NV_MINOR_VERSION)
        {
            // Roll minor version
            status = AuthVarVersionSet();
            goto Cleanup;
        }
#endif
        // Unexpected version or upgrade not permitted
        status = TEE_ERROR_NOT_SUPPORTED;
        goto Cleanup;
    }

    // Success
    status = TEE_SUCCESS;

Cleanup:
    if(IS_VALID(objHandle))
    {
        TEE_CloseObject(objHandle);
    }

    if(IS_VALID(enumHandle))
    {
        TEE_FreePersistentObjectEnumerator(enumHandle);
    }

    return status;
}


static
TEE_Result
AuthVarResetStorage(
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
    UINT64 objID;
    UINT32 objIDLen, i;
    VARTYPE varType;
    TEE_ObjectInfo objInfo;
    TEE_ObjectHandle objHandle;
    TEE_ObjectEnumHandle enumHandle;
    TEE_Result status;

    // Init for object enumeration
    status = TEE_AllocatePersistentObjectEnumerator(&enumHandle);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to create enumerator (0x%x)", status);
        goto Cleanup;
    }

    // Iterate objects
    while (status == TEE_SUCCESS)
    {
        // May need to restart enumerator after object deletion so just do it regardless
        status = TEE_StartPersistentObjectEnumerator(enumHandle, TEE_STORAGE_PRIVATE);
        if (status == TEE_ERROR_ITEM_NOT_FOUND)
        {
            // We're done
            break;
        }

        // Verify success status
        if (status != TEE_SUCCESS)
        {
            VAR_MSG("Failed to clear storage (0x%x)", status);
            goto Cleanup;
        }

        // Get object handle
        status = TEE_GetNextPersistentObject(enumHandle,
                                             &objInfo,
                                             &objID,
                                             &objIDLen);
        if (status != TEE_SUCCESS)
        {
            VAR_MSG("Failed to clear storage (getNext: 0x%x)", status);
            goto Cleanup;
        }

        // Open so we can delete
        status =  TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                           &objID,
                                           objIDLen,
                                           TA_STORAGE_FLAGS,
                                           &objHandle);
        if (status != TEE_SUCCESS)
        {
            VAR_MSG("Failed to clear storage (open: 0x%x)", status);
            goto Cleanup;
        }

        // Delete the object
        TEE_CloseAndDeletePersistentObject1(objHandle);
        objHandle = TEE_HANDLE_NULL;
    }

    // On "normal" successful completion of the above loop our status
    // is TEE_ERROR_ITEM_NOT_FOUND. We don't verify that here since
    // we're not in cleanup and we know nothing has gone awry.

    // Set our version information
    status = AuthVarVersionSet();
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // In the event are recovering from a corrupted variable object we will
    // need to clear out any previous variables which are cached in memory.
    for (i = 0; i < MAX_AUTHVAR_ENTRIES; i++)
    {
        if (VarList[i].Var != NULL)
        {
            TEE_Free(VarList[i].Var);
        }
    }

    // Reset metadata
    memset(VarList, 0, (sizeof(AUTHVAR_META) * MAX_AUTHVAR_ENTRIES));

    // Reset variable info
    for (varType = 0; varType < VTYPE_END; varType++)
    {
        InitializeListHead(&VarInfo[varType].Head);
    }

Cleanup:
    if(IS_VALID(enumHandle))
    {
        TEE_FreePersistentObjectEnumerator(enumHandle);
    }

    return status;
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
    PUEFI_VARIABLE  pVar;
    PWCHAR          name;
    PCGUID          guid;
    ATTRIBUTES      attrib;
    UINT32          size;
    UINT32          objIDLen;
    VARTYPE         varType;
    TEE_Result      status;
    USHORT          i;

    // Initialize variable lists
    for(varType = 0; varType < VTYPE_END; varType++ )
    {
        VAR_MSG("Initializing list %d", varType);
        InitializeListHead(&VarInfo[varType].Head);
    }

    // Check version information. It will be created if necessary.
    status = AuthVarVersionCheck();
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failure on version check");
        goto Cleanup;
    }

    // Allocate object enumerator
    status = TEE_AllocatePersistentObjectEnumerator(&AuthVarEnum);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to create enumerator: 0x%x", status);
        goto Cleanup;
    }

    // Start object enumerator
    status = TEE_StartPersistentObjectEnumerator(AuthVarEnum, TEE_STORAGE_PRIVATE);
    if (status != TEE_SUCCESS)
    {
        // At this point, any non-success status is failure, since we have
        // already created our version object. Even with no variables in
        // storage we should have at least encountered the version object.
        VAR_MSG("Failed to start enumerator: 0x%x", status);
        goto Cleanup;
    }

    // Init index
    i = 0;

    // Iterate over persistent objects
    status = TEE_GetNextPersistentObject(AuthVarEnum,
                                         &objInfo,
                                         &(VarList[i].ObjectID),
                                         &objIDLen);
    // Gather all available objects
    while ((status == TEE_SUCCESS) && (i < MAX_AUTHVAR_ENTRIES))
    {
        // Skip the version object (we trust the storage subsystem to prevent
        // creation of multiple objects with the same object id).
        if (VarList[i].ObjectID == AUTHVAR_VEROBJ)
        {
            // Get next object
            status = TEE_GetNextPersistentObject(AuthVarEnum,
                                                 &objInfo,
                                                 &(VarList[i].ObjectID),
                                                 &objIDLen);
            continue;
        }

        // Sanity check object size
        if (objInfo.dataSize < sizeof(UEFI_VARIABLE))
        {
            status = TEE_ERROR_BAD_STATE;
            VAR_MSG("Failed AuthVarInit: Object too small");
            goto Cleanup;
        }

        // Allocate space for this var
        if (!(pVar = TEE_Malloc(objInfo.dataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            VAR_MSG("Failed AuthVarInit: Malloc");
            goto Cleanup;
        }

        // Enforce data size limits
        if(s_NonVolatileSize + objInfo.dataSize > MAX_NV_STORAGE)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            VAR_MSG("Failed AuthVarInit: Exceeds non-volatile variable max allocation.");
            goto Cleanup;
        }

        s_NonVolatileSize += objInfo.dataSize;

        // Open Object
        if (NvOpenVariable(&(VarList[i])) != TEE_SUCCESS) {
            VAR_MSG("Failed to open NV handle");
            TEE_Panic(status);
        }

        // Read object
        status = TEE_ReadObjectData(VarList[i].ObjectHandle,
                                    (PVOID)pVar,
                                    objInfo.dataSize,
                                    &size);

        // Close object
        NvCloseVariable(&VarList[i]);

        // Sanity check size
        if (objInfo.dataSize != size)
        {
            TEE_Panic(TEE_ERROR_BAD_STATE);
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
        status = TEE_GetNextPersistentObject(AuthVarEnum,
                                             &objInfo,
                                             &(VarList[i].ObjectID),
                                             &objIDLen);
    }

    // Validate status from TEE_GetNextPersistentObject
    if (status != TEE_ERROR_ITEM_NOT_FOUND)
    {
        // The only non-fatal status out of "get next" is ITEM_NOT_FOUND
        TEE_Panic(status);
    }

    // Ensure we don't exceed max object count
    if (i >= MAX_AUTHVAR_ENTRIES)
    {
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // Done, populate next free index and return
    NextFreeIdx = i;
    status = TEE_SUCCESS;

Cleanup:
    // Free enumerator, if necessary
    if (IS_VALID(AuthVarEnum))
    {
        TEE_FreePersistentObjectEnumerator(AuthVarEnum);
    }

#ifdef AUTHVARS_RESET_ON_ERROR
    // Wipe storage if necessary
    if (status != TEE_SUCCESS)
    {
        return AuthVarResetStorage();
    }
#endif

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
    UINT32 i;

    // Iterate variable list freeing resources
    for (i = 0; i < MAX_AUTHVAR_ENTRIES; i++)
    {
        if (VarList[i].ObjectID)
        {
            NvCloseVariable(&(VarList[i]));
            TEE_Free(VarList[i].Var);
        }
    }

    // Clear metadata
    memset(VarList, 0, (sizeof(AUTHVAR_META) * MAX_AUTHVAR_ENTRIES));

    return TEE_SUCCESS;
}


static
BOOL
AuthVarNextFreeIdx(
    USHORT *    index       // OUT
)
{
    USHORT i;

    // Parameter validation
    if (!index)
    {
        return FALSE;
    }

    // Find first free variable index
    for (i = 0; i < MAX_AUTHVAR_ENTRIES; i++)
    {
        if (!(VarList[i].ObjectID))
        {
            break;
        }
    }

    // Yes, MAX_AUTHVAR_ENTRIES can result from calling this
    // function. This means we're maxed out..
    *index = i;
    return TRUE;
}


static
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
    return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                    &(VarMeta->ObjectID),
                                    sizeof(VarMeta->ObjectID),
                                    TA_STORAGE_FLAGS,
                                    &(VarMeta->ObjectHandle));
}


static
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
    TEE_CloseObject(VarMeta->ObjectHandle);
}


TEE_Result
NvCreateVariable(
    PUEFI_VARIABLE  Var     // IN
)
{
    UINT64 qHash[TEE_DIGEST_QWORDS];
    PVOID namePtr;
    TEE_OperationHandle opHandle;
    UINT32 length, dataSize;
    TEE_Result status;
    USHORT i;

    // Parameter validation
    if (!Var)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Use next free and sanity check
    i = NextFreeIdx;
    if (i >= (MAX_AUTHVAR_ENTRIES))
    {
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    // Calculate total size needed to store this variable
    dataSize = sizeof(UEFI_VARIABLE) + Var->NameSize + Var->ExtAttribSize + Var->DataSize;

    // Init for hash operation
    opHandle = TEE_HANDLE_NULL;
    length = TEE_SHA256_HASH_SIZE;

    // Generate a unique ObjectID for this object based on GUID + name.
    // REVISIT: In the unlikely event of a collision, fail the create operation.
    status = TEE_AllocateOperation(&opHandle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to allocate digest operation");
        goto Cleanup;
    }

    // Include VendorGuid first
    TEE_DigestUpdate(opHandle, &(Var->VendorGuid), sizeof(Var->VendorGuid));

    // Then name, finalizing hash
    namePtr = (PVOID)(Var->BaseAddress + Var->NameOffset);
    status = TEE_DigestDoFinal(opHandle, namePtr, Var->NameSize, (PVOID)qHash, &length);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to finalize digest operation");
        goto Cleanup;
    }

    // Assumes TEE_OBJECT_ID_MAX_LEN == 64!
    VarList[i].ObjectID = qHash[0];
    
    // Attempt to create an object for this var
    status = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                        (PVOID)&(VarList[i].ObjectID),
                                        sizeof(VarList[i].ObjectID),
                                        TA_STORAGE_FLAGS, NULL,
                                        (PVOID)Var, dataSize,
                                        &(VarList[i].ObjectHandle));
    // Successful creation?
    if (status != TEE_SUCCESS)
    {
        // REVISIT: This really shouldn't be a panic long-term.
        if (status == TEE_ERROR_ACCESS_CONFLICT)
        {
            VAR_MSG("Collision on ObjectID, duplicate (GUID, Name)?");
            TEE_Panic(TEE_ERROR_ACCESS_CONFLICT);
        }

        // Other unexpected error
        VAR_MSG("Failed to create persistent object with error 0x%x", status);
        goto Cleanup;
    }

    // Write out this variable
    status = TEE_WriteObjectData(VarList[i].ObjectHandle, (PVOID)Var, dataSize);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to write object");
        goto Cleanup;
    }

    // Link to new var
    VarList[i].Var = Var;
    Var->MetaIndex = i;

    // Update next free index
    AuthVarNextFreeIdx(&NextFreeIdx);

    NvCloseVariable(&VarList[i]);

    // Success, return
    status = TEE_SUCCESS;

Cleanup:
    if(IS_VALID(opHandle))
    {
        TEE_FreeOperation(opHandle);
    }
    return status;
}


TEE_Result
NvUpdateVariable(
    PUEFI_VARIABLE  Var     // IN
)
{
    UINT32      newSize;
    TEE_Result  status;
    USHORT      i;

    // Validate parameters
    if (!Var)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Pickup index into metadata
    i = Var->MetaIndex;

    // Make sure the metadata still points to the correct address
    // incase a realloc moved the variable.
    VarList[i].Var = Var;
    
    // Calculate new size of persistent object
    newSize = sizeof(UEFI_VARIABLE) + Var->NameSize + Var->ExtAttribSize + Var->DataSize;

    if (NvOpenVariable(&(VarList[i])) != TEE_SUCCESS) {
        VAR_MSG("Failed to open NV handle");
        TEE_Panic(status);
    }

    // Reset data position for object
    status = TEE_SeekObjectData(VarList[i].ObjectHandle, 0, TEE_DATA_SEEK_SET);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // Resize persistent object
    status = TEE_TruncateObjectData(VarList[i].ObjectHandle, newSize);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // Write object data
    status = TEE_WriteObjectData(VarList[i].ObjectHandle, Var, newSize);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    NvCloseVariable(&VarList[i]);

    // Success, return
    status = TEE_SUCCESS;
Cleanup:
    return status;
}


TEE_Result
NvDeleteVariable(
    PUEFI_VARIABLE  Var     // IN
)
{
    TEE_Result  status;
    USHORT      i;

    // Validate parameters
    if (!Var)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Pickup index into VarList
    i = Var->MetaIndex;

    // Sanity check metadata
    if (Var != VarList[i].Var)
    {
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    if (NvOpenVariable(&(VarList[i])) != TEE_SUCCESS) {
        VAR_MSG("Failed to open NV handle");
        TEE_Panic(status);
    }

    // Close and delete backing object
    status = TEE_CloseAndDeletePersistentObject1(VarList[i].ObjectHandle);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // Free in-memory variable
    TEE_Free(VarList[i].Var);
    VarList[i].Var = NULL;
    VarList[i].ObjectID = 0;

    // Clear metadata
    memset(&(VarList[i]), 0, sizeof(AUTHVAR_META));

    // If necessary, update next free
    if (i < NextFreeIdx)
    {
        NextFreeIdx = i;
    }

    // Success, return
    status = TEE_SUCCESS;
Cleanup:
    return status;
}
