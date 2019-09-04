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
static TEE_ObjectEnumHandle    AuthVarEnumerator = NULL;
static USHORT                  NextFreeIdx = 0;

//
// Global used to track non-volatile storage usage
//
extern UINT32 s_NonVolatileSize;

//
// Prototype(s)
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
// Auth Var storage (de-)init functions
//

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

    // Allocate object enumerator
    status = TEE_AllocatePersistentObjectEnumerator(&AuthVarEnumerator);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to create enumerator: 0x%x", status);
        goto Cleanup;
    }

    // Start object enumerator
    status = TEE_StartPersistentObjectEnumerator(AuthVarEnumerator, TEE_STORAGE_PRIVATE);
    if (status != TEE_SUCCESS)
    {
        VAR_MSG("Failed to start enumerator: 0x%x", status);
        // On first run there will be no objects in storage, this is expected.
        if (status == TEE_ERROR_ITEM_NOT_FOUND)
        {
            VAR_MSG("No stored variables found");
            status = TEE_SUCCESS;
        }
        goto Cleanup;
    }

    // Init index
    i = 0;

    // Iterate over persistent objects
    status = TEE_GetNextPersistentObject(AuthVarEnumerator,
                                         &objInfo,
                                         &(VarList[i].ObjectID),
                                         &objIDLen);
    // Gather all available objects
    while ((status == TEE_SUCCESS) && (i < MAX_AUTHVAR_ENTRIES))
    {
        // Allocate space for this var
        if (!(pVar = TEE_Malloc(objInfo.dataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            VAR_MSG("Failed alloc AuthVarInit");
            goto Cleanup;
        }

        if(s_NonVolatileSize + objInfo.dataSize > MAX_NV_STORAGE)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            VAR_MSG("Failed AuthVarInit: Exceeds non-volatile variable max allocation.");
            goto Cleanup;
        }

        s_NonVolatileSize += objInfo.dataSize;

        if (NvOpenVariable(&VarList[i]) != TEE_SUCCESS) {
            VAR_MSG("Failed to open NV handle");
            TEE_Panic(status);
        }

        // Read object
        status = TEE_ReadObjectData(VarList[i].ObjectHandle,
                                    (PVOID)pVar,
                                    objInfo.dataSize,
                                    &size);

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
        status = TEE_GetNextPersistentObject(AuthVarEnumerator,
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
    if (IS_VALID(AuthVarEnumerator))
    {
        TEE_FreePersistentObjectEnumerator(AuthVarEnumerator);
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

    if (NvOpenVariable(&VarList[i]) != TEE_SUCCESS) {
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

    if (NvOpenVariable(&VarList[i]) != TEE_SUCCESS) {
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
