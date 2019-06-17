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
UINT32 s_VolatileSize = 0;
UINT32 s_NonVolatileSize = 0;

static TEE_ObjectEnumHandle     AuthVarEnumerator = NULL;
AUTHVAR_META                    VarList[MAX_AUTHVAR_ENTRIES] = { 0 };
USHORT                          NextFreeIdx = 0;

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
        DMSG("Initializing list %d", varType);
        InitializeListHead(&VarInfo[varType].Head);
    }

    // Allocate object enumerator
    status = TEE_AllocatePersistentObjectEnumerator(&AuthVarEnumerator);
    if (status != TEE_SUCCESS)
    {
        DMSG("Failed to create enumerator: 0x%x", status);
        goto Cleanup;
    }

    // Start object enumerator
    status = TEE_StartPersistentObjectEnumerator(AuthVarEnumerator, TEE_STORAGE_PRIVATE);
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

        if (NvOpenVariable(&VarList[i]) != TEE_SUCCESS) {
            EMSG("Failed to open NV handle");
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
