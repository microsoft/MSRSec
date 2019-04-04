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
VTYPE_INFO VarInfo[VTYPE_END] =
{
    {
        L"SecureBootVariables", VTYPE_SECUREBOOT,
        { 0 }, TRUE,
    },
    {
        L"BootVariables", VTYPE_BOOT,
        { 0 }, TRUE,
    },
    {
        L"Runtime Private Authenticated Variables", VTYPE_PVT_AUTHENTICATED,
        { 0 }, TRUE,
    },
    {
        L"General Space", VTYPE_GENERAL,
        { 0 }, TRUE,
    },
    {
        L"Volatile Variable", VTYPE_VOLATILE,   // VOLATILE AUTH VARS ARE NOT PERSISTED!
        { 0 }, FALSE,                           // VOLATILE AUTH VARS ARE NOT PERSISTED!
    }
};

//
// Non-Volatile Metadata (runtime only) 
//
AUTHVAR_META    VarList[MAX_AUTHVAR_ENTRIES] = { 0 };

//
// Object enumerator and next free meta index value
//
static TEE_ObjectEnumHandle    AuthVarEnumerator = NULL;
static USHORT                  NextFreeIdx = 0;

//
// Globals to track storage usage
//
UINT32 s_VolatileSize = 0;
UINT32 s_NonVolatileSize = 0;

//
// Handy empty GUID const
//
const GUID GUID_NULL = { 0, 0, 0,{ 0, 0, 0, 0, 0, 0, 0, 0 } };

//
// Helper function prototype(s)
//

static
TEE_Result
NvCreateVariable(
    PUEFI_VARIABLE  Var     // IN
);

static
TEE_Result
NvUpdateVariable(
    PUEFI_VARIABLE  Var     // IN
);

static
TEE_Result
NvDeleteVariable(
    PUEFI_VARIABLE  Var     // IN
);

static
BOOLEAN
CompareEntries(
    PCUNICODE_STRING     Name,      // IN
    PCGUID               Guid,      // IN
    PUEFI_VARIABLE       Var        // IN
);

static
BOOLEAN
GetVariableType(
    PCWSTR      VarName,            // IN
    PCGUID      VendorGuid,         // IN
    ATTRIBUTES  Attributes,         // IN
    PVARTYPE    VarType             // OUT
);

static
BOOLEAN
IsSecureBootVar(
    PCWSTR  VarName,                // IN
    PCGUID  VendorGuid              // IN
);

#ifdef AUTHVAR_DEBUG
static
VOID
AuthVarDumpVarList(
    VOID
);
#endif

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

        // Open object
        status = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                          &(VarList[i].ObjectID),
                                          sizeof(VarList[i].ObjectID),
                                          TA_STORAGE_FLAGS,
                                          &(VarList[i].ObjectHandle));

        // Read object
        status = TEE_ReadObjectData(VarList[i].ObjectHandle,
                                    (PVOID)pVar,
                                    objInfo.dataSize,
                                    &size);
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

//
// Auth Var Mgmt Functions
//

VOID
SearchList(
    PCUNICODE_STRING     UnicodeName,   // IN
    PCGUID               VendorGuid,    // IN
    PUEFI_VARIABLE      *Var,           // OUT
    VARTYPE             *VarType        // OUT
)
/*++

    Routine Description:

        Search the global in-memory list to check if Var has been set.
        Var may be volatile or non-volatile.

    Arguments:

        UnicodeName - Name of the variable being searched

        VendorGuid - GUID of the variable

        Var - Pointer to the variable. NULL if not found.

        VarType - Type used to determine variable's info and storage

    Returns:

        None

 --*/
{
    UINT32 i;

    // Validate parameters
    if (!(UnicodeName) || !(VendorGuid) || !(Var) || !(VarType))
    {
        DMSG("Invalid search parameters");
        return;
    }

    *Var = NULL;

    // Run the list(s)
    for (i = 0; i < ARRAY_SIZE(VarInfo) && *Var == NULL; i++)
    {
        PLIST_ENTRY head = &VarInfo[i].Head;
        PLIST_ENTRY cur = head->Flink;

        while ((cur) && (cur != head))
        {
            if (CompareEntries(UnicodeName, VendorGuid, (PUEFI_VARIABLE)cur))
            {
                *Var = (PUEFI_VARIABLE)cur;
                *VarType = VarInfo[i].Type;
                break;
            }

            cur = cur->Flink;
        }
    }

    return;
}

TEE_Result
CreateVariable(
    PCUNICODE_STRING        UnicodeName,        // IN
    PCGUID                  VendorGuid,         // IN
    ATTRIBUTES              Attributes,         // IN
    PEXTENDED_ATTRIBUTES    ExtAttributes,      // IN
    UINT32                  DataSize,           // IN
    PBYTE                   Data                // IN
)
/*++

    Routine Description:

        Function to create a variable

    Arguments:

        UnicodeName - Name of the variable being created

        VendorGuid - GUID of the variable

        Attibutes - UEFI variable attributes

        DataSize - Size in bytes of Data

        Data - Pointer to the data

    Returns:
    
        TEE_Result

--*/
{
    PUEFI_VARIABLE newVar = NULL;
    PWSTR newStr = NULL;
    PBYTE newData = NULL;
    PEXTENDED_ATTRIBUTES newExt = NULL;
    UINT32 requiredSize = 0, strLen = 0, extAttribLen = 0;
    VARTYPE varType;
    TEE_Result status = TEE_SUCCESS;

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        DMSG("Creating volatile variable");
        
        // Validate length
        if (DataSize == 0)
        {
            // TODO: I believe there are circumstances under which it is permitted
            //       to create a var with zero DataSize. But I guess we'll cross 
            //       that bridge when we come to it.
            status = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Create volatile variable error: Bad parameters.");
            goto Cleanup;
        }

        // Calculate memory requirement for this variable
        requiredSize = sizeof(UEFI_VARIABLE) + UnicodeName->MaximumLength + DataSize;

        // Check if there is enough volatile memory quota
        if(s_VolatileSize + requiredSize > MAX_VOLATILE_STORAGE)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Create volatile variable error: Exceeds volatile variable max allocation.");
            goto Cleanup;
        }

        // Attempt allocation for variable
        if (!(newVar = TEE_Malloc(sizeof(UEFI_VARIABLE), TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Create volatile variable error: Out of memory.");
            goto Cleanup;
        }

        // Attempt allocation for variable name
        if (!(newStr = TEE_Malloc(UnicodeName->MaximumLength, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Create volatile variable error: Out of memory.");
            goto Cleanup;
        }

        // Attempt allocation for variable data
        if (!(newData = TEE_Malloc(DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            TEE_Free(newStr);
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Create volatile variable error: Out of memory.");
            goto Cleanup;
        }

        // Init volatile variable storage
        memset(newVar, 0, sizeof(UEFI_VARIABLE));

        // Guid/Attributes
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;

        // Pointers to name, etc. are proper memory addresses for volatile vars
        newVar->BaseAddress = 0;

        // Init/copy variable name
        newVar->NameSize = UnicodeName->MaximumLength;
        newVar->NameOffset = (UINT_PTR)newStr;
        memmove(newStr, UnicodeName->Buffer, newVar->NameSize);

        // Init/copy variable data
        newVar->DataSize = DataSize;
        newVar->DataOffset = (UINT_PTR)newData;
        memmove(newData, Data, DataSize);

        // Track how much memory is used for volatile variables
        s_VolatileSize += requiredSize;

        // Note the lack of a check against ExtendedAttributes.
        // We do not implement authenticated volatile variables.

        // Add it to the list
        InsertTailList(&(VarInfo[VTYPE_VOLATILE].Head), &newVar->List);

        // Success
        status = TEE_SUCCESS;
        FMSG("Created volatile variable");
        goto Cleanup;
    }
    else
    {
        // Nope, create new non-volatile variable.
        DMSG("Creating non-volatile variable");

        // Which list is this variable destined for?
        if (!GetVariableType(UnicodeName->Buffer, VendorGuid, Attributes, &varType))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Create non-volatile variable error: Bad parameters.");
            goto Cleanup;
        }

        // Get strlen of unicode name
        strLen = UnicodeName->MaximumLength;

        // Get size of extended attributes (if provided)
        if (ExtAttributes)
        {
            extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.Size;
        }
        else
        {
            extAttribLen = 0;
        }

        // Total NV requirement to store this var
        requiredSize = sizeof(UEFI_VARIABLE) + strLen + DataSize + extAttribLen;

        FMSG("Storing 0x%x bytes (variable + name + data)", requiredSize);

        // In-memory allocation for new variable
        if (!(newVar = TEE_Malloc(requiredSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Init pointers to new fields
        newVar->BaseAddress = (UINT_PTR)newVar;
        newStr = (PWSTR)((UINT_PTR)newVar + sizeof(UEFI_VARIABLE));
        newExt = (PEXTENDED_ATTRIBUTES)((UINT_PTR)newStr + strLen);
        newData = (PBYTE)((UINT_PTR)newExt + extAttribLen);

        // REVISIT: Debug, remove
        FMSG("newVar: 0x%lx", (UINT_PTR)newVar);
        FMSG("New string is at 0x%lx, with length 0x%x", (UINT_PTR)newStr, strLen);
        FMSG("New ext is at 0x%lx, with length 0x%x", (UINT_PTR)newExt, extAttribLen);
        FMSG("New data is at 0x%lx, with length 0x%x", (UINT_PTR)newData, DataSize);

        // Init variable structure
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;
        newVar->NameSize = strLen;
        newVar->NameOffset = (UINT_PTR)newStr - newVar->BaseAddress;

        // Copy name and data
        memmove(newStr, UnicodeName->Buffer, strLen);

        // Extended attributes, if necessary
        if (!extAttribLen)
        {
            // No extended attributes
            newVar->ExtAttribSize = 0;
            newVar->ExtAttribOffset = 0;
        }
        else
        {
            // Copy extended attributes
            newVar->ExtAttribSize = extAttribLen;
            newVar->ExtAttribOffset = (UINT_PTR)newExt - newVar->BaseAddress;
            memmove(newExt, ExtAttributes, extAttribLen);
        }

        // Data fields
        newVar->DataSize = DataSize;
        newVar->DataOffset = (UINT_PTR)newData - newVar->BaseAddress;
        memmove(newData, Data, DataSize);

        // Create storage for new variable
        status = NvCreateVariable(newVar);
        if (status != TEE_SUCCESS)
        {
            TEE_Free(newVar);
            goto Cleanup;
        }

        // Update the in-memory list
        InsertTailList(&VarInfo[varType].Head, &newVar->List);
        FMSG("Created non-volatile variable");
    }
Cleanup:
#ifdef AUTHVAR_DEBUG
    AuthVarDumpVarList();
#endif
    return status;
}

TEE_Result
RetrieveVariable(
    PUEFI_VARIABLE       Var,           // IN
    VARIABLE_GET_RESULT *ResultBuf,     // OUT
    UINT32               ResultBufLen,  // IN
    UINT32              *BytesWritten   // OUT (optional)
)
/*++

    Routine Description:

        Function for getting (reading) a variable's data.

    Arguments:

        Var - Pointer to the variable's entry in memory.

        ResultBuf - Buffer to hold result (attributes, datasize, and data)

        ResultBufLen - Size of ResultBuffer

        BytesWritten - total bytes copied into (or needed for) ResultBuf

    Returns:

        TEE_Result

--*/
{
    PBYTE dstPtr, limit;
    UINT_PTR nextOffset;
    PUEFI_VARIABLE currentBlock;
    UINT32 requiredSize, length;
    TEE_Result status = TEE_SUCCESS;

    DMSG("Getting data from variable at 0x%lx", (UINT_PTR)Var);

    // Detect integer overflow
    if (((UINT32)ResultBuf + ResultBufLen) < (UINT32)ResultBuf)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    //Calculate the total size required
    requiredSize = Var->DataSize;
    ResultBuf->DataSize = requiredSize;

    FMSG("Total required size is 0x%x", requiredSize);
    FMSG("ResultBufLen:0x%x, we want to store 0x%x", ResultBufLen, (requiredSize + sizeof(VARIABLE_GET_RESULT)));

    if (ResultBufLen < (requiredSize + sizeof(VARIABLE_GET_RESULT)))
    {
        // This is a common error case, a buffer size of 0 is often passed
        // to check the required size.
        DMSG("Retrieve variable error: result buffer too short.");
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Copy variable data
    ResultBuf->Attributes = Var->Attributes.Flags;
    ResultBuf->Size = sizeof(VARIABLE_GET_RESULT) + ResultBuf->DataSize;
    memcpy(ResultBuf->Data, (Var->BaseAddress + Var->DataOffset), requiredSize);

Cleanup:
    if (BytesWritten) // or needed..
    {
        *BytesWritten = requiredSize + sizeof(VARIABLE_GET_RESULT);
        DMSG("Required buffer size is 0x%x bytes", *BytesWritten);
    }

    return status;
}

TEE_Result
DeleteVariable(
    PUEFI_VARIABLE  Variable    // IN
)
/*++

    Routine Description:

        Delete a variable from in-memory and (if necessary) NV storage

    Arguments:

        Variable - Pointer to in-memory variable

    Returns:

        TEE_Result

--*/
{
    UINT32 varSize;
    TEE_Result status = TEE_SUCCESS;

    DMSG("Deleting variable at 0x%lx", (UINT_PTR)Variable);

    // Calculate Variable size
    varSize = sizeof(UEFI_VARIABLE) + Variable->NameSize +
              Variable->ExtAttribSize + Variable->DataSize;

    // First, is this a volatile variable?
    if (!(Variable->Attributes.NonVolatile))
    {
        FMSG("Volatile delete");

        TEE_Free((PBYTE)Variable->DataOffset);
        TEE_Free((PBYTE)Variable->NameOffset);
        TEE_Free((PBYTE)Variable);

        s_VolatileSize -= varSize;
        if (s_VolatileSize > MAX_VOLATILE_STORAGE) {
            EMSG("Volatile variable size underflow!");
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }
    } else {
        FMSG("Non-volatile delete");
        status = NvDeleteVariable(Variable);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        // No MAX here to detect underflow (has no functional impact anyway)
        s_NonVolatileSize -= varSize;
    }
Cleanup:
#ifdef AUTHVAR_DEBUG
    AuthVarDumpVarList();
#endif
    return status;
}

TEE_Result
AppendVariable(
    PUEFI_VARIABLE          Var,            // IN
    ATTRIBUTES              Attributes,     // IN
    PEXTENDED_ATTRIBUTES    ExtAttributes,  // IN
    PBYTE                   Data,           // IN
    UINT32                  DataSize        // IN
)
/*++

    Routine Description:

        Function for appending to an existing variable.

    Arguments:

        Var - Pointer to a variable's first block.

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    PUEFI_VARIABLE newVar;
    PBYTE dstPtr;
    UINT32 varSize, newSize, extAttribLen;
    TEE_Result  status = TEE_SUCCESS;
    VARTYPE varType;
    DMSG("Appending to variable at 0x%lx", (UINT_PTR)Var);

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        FMSG("Volatile append");
        PBYTE dstPtr = NULL;
        UINT32 newSize = 0;

        // Check overflow on data size
        if ((Var->DataSize + DataSize) < (Var->DataSize))
        {
            EMSG("append error: Overflow on data length");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Calculate new data length
        newSize = Var->DataSize + DataSize;

        // Check if there is enough volatile memory "quota"
        if((s_VolatileSize + DataSize) > MAX_VOLATILE_STORAGE)
        {
            EMSG("Volatile append error: Exceeds volatile variable max allocation.");
            status = TEE_ERROR_OUT_OF_MEMORY;            
            goto Cleanup;
        }

        // Attempt allocation
        if (!(dstPtr = TEE_Realloc(Var->DataOffset, newSize)))
        {
            EMSG("Volatile append error: out of memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Then copy appended data
        memmove(dstPtr + Var->DataSize, Data, DataSize);

        // Update data pointer, Realloc may have moved our data
        Var->DataOffset = dstPtr;
        Var->DataSize = newSize;

        // Track current usage
        s_VolatileSize += DataSize;

        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else {
        // Nope, append to existing non-volatile variable.
        FMSG("Non volatile append");

        // Extended attributes
        if (ExtAttributes)
        {
            // Sanity check extended attributes
            extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.Size;
            if (extAttribLen != Var->ExtAttribSize)
            {
                status = TEE_ERROR_BAD_PARAMETERS;
                goto Cleanup;
            }
        }

        // Current (pre-append) variable size
        varSize = sizeof(UEFI_VARIABLE) + Var->NameSize + Var->ExtAttribSize + Var->DataSize;

        // Calculate new variable size
        newSize = varSize + DataSize;

        // Attempt to realloc variable buffer
        // Remove from the list incase the variable is moved.
        RemoveEntryList(&Var->List);
        if (!(newVar = TEE_Realloc(Var, newSize)))
        {
            EMSG("non-volatile append error: out of memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Add back to the lists
        GetVariableType(newVar->BaseAddress + newVar->NameOffset, &newVar->VendorGuid, Attributes, &varType);
        InsertTailList(&VarInfo[varType].Head, &newVar->List);

        // Update fields and copy append data (realloc may have moved var)
        newVar->BaseAddress = newVar;
        dstPtr = newVar->BaseAddress + newVar->DataOffset + newVar->DataSize;
        memmove(dstPtr, Data, DataSize);
        newVar->DataSize += DataSize;

        // Extended attributes
        if (ExtAttributes)
        {
            dstPtr = newVar->BaseAddress + newVar->ExtAttribOffset;
            memmove(dstPtr, ExtAttributes, extAttribLen);
        }

        // Update variable in nv
        status = NvUpdateVariable(newVar);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        // Success
        status = TEE_SUCCESS;
        goto Cleanup;
    }
Cleanup:
#ifdef AUTHVAR_DEBUG
    AuthVarDumpVarList();
#endif
    return status;
}

TEE_Result
ReplaceVariable(
    PUEFI_VARIABLE          Var,            // IN
    ATTRIBUTES              Attributes,     // IN
    PEXTENDED_ATTRIBUTES    ExtAttributes,  // IN
    PBYTE                   Data,           // IN
    UINT32                  DataSize        // IN
)
/*++

    Routine Description:

        Function for replacing value of an existing variable

    Arguments:

        Var - Pointer to a variable

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    PBYTE srcPtr, limit;
    PUEFI_VARIABLE dstPtr, newVar;
    UINT_PTR nextOffset;
    UINT32 canFit, remaining, extAttribLen, reqSize;
    INT32 length; // Note signed!
    TEE_Result  status = TEE_SUCCESS;
    VARTYPE varType;

    DMSG("Replacing variable at 0x%lx", (UINT_PTR)Var);

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        FMSG("Replacing volatile variable");

        // Yes. Make sure variable doesn't indicate APPEND_WRITE.
        if ((Attributes.AppendWrite))
        {
            EMSG("Replace variable error: Bad parameters");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // We're good, can we re-use this allocation?
        if (DataSize == Var->DataSize) {
            // Yes, skip realloc/free
            memmove((PBYTE)Var->DataOffset, Data, DataSize);
            Var->Attributes.Flags = Attributes.Flags;
            goto Cleanup;
        }

        // Calculate change in length
        length = DataSize - Var->DataSize;

        // Variable increasing in size?
        if (DataSize > Var->DataSize)
        {
            // Make sure it will fit
            if ((s_VolatileSize + length) > MAX_VOLATILE_STORAGE)
            {
                status = TEE_ERROR_OUT_OF_MEMORY;
                goto Cleanup;
            }
        }

        // Realloc variable data
        if (!(dstPtr = TEE_Realloc(Var->DataOffset, DataSize)))
        {
            EMSG("Volatile replace error: out of memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Repalce variable data
        memmove(dstPtr, Data, DataSize);

        // Update fields (also realloc could have moved our data)
        Var->DataOffset = dstPtr;
        Var->DataSize = DataSize;
        Var->Attributes.Flags = Attributes.Flags;

        // Update volatile quota (note length may be negative)
        s_VolatileSize += length;

        // Success, return
        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else
    {
        // No, replace existing non-volatile variable.
        FMSG("Replacing non-volatile variable");

        // Extended attributes
        if (ExtAttributes)
        {
            // Sanity check extended attributes
            extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.Size;
            if (extAttribLen != Var->ExtAttribSize)
            {
                status = TEE_ERROR_BAD_PARAMETERS;
                goto Cleanup;
            }
        }

        // Calculate total size needed to store this variable
        reqSize = sizeof(UEFI_VARIABLE) + Var->NameSize + Var->ExtAttribSize + DataSize;

        // realloc variable
        // Remove from the list incase the variable is moved.
        RemoveEntryList(&Var->List);
        if (!(newVar = TEE_Realloc(Var, reqSize)))
        {
            EMSG("Replace NON volatile variable error: Out of memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Add back to the lists
        GetVariableType(newVar->BaseAddress + newVar->NameOffset, &newVar->VendorGuid, Attributes, &varType);
        InsertTailList(&VarInfo[varType].Head, &newVar->List);

        // Update variable fields and copy data (realloc may have moved var)
        newVar->BaseAddress = newVar;
        newVar->Attributes.Flags = Attributes.Flags;
        newVar->DataSize = DataSize;
        dstPtr = newVar->BaseAddress + newVar->DataOffset;
        memcpy(dstPtr, Data, DataSize);

        // Extended attributes
        if (ExtAttributes)
        {
            dstPtr = newVar->BaseAddress + newVar->ExtAttribOffset;
            memmove(dstPtr, ExtAttributes, extAttribLen);
        }

        // Update variable in nv
        status = NvUpdateVariable(newVar);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        // Success
        status = TEE_SUCCESS;
        goto Cleanup;
    }
Cleanup:
#ifdef AUTHVAR_DEBUG
    AuthVarDumpVarList();
#endif
    return status;
}

VOID
QueryByAttribute(
    ATTRIBUTES  Attributes,             // IN
    PUINT64     MaxVarStorage,          // OUT
    PUINT64     RemainingVarStorage,    // OUT
    PUINT64     MaxVarSize              // OUT
)
/*++

    Routine Description:

        Calculates storage space information for the given attributes

    Arguments:

        Attributes - UEFI variable attributes

        MaxVarStorage - Size of storage for EFI variables associted with specified attributes

        RemainingVarStorage - Storage remaining for EFI variables associted with specified attributes

        MaxVarSize - Maximum size of an individual variable with specified attributes

    Returns:

        VOID

--*/
{   
    VARTYPE varType;
    PUEFI_VARIABLE pVar;
    UINT64 MaxSize = 0;
    UINT64 TotalSize = 0;
    UINT32 VarSize = 0;
    PLIST_ENTRY head, cur;

    // Note that since we are not provided a (name,guid) for a query, we
    // cannot provide information on secureboot variable storage.
    DMSG("Querying variables by attributes");

    // Do we have enough to determine a valid type?
    if (!GetVariableType(NULL, NULL, Attributes, &varType))
    {
        EMSG("Query by attributes error: bad attributes");
        return;
    }

    // GetVariableType doesn't differentiate between volatile/non-volatile
    if(!(Attributes.NonVolatile)) {
        varType = VTYPE_VOLATILE;
    }

    // Init
    head = &VarInfo[varType].Head;
    cur = head->Flink;

    // Run the list for this type
    while ((cur) && (cur != head))
    {
        // Pickup ptr to variable
        pVar = (PUEFI_VARIABLE)cur;

        // From UEFI Spec 2.7:
        // MaximumVariableSize includes overhead needed to store the variable,
        // but not the overhead caused by storing the name.

        // Calculate size for var (volatile vars ExtAttribSize == 0)
        VarSize = sizeof(UEFI_VARIABLE) + pVar->DataSize + pVar->ExtAttribSize;

        // Track sizes
        MaxSize = MAX(MaxSize, VarSize);

        // We count name length in total
        TotalSize += VarSize + pVar->NameSize;
        
        // Goto next entry
        cur = cur->Flink;
    }

    // Fill in output values (max storage first)
    if (MaxVarStorage)
    {
        // No need to differentiate between types for max var storage
        *MaxVarStorage = NV_AUTHVAR_SIZE;
        FMSG("Max storage is 0x%x", (UINT32)MaxVarStorage);
    }

    // Remaining storage by type (volatile/non-volatile)
    if (RemainingVarStorage)
    {
        if(varType == VTYPE_VOLATILE)
        {
            *RemainingVarStorage = (MAX_VOLATILE_STORAGE - s_VolatileSize);
            FMSG("Remaining volatile storage is 0x%x - 0x%x = 0x%x",
                    (UINT32)MAX_VOLATILE_STORAGE,
                    (UINT32)TotalSize,
                    (UINT32)*RemainingVarStorage);
        } else {
            // This is a lie. We don't really have a better answer though.
            *RemainingVarStorage = ((NV_AUTHVAR_SIZE - s_VolatileSize) - s_NonVolatileSize);
            FMSG("Remaining NV storage is 0x%x", (UINT32)RemainingVarStorage);
        }
    }

    // Maximum size for this type
    if (MaxVarSize)
    {
        *MaxVarSize = MaxSize;
        FMSG("Max variable size is 0x%x", (UINT32)MaxSize);
    }

    return;
}

//
// Helper function(s)
//

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
        DMSG("Failed to allocate digest operation");
        goto Cleanup;
    }

    // Include VendorGuid first
    TEE_DigestUpdate(opHandle, &(Var->VendorGuid), sizeof(Var->VendorGuid));

    // Then name, finalizing hash
    namePtr = (PVOID)(Var->BaseAddress + Var->NameOffset);
    status = TEE_DigestDoFinal(opHandle, namePtr, Var->NameSize, (PVOID)qHash, &length);
    if (status != TEE_SUCCESS)
    {
        DMSG("Failed to finalize digest operation");
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
            EMSG("Collision on ObjectID, duplicate (GUID, Name)?");
            TEE_Panic(TEE_ERROR_ACCESS_CONFLICT);
        }

        // Other unexpected error
        EMSG("Failed to create persistent object with error 0x%x", status);
        goto Cleanup;
    }

    // Write out this variable
    status = TEE_WriteObjectData(VarList[i].ObjectHandle, (PVOID)Var, dataSize);
    if (status != TEE_SUCCESS)
    {
        EMSG("Failed to write object");
        goto Cleanup;
    }

    // Link to new var
    VarList[i].Var = Var;
    Var->MetaIndex = i;

    // Update next free index
    AuthVarNextFreeIdx(&NextFreeIdx);

    // Success, return
    status = TEE_SUCCESS;

Cleanup:
    if(IS_VALID(opHandle))
    {
        TEE_FreeOperation(opHandle);
    }
    return status;
}

static
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

    // Success, return
    status = TEE_SUCCESS;
Cleanup:
    return status;
}

static
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

    // Close and delete backing object
    status = TEE_CloseAndDeletePersistentObject1(VarList[i].ObjectHandle);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // Free in-memory variable
    TEE_Free(VarList[i].Var);

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

static
BOOLEAN
CompareEntries(
    PCUNICODE_STRING     Name,      // IN
    PCGUID               Guid,      // IN
    PUEFI_VARIABLE       Var        // IN
)
/*++

    Routine Description:

        Routine for checking if a variable matches a name and GUID.

    Arguments:

        Name - The name to match

        Guid - The GUID to match

        Var - The first block of the variable to compare against

    Returns:

        TRUE if the same, FALSE otherwise

--*/
{    
    BOOLEAN retVal = FALSE;

    // First, matching GUIDS?
    if (memcmp(Guid, &Var->VendorGuid, sizeof(GUID)) == 0)
    {
        // Ok, name strings of the same length?
        // When NameSize was set any extra trailing characters beyond the null
        // terminator were ignored, so it should correctly match Name->Length + WCHAR.
        if (Name->Length == (Var->NameSize - sizeof(WCHAR)))
        {
            // Yes, do they match? (case sensitive!)
            if (wcscmp(Name->Buffer, (PWCHAR)(Var->BaseAddress + Var->NameOffset)) == 0)
            {
                // Win.
                retVal = TRUE;
            }
        }
    }
    return retVal;
}

static
BOOLEAN
GetVariableType(
    PCWSTR      VarName,        // IN
    PCGUID      VendorGuid,     // IN
    ATTRIBUTES  Attributes,     // IN
    PVARTYPE    VarType         // OUT
)
/*++

    Routine Description:

        Function for determining Non-volatile variable type based on
            attributes, and optionally name and GUID.

    Arguments:

        VarName - Name of the variable being searched, NULL to ignore

        VendorGuid - GUID of the variable, NULL to ignore

        Attributes - UEFI attributes of the variable

        VarType - Storage for result

    Returns:

        TRUE - Success, VarType contains variable type

        FALSE - Appended or deleted data, VarType not updated

--*/
{
    // An empty attributes field or guid means this is deleted data
    if (!(Attributes.Flags) || (VendorGuid != NULL && !memcmp(VendorGuid, &GUID_NULL, sizeof(GUID))))
    {
        return FALSE;
    }

    // VarName and VendorGuid may be NULL if we are just determining what
    // type of attributes we have.
    if (VendorGuid != NULL && VarName != NULL && IsSecureBootVar(VarName, VendorGuid))
    {
        *VarType = VTYPE_SECUREBOOT;
        return TRUE;
    }

    // Runtime Auth?
    if ((Attributes.RuntimeAccess) && (Attributes.TimeBasedAuth))
    {
        *VarType = VTYPE_PVT_AUTHENTICATED;
        return TRUE;
    }
    
    // Boot only?
    if ((Attributes.BootService) && !(Attributes.RuntimeAccess))
    {
        *VarType = VTYPE_BOOT;
        return TRUE;
    }

    // None of the above (but assumed NonVolatile).
    *VarType = VTYPE_GENERAL;
    return TRUE;
}

static
BOOLEAN
IsSecureBootVar(
    PCWSTR  VarName,        // IN
    PCGUID  VendorGuid      // IN
)
/*++

    Routine Description:

        Function for checking if a variable is one of DB, DBX, KEK or PK

    Arguments:

        VarName - Name of the variable being searched

        VendorGuid - GUID of the variable

    Returns:

        TRUE if secureboot variable, FALSE otherwise

--*/
{
    BOOLEAN retVal = FALSE;

    // Without (name, guid) we don't know one way or the other
    if (!(VarName) || !(VendorGuid))
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // db/dbx
    if (memcmp(VendorGuid, &EfiSecurityDatabaseGUID, sizeof(GUID)) == 0)
    {
        if (!(wcscmp(VarName, EFI_IMAGE_SECURITY_DATABASE)) ||
            !(wcscmp(VarName, EFI_IMAGE_SECURITY_DATABASE1)))
        {
            retVal = TRUE;
            goto Cleanup;
        }
    }

    // KEK/PK
    if (memcmp(VendorGuid, &EfiGlobalDatabaseGUID, sizeof(GUID)) == 0)
    {
        if (!(wcscmp(VarName, EFI_KEK_SECURITY_DATABASE)) ||
            !(wcscmp(VarName, EFI_PLATFORMKEY_VARIABLE)))
        {
            retVal = TRUE;
            goto Cleanup;
        }
    }

    // No match
    retVal = FALSE;

Cleanup:
    return retVal;
}

// Debug
#ifdef AUTHVAR_DEBUG
PCHAR
ConvertWCharToChar(
    WCHAR   *Unicode,
    CHAR    *Ascii,
    UINT32   AsciiBufferLength
)
{
    CHAR *returnPtr = Ascii;
    while (Unicode != L'\0' && AsciiBufferLength > 1) {
        if (*Unicode <= 0x7F) {
            *Ascii = (CHAR)*Unicode;
        }
        else {
            *Ascii = '#';
        }
        Ascii++;
        Unicode++;
        AsciiBufferLength--;
    }
    *Ascii = '\0';
    return returnPtr;
}

VOID
AuthVarDumpVarList(
    VOID
)
{
    const char *varName;
    UINT32 varSize, i;
    PUEFI_VARIABLE pVar;
    PCCH varType;
    PLIST_ENTRY head, cur;
    const UINT32 maxNameLength = 50;
    CHAR convertedNameBuf[maxNameLength];

    FMSG("================================");
    FMSG("\tVolatile:");
    FMSG("                              | Address | Alloc( Data Size ) | State ");
    
    head = &VarInfo[VTYPE_VOLATILE].Head;
    cur = head->Flink;

    // Run the list for this type
    while ((cur) && (cur != head)) {
        pVar = (PUEFI_VARIABLE)cur;
        varName = pVar->NameOffset;
        varName = ConvertWCharToChar((WCHAR *)varName, convertedNameBuf, maxNameLength);
        varSize = sizeof(UEFI_VARIABLE) + pVar->NameSize + pVar->ExtAttribSize + pVar->DataSize;
        varType = "    ";

        FMSG("%-30s|%#9lx| A:%#6x(D:%#6x) | %s |",
            varName, (UINT_PTR)pVar, varSize, pVar->DataSize, varType);

        cur = cur->Flink;
    }

    FMSG("================================");
    FMSG("\tNon Volatile:");

    for (i = 0; i < MAX_AUTHVAR_ENTRIES; i++)
    {
        if (!VarList[i].Var)
        {
            continue;
        }

        pVar = VarList[i].Var;
        varName = (UINT_PTR)pVar + pVar->NameOffset;
        varName = ConvertWCharToChar((WCHAR *)varName, convertedNameBuf, maxNameLength);
        varSize = sizeof(UEFI_VARIABLE) + pVar->NameSize + pVar->ExtAttribSize + pVar->DataSize;

        if (pVar->Attributes.AuthWrite || pVar->Attributes.TimeBasedAuth) {
            varType = "AUTH";
        }
        else {
            varType = "    ";
        }

        FMSG("%-30s|%#9lx| A:%#6x(D:%#6x) | %s |",
            varName, (UINT_PTR)pVar, varSize, pVar->DataSize, varType);
    }

    FMSG("================================");
}
#endif
