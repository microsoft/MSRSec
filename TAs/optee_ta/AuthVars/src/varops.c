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

#include <varops.h>
#include <varmgmt.h>
#include <varauth.h>

//
// Secureboot variable guids
//
const GUID EfiGlobalDatabaseGUID = EFI_GLOBAL_VARIABLE;
const GUID EfiSecurityDatabaseGUID = EFI_IMAGE_SECURITY_DATABASE_GUID;

//
// Helper function prototype(s)
//

#ifdef AUTHVAR_DEBUG
static
VOID
IMSGBuffer(
    BYTE    *buf,
    UINT32  size
);

extern
PCHAR
ConvertWCharToChar(
    WCHAR   *Unicode,
    CHAR    *Ascii,
    UINT32   AsciiBufferLength
);
#endif

//
// AuthVar functions
//

TEE_Result
GetVariable(
    UINT32               GetParamSize,  // IN
    VARIABLE_GET_PARAM  *GetParam,      // IN
    UINT32              *GetResultSize, // INOUT
    VARIABLE_GET_RESULT *GetResult      // OUT
)
/*++

    Routine Description:

        Function for implementing UEFI GetVariable operation

    Arguments:

        GetParamSize - Length in bytes of input buffer

        GetParam - Pointer to input buffer

        GetResultSize - Length in bytes of output buffer

        GetResult - Pointer to output buffer

    Returns:

        TEE_Result

--*/
{   
    VARTYPE varType;
    PWSTR varName;
    PUEFI_VARIABLE varPtr;
    GUID vendorGuid;
    UNICODE_STRING unicodeName;
    TEE_Result status = TEE_SUCCESS;

#ifdef AUTHVAR_DEBUG
    DMSG("GetVariable");
    char name[64];
    IMSG("\t>>>>>>>>>  %s  >>>>>>>>>", ConvertWCharToChar(GetParam->Name, name, 64));
#endif

    // Validate parameters
    if (!(GetParam) || !(GetResult) || (GetParamSize  < sizeof(VARIABLE_GET_PARAM)))
    {
        EMSG("Get variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Request validation
    if (!(GetResultSize) || (GetParam->Size != sizeof(VARIABLE_GET_PARAM)))
    {
        EMSG("Get variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Size of result buffer
    if (*GetResultSize < sizeof(VARIABLE_GET_RESULT))
    {
        EMSG("Get variable error: Short buffer");
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Validation of var name size
    if (((GetParam->NameSize) == 0) || (GetParam->NameSize % sizeof(WCHAR)))
    {
        EMSG("Get variable error: Null or unaligned name");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Guard against overflow with name string
    if (((GetParam->NameSize + sizeof(VARIABLE_GET_PARAM)) < GetParam->NameSize) ||
        (GetParamSize < (sizeof(VARIABLE_GET_PARAM) + GetParam->NameSize)))
    {
        EMSG("Get variable error: Overflow on name string length");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Retreive (name, guid)
    varName = (PWSTR)(GetParam->Name);
    vendorGuid = GetParam->VendorGuid;

    // Init local name string
    memset(&unicodeName, 0, sizeof(unicodeName));
    unicodeName.Buffer = varName;
    unicodeName.Length = wcslen(unicodeName.Buffer) * sizeof(WCHAR);
    unicodeName.MaximumLength = unicodeName.Length + sizeof(WCHAR);

    // Sanity check max length
    if(unicodeName.MaximumLength > GetParam->NameSize)
    {
        EMSG("Get variable error: Name not null terminated");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Find the variable
    SearchList(&unicodeName, &vendorGuid, &varPtr, &varType);

    // Did we find it?
    if (!(varPtr))
    {
        // No.
        status = TEE_ERROR_ITEM_NOT_FOUND;
        DMSG("Get variable warning: Name not found");
        goto Cleanup;
    }

    // Yes, go get it.
    status = RetrieveVariable(varPtr, GetResult, *GetResultSize, GetResultSize);
    if(status == TEE_ERROR_SHORT_BUFFER) {
        DMSG("Short buffer, need 0x%x bytes", *GetResultSize);
    } else {
        DMSG("Retrieved up to 0x%x bytes into 0x%lx", *GetResultSize, (UINT_PTR)GetResult);
    }

Cleanup:
#ifdef AUTHVAR_DEBUG
    if(status == TEE_SUCCESS)
    {
        IMSGBuffer(GetResult->Data, GetResult->DataSize);
    }
    else
    {   // Non-success return status
        if (status == TEE_ERROR_ITEM_NOT_FOUND || status == TEE_ERROR_SHORT_BUFFER)
        {
            DMSG("Get returned with status: 0x%x", status);
        }
        else
        {
            EMSG("Get failed with status: 0x%x", status);
        }
    }
#endif
    return status;
}

TEE_Result
GetNextVariableName(
    UINT32                       GetNextParamSize,
    VARIABLE_GET_NEXT_PARAM     *GetNextParam,
    UINT32                      *GetNextResultSize,
    VARIABLE_GET_NEXT_RESULT    *GetNextResult
)
/*++

    Routine Description:

        Function implementing UEFI GetNextVariableName operation

    Arguments:

        GetNextParamSize - Length in bytes of input buffer

        GetNextParam - Pointer to input buffer

        GetNextResultSize - Length in bytes of output buffer

        GetNextResult - Pointer to output buffer

    Returns:

        TEE_Result

--*/
{  
    UNICODE_STRING unicodeName;
    GUID vendorGuid;
    PUEFI_VARIABLE varPtr, nextVar;
    PWSTR varName;
    UINT32 size, i;
    TEE_Result status;
    VARTYPE varType;
    UINT16 varNameLen;

    // Validate parameters
    if (!(GetNextParam) || !(GetNextResult) || (GetNextParamSize < sizeof(VARIABLE_GET_NEXT_PARAM)))
    {
        EMSG("Get next variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Request validation
    if (!(GetNextResultSize) || (GetNextParam->Size != sizeof(VARIABLE_GET_NEXT_PARAM)))
    {
        EMSG("Get next variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Size of result buffer
    if (*GetNextResultSize < sizeof(VARIABLE_GET_NEXT_PARAM))
    {
        EMSG("Get next variable error: Short buffer");
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Init for search
    nextVar = NULL;
    varNameLen = GetNextParam->NameSize;

    // Is this the first request?
    if (!varNameLen)
    {
        // Yes, return first variable that can be found in any list
        for (i = 0; i < ARRAY_SIZE(VarInfo); i++)
        {
            if (!IsListEmpty(&VarInfo[i].Head))
            {
                // Pick up first variable
                nextVar = (PUEFI_VARIABLE)VarInfo[i].Head.Flink;
                break;
            }
        }
    }
    else
    {
        // Validation on name length (we already know it's non-zero)
        if (varNameLen % sizeof(WCHAR))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Guard against overflow
        if (((varNameLen + sizeof(VARIABLE_GET_NEXT_PARAM)) < varNameLen) ||
            (GetNextParamSize < (sizeof(VARIABLE_GET_NEXT_PARAM) + varNameLen)))
        {
            EMSG("Get next variable error: Overflow on name string length");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Retreive (name, guid)
        varName = (PWSTR)(GetNextParam->Name);
        vendorGuid = GetNextParam->VendorGuid;

        // Init local name string
        memset(&unicodeName, 0, sizeof(unicodeName));
        unicodeName.Buffer = varName;
        unicodeName.Length = wcslen(unicodeName.Buffer) * sizeof(WCHAR);
        unicodeName.MaximumLength = unicodeName.Length + sizeof(WCHAR);

        // Sanity check max length
        if(unicodeName.MaximumLength > varNameLen)
        {
            EMSG("Get next variable error: Name not null terminated");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Find the last variable in the list
        SearchList(&unicodeName, &vendorGuid, &varPtr, &varType);

        // Did we find it?
        if (varPtr == NULL)
        {
            // No.
            EMSG("Get next variable error: Name not found");
            status = TEE_ERROR_ITEM_NOT_FOUND;
            goto Cleanup;
        }

        // Yes. If this isn't the end of this list, get next.
        if (varPtr->List.Flink != &(VarInfo[varType].Head))
        {
            nextVar = (PUEFI_VARIABLE)varPtr->List.Flink;
        }
        else
        {
            // End of this list, move to the next category
            while (++varType != VTYPE_END)
            {
                if (!IsListEmpty(&(VarInfo[varType].Head)))
                {
                    nextVar = (PUEFI_VARIABLE)VarInfo[varType].Head.Flink;
                    break;
                }
            }
        }
    }

    // Are we done?
    if (nextVar == NULL)
    {
        DMSG("Get next variable done, no more variables left");
        status = TEE_ERROR_ITEM_NOT_FOUND;
        goto Cleanup;
    }

    // Prepare the result buffer with variable size, name, and guid
    size = nextVar->NameSize + sizeof(VARIABLE_GET_NEXT_RESULT);
    if (size < nextVar->NameSize)
    {
        EMSG("Get next variable error: Overflow result buffer");
        status = TEE_ERROR_BAD_STATE;
        goto Cleanup;
    }

    // Validate buffer length
    if (size > *GetNextResultSize)
    {
        DMSG("Get next variable error: Short buffer, need 0x%x bytes", *GetNextResultSize);
        *GetNextResultSize = size;
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Update output buffer
    GetNextResult->NameSize = nextVar->NameSize;
    GetNextResult->VendorGuid = nextVar->VendorGuid;
    varName = nextVar->NameOffset + nextVar->BaseAddress;
    memmove(GetNextResult->Name, varName, nextVar->NameSize);

    // Success, now update size field with bytes written
    *GetNextResultSize = sizeof(VARIABLE_GET_NEXT_RESULT) + nextVar->NameSize;
    GetNextResult->Size = *GetNextResultSize;

    // Success, return
    status = TEE_SUCCESS;

Cleanup:
#ifdef AUTHVAR_DEBUG
    if ((status == TEE_ERROR_SHORT_BUFFER) || (status == TEE_ERROR_ITEM_NOT_FOUND))
    {
        DMSG("Get next variable returned with 0x%x", status);
    } 
    else if (status != TEE_SUCCESS)
    {
        EMSG("Get next variable failed with 0x%x", status);
    }
#endif
    return status;
}

TEE_Result
SetVariable(
    UINT32               SetParamSize,
    VARIABLE_SET_PARAM  *SetParam
)
/*++

    Routine Description:

        Function implementing UEFI SetVariable operation

    Arguments:

        SetParamSize - Length in bytes of input buffer

        SetParam - Pointer to input buffer

    Returns:

        TEE_Result

--*/
{
    EXTENDED_ATTRIBUTES extAttrib = {0};
    UNICODE_STRING unicodeName;
    GUID vendorGuid;
    PBYTE data, content;
    PWSTR varName = NULL;
    PUEFI_VARIABLE varPtr;
    UINT_PTR alignCheck;
    TEE_Result status;
    UINT32 varNameSize, offset;
    UINT32 dataSize, contentSize;
    UINT32 offsetLimit, totalSize;
    VARTYPE varType;
    ATTRIBUTES attrib;
    BOOLEAN duplicateFound = FALSE, isDeleteOperation = FALSE;

#ifdef AUTHVAR_DEBUG
    DMSG("SetVariable");
#endif

    // Validate parameters
    if (!(SetParam) || (SetParamSize < sizeof(VARIABLE_SET_PARAM)) ||
         (SetParam->Size != sizeof(VARIABLE_SET_PARAM)))
    {
        EMSG("Set variable error: Bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Pickup sizes
    dataSize = SetParam->DataSize;
    varNameSize = SetParam->NameSize;
    totalSize = sizeof(VARIABLE_SET_PARAM) + dataSize + varNameSize;
    offsetLimit = SetParamSize - sizeof(VARIABLE_SET_PARAM);

    // Validate sizes
    if ((varNameSize + sizeof(VARIABLE_SET_PARAM) < varNameSize)
        || (dataSize + sizeof(VARIABLE_SET_PARAM) < dataSize)
        || (dataSize + varNameSize < MAX(dataSize, varNameSize))
        || (totalSize < MAX(sizeof(VARIABLE_SET_PARAM), MAX(dataSize, varNameSize))))
    {
        EMSG("Set variable error: Buffer overflow");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Validate offsets
    if ((totalSize < SetParamSize)
        || (SetParam->OffsetName > offsetLimit)
        || (SetParam->OffsetData > offsetLimit)
        || (SetParam->OffsetName + varNameSize > offsetLimit)
        || (SetParam->OffsetData + dataSize > offsetLimit))
    {
        EMSG("Set variable error: Bad parameters (sizes/offsets)");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // We expect the name of the variable before the data (if provided)
    if ((SetParam->DataSize) && (SetParam->OffsetName > SetParam->OffsetData))
    {
        EMSG("Set variable error: Bad parameters (name/size)");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Alignment check on variable name offset
    if (SetParam->OffsetName % sizeof(WCHAR))
    {
        EMSG("Set variable error: Unaligned name");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Now pickup parameter fields
    vendorGuid = SetParam->VendorGuid;
    attrib.Flags = SetParam->Attributes.Flags;

    // And validate alignment
    offset = SetParam->OffsetName;
    alignCheck = ROUNDUP((UINT_PTR)&SetParam->Payload[offset], __alignof__(WCHAR));
    if ((UINT_PTR)&SetParam->Payload[offset] != alignCheck)
    {
        EMSG("Set variable error: Received unaligned data");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
    }
    else
    {
        varName = (PWSTR)ROUNDUP((UINT_PTR)(&SetParam->Payload[offset]), __alignof__(WCHAR));
#ifdef AUTHVAR_DEBUG
        char name[64];
        IMSG("\t<<<<<<<<<  %s  <<<<<<<<<", ConvertWCharToChar(varName, name, 64));
#endif
    }

    // Only need byte alignment on data
    data = &SetParam->Payload[SetParam->OffsetData];

    // Don't consider NULL character in Length
    memset(&unicodeName, 0, sizeof(unicodeName));
    unicodeName.Buffer = varName;
    unicodeName.Length = wcslen(unicodeName.Buffer) * sizeof(WCHAR);
    unicodeName.MaximumLength = unicodeName.Length + sizeof(WCHAR);

    // Sanity check max length
    if(unicodeName.MaximumLength > varNameSize)
    {
        DMSG("Set variable error: Name not null terminated");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Attribute validation
    if ((attrib.Flags & (~EFI_KNOWN_ATTRIBUTES)) != 0)
    {
        EMSG("Set variable error: Unknown attributes");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (attrib.AuthWrite && attrib.TimeBasedAuth)
    {
        EMSG("Set variable error: Inconsistent authentication attributes");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (attrib.AuthWrite || attrib.HwErrorRec)
    {
        EMSG("Set variable error: HwErrorRec not implemented");
        return TEE_ERROR_NOT_IMPLEMENTED;
    }

    // Optimism, from here out
    status = TEE_SUCCESS;

    // Look for existing (guid, name)
    SearchList(&unicodeName, &vendorGuid, &varPtr, &varType);

    // Set() on a variable causes deletion when:
    //   1. Setting a data variable with no access attributes
    //   2. dataSize is zero unless write attribute(s) set
    isDeleteOperation = (!(attrib.Flags & EFI_ACCESS_ATTRIBUTES)) ||
                        ((dataSize == 0) && !(attrib.Flags & EFI_WRITE_ATTRIBUTES));

    // Does the variable exist already?
    if (varPtr != NULL)
    {
        // Yes, it does
        DMSG("Found an existing variable");
        // Existing attributes may only differ in EFI_VARIABLE_APPEND_WRITE
        // unless we are deleting the variable.
        if (!(isDeleteOperation) &&
            (((attrib.Flags) ^ (varPtr->Attributes.Flags)) & ~(EFI_VARIABLE_APPEND_WRITE)))
        {
            EMSG("Set variable error: Inconsistent Attributes");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        // If isDeleteOperation, attrib parameter comes from existing variable
        if (isDeleteOperation)
        {
            attrib.Flags = varPtr->Attributes.Flags;
        }

        // Once ExitBootServices() is performed..
        if ((AuthVarIsRuntime) &&
            // ..only non-volatile variables with runtime access can be set
            !((varPtr->Attributes.RuntimeAccess) & (varPtr->Attributes.NonVolatile)))
        {
            EMSG("Set variable error: Can only set runtime access variables now");
            return TEE_ERROR_ACCESS_DENIED;
        }

        // If this is an existing authenticated variable, perform security check
        if (varPtr->Attributes.TimeBasedAuth)
        {
            DMSG("TimeBasedAuth");

            // REVISIT: duplicate search is not implemented at this time
            status = AuthenticateSetVariable(
                &unicodeName,
                &vendorGuid,
                varPtr,
                attrib,
                data,
                dataSize,
                &extAttrib,
                &duplicateFound, // REVISIT: Always FALSE
                &content,
                &contentSize);

            if (status != TEE_SUCCESS)
            {
                EMSG("Set variable error: Authentication failed with status: %x", status);
                goto Cleanup;
            }

            // Necessary if/when duplicate search is implemented
            data = content;
            dataSize = contentSize;
        }

        // Is this a deletion?
        if (isDeleteOperation)
        {
            DMSG("Deleting variable");
            RemoveEntryList((PLIST_ENTRY)varPtr);
            status = DeleteVariable(varPtr);
            goto Cleanup;
        }

        // Is this an append operation?
        if (attrib.AppendWrite)
        {
            DMSG("Appending variable");
            status = AppendVariable(varPtr, attrib, &extAttrib, data, dataSize);
            goto Cleanup;
        }

        // Neither? Then we are attempting replacement. Once ExitBootServices()
        // is performed only non-volatile variables that have runtime access can
        // be set. Variables that are not non-volatile are read-only data
        // variables once ExitBootServices() is performed. Note that Caller is
        // responsible for following BS-implies-RT rule.
        if ((!(AuthVarIsRuntime) && (attrib.BootService)) ||
            ((AuthVarIsRuntime) && (attrib.RuntimeAccess) && (attrib.NonVolatile)))
        {
            DMSG("Replacing variable");
            status = ReplaceVariable(varPtr, attrib, &extAttrib, data, dataSize);
            goto Cleanup;
        }

        // If we get here, then one or more parameters are invalid.
        EMSG("Set variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Variable doesn't already exist. Are we attempting deletion?
    if ((dataSize == 0) && isDeleteOperation)
    {
        status = TEE_ERROR_ITEM_NOT_FOUND;
        DMSG("Attempted deletion of non-existent variable.");
        goto Cleanup;
    }

    // No, then new variable creation. For NV, BS and BS+RT is allowed. RT-only
    // is invalid. However, caller is responsible for following BS-implies-RT rule.
    if ((attrib.NonVolatile) && (attrib.BootService))
    {
        DMSG("Creating non-volatile variable");
        if (attrib.TimeBasedAuth)
        {
            // REVISIT: duplicate search is not implemented at this time
            status = AuthenticateSetVariable(
                &unicodeName,
                &vendorGuid,
                NULL,
                attrib,
                data,
                dataSize,
                &extAttrib,
                &duplicateFound, // REVISIT: Always FALSE
                &content,
                &contentSize);

            if (status != TEE_SUCCESS)
            {
                EMSG("Set variable error: Authentication failed with status: %x", status);
                goto Cleanup;
            }

            // Necessary if/when duplicate search is implemented
            data = content;
            dataSize = contentSize;
        }

        // Create non-volatile variable
        status = CreateVariable(&unicodeName, &vendorGuid, attrib, &extAttrib, dataSize, data);
        goto Cleanup;
    }

    // Final possibility, could be a volatile variable and !RT yet
    if (!(attrib.NonVolatile) && !(AuthVarIsRuntime) && (attrib.BootService))
    {
        DMSG("Creating volatile variable");
        // REVISIT: Implement volatile auth variables if necessary (so far it isn't)
        if (attrib.TimeBasedAuth)
        {
            EMSG("Set variable error: Volatile time auth not implemented!");
            status = TEE_ERROR_NOT_IMPLEMENTED;
            goto Cleanup;
        }

        // Create volatile variable
        status = CreateVariable(&unicodeName, &vendorGuid, attrib, &extAttrib, dataSize, data);
        goto Cleanup;
    }

    // If we get here, then one or more parameters are invalid.
    EMSG("Set variable error: Bad parameters");
    status = TEE_ERROR_BAD_PARAMETERS;
    goto Cleanup;

Cleanup:
    // REVISIT: Always FALSE, but if/when it's implemented this will be necessary
    if (duplicateFound)
    {
        IMSG("Cleaning up duplicate authenticated variable content");
        TEE_Free(content);
    }

#ifdef AUTHVAR_DEBUG // REVISIT: Remove these
    if(status == TEE_SUCCESS)
    {
        IMSGBuffer(&SetParam->Payload[SetParam->OffsetData], dataSize);
    }
    else if (status == TEE_ERROR_ITEM_NOT_FOUND)
    {
        DMSG("Set returned with status: 0x%x", status);
    } 
    else 
    {
        EMSG("Set failed with status: 0x%x", status);
    }
#endif

    return status;
}

TEE_Result
QueryVariableInfo(
    UINT32                   QueryParamSize,    // IN
    VARIABLE_QUERY_PARAM    *QueryParam,        // IN
    UINT32                  *QueryResultSize,   // INOUT
    VARIABLE_QUERY_RESULT   *QueryResult        // OUT
)
/*++

    Routine Description:

        Function for implementing UEFI QueryVariableInfo operation

    Arguments:

        QueryParamSize - Length in bytes of input buffer

        QueryParam - Pointer to input buffer

        QueryResultSize - Length in bytes of output buffer

        QueryResult - Pointer to output buffer

    Returns:

        TEE_Result

--*/
{
    TEE_Result  status;
    ATTRIBUTES  attrib;

    // Validate parameters
    if (!(QueryParam) || !(QueryResult) || (QueryParamSize  < sizeof(VARIABLE_QUERY_PARAM)))
    {
        EMSG("Query variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Request validation
    if (!(QueryResultSize) || (QueryParam->Size != sizeof(VARIABLE_QUERY_PARAM)))
    {
        EMSG("Query variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Size of result buffer
    if (*QueryResultSize < sizeof(VARIABLE_QUERY_RESULT))
    {
        EMSG("Query variable error: Bad parameters");
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Pick up query attributes
    attrib.Flags = QueryParam->Attributes.Flags;

    // Validate requested attributes
    if ((attrib.Flags & ~(EFI_KNOWN_ATTRIBUTES)) 
        || ((AuthVarIsRuntime) && (attrib.BootService))
        || (attrib.AuthWrite) || (attrib.HwErrorRec))
    {
        EMSG("Query variable error: Bad parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Note that since we are not provided a (guid, name) for a query, we
    // cannot provide information on secureboot variable storage.
    QueryByAttribute(
        attrib,
        &(QueryResult->MaximumVariableStorageSize),
        &(QueryResult->RemainingVariableStorageSize),
        &(QueryResult->MaximumVariableSize));

    // Update sizes and return
    QueryResult->Size = *QueryResultSize = sizeof(VARIABLE_QUERY_RESULT);
    status = TEE_SUCCESS;

Cleanup:
    if(status != TEE_SUCCESS)
    {
        EMSG("Set failed with status: 0x%x", status);
    }
    return status;
}

#ifdef AUTHVAR_DEBUG
static
VOID
IMSGBuffer(
    BYTE        *Buf,
    UINT32      Size
)
{
    CHAR    string[1024];
    CHAR    *ptr = string;
    UINT32  inputNum = 0;
    UINT32  maxLines = 10;

    while (inputNum < Size) {
        uint8_t highByte = Buf[inputNum] >> 0x4;
        uint8_t lowByte = Buf[inputNum] & 0x0F;
        *(ptr++) = highByte < 0xA ? '0' + highByte : 'A' + (highByte - 0xA);
        *(ptr++) = lowByte < 0xA ? '0' + lowByte : 'A' + (lowByte - 0xA);

        inputNum++;

        if ((inputNum) % 32 == 0) {
            *(ptr++) = '\0';
            IMSG("%s", string);
            ptr = string;
            maxLines--;
        }
        else if ((inputNum) % 8 == 0) {
            *(ptr++) = ' ';
            *(ptr++) = ' ';
            *(ptr++) = ' ';
            *(ptr++) = ' ';
            *(ptr++) = ' ';
        }
        else {
            *(ptr++) = ' ';
        }

        if (!maxLines) {
            *(ptr++) = '.';
            *(ptr++) = '.';
            *(ptr++) = '.';
            break;
        }
    }
    *ptr = '\0';
    if (string[0] != '\0') {
        IMSG("%s", string);
    }
}
#endif