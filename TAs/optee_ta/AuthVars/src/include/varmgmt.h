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

#pragma once
#include <varops.h>

 // For cleaner descriptor validation
#define IS_VALID(a)         ((a) != (TEE_HANDLE_NULL))

 // Storage flags
#define TA_STORAGE_FLAGS    (TEE_DATA_FLAG_ACCESS_READ  | \
                             TEE_DATA_FLAG_ACCESS_WRITE | \
                             TEE_DATA_FLAG_ACCESS_WRITE_META)

 // Maximum number of variables we'll track
#define MAX_AUTHVAR_ENTRIES     (256)

 // MUST MATCH TA_DATA_SIZE (user_ta_header_defines.h)
#define NV_AUTHVAR_SIZE         (512 * 1024) // = 0x80000

 // Maximum possible storage (TA_DATA_SIZE) for volatile vars
#define MAX_VOLATILE_STORAGE    (0x40000)   // = NV_AUTHVAR_SIZE / 2

// (guid,name) digest quadword count
#define TEE_DIGEST_QWORDS      ((TEE_SHA256_HASH_SIZE) / sizeof(UINT64))

// Update if architected objectID length changes!
#if TEE_OBJECT_ID_MAX_LEN > 64
#error "Unexpected TEE_OBJECT_ID_MAX_LEN!"
#else
typedef struct _AUTHVAR_META
{
    UINT64              ObjectID;       // Storage object identifier
    TEE_ObjectHandle    ObjectHandle;   // Handle to open storage object
    PUEFI_VARIABLE      Var;            // In-memory variable
} AUTHVAR_META, *PAUTHVAR_META;
#endif 

TEE_Result
AuthVarInitStorage(
    VOID
);

TEE_Result
AuthVarCloseStorage(
    VOID
);

VOID
SearchList(
    PCUNICODE_STRING     UnicodeName,   // IN
    PCGUID               VendorGuid,    // IN
    PUEFI_VARIABLE      *Var,           // OUT
    VARTYPE             *VarType        // OUT
);

TEE_Result
CreateVariable(
    PCUNICODE_STRING        UnicodeName,        // IN
    PCGUID                  VendorGuid,         // IN
    ATTRIBUTES              Attributes,         // IN
    PEXTENDED_ATTRIBUTES    ExtAttributes,      // IN
    UINT32                  DataSize,           // IN
    PBYTE                   Data                // IN
);

TEE_Result
RetrieveVariable(
    PUEFI_VARIABLE       Var,           // IN
    VARIABLE_GET_RESULT *ResultBuf,     // OUT
    UINT32               ResultBufLen,  // IN
    UINT32              *BytesWritten   // OUT (optional)
);

TEE_Result
DeleteVariable(
    PUEFI_VARIABLE  Variable    // IN
);

TEE_Result
AppendVariable(
    PUEFI_VARIABLE          Var,            // IN
    ATTRIBUTES              Attributes,     // IN
    PEXTENDED_ATTRIBUTES    ExtAttributes,  // IN
    PBYTE                   Data,           // IN
    UINT32                  DataSize        // IN
);

TEE_Result
ReplaceVariable(
    PUEFI_VARIABLE          Var,            // IN
    ATTRIBUTES              Attributes,     // IN
    PEXTENDED_ATTRIBUTES    ExtAttributes,  // IN
    PBYTE                   Data,           // IN
    UINT32                  DataSize        // IN
);

VOID
QueryByAttribute(
    ATTRIBUTES  Attributes,             // IN
    PUINT64     MaxVarStorage,          // OUT
    PUINT64     RemainingVarStorage,    // OUT
    PUINT64     MaxVarSize              // OUT
);

#ifdef AUTHVAR_DEBUG
VOID
AuthVarDumpVarListImpl(
    VOID
);
#endif