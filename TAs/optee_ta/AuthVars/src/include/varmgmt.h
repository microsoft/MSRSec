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
#include <nvmem.h>

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

BOOLEAN
GetVariableType(
    PCWSTR      VarName,            // IN
    PCGUID      VendorGuid,         // IN
    ATTRIBUTES  Attributes,         // IN
    PVARTYPE    VarType             // OUT
);

#ifdef AUTHVAR_DEBUG
VOID
AuthVarDumpVarListImpl(
    VOID
);
#endif