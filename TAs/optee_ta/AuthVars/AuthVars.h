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

#ifndef AUTHVARS_TA_H
#define AUTHVARS_TA_H

#include <varops.h>

//
// This UUID is generated with uuidgen
//
#define TA_AUTHVARS_UUID { 0x2d57c0f7, 0xbddf, 0x48ea, \
    {0x83, 0x2f, 0xd8, 0x4a, 0x1a, 0x21, 0x93, 0x01}}

//
// The TAFs ID implemented in this TA
//
#define TA_AUTHVAR_GET_VARIABLE         (0) // Get authenticated variable
#define TA_AUTHVAR_GET_NEXT_VARIABLE    (1) // Get next autheiticated variable
#define TA_AUTHVAR_SET_VARIABLE         (2) // Set authenticated variable
#define TA_AUTHVAR_QUERY_VARINFO        (3) // Query authenticated variable info
#define TA_AUTHVAR_EXIT_BOOT_SERVICES   (4) // Used to signal ExitBootServices()

//
// Macro for intentionally unreferenced parameters
//
#define UNREFERENCED_PARAMETER(_Parameter_) (void)(_Parameter_)

//
// Shorthand for TA functions taking uniform arg types
//
#define TA_ALL_PARAM_TYPE(a) TEE_PARAM_TYPES((a), (a), (a), (a))

//
// External functions supporting initialization
//
extern int  AuthVarInitStorage();
extern void AuthVarCloseStorage();

#endif /* AUTHVARS_TA_H */