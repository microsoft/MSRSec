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

#define EFI_IMAGE_SECURITY_DATABASE     L"db"
#define EFI_IMAGE_SECURITY_DATABASE1    L"dbx"
#define EFI_KEK_SECURITY_DATABASE       L"KEK"
#define EFI_PLATFORMKEY_VARIABLE        L"PK"

#define EFI_CERT_X509_GUID \
    { 0xa5c059a1, 0x94e4, 0x4aa7, \
    { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } }

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
    { 0xd719b2cb, 0x3d3a, 0x4596, \
    { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67, 0x65, 0x6f } }

#define EFI_GLOBAL_VARIABLE     \
    { 0x8BE4DF61, 0x93CA, 0x11d2, \
    { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } }

#define EFI_CERT_TYPE_PKCS7_GUID \
    { 0x4aafd29d, 0x68df, 0x49ee, \
    { 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7 } }

#pragma pack(push, 1)
typedef struct _EFI_TIME
{
    UINT16 Year;
    UINT8 Month;
    UINT8 Day;
    UINT8 Hour;
    UINT8 Minute;
    UINT8 Second;
    UINT8 Pad1;
    UINT32 Nanosecond;
    INT16 TimeZone;
    UINT8 Daylight;
    UINT8 Pad2;
} EFI_TIME;
#pragma pack(pop)

#define EFI_VARIABLE_NON_VOLATILE                           0x01UL
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                     0x02UL
#define EFI_VARIABLE_RUNTIME_ACCESS                         0x04UL
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                  0x08UL
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS             0x10UL
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS  0x20UL
#define EFI_VARIABLE_APPEND_WRITE                           0x40UL

#define EFI_KNOWN_ATTRIBUTES     (EFI_VARIABLE_NON_VOLATILE |\
                                  EFI_VARIABLE_BOOTSERVICE_ACCESS |\
                                  EFI_VARIABLE_RUNTIME_ACCESS |\
                                  EFI_VARIABLE_HARDWARE_ERROR_RECORD |\
                                  EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |\
                                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |\
                                  EFI_VARIABLE_APPEND_WRITE)

#define EFI_WRITE_ATTRIBUTES    (EFI_VARIABLE_APPEND_WRITE |\
                                 EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |\
                                 EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

#define EFI_ACCESS_ATTRIBUTES   (EFI_VARIABLE_BOOTSERVICE_ACCESS |\
                                 EFI_VARIABLE_RUNTIME_ACCESS |\
                                 EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |\
                                 EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
