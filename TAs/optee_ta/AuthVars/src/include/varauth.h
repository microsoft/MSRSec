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
#include <varmgmt.h>

 // Selector for cert parsing (parse all or x509 only)
typedef enum _PARSE_SECURE_BOOT_OP {
    ParseOpAll = 0,
    ParseOpX509,
} PARSE_SECURE_BOOT_OP;

// The WIN_CERTIFICATE structure is part of the PE/COFF specification.
#pragma pack(push, 1)
typedef struct _WIN_CERTIFICATE
{
    //
    // The length of the entire certificate,
    // including the length of the header, in bytes.
    //

    UINT32 dwLength;

    //
    // The revision level of the WIN_CERTIFICATE
    // structure. The current revision level is 0x0200.
    //

    UINT16 wRevision;

    //
    // The certificate type. See WIN_CERT_TYPE_xxx for the UEFI
    // certificate types. The UEFI specification reserves the range of
    // certificate type values from 0x0EF0 to 0x0EFF.
    //

    UINT16 wCertificateType;

    //
    // The following is the actual certificate. The format of
    // the certificate depends on wCertificateType.
    //
    // UINT8 bCertificate[ANYSIZE_ARRAY];
    //

} WIN_CERTIFICATE;
#pragma pack(pop)

//
// Certificate which encapsulates a GUID-specific digital signature
//

#pragma pack(push, 1)
typedef struct _WIN_CERTIFICATE_UEFI_GUID
{
    //
    // This is the standard WIN_CERTIFICATE header, where
    // wCertificateType is set to WIN_CERT_TYPE_UEFI_GUID.
    //

    WIN_CERTIFICATE Hdr;

    //
    // This is the unique id which determines the
    // format of the CertData.
    //

    GUID CertType;

    //
    // The following is the certificate data. The format of
    // the data is determined by the CertType.
    // If CertType is EFI_CERT_TYPE_RSA2048_SHA256_GUID,
    // the CertData will be EFI_CERT_BLOCK_RSA_2048_SHA256 structure.
    //

    UINT8 CertData[1];
} WIN_CERTIFICATE_UEFI_GUID;
#pragma pack(pop)

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002
#define WIN_CERT_TYPE_EFI_PKCS115       0x0EF0
#define WIN_CERT_TYPE_EFI_GUID          0x0EF1

#pragma pack(push, 1)
typedef struct _EFI_SIGNATURE_DATA
{

    //
    // An identifier which identifies the agent which added the signature to the list.
    //

    GUID  SignatureOwner;

    //
    // The format of the signature is defined by the SignatureType.
    //
    // UINT8 SignatureData[1];

} EFI_SIGNATURE_DATA;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _EFI_SIGNATURE_LIST
{
    //
    // Type of the signature. GUID signature types are defined in below.
    //
    GUID SignatureType;

    //
    // Total size of the signature list, including this header.
    //
    UINT32 SignatureListSize;

    //
    // Size of the signature header which precedes the array of signatures.
    //
    UINT32 SignatureHeaderSize;

    //
    // Size of each signature.
    //
    UINT32 SignatureSize;

    //
    // Header before the array of signatures. The format of this header is specified
    // by the SignatureType.
    //
    // UINT8 SignatureHeader[SignatureHeaderSize];

    //
    // An array of signatures. Each signature is SignatureSize bytes in length.
    //
    // EFI_SIGNATURE_DATA Signatures[][SignatureSize];
} EFI_SIGNATURE_LIST;
#pragma pack(pop)

//
// EFI specific authentication structures
//

#pragma pack(push, 1)
typedef struct _EFI_VARIABLE_AUTHENTICATION_2
{

    //
    // For the TimeStamp value, components Pad1, Nanosecond, TimeZone, Daylight and
    // Pad2 shall be set to 0. This means that the time shall always be expressed in GMT.
    //
    EFI_TIME TimeStamp;

    //
    // Only a CertType of  EFI_CERT_TYPE_PKCS7_GUID is accepted.
    //
    WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;
#pragma pack(pop)

TEE_Result
AuthenticateSetVariable(
    PCUNICODE_STRING         UnicodeName,
    PGUID                    VendorGuid,
    PCUEFI_VARIABLE          VarPtr,
    ATTRIBUTES               Attributes,
    PBYTE                    Data,
    UINT32                   DataSize,
    PEXTENDED_ATTRIBUTES     ExtendedAttributes,
    PBOOLEAN                 DuplicateFound,
    PBYTE                   *Content,
    PUINT32                  ContentSize
);