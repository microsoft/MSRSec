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

#include <varauth.h>
#include <varmgmt.h>

// WC related definitions (in here for clarity's sake)
#define MAX_DECODED_CERTS   10
#define WC_CHECK(x)       if ((x) < 0) { DMSG("WCCHECK: %x", x); status = FALSE; goto Cleanup; }

static BYTE Sha256SignatureBlock[] = { 
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20, 0xDE, 0x16, 0x52, 0x8A, 0x1E,
    0x6F, 0x3C, 0x82, 0x29, 0x94, 0x89, 0x37, 0xB3,
    0x95, 0x84, 0x1F, 0xFA, 0xB8, 0x6A, 0x10, 0x03,
    0x8A, 0x87, 0x80, 0x46, 0x0F, 0xDB, 0xF6, 0x6D,
    0x44, 0x1E, 0x9F };

 // Track PK set/unset 
BOOL SecureBootInUserMode = FALSE;

// Usage for #def'ed GUIDs
static CONST GUID EfiCertX509Guid = EFI_CERT_X509_GUID;
static CONST GUID EfiCertTypePKCS7Guid = EFI_CERT_TYPE_PKCS7_GUID;

// Selector for cert parsing (parse all or x509 only)
typedef enum _PARSE_SECURE_BOOT_OP {
    ParseOpAll = 0,
    ParseOpX509,
} PARSE_SECURE_BOOT_OP;

// Storage for secureboot variable information
static CONST SECUREBOOT_VARIABLE_INFO SecurebootVariableInfo[] =
{
    {
        SecureBootVariablePK,                                     // Id
        {                                                         
            sizeof(EFI_PLATFORMKEY_VARIABLE) - sizeof(WCHAR),     // Length
            sizeof(EFI_PLATFORMKEY_VARIABLE),                     // MaximumLength
            (CONST PWCH) EFI_PLATFORMKEY_VARIABLE,                // Buffer
        },                                                        
        EFI_GLOBAL_VARIABLE,                                      // VendorGuid
    },                                                            
    {                                                             
        SecureBootVariableKEK,                                    // Id
        {                                                         
            sizeof(EFI_KEK_SECURITY_DATABASE) - sizeof(WCHAR),    // Length
            sizeof(EFI_KEK_SECURITY_DATABASE),                    // MaximumLength
            (CONST PWCH) EFI_KEK_SECURITY_DATABASE,               // Buffer
        },                                                        
        EFI_GLOBAL_VARIABLE,                                      // VendorGuid
    },
    {
        SecureBootVariableDB,                                     // Id
        {                                                         
            sizeof(EFI_IMAGE_SECURITY_DATABASE) - sizeof(WCHAR),  // Length
            sizeof(EFI_IMAGE_SECURITY_DATABASE),                  // MaximumLength
            (CONST PWCH) EFI_IMAGE_SECURITY_DATABASE,             // Buffer
        },                                                        
        EFI_IMAGE_SECURITY_DATABASE_GUID,                         // VendorGuid
    },
    {
        SecureBootVariableDBX,                                    // Id
        {
            sizeof(EFI_IMAGE_SECURITY_DATABASE1) - sizeof(WCHAR), // Length
            sizeof(EFI_IMAGE_SECURITY_DATABASE1),                 // MaximumLength
            (CONST PWCH) EFI_IMAGE_SECURITY_DATABASE1,            // Buffer
        },
        EFI_IMAGE_SECURITY_DATABASE_GUID,                         // VendorGuid
    },
};

//
// Prototypes
//

static
BOOLEAN
WrapPkcs7Data(
    CONST UINT8 *P7Data,            // IN
    UINTN P7Length,                 // IN
    BOOLEAN *WrapFlag,              // OUT
    UINT8 **WrapData,               // OUT
    UINTN *WrapDataSize             // OUT
);

static 
UINT32
GetStartOfVal(
    PBYTE Message,                  // IN
    UINT32 Position                 // IN
);

static
BOOLEAN
Pkcs7Verify(
    CONST BYTE *P7Data,             // IN
    UINTN P7Length,                 // IN
    UINT32 CertCount,               // IN
    CERTIFICATE *CertList,          // IN
    CONST BYTE *InData,             // IN
    UINTN DataLength                // IN
);

static
TEE_Result
ParseSecurebootVariable(
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PARSE_SECURE_BOOT_OP Op,        // IN
    CERTIFICATE *Certs,             // INOUT
    PUINT32 CertCount               // INOUT
);

TEE_Result
ReadSecurebootVariable(
    SECUREBOOT_VARIABLE Id,     // IN
    BYTE** Data,                // OUT
    PUINT32 DataSize            // OUT
);

static
TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE Var1,       // IN
    SECUREBOOT_VARIABLE Var2,       // IN
    CERTIFICATE **Certs,            // INOUT              
    UINT32 *NumberOfCerts           // OUT
);

static
TEE_Result
CheckSignatureList(
    EFI_SIGNATURE_LIST* SignatureList,  // IN
    BYTE *SignatureListEnd,             // IN
    UINT32 *NumberOfEntries             // OUT
);

static
TEE_Result
CheckForDuplicateSignatures(
    PCUEFI_VARIABLE Var,            // IN
    BYTE *Data,                     // IN
    UINT32 DataSize,                // IN
    BOOLEAN *DuplicatesFound,       // OUT
    BYTE **NewData,                 // OUT
    UINT32 *NewDataSize             // OUT
);

static
TEE_Result
ValidateParameters(
    BYTE *Data,                     // IN
    UINT32 DataSize,                // IN
    PBYTE *SignedData,              // OUT
    UINT32 *SignedDataSize,         // OUT
    PBYTE *ActualData,              // OUT
    UINT32 *ActualDataSize,         // OUT
    EFI_TIME *EfiTime               // OUT
);

static
TEE_Result
SecureBootVarAuth(
    SECUREBOOT_VARIABLE Id,         // IN
    PBYTE AuthenticationData,       // IN
    UINT32 AuthenticationDataSize,  // IN
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PBYTE DataToVerify,             // IN
    UINT32 DataToVerifySize         // IN
);

static
BOOLEAN
IdentifySecurebootVariable(
    PCWSTR VariableName,            // IN
    PCGUID VendorGuid,              // IN
    PSECUREBOOT_VARIABLE Id         // OUT
);

static
TEE_Result
VerifyTime(
    EFI_TIME *FirstTime,            // IN
    EFI_TIME *SecondTime            // IN
);

static
BOOLEAN
IsAfter(
    EFI_TIME *FirstTime,            // IN
    EFI_TIME *SecondTime            // IN
);

//
// Auth functions
//

static
BOOLEAN
WrapPkcs7Data(
    CONST UINT8  *P7Data,           // IN
    UINTN        P7Length,          // IN
    BOOLEAN      *WrapFlag,         // OUT
    UINT8        **WrapData,        // OUT
    UINTN        *WrapDataSize      // OUT
)
/*++
    Routine Descrition:

        Check if P7Data is a wrapped ContentInfo structure. If not,
        allocate a new structure to wrap P7Data.

        Caution: This function may receive untrusted input. Since a UEFI 
        Authenticated Variable is external input, this function will do
        basic checking of PKCS#7 data structure.

    Arguments:

        P7Data - Pointer to the PKCS#7 message to verify.

        P7Length - Length of the PKCS#7 message in bytes.

        WrapFlag - Receives TRUE if P7Data is ContentInfo struct, otherwise FALSE.

        WrapData - If return status of this function is TRUE:
                     1) WrapData = pointer to P7Data when WrapFlag == TRUE
                     2) WrapData = pointer to new ContentInfo struct otherwise.
                        It is the caller's responsibility to free this buffer.

        WrapDataSize - Length of structure pointed to by WrapData in bytes.

    Returns:

        TRUE    The operation is finished successfully.

        FALSE   The operation is failed due to lack of resources.

--*/

{
    UINT8 mOidValue[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
    UINT8 *signedData;
    BOOLEAN wrapped = FALSE;

    // Determine whether input P7Data is a wrapped ContentInfo structure
    if ((P7Data[4] == 0x06) && (P7Data[5] == 0x09))
    {
        if (memcmp(P7Data + 6, mOidValue, sizeof(mOidValue)) == 0)
        {
            if ((P7Data[15] == 0xA0) && (P7Data[16] == 0x82))
            {
                wrapped = TRUE;
            }
        }
    }

    // If already wrapped then update outputs and return
    if (wrapped)
    {
        *WrapData = (UINT8 *)P7Data;
        *WrapDataSize = P7Length;
        *WrapFlag = wrapped;
        return TRUE;
    }

    // Wrap PKCS#7 signed data to a ContentInfo structure
    *WrapDataSize = P7Length + 19;
    *WrapData = TEE_Malloc(*WrapDataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO);
    if (*WrapData == NULL)
    {
        // Unable to alloc buffer
        *WrapFlag = wrapped;
        return FALSE;
    }

    signedData = *WrapData;

    //
    // Part1: 0x30, 0x82.
    //
    signedData[0] = 0x30;
    signedData[1] = 0x82;

    //
    // Part2: Length1 = P7Length + 19 - 4, in big endian.
    //
    signedData[2] = (UINT8)(((UINT16)(*WrapDataSize - 4)) >> 8);
    signedData[3] = (UINT8)(((UINT16)(*WrapDataSize - 4)) & 0xff);

    //
    // Part3: 0x06, 0x09.
    //
    signedData[4] = 0x06;
    signedData[5] = 0x09;

    //
    // Part4: OID value -- 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x02.
    //
    memcpy(signedData + 6, mOidValue, sizeof(mOidValue));

    //
    // Part5: 0xA0, 0x82.
    //
    signedData[15] = 0xA0;
    signedData[16] = 0x82;

    //
    // Part6: Length2 = P7Length, in big endian.
    //
    signedData[17] = (UINT8)(((UINT16)P7Length) >> 8);
    signedData[18] = (UINT8)(((UINT16)P7Length) & 0xff);

    //
    // Part7: P7Data.
    //
    memcpy(signedData + 19, P7Data, P7Length);

    *WrapFlag = wrapped;
    return TRUE;
}

static 
UINT32
GetStartOfVal(
    PBYTE Message,      // IN
    UINT32 Position     // IN
)
/*++
    Routine Description:

        All DER objects are {tag, len, val}, but length is itself variable
        in length. This function returns the start of the value so that we
        can add the length returned by the regular parsing functions.

    Argument:

        Message - Pointer to object (byte pointer to start)

        Position - Index of structure in Message

    Returns:

        Index of first byte of val
--*/
{
    BYTE lenByte = (unsigned char)Message[Position + 1];
    UINT32 numBytes = Message[Position + 1] & 0x7f;

    if (lenByte < 127)
    {
        return Position + 1 + 1;
    }
    return Position + numBytes + 2;
}

static
BOOLEAN
Pkcs7Verify(
    CONST BYTE         *P7Data,         // IN
    UINTN               P7Length,       // IN
    UINT32              CertCount,      // IN
    CERTIFICATE        *CertList,       // IN
    CONST BYTE         *InData,         // IN
    UINTN               DataLength      // IN
)
/*++

    Routine Description:

        Verifies the validility of PKCS#7 signed data as described in
        "PKCS #7: Cryptographic Message Syntax Standard". The input
        signed data could be wrapped in a ContentInfo structure.

        If P7Data or InData is NULL, then return FALSE. If P7Length 
        DataLength overflow, then return FAlSE.

        Caution: This function may receive untrusted input. A UEFI Authenticated
        Variable is external input, so this function will do basic checking
        for PKCS#7 data structure.

    Arguments:

        P7Data - Pointer to the PKCS#7 message to verify

        P7Length - Length of the PKCS#7 message in bytes

        CertCount - Optional, number of entries in CertList

        CertList - Pointer certificate list used for verification

        InData - Pointer to the content to be verified

        DataLength - Length of InData in bytes

    Returns:

        TRUE - The specified PKCS#7 signed data is valid.

        FALSE - Invalid PKCS#7 signed data.

--*/
{
    BYTE signature[4096];
    BYTE buffer[1024];
    DecodedCert cert[MAX_DECODED_CERTS];
    wc_Sha256 hashCtx;
    BYTE signerSerialNumber[64];
    RsaKey pubKey;
    mp_int mpInt;
    BYTE *bytePtr = NULL;
    BYTE *signedData = NULL;
    DecodedCert *certList = NULL;
    DecodedCert *match = NULL;
    UINTN signedDataSize = 0;
    UINT32 i, p = 0; // msg Ptr 
    UINT32 startOfPtr, endOfPtr;
    UINT32 count = 0, index = 0;
    UINT32 oidVal, startOfCerts, endOfCerts;
    UINT32 length, numCerts;
    INT32 sigLength, signerSerialSize = 64;
    INT32 seqLength, setLength;
    INT32 certsLength, matchingCert = -1;
    BOOLEAN wrapped = FALSE;
    BOOLEAN status = FALSE;

    // Check input parameters.
    if ((P7Data == NULL) || (P7Length > INT_MAX) ||
        (InData == NULL) || (DataLength > INT_MAX))
    {
        status = FALSE;
        goto Cleanup;
    }

    // If we have a cert list, verify size
    if ((CertCount) && !(CertList))
    {
        status = FALSE;
        goto Cleanup;
    }

    // Wrap PKCS7 data, if necessary
    // if (!WrapPkcs7Data(P7Data, P7Length, &wrapped, &signedData, &signedDataSize))
    // {
    //     status = FALSE;
    //     goto Cleanup;
    // }
    //
    // if (wrapped)
    // {
    //     // REVISIT: We don't handle this yet
    // }

    signedData = P7Data;
    signedDataSize = P7Length;

    // REVISIT: Parse this by hand because WolfCrypt cannot (yet)
    //   0:  SignedData ::= SEQUENCE    {
    //   1:    version CMSVersion,
    //   2:    digestAlgorithms DigestAlgorithmIdentifiers,
    //   3:    encapContentInfo EncapsulatedContentInfo,
    //   4:    certificates [0] IMPLICIT CertificateSet OPTIONAL,
    //   5:    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    //   6:    signerInfos SignerInfos  }

    // 0:
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));

    // 1: version CMSVersion
    WC_CHECK(GetInt(&mpInt, signedData, &p, signedDataSize));
    mp_free(&mpInt);

    // 2: digestAlgorithms DigestAlgorithmIdentifiers
    //    DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
    startOfPtr = GetStartOfVal(signedData, p);
    WC_CHECK(GetSet(signedData, &p, &setLength, signedDataSize));
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));
    WC_CHECK(GetObjectId(signedData, &p, &oidVal, 0, signedDataSize));

    // We only support a single hash OID (sha256)
    if (oidVal != SHA256h)
    {
        status = FALSE;
        goto Cleanup;
    }

    // Skip to the end of the DigestAlgorithmIdentifiers set
    p = startOfPtr + setLength;

    // 3: encapContentInfo EncapsulatedContentInfo
    //    EncapsulatedContentInfo ::= SEQUENCE {
    //      eContentType ContentType,
    //      eContent[0] EXPLICIT OCTET STRING OPTIONAL
    //    }
    startOfPtr = GetStartOfVal(signedData, p);
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));
    WC_CHECK(GetObjectId(signedData, &p, &oidVal, 0, signedDataSize));

    // Is the type correct?
    if (oidVal != DATA)
    {
        status = FALSE;
        goto Cleanup;
    }

    // Do we have an eContent[0]?
    if (p < startOfPtr + seqLength)
    {
        // REVISIT: extract the: eContent[0] EXPLICIT OCTET STRING OPTIONAL
    }

    // 4: certificates [0] IMPLICIT CertificateSet OPTIONAL
    startOfCerts = GetStartOfVal(signedData, p);
    bytePtr = &signedData[p++];
    if (*bytePtr != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC))
    {
        status = FALSE;
        goto Cleanup;
    }

    // This is the length of the complete cert list
    WC_CHECK(GetLength(signedData, &p, &certsLength, signedDataSize));
    endOfCerts = startOfCerts + certsLength;

    // REVISIT: Not sure why the length above is wrong
    certsLength += 128;
    for (count = 0; count < 10; count++)
    {
        // The cert is a SEQUENCE, so find the length of this cert
        startOfPtr = p; // Save p for later..
        if (GetSequence(signedData, &p, &seqLength, certsLength) < 0)
        {
            break;
        }

        endOfPtr = p;
        length = seqLength + (endOfPtr - startOfPtr);
        InitDecodedCert(&cert[count], signedData + startOfPtr, length, 0);

        // Ensure the cert parses
        if (ParseCert(&cert[count], CERT_TYPE, NO_VERIFY, 0))
        {
            status = FALSE;
            goto Cleanup;
        }

        // Are we at the end?
        p = startOfPtr + length;
        if (p == endOfCerts)
        {
            break;
        }

        // ...or worse, did we run off the end?
        if (p > endOfCerts)
        {
            status = FALSE;
            goto Cleanup;
        }
    }

    // If we've been given a CertList use that instead.
    // (We still went through the above loop since we need to establish 'p')
    if (CertCount)
    {
        certList = CertList;
        numCerts = CertCount;
    }
    else
    {
        certList = cert;
        numCerts = count;
    }

    // 5: crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
    // REVISIT: Unnecessary right now

    // 6: signerInfos SignerInfos
    //    SignerInfo ::= SEQUENCE {
    //        6A:  version CMSVersion,
    //        6B:  sid SignerIdentifier,
    //        6C:  digestAlgorithm DigestAlgorithmIdentifier,
    //        6D:  signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    //        6E:  signatureAlgorithm SignatureAlgorithmIdentifier,
    //        6F:  signature SignatureValue,
    //        6G:  unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
    WC_CHECK(GetSet(signedData, &p, &setLength, signedDataSize));
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));

    // 6A: version CMSVersion
    WC_CHECK(GetInt(&mpInt, signedData, &p, signedDataSize));
    mp_free(&mpInt); // REVISIT: Check the version?

    // 6B: sid SignerIdentifier:  The signer idnetifier contains a subject
    // name and a serial number. We will just use the serial number.
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));

    startOfPtr = GetStartOfVal(signedData, p);
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));

    // Skip the DN, and just use the serial number to find the cert
    p = startOfPtr + seqLength;

    // Get the signer cert serial number
    WC_CHECK(GetSerialNumber(signedData, &p, signerSerialNumber, &signerSerialSize, signedDataSize));

    // Get the hash alg	
    startOfPtr = GetStartOfVal(signedData, p);
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));

    // Just get the first hash alg oid (sha256)
    WC_CHECK(GetObjectId(signedData, &p, &oidVal, 0, signedDataSize));

    // We only support sha256
    if (oidVal != SHA256h)
    {
        status = FALSE;
        goto Cleanup;
    }

    // Skip the null
    p = startOfPtr + seqLength;

    // 6E: Get the signature alg
    startOfPtr = GetStartOfVal(signedData, p);
    WC_CHECK(GetSequence(signedData, &p, &seqLength, signedDataSize));

    // Just get the first hash
    WC_CHECK(GetObjectId(signedData, &p, &oidVal, 0, signedDataSize));

    // Skip the null
    p = startOfPtr + seqLength;

    // 6F: Get the signature as a simple OCTET STRING
    p++; // (REVISIT: TAG?)
    WC_CHECK(GetLength(signedData, &p, &sigLength, signedDataSize));
    memcpy(signature, signedData + p, sigLength);

    // Get the cert that matches the serial number
    for (i = 0; i < numCerts; i++)
    {
        // Try matching on size first
        if (signerSerialSize != certList[i].serialSz)
        {
            continue;
        }

        // Sizes match, how about the bytes?
        if (memcmp(signerSerialNumber, certList[i].serial, signerSerialSize) != 0)
        {
            continue;
        }

        // We have a match
        matchingCert = i;
        DMSG("match!!: %x", matchingCert);
        break;
    }

    // Do we have a match?
    if (matchingCert == -1)
    {
        status = FALSE;
        goto Cleanup;
    }

    // Compute exptected hash value
    WC_CHECK(wc_InitSha256(&hashCtx));
    WC_CHECK(wc_Sha256Update(&hashCtx, InData, DataLength));

    // Place digest within signature block
    bytePtr = (BYTE*)(Sha256SignatureBlock + 19);
    WC_CHECK(wc_Sha256Final(&hashCtx, bytePtr));

    // Now, use the decoded cert to validate the signature
    match = &certList[matchingCert];
    wc_InitRsaKey(&pubKey, NULL);

    index = 0;
    WC_CHECK(wc_RsaPublicKeyDecode(match->publicKey, &index, &pubKey, 8192));

    // REVISIT: This operation won't work in a general case. Really need to 
    // do a signature verifification against the Sha256SignatureBlock.
    length = wc_RsaSSL_Verify(signature, sigLength, buffer, sizeof(buffer), &pubKey);

    DMSG("length: %x", length);

    // Error or unexpected langth?
    if (length != sizeof(Sha256SignatureBlock))
    {
        status = FALSE;
        goto Cleanup;
    }


    // Verify signature
    if (memcmp(Sha256SignatureBlock, buffer, sizeof(Sha256SignatureBlock)))
    {
    DMSG("FAILED VERIFY");

        status = FALSE;
        goto Cleanup;
    }
    DMSG("!!!!VERIFY!!!!");

    // We have a match
    status = TRUE;

Cleanup:
// REVISIT: UNCOMMENT IF/WHEN WRAPPING IS IMPLEMENTED
//    if (!wrapped)
//    {
//        TEE_Free(signedData);
//    }

    for (i = 0; i < count; i++)
    {
        FreeDecodedCert(&(cert[i]));
    }

    return status;
}

static
TEE_Result
ParseSecurebootVariable(
    PBYTE Data,                 // IN
    UINT32 DataSize,            // IN
    PARSE_SECURE_BOOT_OP Op,    // IN
    CERTIFICATE *Certs,         // INOUT
    PUINT32 CertCount           // INOUT
)
/*++

    Routine Description:

        Function used to parse a retrieved secureboot variable

    Arguments:

        Data - Content of an authenticated secureboot variable

        DataSize - Size in bytes of Data

        Op - Opcode to choose between parsing all certs or only x509 certs

        Certs - If NULL, CertCount receives total number of certs in variable filtered by Op
                If non-NULL, Certs contains a list of certificates

        CertCount - contains total number of certs in variable filtered by Op

    Returns:

        TEE_Result

--*/
{
    PBYTE sigListIndex, sigListLimit, certEntry, firstCert = NULL;
    EFI_SIGNATURE_LIST *signatureList = NULL;
    WIN_CERTIFICATE_UEFI_GUID *authPtr = NULL;
    UINT32 sigListOffset, certCount = 0, i, index, listEntries = 0, certSize = 0;
    TEE_Result status = TEE_SUCCESS;
    BOOLEAN doAlloc = FALSE;

    // Validate size
    if (DataSize < sizeof(EFI_SIGNATURE_LIST))
    {
        DMSG("here");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Pickup offset to signature list structure(s)
    authPtr = &((EFI_VARIABLE_AUTHENTICATION_2 *)Data)->AuthInfo;
    sigListOffset = authPtr->Hdr.dwLength;
    
    // Calculate start and end for list structure(s)
    sigListIndex = (PBYTE)((UINTN)authPtr + sigListOffset);
    sigListLimit = Data + DataSize;

    DMSG("DATA: %x DATASIZE: %x", Data, DataSize);
    DMSG("slO: %x slI: %x slL: %x", sigListOffset, sigListIndex, sigListLimit);

    // Integer overflow check
    if ((UINTN)sigListLimit <= (UINTN)Data)
    {
        DMSG("here");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Init cert list index
    index = 0;

    // Enumerate signature list(s)
    while (sigListIndex < sigListLimit)
    {
        doAlloc = FALSE;
        signatureList = (EFI_SIGNATURE_LIST*)sigListIndex;

        DMSG("slO: %x slI: %x slL: %x", sigListOffset, sigListIndex, sigListLimit);

        // Sanity check signature list
        status = CheckSignatureList(signatureList, sigListLimit, &listEntries);
        if (status != TEE_SUCCESS)
        {
            DMSG("here");
            goto Cleanup;
        }
        DMSG("listEntries: %x", listEntries);

        if (Op == ParseOpAll)
        {
            certCount += listEntries;
            certSize = signatureList->SignatureSize;
            firstCert = (PBYTE)signatureList + sizeof(EFI_SIGNATURE_LIST);
            doAlloc = TRUE;
        }
        else if (Op == ParseOpX509)
        {
            if (!(memcmp(&signatureList->SignatureType, &EfiCertX509Guid, sizeof(GUID))))
            {
                certCount += listEntries;
                certSize = signatureList->SignatureSize - sizeof(EFI_SIGNATURE_DATA);
                firstCert = (PBYTE)signatureList + sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA);
                DMSG("here");
                doAlloc = TRUE;
            }
        }
        else
        {
            // Bad Op value
            DMSG("here");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        //  Do we have certs to parse and a list to add them to?
        if ((doAlloc) && (Certs != NULL))
        {
            for (i = 0; i < listEntries; i++)
            {
                // If we didn't find anything, we shouldn't be here
                if (!(firstCert))
                {
                    TEE_Panic(TEE_ERROR_BAD_STATE);
                    status = TEE_ERROR_BAD_STATE;
                    goto Cleanup;
                }

                // Calculate location of next cert entry
                certEntry = firstCert + (i * signatureList->SignatureSize);

                // Sanity check
                if (index >= *CertCount)
                {
                    DMSG("here");
                    status = TEE_ERROR_BAD_PARAMETERS;
                    goto Cleanup;
                }

                // Init and parse cert (wolfcrypt)
                InitDecodedCert(&Certs[index], certEntry, certSize, 0);
                if (ParseCert(&Certs[index], CERT_TYPE, NO_VERIFY, 0))
                {
                    DMSG("here");
                    status = TEE_ERROR_BAD_PARAMETERS;
                    goto Cleanup;
                }

                index++;
            }
        }
        // Advance to next signature list
        sigListIndex += signatureList->SignatureListSize;
    }

    // Index/limit mismatch?
    if (sigListIndex != sigListLimit)
    {
        DMSG("here");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Update count with number of certs parsed
    *CertCount = certCount;

Cleanup:
    return status;
}

TEE_Result
ReadSecurebootVariable(
    SECUREBOOT_VARIABLE Id,     // IN
    BYTE** Data,                // OUT
    PUINT32 DataSize            // OUT
)
/*++

    Routine Description:

        This function reads a secureboot authenticated variable

    Arguments:

        Id - Enum selecting secureboot variable

        Data - Content of the variable

        DataSize - Size in bytes of the variable

    Returns:

        Status Code

--*/
{
    VARIABLE_GET_RESULT szres = { 0 };
    PVARIABLE_GET_RESULT result = NULL;
    UINT32 size, expectedSize;
    PUEFI_VARIABLE var = NULL;
    TEE_Result status;
    VARTYPE variableType;

    // Read the data from non volatile storage.
    SearchList(&SecurebootVariableInfo[Id].UnicodeName,
               &SecurebootVariableInfo[Id].VendorGuid,
               &var, &variableType);

    if (!var)
    {
        status = TEE_ERROR_ITEM_NOT_FOUND;
        goto Cleanup;
    }

    // REVISIT: Would be better if we were not required to provide
    //          a resultBuf (szres) if all we want is the size
    status = RetrieveVariable(var, &szres, 0, &size);
    if (status != TEE_ERROR_SHORT_BUFFER)
    {
        DMSG("retrieve failed NSB");
        goto Cleanup;
    }

    if (!(result = TEE_Malloc(size, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
    {
        DMSG("out of memory size: %x", size);
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    status = RetrieveVariable(var, result, size, &size);
    if (status != TEE_SUCCESS)
    {
        DMSG("retrieve failed");
        goto Cleanup;
    }

    // Pass along pointer to secure boot variable
    *Data = result;
    *DataSize = result->DataSize;

Cleanup:
    if((status != TEE_SUCCESS) && (result))
    {
        TEE_Free(result);
    }
    return status;
}

static
TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE PK,
    SECUREBOOT_VARIABLE KEK,
    CERTIFICATE **Certs,
    PUINT32 CertCount
)
/*++

    Routine Description:

        Function to read and populate X509 certs from secureboot variables

    Arguments:

        PK - Enum selecting secureboot variable

        KEK - Enum selecting secureboot variable

        Certs - Supplies a list of certificates parsed from both the variables

        CertCount - supplies number of certs in Certs

    Returns:

        Status Code

--*/
{
    CERTIFICATE *certs = NULL;
    PVARIABLE_GET_RESULT PKvar = NULL, KEKvar = NULL;
    UINT32 PKcount = 0, KEKcount = 0;
    UINT32 totalParsed, PKsize, KEKsize, i;
    TEE_Result status = TEE_ERROR_ACCESS_DENIED;
    BOOLEAN needKEK = FALSE;

    // We know need the PK, how about KEK database?
    if (KEK == SecureBootVariableKEK)
    {
        needKEK = TRUE;
    }

    // Read the variable(s)
    status = ReadSecurebootVariable(PK, &PKvar, &PKsize);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // Pick up x509 cert(s) from PK
    status = ParseSecurebootVariable(PKvar->Data, PKsize, ParseOpX509, NULL, &PKcount);
    if (status != TEE_SUCCESS)
    {
        DMSG("here");
        goto Cleanup;
    }

    // Do we need to also collect certs from KEK database?
    if (needKEK)
    {
        // Read the variable(s)
        status = ReadSecurebootVariable(KEK, &KEKvar, &KEKsize);
        if (status != TEE_SUCCESS)
        {
            DMSG("here");
            goto Cleanup;
        }

        // Pick up x509 cert(s) from KEK
        status = ParseSecurebootVariable(KEKvar->Data, KEKsize, ParseOpX509, NULL, &KEKcount);
        if (status != TEE_SUCCESS)
        {
            DMSG("here");
            goto Cleanup;
        }
    }

    // Alloc space for collected certs
    certs = TEE_Malloc((sizeof(CERTIFICATE) * (PKcount + KEKcount)), TEE_USER_MEM_HINT_NO_FILL_ZERO);
    if (!certs)
    {
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    // Now do the allocs
    totalParsed = PKcount;

    status = ParseSecurebootVariable(PKvar->Data, PKsize, ParseOpX509, certs, &totalParsed);
    if (status != TEE_SUCCESS)
    {
        DMSG("here");
        goto Cleanup;
    }

    // Should not happen
    if (totalParsed != PKcount)
    {
        TEE_Panic(TEE_ERROR_BAD_STATE);
        status = TEE_ERROR_BAD_STATE;
        goto Cleanup;
    }

    if (needKEK)
    {
        totalParsed = KEKcount;

        status = ParseSecurebootVariable(KEKvar->Data, KEKsize, ParseOpX509, &certs[PKcount], &totalParsed);
        if (status != TEE_SUCCESS)
        {
            DMSG("here");
            goto Cleanup;
        }

        // Should not happen
        if (totalParsed != KEKcount)
        {
            TEE_Panic(TEE_ERROR_BAD_STATE);
            status = TEE_ERROR_BAD_STATE;
            goto Cleanup;
        }
    }

    *Certs = certs;
    *CertCount = PKcount + KEKcount;
    DMSG("NumberOfCerts: %x", CertCount);

Cleanup:
    TEE_Free(PKvar);
    TEE_Free(KEKvar);

    if (status != TEE_SUCCESS)
    {
        for (i = 0; i < PKcount; i++)
        {
            FreeDecodedCert(&(certs[i]));
        }

        for (i = PKcount; i < (PKcount + KEKcount); i++)
        {
            FreeDecodedCert(&(certs[i]));
        }
    }

    return status;
}

static
TEE_Result
CheckSignatureList(
    EFI_SIGNATURE_LIST* SignatureList,  // IN
    PBYTE SignatureListEnd,             // IN
    PUINT32 NumberOfEntries             // OUT
)
/*++

    Routine Description:

        Function to check the correctness of EFI Signature Lists

    Arguments:

        SignatureList - Pointer to a single EFI signature list

        SignatureListEnd - End of list

        NumberOfEntries - Total number of signatures in this list

    Returns:

        Status Code

--*/
{
    INT32 listBytes;
    TEE_Result status = TEE_ERROR_BAD_PARAMETERS; // Assume failure

    DMSG("SL: %x, slEnd: %x, so(SL): %x, sls: %x",
        (PBYTE)SignatureList, SignatureListEnd, sizeof(EFI_SIGNATURE_LIST), SignatureList->SignatureListSize);

    // Sanity checks on the signature list
    if (((SignatureListEnd - (PBYTE)SignatureList) < (INT_PTR)sizeof(EFI_SIGNATURE_LIST))
        || (((PBYTE)SignatureList + SignatureList->SignatureListSize) < (PBYTE)SignatureList)
        || (((PBYTE)SignatureList + SignatureList->SignatureListSize) > SignatureListEnd))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        DMSG("here");
        goto Cleanup;
    }

    // Sanity check list size
    if ((SignatureList->SignatureListSize == 0) ||
        (SignatureList->SignatureListSize < sizeof(EFI_SIGNATURE_LIST)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        DMSG("here");
        goto Cleanup;
    }

    // Ensure list size is non-zero and a multiple of SignatureSize
    listBytes = SignatureList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST);
    if ((listBytes <= 0) || (listBytes % SignatureList->SignatureSize))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        DMSG("here");
        goto Cleanup;
    }

    // We only deal with EFI_CERT_X509_GUID-type certs and it has no header
    if (SignatureList->SignatureHeaderSize != 0)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        DMSG("here");
        goto Cleanup;
    }

    // All checks passed.
    status = TEE_SUCCESS;
    *NumberOfEntries = (SignatureList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST)) /
                                        SignatureList->SignatureSize;
    DMSG("here");

Cleanup:
    return status;
}

static
TEE_Result
CheckForDuplicateSignatures(
    PCUEFI_VARIABLE Var,            // IN
    BYTE *Data,                     // IN
    UINT32 DataSize,                // IN
    BOOLEAN *DuplicatesFound,       // OUT
    BYTE **NewData,                 // OUT
    UINT32 *NewDataSize             // OUT
)
// REVISIT: We don't need this function (yet?)
{
    UNUSED_PARAMETER(Var);
    *DuplicatesFound = FALSE;
    *NewData = Data;
    *NewDataSize = DataSize;
    return TEE_SUCCESS;
}

TEE_Result
AuthenticateSetVariable(
    PCUNICODE_STRING         UnicodeName,           // IN
    PGUID                    VendorGuid,            // IN
    PCUEFI_VARIABLE          Var,                   // IN
    ATTRIBUTES               Attributes,            // IN
    PBYTE                    Data,                  // IN
    UINT32                   DataSize,              // IN
    PEXTENDED_ATTRIBUTES     ExtendedAttributes,    // IN
    PBOOLEAN                 DuplicateFound,        // IN
    PBYTE                   *Content,               // OUT
    PUINT32                  ContentSize            // OUT
)
/*++

    Routine Description:

        Function for authenticating a variable based on EFI_VARIABLE_AUTHENTICATION_2.
        This is time based authentication

    Arguments:

        UnicodeName - Name of variable

        VendorGuid - GUID of the variable

        Var - Pointer to in-memory representation of the variable

        Attributes - UEFI variable attributes

        Data - supplies data (Serialization of Authentication structure and variable's content)

        DataSize - Size in bytes of Data

        ExtendedAttributes - Optional attributes for authenticated variables

        DuplicateFound - TRUE if duplicates are found in the content being appended to the existing content

        Content - If duplicates are found in the content being appended to the existing content,
        the redundant signatures are stripped and this field points to that reduced content
        (Memory is allocated within this method and should be freed by caller)

        ContentSize - Size in bytes of Content

    Returns:

        TEE_Result

--*/
{
    EFI_TIME efiTime, *prevEfiTime;
    PEXTENDED_ATTRIBUTES pExtAttrib;
    PBYTE data = NULL, signedData = NULL, dataToVerify = NULL, newData = NULL;
    UINT32 dataSize, signedDataSize, dataToVerifySize, newDataSize, index;
    SECUREBOOT_VARIABLE id;
    TEE_Result status = TEE_ERROR_ACCESS_DENIED;
    BOOLEAN duplicatesFound = FALSE;
    BOOLEAN isDeleteOperation = FALSE;

    DMSG("authset: DataSize: %x", DataSize);
    DMSG("authset: Data: %p", Data);

    // Is this a delete operation?
    if (!DataSize)
    {
        if (!Var)
        {
            // Can't verify a deleteion of a non-existant var
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }
        else {
            isDeleteOperation = TRUE;
            DataSize = Var->DataSize;
            DMSG("newDS: %x", DataSize);
            Data = (PBYTE)(Var->BaseAddress + Var->DataOffset);
            DMSG("newdata: %p", Data);
        }
    }

    // NOTE!: This function assumes we have already verified parameters to the 
    //        point where we know whether or not this is a valid delete operation.
    //        Therefore, we assume that !(DataSize) && (Var) means delete. Further, 
    //        we can't assume we have a valid data pointer on a delete so time
    //        checking isn't relevant in this case.

    // Parse parameters
    status = ValidateParameters(Data, DataSize, &signedData, &signedDataSize, &data, &dataSize, &efiTime);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }
    
    // If we have a time field, make sure it is updated (unless this is an append)
    if ((Attributes.AppendWrite) || (Var == NULL))
    {
        prevEfiTime = NULL;
    }
    else
    {
        // REVISIT: This should be an assert
        if (!(Var->ExtAttribOffset))
        {
            DMSG("ASSERT ExtAttribOffset: %lx", Var->ExtAttribOffset);
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Authenticated volatile variables are not implemented, we know this is an offset
        pExtAttrib = (PEXTENDED_ATTRIBUTES)((UINT_PTR)Var + Var->ExtAttribOffset);
        prevEfiTime = &pExtAttrib->EfiTime;
    }

    // If we have new data (i.e., !(isDeleteOperation)), validate prev/new efiTime.
    if (!(isDeleteOperation))
    {
        status = VerifyTime(&efiTime, prevEfiTime);
        if (status != TEE_SUCCESS)
        {
            DMSG("FAILED VerifyTime %lx", (UINTN)Var->ExtAttribOffset);
            goto Cleanup;
        }
    }

    // Integer overflow check.
    if (((UINT32)UnicodeName->Buffer + UnicodeName->Length) < (UINT32)UnicodeName->Buffer)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Calculate data-to-verify size
    dataToVerifySize = UnicodeName->Length + sizeof(GUID) + sizeof(UINT32) + sizeof(EFI_TIME) + dataSize;

    // Integer overflow check.
    if (dataToVerifySize < dataSize)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    DMSG("Malloc dataToVerifySize: %x", dataToVerifySize);

    // Allocate buffer for use during verification
    if (!(dataToVerify = TEE_Malloc(dataToVerifySize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
    {
        status = TEE_ERROR_OUT_OF_MEMORY;
        DMSG("FAILED Malloc");
        goto Cleanup;
    }

    // Construct verification buffer
    index = 0;
    memmove(dataToVerify + index, UnicodeName->Buffer, UnicodeName->Length);
    index += UnicodeName->Length;

    memmove(dataToVerify + index, VendorGuid, sizeof(GUID));
    index += sizeof(GUID);

    memmove(dataToVerify + index, &Attributes.Flags, sizeof(UINT32));
    index += sizeof(UINT32);

    memmove(dataToVerify + index, &efiTime, sizeof(EFI_TIME));
    index += sizeof(EFI_TIME);

    memmove(dataToVerify + index, data, dataSize);
    index += dataSize;

    // REVISIT: Should be an assert
    if (!(index == dataToVerifySize))
    {
        DMSG("ASSERT %x (index) != %x (dataToVerifySize)", index, dataToVerifySize);
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    DMSG("IdentifySecureBootVarialbe");

    // Proceed only if this is a secure boot variable
    if (IdentifySecurebootVariable(UnicodeName->Buffer, VendorGuid, &id))
    {
        DMSG("Doing securebootvarauth");

        status = SecureBootVarAuth(id, signedData, signedDataSize, data, dataSize, dataToVerify, dataToVerifySize);
        if (status != TEE_SUCCESS)
        {
            DMSG("FAILED SecureBootVarAuth %x", status);
            goto Cleanup;
        }
        DMSG("ret from SecureBootVarAuth %x", status);

    }
    else
    {
        // Private authenticated variables not implemented
        status = TEE_ERROR_NOT_IMPLEMENTED;
        DMSG("Private authenticated variables not implemented");
        goto Cleanup;
    }

    // As per UEFI specification, the driver does not have to append signature values
    // of GUID EFI_IMAGE_SECURITY_DATABASE_GUID which are already present in the variable.
    if ( (Var != NULL) &&
        ((id == SecureBootVariableDB) || (id == SecureBootVariableDBX)) &&
        (Attributes.AppendWrite))
    {
        DMSG("Checking for duplicate signatures");
        status = CheckForDuplicateSignatures(Var, data, dataSize, &duplicatesFound, &newData, &newDataSize);
        if (status != TEE_SUCCESS)
        {
            DMSG("FAILED CheckForDuplicateSignatures: %x", status);
            goto Cleanup;
        }
    }

    // REVISIT: Always false right now
    if (duplicatesFound)
    {
        *Content = newData;
        *ContentSize = newDataSize;
    }
    else
    {
        *Content = data;
        *ContentSize = dataSize;
    }

    // REVISIT: Always false right now
    *DuplicateFound = duplicatesFound;

    // Init extended attributes if necessary
    if (ExtendedAttributes)
    {
        memset(ExtendedAttributes, 0, sizeof(EXTENDED_ATTRIBUTES));
        ExtendedAttributes->EfiTime = efiTime;
    }

    // Success, return
    status = TEE_SUCCESS;

Cleanup:
    if (dataToVerify)
    {
        TEE_Free(dataToVerify);
    }

    return status;
}

static
TEE_Result
ValidateParameters(
    PBYTE        Data,              // IN
    UINT32       DataSize,          // IN
    PBYTE       *SignedData,        // OUT
    UINT32      *SignedDataSize,    // OUT
    PBYTE       *ActualData,        // OUT
    UINT32      *ActualDataSize,    // OUT
    EFI_TIME    *EfiTime            // OUT
)
/*++

    Routine Description:

        Function to parse data parameter from UEFI SetVariable function.
        It is parsed into the signed data field, timestamp, and content.

    Arguments:

        Data - Data parameter from the original SetVariable Function

        DataSize - Size in bytes of Data

        SignedData - Supplies the PKCS#7 Signed Data parsed from Data

        SignedDataSize - Size in bytes of SignedData

        ActualData - Content of the variable

        ActualDataSize - Size in bytes of the variable

        EfiTime - Timestamp parsed from Data

    Returns:

        TEE_Result

--*/
{
    WIN_CERTIFICATE_UEFI_GUID *winCertUefiGuid;
    EFI_VARIABLE_AUTHENTICATION_2 *efiVarAuth2;
    UINT32 winCertUefiGuidSize, efiVarAuth2Size;
    TEE_Result status;

    // Guard against overflow
    if (((UINT32)Data + DataSize) <= (UINT32)Data)
    {
        DMSG("ovflw");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Validate our data size
    winCertUefiGuidSize = sizeof(WIN_CERTIFICATE) + sizeof(GUID);
    efiVarAuth2Size = winCertUefiGuidSize + sizeof(EFI_TIME);
    if (DataSize < efiVarAuth2Size)
    {
        DMSG("vds");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Check data alignment
    if (((UINT32)Data % __alignof(EFI_VARIABLE_AUTHENTICATION_2)) != 0)
    {
        DMSG("alignment");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    efiVarAuth2 = (EFI_VARIABLE_AUTHENTICATION_2*)Data;
    winCertUefiGuid = (WIN_CERTIFICATE_UEFI_GUID *)&efiVarAuth2->AuthInfo;

    if (memcmp(&winCertUefiGuid->CertType, &EfiCertTypePKCS7Guid, sizeof(GUID)) != 0)
    {
        DMSG("certtype?");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // All prechecks passed, now get the PKCS#7 signed data value and content
    *EfiTime = efiVarAuth2->TimeStamp;
    if (winCertUefiGuid->Hdr.dwLength < winCertUefiGuidSize)
    {
        DMSG("tmstp");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *SignedDataSize = winCertUefiGuid->Hdr.dwLength - winCertUefiGuidSize;
    if ((DataSize - efiVarAuth2Size) < *SignedDataSize)
    {
        DMSG("wincerkjjkhsdfh");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *ActualDataSize = DataSize - efiVarAuth2Size - *SignedDataSize;
    *SignedData = (PBYTE)(&efiVarAuth2->AuthInfo.CertData[0]);
    if ((UINT32)*SignedData + *SignedDataSize <= (UINT32)*SignedData)
    {
        DMSG("otherthing");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *ActualData = (PBYTE)(*SignedData + *SignedDataSize);
    if ((UINT32)*ActualData + *ActualDataSize <= (UINT32)*ActualData)
    {
        DMSG("last thing");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    status = TEE_SUCCESS;
    
Cleanup:
    return status;
}

static
TEE_Result
SecureBootVarAuth(
    SECUREBOOT_VARIABLE Id,         // IN
    PBYTE AuthenticationData,       // IN
    UINT32 AuthenticationDataSize,  // IN
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PBYTE DataToVerify,             // IN
    UINT32 DataToVerifySize         // IN
)
/*++

    Routine Description:

        Function to authenticate access to secure boot variable.

    Arguments:

        Id - Enum selecting secureboot variable

        AuthenticationData - PKCS#7 Signed Data to authenticate Data

        AuthenticationDataSize - Size in bytes of AuthenticationData

        Data - Content of the variable

        DataSize - Size in bytes of the variable

        DataToVerify - Content of the data to verify packet.

        DataToVerifySize - Size in bytes of the data to verify packet.

    Returns:

        Status Code

    Notes:

        Comparison with EDKII AuthService::VerifyTimeBasedPayload
         - AuthenticationData === SigData
         - Data === NewData
           - The serialized stream of the UEFI variable info + payload data.
--*/
{
    SECUREBOOT_VARIABLE needKEK;
    DecodedCert *certs = NULL;
    UINT32 certCount = 0, i;
    TEE_Result status = TEE_ERROR_ACCESS_DENIED;
    BOOLEAN verifyStatus = FALSE;

    // Unused parameters
    UNUSED_PARAMETER(Data);
    UNUSED_PARAMETER(DataSize);

    // Assume we won't need to also check against KEK database
    needKEK = SecureBootVariableEnd;

    // Are we trying to touch db(x)?
    if ((Id == SecureBootVariableDB) || (Id == SecureBootVariableDBX))
    {
        // Yes, need KEK too
        needKEK = SecureBootVariableKEK;
    }
    else
    {
        // Ok, not db(x), is Id valid?
        if ((Id != SecureBootVariablePK) && (Id != SecureBootVariableKEK))
        {
            // No, bad secure boot variable ID
            status = TEE_ERROR_ACCESS_DENIED;
            goto Cleanup;
        }
    }

    // Perform signature validation and check if we trust the signing certificate
    if (SecureBootInUserMode)
    {
        // In user mode touching a secure boot variable, collect certs for auth
        status = PopulateCerts(SecureBootVariablePK, needKEK, &certs, (PUINT32)&certCount);
        if (status != TEE_SUCCESS)
        {
            DMSG("Populate certs failed");
            goto Cleanup;
        }

        // Nothing returned, not expected but definitely fatal
        if (certs == NULL)
        {
            status = TEE_ERROR_ACCESS_DENIED;
            goto Cleanup;
        }

        // Do the verification
        verifyStatus = Pkcs7Verify(AuthenticationData, AuthenticationDataSize,
                                   certCount, certs,
                                   DataToVerify, DataToVerifySize);

        // Free resources used on verify
        for (i = 0; i < certCount; i++)
        {
            FreeDecodedCert(&(certs[i]));
        }

        // Free list
        TEE_Free(certs);

        // Success/failure
        if (!verifyStatus)
        {
            status = TEE_ERROR_ACCESS_DENIED;
            goto Cleanup;
        }
    }
    // We're in setup mode, only PK needs to be signed (self-signed)
    else
    {
        if (Id == SecureBootVariablePK)
        {
            // Verify Pkcs7 AuthenticationData
            verifyStatus = Pkcs7Verify(AuthenticationData, AuthenticationDataSize,
                                       0, NULL,
                                       DataToVerify, DataToVerifySize);

            // Success/failure
            if (!verifyStatus)
            {
                status = TEE_ERROR_ACCESS_DENIED;
                goto Cleanup;
            }

            // Switch from setup mode
            SecureBootInUserMode = TRUE;
        }
        else
        {
            // Already validated Id so we're good
            verifyStatus = TRUE;
        }
    }

    // Ensure proper return status on fall through
    if (verifyStatus)
    {
        status = TEE_SUCCESS;
    }

 Cleanup:
    return status;
}

static
BOOLEAN
IdentifySecurebootVariable(
    PCWSTR VariableName,        // IN
    PCGUID VendorGuid,          // IN
    PSECUREBOOT_VARIABLE Id     // OUT
)
/*++

    Routine Description:

        Function to determine if a variable is one of the known secureboot authenticated variables

    Arguments:

        VariableName - Name of the variable

        VendorGuid - Vendor Guid of the variable

        Id - Enum identifying the secureboot variable

    Returns:

        TRUE if one of the known secureboot authenticated variables

        FALSE otherwise

--*/
{
    UINT32 i;
    BOOLEAN retVal = FALSE;

    for (i = 0; i < SecureBootVariableEnd; i++)
    {
        if ((memcmp(VendorGuid, &SecurebootVariableInfo[i].VendorGuid, sizeof(GUID)) == 0) &&
            (wcscmp(VariableName, SecurebootVariableInfo[i].UnicodeName.Buffer) == 0))
        {
            *Id = SecurebootVariableInfo[i].Id;
            retVal = TRUE;
            break;
        }
    }

    return retVal;
}

static
TEE_Result
VerifyTime(
    EFI_TIME    *FirstTime,
    EFI_TIME    *SecondTime
)
/*++

    Routine Description:

        Verifies EFI time as per UEFI requirements.

    Arguments:

        FirstTime - Timestamp which is checked for correctness

        SecondTime - Optional. If provided, should be "not after" FirstTime

    Return Value:

        TRUE - Success

        FALSE - Failure

--*/
{
    // Some validation on FirstTime
    if ((FirstTime->Pad1 != 0) ||
        (FirstTime->Nanosecond != 0) ||
        (FirstTime->TimeZone != 0) ||
        (FirstTime->Daylight != 0) ||
        (FirstTime->Pad2 != 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Have an EFI_TIME to compare?
    if (!SecondTime)
    {
        return TEE_SUCCESS;
    }

    // Ensure FirstTime is not after SecondTime
    if (IsAfter(SecondTime, FirstTime))
    {
        return TEE_ERROR_ACCESS_DENIED;
    }

    return TEE_SUCCESS;
}

static
BOOLEAN
IsAfter(
    EFI_TIME *FirstTime,        // IN
    EFI_TIME *SecondTime        // IN
)
{
    if (FirstTime->Year != SecondTime->Year)
    {
        return (FirstTime->Year < SecondTime->Year);
    }
    else if (FirstTime->Month != SecondTime->Month)
    {
        return (FirstTime->Month < SecondTime->Month);
    }
    else if (FirstTime->Day != SecondTime->Day)
    {
        return (FirstTime->Day < SecondTime->Day);
    }
    else if (FirstTime->Hour != SecondTime->Hour)
    {
        return (FirstTime->Hour < SecondTime->Hour);
    }
    else if (FirstTime->Minute != SecondTime->Minute)
    {
        return (FirstTime->Minute < SecondTime->Minute);
    }
    return (FirstTime->Second < SecondTime->Second);
}