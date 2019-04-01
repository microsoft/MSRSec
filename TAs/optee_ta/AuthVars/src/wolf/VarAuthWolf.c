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

 // WolfCrypt includes and related defintions
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/pkcs7.h>

// Wolf cert type
typedef DecodedCert CERTIFICATE, *PCERTIFICATE;

// Usage for #def'ed GUIDs
extern const GUID EfiCertX509Guid;
extern const GUID EfiCertTypePKCS7Guid;

 // WC related definitions
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

//
// Library-specific functions (implemented for each of OSSL, WolfSSL, etc.):
//  1. FreeCertList            - Free resources associated with Certificate(s)
//  2. Pkcs7Verify             - Validate PKCS7 data
//  3. PopulateCerts           - Pull certificate(s) from secure boot variables
//
// Static library-specific functions (helper functions):
//  1. ParseSecurebootVariable - Dependency of PopulateCerts
//  2. Other(s)                - For WolfSSL: GetStartOfVal()
//
// External dependencies for Library-specific functions:
//  1. WrapPkcs7Data          - General purpose PKCS7 wrapper
//  2. CheckSignatureList     - Validate signature list
//  3. ReadSecurebootVariable - For reading secure boot variable(s)
//

//
// Prototype(s)
//

VOID
FreeCertList(
    PVOID       CertList,
    UINT32      CertCount
);

BOOLEAN
Pkcs7Verify(
    CONST BYTE *P7Data,             // IN
    UINT32 P7Length,                // IN
    UINT32 CertCount,               // IN
    CERTIFICATE *CertList,          // IN
    CONST BYTE *InData,             // IN
    UINT32 DataLength               // IN
);

TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE Var1,       // IN
    SECUREBOOT_VARIABLE Var2,       // IN
    CERTIFICATE **Certs,            // INOUT              
    UINT32 *NumberOfCerts           // OUT
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

static
UINT32
GetStartOfVal(
    PBYTE Message,                  // IN
    UINT32 Position                 // IN
);

//
// Extern (varauth.c)
//

extern
BOOLEAN
WrapPkcs7Data(
    CONST UINT8 *P7Data,            // IN
    UINT32 P7Length,                // IN
    BOOLEAN *WrapFlag,              // OUT
    UINT8 **WrapData,               // OUT
    PUINT32 WrapDataSize            // OUT
);

extern
TEE_Result
CheckSignatureList(
    EFI_SIGNATURE_LIST* SignatureList,  // IN
    PBYTE SignatureListEnd,             // IN
    PUINT32 NumberOfEntries             // OUT
);

extern
TEE_Result
ReadSecurebootVariable(
    SECUREBOOT_VARIABLE Id,     // IN
    BYTE** Data,                // OUT
    PUINT32 DataSize            // OUT
);

//
// WolfSSL AuthVar functions
//

VOID
FreeCertList(
    PVOID       CertList,
    UINT32      CertCount
)
{
    UINT32 i;
    CERTIFICATE *decodedCerts = CertList;

    // Validate parameters
    if (!CertCount || !CertList)
    {
        return;
    }

    // Free resources used on verify
    for (i = 0; i < CertCount; i++)
    {
        FreeDecodedCert(&(decodedCerts[i]));
    }

    // Free list
    TEE_Free(CertList);

}

BOOLEAN
Pkcs7Verify(
    CONST BYTE         *P7Data,         // IN
    UINT32              P7Length,       // IN
    UINT32              CertCount,      // IN
    CERTIFICATE        *CertList,       // IN
    CONST BYTE         *InData,         // IN
    UINT32              DataLength      // IN
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
    UINT32 signedDataSize = 0;
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
    sigListIndex = (PBYTE)((UINT_PTR)authPtr + sigListOffset);
    sigListLimit = Data + DataSize;

    DMSG("DATA: %x DATASIZE: %x", Data, DataSize);
    DMSG("slO: %x slI: %x slL: %x", sigListOffset, sigListIndex, sigListLimit);

    // Integer overflow check
    if ((UINT_PTR)sigListLimit <= (UINT_PTR)Data)
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
PopulateCerts(
    SECUREBOOT_VARIABLE PK,     // IN
    SECUREBOOT_VARIABLE KEK,    // IN
    CERTIFICATE **Certs,        // INOUT
    PUINT32 CertCount           // OUT
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
    TEE_Result status;
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
    certs = TEE_Malloc((sizeof(CERTIFICATE) * (PKcount + KEKcount)), TEE_MALLOC_FILL_ZERO);
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
