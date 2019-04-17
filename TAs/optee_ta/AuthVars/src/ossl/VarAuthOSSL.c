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

// OpenSSL includes
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>

// OpenSSL certificate type
typedef struct _CRYPTOAPI_BLOB {
    ULONG   cbData;
    UCHAR   *pbData;
} CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB;

// Usage for #def'ed GUIDs
extern const GUID EfiCertX509Guid;
extern const GUID EfiCertTypePKCS7Guid;

//
// Library-specific functions (implemented for each of OSSL, WolfSSL, etc.):
//  1. FreeCertList            - Free resources associated with Certificate(s)
//  2. Pkcs7Verify             - Validate PKCS7 data
//  3. PopulateCerts           - Pull certificate(s) from secure boot variables
//
// Static library-specific functions (helper functions):
//  1. ParseSecurebootVariable - Dependency of PopulateCerts
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
    PCRYPT_DATA_BLOB CertList,      // IN
    UINT32 CertCount                // IN
);

BOOLEAN
Pkcs7Verify(
    CONST BYTE *P7Data,             // IN
    UINT32 P7Length,                // IN
    UINT32 CertCount,               // IN
    CRYPT_DATA_BLOB *CertList,      // IN
    CONST BYTE *InData,             // IN
    UINT32 DataLength               // IN
);

TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE PK,         // IN
    SECUREBOOT_VARIABLE KEK,        // IN
    CRYPT_DATA_BLOB **Certs,        // OUT              
    UINT32 *CertCount               // OUT
);

static
BOOLEAN
X509PopCertificate(
    VOID *X509Stack,                // IN
    UINT8 **Cert,                   // OUT
    UINT32 *CertSize                // OUT
);

static
BOOLEAN
Pkcs7GetSigners(
    CONST UINT8 *P7Data,            // IN
    UINT32 P7Length,                // IN
    UINT8 **CertStack,              // OUT
    UINT32 *StackLength,            // OUT
    UINT8 **TrustedCert,            // OUT
    UINT32 *CertLength              // OUT
);

static
TEE_Result
ParseSecurebootVariable(
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PARSE_SECURE_BOOT_OP Op,        // IN
    CRYPT_DATA_BLOB *Certs,         // INOUT
    PUINT32 NumberOfCerts           // INOUT
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
// OpenSSL AuthVar functions
//

VOID
FreeCertList(
    CRYPT_DATA_BLOB    *CertList,           // IN
    UINT32              CertCount           // IN
)
/*++

    Routine Description:

        Frees resources associated with library-specific cert types

    Arguments:

        CertList - Pointer to a list of CRYPT_DATA_BLOB structures

        CertCount - Number of entries in CertList

    Returns:

        None

--*/
{
    UINT32 i;

    // Validate parameters
    if (!CertCount || !CertList)
    {
        return;
    }

    // Free resources used on verify
    for (i = 0; i < CertCount; i++)
    {
        TEE_Free(CertList[i].pbData);
    }

    // Free list
    TEE_Free(CertList);
}

/**
  Pop single certificate from STACK_OF(X509).

  If X509Stack, Cert, or CertSize is NULL, then return FALSE.

  @param[in]  X509Stack       Pointer to a X509 stack object.
  @param[out] Cert            Pointer to a X509 certificate.
  @param[out] CertSize        Length of output X509 certificate in bytes.

  @retval     TRUE            The X509 stack pop succeeded.
  @retval     FALSE           The pop operation failed.

**/
static
BOOLEAN
X509PopCertificate(
    VOID  *X509Stack,               // IN
    UINT8 **Cert,                   // OUT
    UINT32 *CertSize                // OUT
)
/*++

    Routine Description:

        Pop single certificate from STACK_OF(X509)

    Arguments:

        X509Stack - Pointer to X509 stack object

        Cert - Buffer to receive X509 cert bytes

        CertSize - Receives length in bytes of Cert

    Returns:

        TRUE - Success

        FALSE - Otherwise

--*/
{
    BIO *CertBio = NULL;
    X509 *X509Cert;
    STACK_OF(X509) *CertStack;
    BUF_MEM *Ptr;
    VOID *Buffer = NULL;
    INT32 Length, Result;
    BOOLEAN Status;

    // Parameter validation
    if (!X509Stack || !Cert || !CertSize)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Init
    CertStack = (STACK_OF(X509) *) X509Stack;
    X509Cert = sk_X509_pop(CertStack);
    if (X509Cert == NULL)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // New BIO
    CertBio = BIO_new(BIO_s_mem());
    if (CertBio == NULL)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // DER encode
    Result = i2d_X509_bio(CertBio, X509Cert);
    if (Result == 0)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Get pointer to underlying BUF_MEM structure (retrieve length)
    BIO_get_mem_ptr(CertBio, &Ptr);
    Length = (INT32)(Ptr->length);
    if (Length <= 0)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Allocate buffer for cert
    if (!(Buffer = TEE_Malloc(Length, TEE_MALLOC_FILL_ZERO)))
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Do the copy
    Result = BIO_read(CertBio, Buffer, Length);
    if (Result != Length)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Outputs and success
    *Cert = Buffer;
    *CertSize = Length;
    Status = TRUE;

Cleanup:
    BIO_free(CertBio);
    if (!Status && Buffer)
    {
        TEE_Free(Buffer);
    }

    return Status;
}

static
BOOLEAN
Pkcs7GetSigners(
    CONST UINT8 *P7Data,            // IN
    UINT32 P7Length,                // IN
    UINT8 **CertStack,              // OUT
    UINT32 *StackLength,            // OUT
    UINT8 **TrustedCert,            // OUT
    UINT32 *CertLength              // OUT
)
/*++

    Routine Description:

        Get the signer's certificates from PKCS#7 signed data as described in
        "PKCS #7: Cryptographic Message Syntax Standard". The input signed data
        could be wrapped in a ContentInfo structure.

        If P7Data, CertStack, StackLength, TrustedCert or CertLength is NULL,
        then return FALSE. If P7Length overflow, then return FALSE.

        Caution: This function may receive untrusted input. UEFI Authenticated
        Variable is external input, so this function will do basic check for
        PKCS#7 data structure.

    Arguments:

        P7Data - Pointer to the PKCS#7 message to verify.

        P7Length - Length of the PKCS#7 message in bytes.

        CertStack - Pointer to Signer's certificates retrieved from P7Data.
                   
        StackLength - Length of signer's certificates in bytes.
  
        TrustedCert - Pointer to a trusted certificate from Signer's certificates.

        CertLength - Length of the trusted certificate in bytes.

    Returns:

        TRUE - Success

        FALSE - Otherwise

--*/
{
    PKCS7 *Pkcs7;
    UINT8 *SignedData;
    CONST UINT8 *Temp;
    UINT32 SignedDataSize;
    STACK_OF(X509) *Stack;
    UINT8 *CertBuf, *OldBuf, *SingleCert;
    UINT32 BufferSize, OldSize, SingleCertSize;
    BOOLEAN Wrapped, Status;
    UINT8 Index;

    // Validate parameters
    if ((P7Data == NULL) || (CertStack == NULL) || (StackLength == NULL) ||
        (TrustedCert == NULL) || (CertLength == NULL) || (P7Length > INT_MAX))
    {
        return FALSE;
    }

    // REVISIT: Is this necessary?
    Status = WrapPkcs7Data(P7Data, P7Length, &Wrapped, &SignedData, &SignedDataSize);
    if (!Status)
    {
        return Status;
    }

    // Sanity check data size
    if (SignedDataSize > INT_MAX)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Assume failure
    Status = FALSE;

    // Init for Cleanup
    Pkcs7 = NULL;
    Stack = NULL;
    CertBuf = NULL;
    OldBuf = NULL;
    SingleCert = NULL;

    // Retrieve PKCS#7 Data
    Temp = SignedData;
    Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&Temp, (int)SignedDataSize);
    if (Pkcs7 == NULL)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Check if it's PKCS#7 Signed Data
    if (!PKCS7_type_is_signed(Pkcs7))
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Get signer's certs
    Stack = PKCS7_get0_signers(Pkcs7, NULL, PKCS7_BINARY);
    if (Stack == NULL)
    {
        Status = FALSE;
        goto Cleanup;
    }

    //
    // Convert CertStack to buffer in following format:
    // UINT8  CertNumber;
    // UINT32 Cert1Length;
    // UINT8  Cert1[];
    // UINT32 Cert2Length;
    // UINT8  Cert2[];
    // ...
    // UINT32 CertnLength;
    // UINT8  Certn[];
    //
    BufferSize = sizeof(UINT8);
    OldSize = BufferSize;

    // Iterate cert stack
    for (Index = 0; ; Index++)
    {
        Status = X509PopCertificate(Stack, &SingleCert, &SingleCertSize);
        if (!Status)
        {
            break;
        }

        OldSize = BufferSize;
        OldBuf = CertBuf;
        BufferSize = OldSize + SingleCertSize + sizeof(UINT32);

        // Alloc buffer for new length (REVISIT: Consider TEE_Realloc)
        CertBuf = TEE_Malloc(BufferSize, TEE_USER_MEM_HINT_NO_FILL_ZERO);
        if (CertBuf == NULL)
        {
            Status = FALSE;
            goto Cleanup;
        }

        // Free prev buffer
        if (OldBuf != NULL)
        {
            memcpy(CertBuf, OldBuf, OldSize);
            TEE_Free(OldBuf);
            OldBuf = NULL;
        }

        // May be unaligned
        memcpy((UINT32 *)(CertBuf + OldSize), &SingleCertSize, sizeof(UINT32));

        // Copy cert
        memcpy(CertBuf + OldSize + sizeof(UINT32), SingleCert, SingleCertSize);

        // Free pop'ed cert
        TEE_Free(SingleCert);
        SingleCert = NULL;
    }

    if (CertBuf != NULL) {

        // Update CertNumber.
        CertBuf[0] = Index;

        // Outputs
        *CertLength = BufferSize - OldSize - sizeof(UINT32);
        *TrustedCert = TEE_Malloc(*CertLength, TEE_USER_MEM_HINT_NO_FILL_ZERO);
        if (*TrustedCert == NULL)
        {
            Status = FALSE;
            goto Cleanup;
        }

        // Outputs and success
        memcpy(*TrustedCert, CertBuf + OldSize + sizeof(UINT32), *CertLength);
        *CertStack = CertBuf;
        *StackLength = BufferSize;
        Status = TRUE;
    }

Cleanup:
    // Release Resources
    if (!Wrapped)
    {
        TEE_Free(SignedData);
    }

    if (Pkcs7 != NULL)
    {
        PKCS7_free(Pkcs7);
    }

    if (Stack != NULL)
    {
        sk_X509_pop_free(Stack, X509_free);
    }

    if (SingleCert != NULL)
    {
        TEE_Free(SingleCert);
    }

    if (!Status && (CertBuf != NULL))
    {
        TEE_Free(CertBuf);
        *CertStack = NULL;
    }

    if (OldBuf != NULL) 
    {
        TEE_Free(OldBuf);
    }

    return Status;
}

BOOLEAN
Pkcs7Verify(
    CONST BYTE *P7Data,         // IN
    UINT32 P7Length,            // IN
    UINT32 CertCount,           // IN
    CRYPT_DATA_BLOB *CertList,  // IN
    CONST BYTE *InData,         // IN
    UINT32 DataLength           // IN
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
    PKCS7 *Pkcs7;
    BIO *DataBio;
    X509 *Cert;
    X509_STORE *CertStore;
    UINT8 *SignedData;
    CONST UINT8 *Temp;
    UINT8 *signerCerts = NULL, *rootCert = NULL;
    UINT32 i, SignedDataSize;
    UINT32 rootCertSize, signerCertStackSize;
    BOOLEAN Wrapped, Status;

    // Parameter validation
    if ((P7Data == NULL) || (InData == NULL) || (P7Length > INT_MAX) ||
        (CertCount > INT_MAX) || (DataLength > INT_MAX))
    {
        return FALSE;
    }

    // Init for Cleanup
    Pkcs7 = NULL;
    DataBio = NULL;
    Cert = NULL;
    CertStore = NULL;

    // Register & Initialize necessary digest algorithms for PKCS#7 Handling
    if (EVP_add_digest(EVP_md5()) == 0) {
        return FALSE;
    }
    if (EVP_add_digest(EVP_sha1()) == 0) {
        return FALSE;
    }
    if (EVP_add_digest(EVP_sha256()) == 0) {
        return FALSE;
    }
    if (EVP_add_digest(EVP_sha384()) == 0) {
        return FALSE;
    }
    if (EVP_add_digest(EVP_sha512()) == 0) {
        return FALSE;
    }
    if (EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA) == 0) {
        return FALSE;
    }

    // REVISIT: Is this necessary?
    Status = WrapPkcs7Data(P7Data, P7Length, &Wrapped, &SignedData, &SignedDataSize);
    if (!Status)
    {
        goto Cleanup;
    }

    // Retrieve PKCS#7 Data
    if (SignedDataSize > INT_MAX)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Decode PKCS7 data
    Temp = SignedData;
    Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&Temp, (int)SignedDataSize);
    if (Pkcs7 == NULL)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Check if it's PKCS#7 Signed Data
    if (!PKCS7_type_is_signed(Pkcs7))
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Setup X509 Store for trusted certificate
    CertStore = X509_STORE_new();
    if (CertStore == NULL)
    {
        Status = FALSE;
        goto Cleanup;
    }

    //
    // Were we given a set of certs?
    //
    if (CertList)
    {
        // Yes, process cert list
        for (i = 0; i < CertCount; i++)
        {
            // DER->X509
            Cert = d2i_X509(NULL, CertList[i].pbData, CertList[i].cbData);
            if (Cert == NULL)
            {
                Status = FALSE;
                goto Cleanup;
            }

            // Add to trusted cert store
            if (!(X509_STORE_add_cert(CertStore, Cert)))
            {
                Status = FALSE;
                goto Cleanup;
            }
        }

    }
    else
    {
        // No, get signers
        Status = Pkcs7GetSigners(P7Data,
                                 P7Length,
                                 &signerCerts,
                                 &signerCertStackSize,
                                 &rootCert,
                                 &rootCertSize);

        // Free this up front, we don't need it.
        if (signerCerts)
        {
            TEE_Free(signerCerts);
        }

        // Error on getting signer's certs?
        if (!Status)
        {
            goto Cleanup;
        }

        // DER->X509
        Cert = d2i_X509(NULL, &rootCert, rootCertSize);
        if (Cert == NULL)
        {
            Status = FALSE;
            goto Cleanup;
        }

        // Add to trusted cert store
        if (!(X509_STORE_add_cert(CertStore, Cert)))
        {
            Status = FALSE;
            goto Cleanup;
        }
    }

    // For generic PKCS#7 handling, InData may be NULL if the content is present
    // in PKCS#7 structure. So ignore NULL checking here.
    DataBio = BIO_new(BIO_s_mem());
    if (DataBio == NULL)
    {
        Status = FALSE;
        goto Cleanup;
    }

    if (BIO_write(DataBio, InData, (int)DataLength) <= 0)
    {
        Status = FALSE;
        goto Cleanup;
    }

    // Allow partial certificate chains, terminated by a non-self-signed but
    // still trusted intermediate certificate. Also disable time checks.
    X509_STORE_set_flags(CertStore,
        X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_NO_CHECK_TIME);

    // OpenSSL PKCS7 Verification by default checks for SMIME (email signing) and
    // doesn't support the extended key usage for Authenticode Code Signing.
    // Bypass the certificate purpose checking by enabling any purposes setting.
    X509_STORE_set_purpose(CertStore, X509_PURPOSE_ANY);

    // Verifies the PKCS#7 signedData structure
    Status = (BOOLEAN)PKCS7_verify(Pkcs7, NULL, CertStore, DataBio, NULL, PKCS7_BINARY);

Cleanup:
    // Release Resources
    BIO_free(DataBio);
    X509_free(Cert);
    X509_STORE_free(CertStore);
    PKCS7_free(Pkcs7);
    if (!Wrapped)
    {
        TEE_Free(SignedData);
    }

    return Status;
}

TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE PK,     // IN
    SECUREBOOT_VARIABLE KEK,    // IN
    CRYPT_DATA_BLOB **Certs,    // OUT              
    UINT32 *CertCount           // OUT
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

        TEE_Result

--*/
{
    PCRYPT_DATA_BLOB certs = NULL;
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
        goto Cleanup;
    }

    // Do we need to also collect certs from KEK database?
    if (needKEK)
    {
        // Read the variable(s)
        status = ReadSecurebootVariable(KEK, &KEKvar, &KEKsize);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        // Pick up x509 cert(s) from KEK
        status = ParseSecurebootVariable(KEKvar->Data, KEKsize, ParseOpX509, NULL, &KEKcount);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }
    }

    DMSG("Finished counting certs. Count1 = %u, Count2 = %u", PKcount, KEKcount);
    certs = TEE_Malloc(sizeof(CRYPT_DATA_BLOB) * (PKcount + KEKcount), TEE_MALLOC_FILL_ZERO);
    if (!certs)
    {
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    // Now do the allocs
    DMSG("Now populating certs");
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
            TEE_Free(certs[i].pbData);
        }

        for (i = PKcount; i < (PKcount + KEKcount); i++)
        {
            TEE_Free(certs[i].pbData);
        }

        TEE_Free(certs);
    }

    return status;
}

static
TEE_Result
ParseSecurebootVariable(
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PARSE_SECURE_BOOT_OP Op,        // IN
    CRYPT_DATA_BLOB *Certs,         // INOUT
    PUINT32 CertCount               // INOUT
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
    PBYTE crtPtr, sigListIndex, sigListLimit, certEntry, firstCert = NULL;
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

                // Alloc for cert (openssl)
                if (!(crtPtr = TEE_Malloc(certSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
                {
                    DMSG("out of memory size: %x", certSize);
                    status = TEE_ERROR_OUT_OF_MEMORY;
                    goto Cleanup;
                }

                // Add cert (openssl)
                Certs[index].cbData = certSize;
                Certs[index].pbData = crtPtr;
                memmove(Certs[index].pbData, certEntry, certSize);
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
    // We assume our caller handles TEE_Free on non-TEE_SUCCESS status
    return status;
}