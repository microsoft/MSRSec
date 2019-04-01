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

// Usage for #def'ed GUIDs
extern const GUID EfiCertX509Guid;
extern const GUID EfiCertTypePKCS7Guid;

// OpenSSL certificate type
typedef struct _CRYPTOAPI_BLOB {
    ULONG   cbData;
    UCHAR   *pbData;
} CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB;

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
    CRYPT_DATA_BLOB **Certs,        // INOUT              
    UINT32 *NumberOfCerts           // OUT
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
    PCRYPT_DATA_BLOB    CertList,           // IN
    UINT32              CertCount           // IN
)
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

BOOLEAN
Pkcs7Verify(
    CONST BYTE         *P7Data,         // IN
    UINT32              P7Length,       // IN
    UINT32              CertCount,      // IN
    CRYPT_DATA_BLOB    *CertList,       // IN
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
    PKCS7       *Pkcs7;
    BIO         *DataBio;
    BOOLEAN     Status;
    X509        *Cert;
    X509_STORE  *CertStore;
    UINT8       *SignedData;
    CONST UINT8 *Temp;
    UINT32      SignedDataSize;
    BOOLEAN     Wrapped;

    //
    // Check input parameters.
    //
    if (P7Data == NULL || CertList == NULL || InData == NULL ||
        P7Length > INT_MAX || CertCount > INT_MAX || DataLength > INT_MAX) {
        return FALSE;
    }

    Pkcs7 = NULL;
    DataBio = NULL;
    Cert = NULL;
    CertStore = NULL;

    //
    // Register & Initialize necessary digest algorithms for PKCS#7 Handling
    //
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

    Status = WrapPkcs7Data(P7Data, P7Length, &Wrapped, &SignedData, &SignedDataSize);
    if (!Status) {
        return Status;
    }

    Status = FALSE;

    //
    // Retrieve PKCS#7 Data (DER encoding)
    //
    if (SignedDataSize > INT_MAX) {
        goto _Exit;
    }

    Temp = SignedData;
    Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&Temp, (int)SignedDataSize);
    if (Pkcs7 == NULL) {
        goto _Exit;
    }

    //
    // Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
    //
    if (!PKCS7_type_is_signed(Pkcs7)) {
        goto _Exit;
    }

    //
    // Read DER-encoded root certificate and Construct X509 Certificate
    //
    Temp = CertList;
    Cert = d2i_X509(NULL, &Temp, (long)CertCount);
    if (Cert == NULL) {
        goto _Exit;
    }

    //
    // Setup X509 Store for trusted certificate
    //
    CertStore = X509_STORE_new();
    if (CertStore == NULL) {
        goto _Exit;
    }
    if (!(X509_STORE_add_cert(CertStore, Cert))) {
        goto _Exit;
    }

    //
    // For generic PKCS#7 handling, InData may be NULL if the content is present
    // in PKCS#7 structure. So ignore NULL checking here.
    //
    DataBio = BIO_new(BIO_s_mem());
    if (DataBio == NULL) {
        goto _Exit;
    }

    if (BIO_write(DataBio, InData, (int)DataLength) <= 0) {
        goto _Exit;
    }

    //
    // Allow partial certificate chains, terminated by a non-self-signed but
    // still trusted intermediate certificate. Also disable time checks.
    //
    X509_STORE_set_flags(CertStore,
        X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_NO_CHECK_TIME);

    //
    // OpenSSL PKCS7 Verification by default checks for SMIME (email signing) and
    // doesn't support the extended key usage for Authenticode Code Signing.
    // Bypass the certificate purpose checking by enabling any purposes setting.
    //
    X509_STORE_set_purpose(CertStore, X509_PURPOSE_ANY);

    //
    // Verifies the PKCS#7 signedData structure
    //
    Status = (BOOLEAN)PKCS7_verify(Pkcs7, NULL, CertStore, DataBio, NULL, PKCS7_BINARY);

_Exit:
    //
    // Release Resources
    //
    BIO_free(DataBio);
    X509_free(Cert);
    X509_STORE_free(CertStore);
    PKCS7_free(Pkcs7);

    if (!Wrapped) {
        OPENSSL_free(SignedData);
    }

    return Status;
}

TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE PK,     // IN
    SECUREBOOT_VARIABLE KEK,    // IN
    PCRYPT_DATA_BLOB *Certs,    // INOUT              
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