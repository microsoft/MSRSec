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

 // OSSL cert type
typedef struct _CRYPTOAPI_BLOB {
    ULONG   cbData;
    UCHAR   *pbData;
} CERTIFICATE, *PCERTIFICATE, CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB;

//
// Library-specific functions (implemented for each of OSSL, WolfSSL, etc.):
//  1. FreeCertList            - Free resources associated with Certificate(s)
//  2. Pkcs7Verify             - Validate PKCS7 data
//  3. PopulateCerts           - Pull certificate(s) from secure boot variables
//  4. Certificate type        - For OpenSSL: PCRYPT_DATA_BLOB
//
// Static library-specific functions (helper functions):
//  1. ParseSecurebootVariable - Dependency of PopulateCerts
//  2. Other(s)                - For OpenSSL: X509VerifyCb()
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
    PVOID       CertList,           // IN
    UINT32      CertCount           // IN
);

BOOLEAN
Pkcs7Verify(
    CONST BYTE *P7Data,             // IN
    UINTN P7Length,                 // IN
    UINT32 CertCount,               // IN
    CERTIFICATE *CertList,          // IN
    CONST BYTE *InData,             // IN
    UINTN DataLength                // IN
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
ParseSecurebootVariables(
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PARSE_SECURE_BOOT_OP Op,        // IN
    CERTIFICATE *Certs,             // INOUT
    PUINT32 NumberOfCerts           // INOUT
);

static
int
X509VerifyCb(
    int              Status,        // IN
    X509_STORE_CTX  *Context        // IN
);

//
// Extern (varauth.c)
//

extern
BOOLEAN
WrapPkcs7Data(
    CONST UINT8 *P7Data,            // IN
    UINTN P7Length,                 // IN
    BOOLEAN *WrapFlag,              // OUT
    UINT8 **WrapData,               // OUT
    UINTN *WrapDataSize             // OUT
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
    PVOID       CertList,           // IN
    UINT32      CertCount           // IN
)
{
    UINT32 i;
    PCRYPT_DATA_BLOB certs = CertList;

    // Validate parameters
    if (!CertCount || !CertList)
    {
        return;
    }

    // Free resources used on verify
    for (i = 0; i < CertCount; i++)
    {
        TEE_Free(certs[i].pbData);
    }

    // Free list
    TEE_Free(CertList);
}

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
    PKCS7       *Pkcs7;
    BIO         *DataBio;
    BOOLEAN     Status;
    X509        *Cert;
    X509_STORE  *CertStore;
    UINT8       *SignedData;
    UINT8       *Temp;
    UINTN       SignedDataSize;
    BOOLEAN     Wrapped;

    //
    // Check input parameters.
    //
    if (P7Data == NULL || TrustedCert == NULL || InData == NULL ||
        P7Length > INT_MAX || CertLength > INT_MAX || DataLength > INT_MAX) {
        return FALSE;
    }

    // TODO: PKCS7GETSIGNERS FIRST if NULL/0
    //
//    verifyStatus = Pkcs7GetSigners(AuthenticationData,
//                                   AuthenticationDataSize,
//                                   &signerCerts,
//                                   &signerCertStackSize,
//                                   &rootCert,
//                                   &rootCertSize);
//    if (!verifyStatus)
//    {
//        return FALSE;
//    }

    Pkcs7 = NULL;
    DataBio = NULL;
    Cert = NULL;
    CertStore = NULL;

    //
    // Register & Initialize necessary digest algorithms for PKCS#7 Handling
    //
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


    //foreach certificate in list
    {


    //
    // Read DER-encoded root certificate and Construct X509 Certificate
    //
    Cert = d2i_X509(NULL, &TrustedCert, (long)CertLength);
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
    // Register customized X509 verification callback function to support
    // trusted intermediate certificate anchor.
    //
    CertStore->verify_cb = X509VerifyCb;

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

    if (signerCerts != NULL)
    {
        free(signerCerts);
    }

    if (rootCert != NULL)
    {
        free(rootCert);
    }

    return Status;
}

static
int
X509VerifyCb(
    int              Status,
    X509_STORE_CTX  *Context
)
/*++
    Routine Description:

        Verification callback function to override any existing callbacks in
        OpenSSL for intermediate certificate supports.

    Arguments:

        Status - Original status before calling this callback.

        Context - X509 store context.

    Returns:

        1   Current X509 certificate is verified successfully.

        0   Verification failed.

--*/
{
    X509_OBJECT  *Obj;
    INTN         Error;
    INTN         Index;
    INTN         Count;

    Obj = NULL;
    Error = (INTN)X509_STORE_CTX_get_error(Context);

    //
    // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT and X509_V_ERR_UNABLE_TO_GET_ISSUER_
    // CERT_LOCALLY mean a X509 certificate is not self signed and its issuer
    // can not be found in X509_verify_cert of X509_vfy.c.
    // In order to support intermediate certificate node, we override the
    // errors if the certification is obtained from X509 store, i.e. it is
    // a trusted ceritifcate node that is enrolled by user.
    // Besides,X509_V_ERR_CERT_UNTRUSTED and X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
    // are also ignored to enable such feature.
    //
    if ((Error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) ||
        (Error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
        Obj = (X509_OBJECT *)TEE_Malloc(sizeof(X509_OBJECT), TEE_USER_MEM_HINT_NO_FILL_ZERO);
        if (Obj == NULL) {
            return 0;
        }

        Obj->type = X509_LU_X509;
        Obj->data.x509 = Context->current_cert;

        CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);

        if (X509_OBJECT_retrieve_match(Context->ctx->objs, Obj)) {
            Status = 1;
        }
        else {
            //
            // If any certificate in the chain is enrolled as trusted certificate,
            // pass the certificate verification.
            //
            if (Error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
                Count = (INTN)sk_X509_num(Context->chain);
                for (Index = 0; Index < Count; Index++) {
                    Obj->data.x509 = sk_X509_value(Context->chain, (int)Index);
                    if (X509_OBJECT_retrieve_match(Context->ctx->objs, Obj)) {
                        Status = 1;
                        break;
                    }
                }
            }
        }

        CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
    }

    if ((Error == X509_V_ERR_CERT_UNTRUSTED) ||
        (Error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)) {
        Status = 1;
    }

    if (Obj != NULL) {
        OPENSSL_free(Obj);
    }

    return Status;
}

TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE Var1,       // IN
    SECUREBOOT_VARIABLE Var2,       // IN
    PCRYPT_DATA_BLOB *Certs,        // INOUT              
    UINT32 *NumberOfCerts           // OUT
)
/*++

    Routine Description:

        Routine for reading and populating X509 certs from secureboot variables

    Arguments:

        Var1 - Enum selecting secureboot variable

        Var1 - Enum selecting secureboot variable

        Certs - Supplies a list of certificates parsed from both the variables

        NumberOfCerts - supplies number of certs in Certs

    Returns:

        TEE_Result

--*/
{
    ERR_INIT_STATUS;
    UINT32 count1 = 0, count2 = 0, i, parsedCount, data1Size = 0, data2Size = 0;
    PCRYPT_DATA_BLOB certs = NULL;
    PBYTE data1 = NULL, data2 = NULL;

    //
    // Read the variables
    //

    ERR_PASS(ReadSecurebootVariables(Var1,
        &data1,
        &data1Size));


    if (Var2 != SecureBootVariableEnd)
    {
        ERR_PASS(ReadSecurebootVariables(Var2,
            &data2,
            &data2Size));
    }

    //
    // First, find how many certs qualify and allocate memory for the list accordingly
    //

    ERR_PASS(ParseSecurebootVariables(data1,
        data1Size,
        ParseForX509Certs,
        NULL,
        &count1));

    if (Var2 != SecureBootVariableEnd)
    {
        ERR_PASS(ParseSecurebootVariables(data2,
            data2Size,
            ParseForX509Certs,
            NULL,
            &count2));
    }

    LOGA("Finished counting certs. Count1 = %u, Count2 = %u", count1, count2);

    certs = WtrSecAllocateMemory(sizeof(CRYPT_DATA_BLOB) * (count1 + count2));

    RET_ERROR_IF_NULL(certs, STATUS_NO_MEMORY);

    RtlZeroMemory(certs,
        sizeof(CRYPT_DATA_BLOB) * (count1 + count2));

    LOG("Now populating certs");

    parsedCount = count1;

    ERR_PASS(ParseSecurebootVariables(data1,
        data1Size,
        ParseForX509Certs,
        certs,
        &parsedCount));

    TREE_ASSERT(parsedCount == count1);

    if (Var2 != SecureBootVariableEnd)
    {
        parsedCount = count2;

        ERR_PASS(ParseSecurebootVariables(data2,
            data2Size,
            ParseForX509Certs,
            &certs[count1],
            &parsedCount));
        TREE_ASSERT(parsedCount == count2);
    }

    *Certs = certs;
    *NumberOfCerts = count1 + count2;

cleanup:
    WtrSecFreeMemory(data1);
    WtrSecFreeMemory(data2);

    if (!NT_SUCCESS(ERR_VAR))
    {
        for (i = 0; i < (count1 + count2); i++)
        {
            WtrSecFreeMemory(certs[i].pbData);
        }
        WtrSecFreeMemory(certs);
    }

    ERR_RETURN_STATUS;
}

static
TEE_Result
ParseSecurebootVariables(
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PARSE_SECURE_BOOT_OP Op,        // IN
    PCRYPT_DATA_BLOB Certs,         // INOUT
    PUINT32 NumberOfCerts           // INOUT
)
/*++

    Routine Description:

        Routine for implementing UEFI GetNextVariableName operation

    Arguments:

        Data - Content of an authenticated secureboot variable

        DataSize - Size in bytes of Data

        Op - Opcode to choose between parsing all certs or only x509 certs

        Certs - If NULL, NumberOfCerts contains total number of certs in variable filtered by Op
                If non-NULL, Certs contains a list of certificates

        NumberOfCerts - contains total number of certs in variable filtered by Op

    Returns:

        TEE_Result

--*/
{
    ERR_INIT_STATUS;

    UINT32 numberOfCerts = 0, index = 0, i, numberOfEntries, certSize = 0;
    PBYTE locationInSigLists, locationEnd, certEntry, firstCert = NULL;
    EFI_SIGNATURE_LIST* signatureList;
    BOOLEAN alloc = FALSE;

    locationInSigLists = Data;
    locationEnd = Data + DataSize;

    if (DataSize < sizeof(EFI_SIGNATURE_LIST))
    {
        ERR_GENERATE(STATUS_INVALID_PARAMETER);
    }

    //
    // Integer overflow check
    //
    if ((UINT32)locationEnd <= (UINT32)Data)
    {
        ERR_GENERATE(STATUS_INVALID_PARAMETER);
    }

    while (locationInSigLists < locationEnd)
    {
        alloc = FALSE;
        signatureList = (EFI_SIGNATURE_LIST*)locationInSigLists;

        ERR_PASS(CheckSignatureListSanity(signatureList,
            locationEnd,
            &numberOfEntries));

        if (Op == ParseAllSignature)
        {
            numberOfCerts += numberOfEntries;
            certSize = signatureList->SignatureSize;
            firstCert = (PBYTE)signatureList + sizeof(EFI_SIGNATURE_LIST);
            alloc = TRUE;
        }

        else if ((Op == ParseForX509Certs) &&
            (memcmp(&signatureList->SignatureType,
                &EfiCertX509Guid,
                sizeof(GUID)) == 0))
        {
            numberOfCerts += numberOfEntries;
            certSize = signatureList->SignatureSize - sizeof(EFI_SIGNATURE_DATA);
            firstCert = (PBYTE)signatureList + sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA);
            alloc = TRUE;
        }

        if (alloc)
        {
            if (Certs != NULL)
            {
                for (i = 0; i < numberOfEntries; i++)
                {
                    TREE_ASSERT(firstCert != NULL);

                    certEntry = firstCert + (i * signatureList->SignatureSize);

                    if (index >= *NumberOfCerts)
                    {
                        ERR_GENERATE(STATUS_INTERNAL_ERROR);
                    }

                    Certs[index].cbData = certSize;

                    Certs[index].pbData = WtrSecAllocateMemory(certSize);

                    RET_ERROR_IF_NULL(Certs[index].pbData, STATUS_NO_MEMORY);

                    memmove(Certs[index].pbData,
                        certEntry,
                        certSize);

                    index++;
                }
            }
        }

        locationInSigLists += signatureList->SignatureListSize;
    }

    if (locationInSigLists != locationEnd)
    {
        ERR_GENERATE(STATUS_INVALID_SIGNATURE);
    }

    LOG("Done parsing variable");

    *NumberOfCerts = numberOfCerts;

cleanup:
    if (!ERR_SUCCESS(ERR_VAR))
    {
        for (i = 0; (i < index) && (i < *NumberOfCerts); i++)
        {
            WtrSecFreeMemory(Certs[i].pbData);
        }
    }

    ERR_RETURN_STATUS;
}