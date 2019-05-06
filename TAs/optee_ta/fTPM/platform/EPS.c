/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
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

//
// Platform Endorsement Primary Seed
//

#include "TpmError.h"
#include "Admin.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

//
// To allow for future proofing the OP-TEE property will generate a SHA512
// hash, although the current source of data is only 32 bytes, and the TPM
// currently only requests 32 bytes for the endorsement seed.
//
#define TEE_EPS_SIZE      SHA512_DIGEST_SIZE

void
_plat__GetEPS(size_t Size, uint8_t *EndorsementSeed)
{
    TEE_Result Result = TEE_ERROR_ITEM_NOT_FOUND;
    uint8_t EPS[TEE_EPS_SIZE] = { 0 };
    size_t EPSLen = sizeof(EPS);
    size_t RandBytesGathered = 0;
    uint32_t RandReturn;

    DMSG("EPS Size=%d", Size);
    DMSG("EPS property size=%d",TEE_EPS_SIZE);

    Result = TEE_GetPropertyAsBinaryBlock(TEE_PROPSET_TEE_IMPLEMENTATION,
                                          "com.microsoft.ta.endorsementSeed",
                                          EPS,
                                          &EPSLen);

    if ((Result == TEE_SUCCESS) && (EPSLen >= Size)) {
        IMSG("fTPM retrieved hardware based EPS.");
        memcpy(EndorsementSeed, EPS, Size);
    } else {
        // We failed to access the property. We can't continue without it
        // and we can't just fail to manufacture, so randomize EPS and 
        // continue. If necessary, fTPM TA storage can be cleared, or the
        // TA updated, and we can trigger remanufacture and try again.
        IMSG("fTPM was unable to derive an EPS, falling back to random generation.");
        
        RandBytesGathered = 0;
        while( RandBytesGathered < Size ) {
            RandReturn = _plat__GetEntropy((EndorsementSeed + RandBytesGathered), (Size - RandBytesGathered));
            FMSG("Got %d of %d bytes back for a total of %d", RandReturn, Size, RandBytesGathered);
            if (RandReturn >= 0) {
                RandBytesGathered += RandReturn;
            } else {
                EMSG("fTPM failed to generate a backup random EPS!");
                TEE_Panic(TEE_ERROR_SECURITY);
            }
        }
    }

#ifdef fTPMDebug
    {
        uint32_t x;
        uint8_t *seed = EndorsementSeed;
        DMSG("TEE_GetProperty 0x%x, seedLen 0x%x\n", Result, Size);
        for (x = 0; x < Size; x = x + 8) {
            DMSG(" seed(%2.2d): %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                seed[x + 0], seed[x + 1], seed[x + 2], seed[x + 3],
                seed[x + 4], seed[x + 5], seed[x + 6], seed[x + 7]);
        }
    }
#endif

    return;
}
