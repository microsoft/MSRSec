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

#ifndef _COMBINEDNVMEMORY_H
#define _COMBINEDNVMEMORY_H

#include <PlatformData.h>
#define ROUNDUP(x, y)			((((x) + (y) - 1) / (y)) * (y))

//
// NV Memory is currently 0x4000, to enforce transactional writes leave it as a single block
// for now.
//
//#define NV_BLOCK_SIZE           (0x4000UL)
#define NV_BLOCK_SIZE           (0x1000UL)

// Actual size of Admin space used. (See note in NVMem.c):
//      sizeof(TPM_CHIP_STATE)   - 1 * sizeof(UINT32)
//      sizeof(FTPM_PPI_STATE)   - 3 * sizeof(UINT32)
#define ADMIN_STATE_SIZE    0x10

// Admin space tacked on to NV, padded out to NV_BLOCK_SIZE alignment.
// NOTE: We assume we have at least sizeof(UINT64) bytes in this padding!
#define NV_ADMIN_STATE_SIZE     ROUNDUP(ADMIN_STATE_SIZE, NV_BLOCK_SIZE)

// Total allocation of the fTPM TA's storage for Authenticated Variables
//      fTPM TA storage (128K total):
//                        16K   (0x4000  bytes) - TPM NV storage
//                         1k   (0x1000  bytes) - fTPM "Admin" state
//          128K - (16K + 1k)   (0x1B000 bytes) - AuthVar storage
#define NV_TPM_STORAGE_SIZE ROUNDUP(NV_MEMORY_SIZE + NV_ADMIN_STATE_SIZE, NV_BLOCK_SIZE)

// Align all data to 64 bit alignment
#define NV_ALIGNMENT     __alignof__(UINT64)

//
// Note that NV_TOTAL_MEMORY_SIZE *MUST* be a factor of NV_BLOCK_SIZE.
//
#define NV_TOTAL_MEMORY_SIZE ROUNDUP(NV_TPM_STORAGE_SIZE, NV_BLOCK_SIZE)

#define NV_BLOCK_COUNT      ((NV_TOTAL_MEMORY_SIZE) / (NV_BLOCK_SIZE))

//
// This offset puts the revision field at the end of the TPM Admin
// state. The Admin space in NV is down to 0x14 bytes but is padded out
// to NV_BLOCK_SIZE bytes to avoid alignment issues and allow for growth.
//
// REVISIT: Consider defining a type for the chip revision and managing it 
//          in the same context as other "Admin" state.
//
#define NV_CHIP_REVISION_OFFSET ( (NV_TPM_STORAGE_SIZE) + (NV_ADMIN_STATE_SIZE) - (sizeof(UINT64)) )

#endif
