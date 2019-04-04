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
// NV memory handling
//

#include "TpmError.h"
#include "Admin.h"
#include "VendorString.h"
#include "stdint.h"
#include "malloc.h"
#include "string.h"
#include "NvMemoryLayout.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>



// Used to translate nv offset to block map offset
#define NV_INDEX_MASK       (0xC0UL)
#define NV_BLOCK_MASK       (0x3FUL)

//
// For cleaner descriptor validation
//
#define IS_VALID(a) ((a) != (TEE_HANDLE_NULL))

//
// Storage flags
//
#define TA_STORAGE_FLAGS (TEE_DATA_FLAG_ACCESS_READ  | \
                          TEE_DATA_FLAG_ACCESS_WRITE | \
                          TEE_DATA_FLAG_ACCESS_WRITE_META)

//
// The base Object ID for fTPM storage
//
static const UINT32 s_StorageObjectID = 0x54504D00;	// 'TPM00'

//
// Object handle list for persistent storage objects containing NV
//
static TEE_ObjectHandle s_NVStore[NV_BLOCK_COUNT] = { TEE_HANDLE_NULL };

//
// Map for tacking clean/dirty NV blocks
//
static bool s_blockMap[NV_BLOCK_COUNT] = { 0 };
static bool s_dirty = TRUE;

//
// Shortcut for 'dirty'ing all NV blocks.
//
#define NV_DIRTY_ALL(x)                     \
{                                           \
s_dirty = TRUE;                             \
for (int i = 0; i < NV_BLOCK_COUNT; i++) \
    x[i] = (TRUE);                     \
}

//
// NV state
//
static BOOL  s_NVChipFileNeedsManufacture = FALSE;
static BOOL  s_NVInitialized = FALSE;

//
// Firmware revision
//
static const UINT32 firmwareV1 = FIRMWARE_V1;
static const UINT32 firmwareV2 = FIRMWARE_V2;

//
// Revision fro NVChip
//
static UINT64 s_chipRevision = 0;

VOID
_plat__NvInitFromStorage()
{
	DMSG("_plat__NvInitFromStorage()");
	UINT32 i;
	BOOL initialized;
	UINT32 objID;
	UINT32 bytesRead;
	TEE_Result Result;

	// Don't re-initialize.
	if (s_NVInitialized) {
		return;
	}

	//
	// If the NV file is successfully read from the storage then
	// initialized must be set. We are setting initialized to true
	// here but if an error is encountered reading the NV file it will
	// be reset.
	//

	initialized = TRUE;


	// Collect storage objects and init NV.
	for (i = 0; i < NV_BLOCK_COUNT; i++) {

		// Form storage object ID for this block.
		objID = s_StorageObjectID + i;

		DMSG("fTPM:Opening block %d of %d", i, NV_BLOCK_COUNT);

		// Attempt to open TEE persistent storage object.
		Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
									      (void *)&objID,
									      sizeof(objID),
									      TA_STORAGE_FLAGS,
									      &s_NVStore[i]);

		// If the open failed, try to create this storage object.
		if (Result != TEE_SUCCESS) {

			// There was an error, fail the init, NVEnable can retry.
			if (Result != TEE_ERROR_ITEM_NOT_FOUND) {
				DMSG("fTPM: Failed to open fTPM storage object %d", i);
				goto Error;
			}

			DMSG("fTPM: block %d not found, creating", i);

			// Storage object was not found, create it.
			Result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
										        (void *)&objID,
										        sizeof(objID),
										        TA_STORAGE_FLAGS,
										        NULL,
										        (void *)&(s_NV[i * NV_BLOCK_SIZE]),
										        NV_BLOCK_SIZE,
										        &s_NVStore[i]);

			// There was an error, fail the init, NVEnable can retry.
			if (Result != TEE_SUCCESS) {
				DMSG("Failed to create fTPM storage object");
				goto Error;
			}

			// A clean storage object was created, we must (re)manufacture.
			s_NVChipFileNeedsManufacture = TRUE;

			// To ensure NV is consistent, force a write back of all NV blocks
            NV_DIRTY_ALL(s_blockMap);

			// Need to re-initialize
			initialized = FALSE;

			IMSG("Created fTPM storage object, i: 0x%x, s: 0x%x, id: 0x%x, h:0x%x\n",
				i, NV_BLOCK_SIZE, objID, s_NVStore[i]);
		}
		else
        {
			DMSG("fTPM: block %d loaded!", i);
			// Successful open, now read fTPM storage object.
			Result = TEE_ReadObjectData(s_NVStore[i],
										(void *)&(s_NV[i * NV_BLOCK_SIZE]),
										NV_BLOCK_SIZE,
										&bytesRead);

			// Give up on failed or incomplete reads.
			if ((Result != TEE_SUCCESS) || (bytesRead != NV_BLOCK_SIZE)) {
				DMSG("Failed to read fTPM storage object");
				goto Error;
			}

			DMSG("Read fTPM storage object, i: 0x%x, s: 0x%x, id: 0x%x, h:0x%x\n",
				i, bytesRead, objID, s_NVStore[i]);
		}
	}

    // Storage objects are open and valid, next validate revision. Note that a
    // change to s_chipRevision width also requires a change to NvMemoryLayout.h.
	s_chipRevision = ((((UINT64)firmwareV2) << 32) | (firmwareV1));
	if ((s_chipRevision != *(UINT64*)&(s_NV[NV_CHIP_REVISION_OFFSET]))) {

		// Failure to validate revision, re-init (only the TPM's NV memory)
		memset(s_NV, 0, (NV_TPM_STORAGE_SIZE));

        // Going to manufacture, ensure zero flags
        g_chipFlags.flags = 0;

        // Save flags
        _admin__SaveChipFlags();

		// Dirty the block map, we're going to re-init.
        _plat__MarkDirtyBlocks(0, (NV_TPM_STORAGE_SIZE));

		// Init with proper revision
		s_chipRevision = ((((UINT64)firmwareV2) << 32) | (firmwareV1));
		*(UINT64*)&(s_NV[NV_CHIP_REVISION_OFFSET]) = s_chipRevision;

		DMSG("Failed to validate revision. Did we just (re)-init?");

		// Force (re)manufacture.
		s_NVChipFileNeedsManufacture = TRUE;

		// Need to re-initialize
		initialized = FALSE;

		return;
	}

	s_NVInitialized = initialized;

	return;

Error:
	s_NVInitialized = FALSE;
	for (i = 0; i < NV_BLOCK_COUNT; i++) {
		if (IS_VALID(s_NVStore[i])) {
			TEE_CloseObject(s_NVStore[i]);
			s_NVStore[i] = TEE_HANDLE_NULL;
		}
	}

	return;
}


static void
_plat__NvWriteBack()
{
    UINT32 i;
	UINT32 objID;
	TEE_Result Result;
    
	// Exit if no dirty blocks.
	if ((!s_dirty) || (!s_NVInitialized)) {
		return;
	}

    DMSG("Start writeback.");

	// Write dirty blocks.
    for (i = 0; i < NV_BLOCK_COUNT; i++) {

        // Dirty block?
        if ((s_blockMap[i] )) {

			// Form storage object ID for this block.
			objID = s_StorageObjectID + i;
            
			// Move data position associated with handle to start of block.
            Result = TEE_SeekObjectData(s_NVStore[i], 0, TEE_DATA_SEEK_SET);
			if (Result != TEE_SUCCESS) {
				DMSG("e");
				goto Error;
			}

			// Write out this block.
			DMSG("Writing block at 0x%x back", &(s_NV[i * NV_BLOCK_SIZE]));
            Result = TEE_WriteObjectData(s_NVStore[i],
									     (void *)&(s_NV[i * NV_BLOCK_SIZE]),
                                         NV_BLOCK_SIZE);
			if (Result != TEE_SUCCESS) {
				DMSG("e");
				goto Error;
			}
            
			// Force storage stack to update its backing store
            /*TEE_CloseObject(s_NVStore[i]);
            
            Result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                              (void *)&objID,
                                              sizeof(objID),
                                              TA_STORAGE_FLAGS,
                                              &s_NVStore[i]);*/
			// Success?
			if (Result != TEE_SUCCESS) {
				DMSG("e");
				goto Error;
			}

			// Clear dirty bit.
            s_blockMap[i] = FALSE;
        }
    }

	s_dirty = FALSE;
    DMSG("Done writeback");

    return;

Error:
	// Error path.
	DMSG("NV writeback failed, closing storage.");
	s_NVInitialized = FALSE;
	for (i = 0; i < NV_BLOCK_COUNT; i++) {
		if (IS_VALID(s_NVStore[i])) {
			TEE_CloseObject(s_NVStore[i]);
			s_NVStore[i] = TEE_HANDLE_NULL;
		}
	}

	return;
}


BOOL
_plat__NvNeedsManufacture()
{
    return s_NVChipFileNeedsManufacture;
}

//***_plat__NVEnable()
// Enable NV memory.
//
// This version just pulls in data from a file. In a real TPM, with NV on chip,
// this function would verify the integrity of the saved context. If the NV
// memory was not on chip but was in something like RPMB, the NV state would be
// read in, decrypted and integrity checked.
//
// The recovery from an integrity failure depends on where the error occurred. It
// it was in the state that is discarded by TPM Reset, then the error is
// recoverable if the TPM is reset. Otherwise, the TPM must go into failure mode.
// return type: int
//      0           if success
//      > 0         if receive recoverable error
//      <0          if unrecoverable error
LIB_EXPORT int
_plat__NVEnable(
    void            *platParameter  // IN: platform specific parameters
	)
{
    UNREFERENCED_PARAMETER(platParameter);
	DMSG("_plat__NVEnable()");


    UINT32 retVal = 0;
    UINT32 firmwareV1 = FIRMWARE_V1;
    UINT32 firmwareV2 = FIRMWARE_V2;

    // Don't re-open the backing store.
    if (s_NVInitialized) {
        return 0;
    }

	DMSG("s_NV is at 0x%x and is size 0x%x", (uint32_t)s_NV, NV_TOTAL_MEMORY_SIZE);

	// Clear NV
    memset(s_NV, 0, NV_TOTAL_MEMORY_SIZE);

    // Prepare for potential failure to retreieve NV from storage
    s_chipRevision = ((((UINT64)firmwareV2) << 32) | (firmwareV1));
    *(UINT64*)&(s_NV[NV_CHIP_REVISION_OFFSET]) = s_chipRevision;

    // Pick up our NV memory.
    _plat__NvInitFromStorage();

    // Were we successful?
    if (!s_NVInitialized) {
        // Arriving here means one of two things: Either there existed no
        // NV state before we came along and we just (re)initialized our
        // storage. Or there is an error condition preventing us from 
        // accessing storage.  Check which is the case.
        if (s_NVChipFileNeedsManufacture == FALSE) {
            // This condition means we cannot access storage. However, it
            // isn't up to the platform layer to decide what to do in this
            // case. The decision to proceed is made in the fTPM init code
            // in TA_CreateEntryPoint. Here, we're going to make sure that,
            // should we decide not to just TEE_Panic, we can continue
            // execution after (re)manufacture. Later an attempt at re-init
            // can be made by calling _plat__NvInitFromStorage again.
            retVal = 0;
        }
        else {
            retVal = 1;
        }

        // Going to manufacture, zero flags
        g_chipFlags.flags = 0;

        // Save flags
        _admin__SaveChipFlags();

        // Now we're done
        s_NVInitialized = TRUE;

        return retVal;
    }
    else {
        // In the transition out of UEFI to Windows, we may not tear down
        // the TA. We close out one session and start another. This means
        // our s_NVChipFileNeedsManufacture flag, if set, will be stale.
        // Make sure we don't re-manufacture.
        s_NVChipFileNeedsManufacture = FALSE;

        // We successfully initialized NV now pickup TPM state.
        _admin__RestoreChipFlags();

		// Success
		retVal = 1;
    }

    return retVal;
}

//***_platNVDisable()
// Disable NV memory
LIB_EXPORT void
_plat__NVDisable(void)
{
	UINT32 i;

    if (!s_NVInitialized) {
        return;
    }

	// Final write
    _plat__NvWriteBack();

	// Close out all handles
	for (i = 0; i < NV_BLOCK_COUNT; i++) {
		if (IS_VALID(s_NVStore[i])) {
			TEE_CloseObject(s_NVStore[i]);
			s_NVStore[i] = TEE_HANDLE_NULL;
		}
	}

	// We're no longer init-ed
	s_NVInitialized = FALSE;

    return;
}

//***_plat__IsNvAvailable()
// Check if NV is available
// return type: int
//      0               NV is available
//      1               NV is not available due to write failure
//      2               NV is not available due to rate limit
LIB_EXPORT int
_plat__IsNvAvailable(void)
{
    // This is not enabled for OpTEE TA. Storage is always available.
    return 0;
}

//*** _plat__NvIsDifferent()
// This function checks to see if the NV is different from the test value. This is
// so that NV will not be written if it has not changed.
// return value: int
//  TRUE(1)    the NV location is different from the test value
//  FALSE(0)   the NV location is the same as the test value
LIB_EXPORT int
_plat__NvIsDifferent(
    unsigned int         startOffset,         // IN: read start
    unsigned int         size,                // IN: size of bytes to read
    void                *data                 // IN: data buffer
)
{
    return (memcmp(&s_NV[startOffset], data, size) != 0);
}

//***_plat__NvMemoryRead()
// Function: Read a chunk of NV memory
LIB_EXPORT void
_plat__NvMemoryRead(
    unsigned int        startOffset,         // IN: read start
    unsigned int        size,                // IN: size of bytes to read
    void                *data                // OUT: data buffer
)
{
    pAssert((startOffset + size) <= NV_TOTAL_MEMORY_SIZE);
    pAssert(s_NV != NULL);

    memcpy(data, &s_NV[startOffset], size);
}

void
_plat__MarkDirtyBlocks (
	unsigned int		startOffset,
	unsigned int		size
)
{
	unsigned int blockEnd;
	unsigned int blockStart;	
    unsigned int i;

	pAssert(startOffset + size <= NV_TOTAL_MEMORY_SIZE);
	
	//
	// Integer math will round down to the start of the block.
	// blockEnd is actually the last block + 1.
	//

	blockStart = startOffset / NV_BLOCK_SIZE;
	blockEnd = (startOffset + size) / NV_BLOCK_SIZE;
	if ((startOffset + size) % NV_BLOCK_SIZE != 0) {
		blockEnd += 1;
	}

	DMSG("Marking blocks %d to %d dirty", blockStart, blockEnd);
    // Dirty block range
	for (i = blockStart; i < blockEnd; i++) {
        // Mark dirty
		s_blockMap[i] = TRUE;
	}

	s_dirty = TRUE;
}

//***_plat__NvMemoryWrite()
// This function is used to update NV memory. The "write" is to a memory copy of
// NV. At the end of the current command, any changes are written to
// the actual NV memory.
// NOTE: A useful optimization would be for this code to compare the current 
// contents of NV with the local copy and note the blocks that have changed. Then
// only write those blocks when _plat__NvCommit() is called.
LIB_EXPORT void
_plat__NvMemoryWrite(
    unsigned int        startOffset,         // IN: write start
    unsigned int        size,                // IN: size of bytes to read
    void                *data                // OUT: data buffer
)
{
    pAssert(startOffset + size <= NV_TOTAL_MEMORY_SIZE);
    pAssert(s_NV != NULL);

	_plat__MarkDirtyBlocks(startOffset, size);
    memcpy(&s_NV[startOffset], data, size);
}

//***_plat__NvMemoryClear()
// Function is used to set a range of NV memory bytes to an implementation-dependent
// value. The value represents the erase state of the memory.
LIB_EXPORT void
_plat__NvMemoryClear(
    unsigned int     startOffset,           // IN: clear start
    unsigned int     size                   // IN: size of bytes to clear
    )
{
    pAssert(startOffset + size <= NV_TOTAL_MEMORY_SIZE);

	_plat__MarkDirtyBlocks(startOffset, size);
    memset(&s_NV[startOffset], 0, size);
}

//***_plat__NvMemoryMove()
// Function: Move a chunk of NV memory from source to destination
//      This function should ensure that if there overlap, the original data is
//      copied before it is written
LIB_EXPORT void
_plat__NvMemoryMove(
    unsigned int        sourceOffset,         // IN: source offset
    unsigned int        destOffset,           // IN: destination offset
    unsigned int        size                  // IN: size of data being moved
)
{
    pAssert(sourceOffset + size <= NV_TOTAL_MEMORY_SIZE);
    pAssert(destOffset + size <= NV_TOTAL_MEMORY_SIZE);
    pAssert(s_NV != NULL);

	_plat__MarkDirtyBlocks(sourceOffset, size);
	_plat__MarkDirtyBlocks(destOffset, size);

    memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);
}

//***_plat__NvCommit()
// Update NV chip
// return type: int
//  0       NV write success
//  non-0   NV write fail
LIB_EXPORT int
_plat__NvCommit(void)
{
    _plat__NvWriteBack();
    return 0;
}


//***_plat__SetNvAvail()
// Set the current NV state to available.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void
_plat__SetNvAvail(void)
{
    // NV will not be made unavailable on this platform
    return;
}

//***_plat__ClearNvAvail()
// Set the current NV state to unavailable.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void
_plat__ClearNvAvail(void)
{
    // The anti-set; not on this platform.
    return;
}

