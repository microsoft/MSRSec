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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include "fTPM.h"

//
// Initialization
//
bool fTPMInitialized = false;

//
// Local (SW) command buffer
//
static uint8_t fTPMCommand[MAX_COMMAND_SIZE];

//
// A subset of TPM return codes (see TpmTypes.h)
//
typedef uint32_t TPM_RC;
typedef uint16_t TPM_ST;
#define RC_VER1             (TPM_RC) (0x100)
#define RC_WARN             (TPM_RC) (0x900)
#define TPM_RC_SUCCESS      (TPM_RC) (0x000)
#define TPM_RC_FAILURE      (TPM_RC) (RC_VER1+0x001)
#define TPM_RC_RETRY        (TPM_RC) (RC_WARN+0x022)
#define TPM_ST_NO_SESSIONS  (TPM_ST) (0x8001)

//
// Command/response sizes we care about
//
#define STARTUP_SIZE            0x0C
#define MIN_RESPONSE_SIZE       0x0A
#define RETRY_RESPONSE_SIZE     MIN_RESPONSE_SIZE


//
// Helper functions for byte ordering of TPM commands/responses
//
static uint16_t SwapBytes16(uint16_t Value)
{
    return (uint16_t)((Value << 8) | (Value >> 8));
}


static uint32_t SwapBytes32(uint32_t Value)
{
    uint32_t  LowerBytes;
    uint32_t  HigherBytes;

    LowerBytes = (uint32_t)SwapBytes16((uint16_t)Value);
    HigherBytes = (uint32_t)SwapBytes16((uint16_t)(Value >> 16));

    return (LowerBytes << 16 | HigherBytes);
}


//
// Read response code from a TPM response buffer
//
static uint32_t fTPMResponseCode(uint32_t ResponseSize, 
                                 uint8_t *ResponseBuffer)
{
    union {
        uint32_t Data;
        uint8_t Index[4];
    } Value;

    // In case of too-small response size, assume failure.
    if (ResponseSize < MIN_RESPONSE_SIZE) {
        return TPM_RC_FAILURE;
    }

    Value.Index[0] = ResponseBuffer[6];
    Value.Index[1] = ResponseBuffer[7];
    Value.Index[2] = ResponseBuffer[8];
    Value.Index[3] = ResponseBuffer[9];

    return SwapBytes32(Value.Data);
}

//
// Craft a TPM_RC_RETRY response buffer
//
static void fTPMRetry(uint32_t *ResponseSize,
                      uint8_t  *ResponseBuffer)
{
    uint8_t *index = ResponseBuffer;

    // Validate arguments
    if (!ResponseSize || !ResponseBuffer) {
        return;
    }

    // Validate buffer size
    if (*ResponseSize < RETRY_RESPONSE_SIZE) {
        *ResponseSize = 0;
        return;
    }

    // Session tag
    *(TPM_ST*)index = TPM_ST_NO_SESSIONS;
    index += sizeof(TPM_ST);

    // Size
    *(uint32_t*)index = 0x0000000A;
    index += sizeof(uint32_t);

    // Response code
    *(TPM_RC*)index = TPM_RC_RETRY;
    index += sizeof(TPM_RC);

    // Bytes written
    *ResponseSize = index - ResponseBuffer;
}

//
// Perform TPM startup operations
//
static TEE_Result fTPMStartup()
{
    uint8_t startupClear[STARTUP_SIZE] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c,
                                           0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
    uint8_t startupState[STARTUP_SIZE] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c,
                                           0x00, 0x00, 0x01, 0x44, 0x00, 0x01 };
    uint8_t *respBuf;
    uint32_t respLen;

    // Don't re-init
    if (fTPMInitialized) {
        return TEE_SUCCESS;
    }

    // Initialize NV admin state (idempotent)
    _admin__NvInitState();

    // This occurs on error or when there was no previous NV state,
    // i.e., on first boot, or after recovering from data loss, or
    // platform storage reset/clear, etc.
    if (_plat__NvNeedsManufacture()) {
        FTPM_MSG("TPM_Manufacture\n");
        TPM_Manufacture(1);
    }

    // "Power-On" the platform
    _plat__Signal_PowerOn();

    // Internal init for reference implementation
    _TPM_Init();

    // TODO: The following should be an assert
    // About to use the startup command buffer for the response,
    // so sanity check STARTUP_SIZE against MIN_RESPONSE_SIZE
    if (STARTUP_SIZE < MIN_RESPONSE_SIZE) {
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // Startup with state
    if (g_chipFlags.fields.TpmStatePresent) {

        // Re-use request buffer for response (ignored)
        respBuf = startupState;
        respLen = STARTUP_SIZE;

        _plat__RunCommand(STARTUP_SIZE, startupState, &respLen, &respBuf);
        if (fTPMResponseCode(respLen, respBuf) == TPM_RC_SUCCESS) {
            goto Exit;
        }

        FTPM_MSG("Fall through to startup clear\n");
        goto Clear;
    }

Clear:
    // Re-use request buffer for response (ignored)
    respBuf = startupClear;
    respLen = STARTUP_SIZE;

    // Fall back to a Startup Clear
    _plat__RunCommand(STARTUP_SIZE, startupClear, &respLen, &respBuf);

Exit:
    // Init is complete, indicate so in fTPM admin state.
    g_chipFlags.fields.TpmStatePresent = 1;
    _admin__SaveChipFlags();

    // Success
    fTPMInitialized = true;
    return TEE_SUCCESS;
}


// 
// Called when TA instance is created. This is the first call to the TA.
// 
TEE_Result TA_CreateEntryPoint(void)
{
    uint32_t nvStatus;

    // Don't re-init
    if (fTPMInitialized) {
        return TEE_SUCCESS;
    }

    // Initialize NV admin state (idempotent)
    _admin__NvInitState();

    // If we encounter an unrecoverable error, we cannot continue.
    if ((nvStatus = _plat__NVEnable(NULL)) < 0) {
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // If NV is available, perform startup
    if (nvStatus == TA_NV_AVAILABLE) {
        fTPMStartup();
    }

    // Success
    return TEE_SUCCESS;
}


// 
// Called when TA instance destroyed.  This is the last call in the TA.
// 
void TA_DestroyEntryPoint(void)
{
    // We should only see this called after the OS has shutdown and there
    // will be no further commands sent to the TPM. Right now, just close
    // our storage object, becasue the TPM driver should have already
    // shutdown cleanly.
    _plat__NVDisable();
    
    // De-init
    fTPMInitialized = false;

    return;
}


// 
// Called when a new session is opened to the TA.
// 
TEE_Result TA_OpenSessionEntryPoint(uint32_t    param_types,
                                    TEE_Param   params[4],
                                    void        **sess_ctx)
{
    uint32_t exp_param_types = TA_ALL_PARAM_TYPE(TEE_PARAM_TYPE_NONE);

    // Unreferenced parameters
    UNREFERENCED_PARAMETER(params);
    UNREFERENCED_PARAMETER(sess_ctx);

    // Single-session TA!
    FTPM_MSG("Open session");

    // Validate parameter types
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}


//
// Called when a session is closed.
//
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    // Unused parameter(s)
    UNREFERENCED_PARAMETER(sess_ctx);
}


//
// Called to handle command submission.
//
static TEE_Result fTPM_Submit_Command(uint32_t  param_types,
                                      TEE_Param params[4]
)
{
    uint8_t *cmdBuf, *respBuf;
    uint32_t cmdLen, respLen, nvStatus;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_INOUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    // Command submission
    FTPM_MSG("fTPM submit command");

    // Validate parameter types
    if (param_types != exp_param_types) {
        FTPM_MSG("Bad param type(s)\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Sanity check our buffer sizes
    if ((params[0].memref.size == 0) ||
        (params[1].memref.size == 0) ||
        (params[0].memref.size > MAX_COMMAND_SIZE) ||
        (params[1].memref.size > MAX_RESPONSE_SIZE)) {
        FTPM_MSG("Bad param size(s)\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // We may have deferred storage initialization. Handle it now.
    if (!fTPMInitialized) {

        // Attempt NV enable
        if ((nvStatus = _plat__NVEnable(NULL)) < 0) {
            // Unrecoverable error, panic.
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }

        // If storage is not available yet, return TPM_RC_RETRY
        if (nvStatus != TA_NV_AVAILABLE) {

            // Using response buffer
            respBuf = (uint8_t *)(params[1].memref.buffer);
            respLen = params[1].memref.size;

            // Sanity check response buffer length
            if (respLen < RETRY_RESPONSE_SIZE) {
                return TEE_ERROR_BAD_PARAMETERS;
            }

            // Get TPM_RC_RETRY in the response buffer
            fTPMRetry(respBuf, &respLen);
            if (respLen != RETRY_RESPONSE_SIZE) {
                TEE_Panic(TEE_ERROR_BAD_STATE);
            }

            // Return response
            FTPM_MSG("TPM_RC_RETRY (TA_NV_AVAILABLE)");
            return TEE_SUCCESS;
        }

        // Success, start the TPM
        fTPMStartup();
    }

    // Copy command locally
    memcpy(fTPMCommand, params[0].memref.buffer, params[0].memref.size);

    // Pull the command length from the actual TPM command. The memref size
    // field descibes the buffer containing the command, not the command.
    cmdBuf = fTPMCommand;
    cmdLen = BYTE_ARRAY_TO_UINT32((uint8_t *)&(cmdBuf[2]));

    // Sanity check cmd length included in TPM command
    if (cmdLen > params[0].memref.size) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Pointers to buffers
    respBuf = (uint8_t *)(params[1].memref.buffer);
    respLen = params[1].memref.size;

    // Check if this is a PPI Command
    if (!_admin__PPICommand(cmdLen, cmdBuf, &respLen, &respBuf)) {
        // If not, pass through to TPM
        _plat__RunCommand(cmdLen, cmdBuf, &respLen, &respBuf);
    }

    // Unfortunately, this cannot be done until after we have our response in
    // hand. We will, however, make an effort to return at least a portion of
    // the response along with TEE_ERROR_SHORT_BUFFER.
    if (respLen > params[1].memref.size)
    {
        FTPM_MSG("Insufficient buffer length RS: 0x%x > BL: 0x%x\n", respLen, params[1].memref.size);
        return TEE_ERROR_SHORT_BUFFER;
    }

    FTPM_MSG("Success, RS: 0x%x\n", respLen);
    return TEE_SUCCESS;
}


//
// Called to handle PPI commands
//
static TEE_Result fTPM_Emulate_PPI(uint32_t  param_types,
                                   TEE_Param params[4]
)
{
    uint8_t *cmdBuf, *respBuf;
    uint32_t cmdLen, respLen;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                               TEE_PARAM_TYPE_MEMREF_INOUT,
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    if (param_types != exp_param_types) {
        FTPM_MSG("Bad param type(s)\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Sanity check our buffer sizes
    if ((params[0].memref.size == 0) ||
        (params[1].memref.size == 0) ||
        (params[0].memref.size > MAX_COMMAND_SIZE) ||
        (params[1].memref.size > MAX_RESPONSE_SIZE)) {
        FTPM_MSG("Bad param size(s)\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Copy command locally
    memcpy(fTPMCommand, params[0].memref.buffer, params[0].memref.size);

    // Prep for PPI request
    cmdBuf = fTPMCommand;
    cmdLen = params[0].memref.size;
    respBuf = (uint8_t *)(params[1].memref.buffer);
    respLen = params[1].memref.size;

    // Pass along to platform PPI processing
    if (_admin__PPIRequest(cmdLen, cmdBuf, &respLen, &respBuf)) {
        FTPM_MSG("Handled PPI command via TA interface\n");
    }
    else {
        FTPM_MSG("Failed to handle PPI command via TA interface\n");
    }

    if (respLen > params[1].memref.size) {
        FTPM_MSG("Insufficient buffer length RS: 0x%x > BL: 0x%x\n", respLen, params[1].memref.size);
        return TEE_ERROR_SHORT_BUFFER;
    }

    // Success
    params[1].memref.size = respLen;
    return TEE_SUCCESS;
}


// 
// Called when a TA is invoked. Note, paramters come from normal world.
// 
TEE_Result TA_InvokeCommandEntryPoint(void      *sess_ctx,
                                      uint32_t   cmd_id,
                                      uint32_t   param_types,
                                      TEE_Param  params[4])
{
    TEE_Result Status;

    // Unused parameter(s)
    UNREFERENCED_PARAMETER(sess_ctx);

    // Handle command invocation
    switch (cmd_id) {

        case TA_FTPM_SUBMIT_COMMAND: {
            Status = fTPM_Submit_Command(param_types, params);
            return Status;
        }

        case TA_FTPM_EMULATE_PPI: {
            Status = fTPM_Emulate_PPI(param_types, params);
            return Status;
        }

        default: {
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
}