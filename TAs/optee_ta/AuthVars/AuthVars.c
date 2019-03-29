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

#define STR_TRACE_USER_TA "AuthVars"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "AuthVars.h"

#define TA_ALL_PARAM_TYPE(type) TEE_PARAM_TYPES(type, type, type, type)

//
// Initialization
//
BOOL AuthVarInitialized = false;

//
// ExitBootServices called?
//
BOOL AuthVarIsRuntime = false;

// 
// Called when TA instance is created. This is the first call to the TA.
// 
TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result status;

    // If we've been here before, don't init again.
    if (AuthVarInitialized)
    {
        DMSG("TA_CreateEntryPoint called when AuthVarInitialized == TRUE");
        return TEE_SUCCESS;
    }

    // If we fail to open storage we cannot continue.
    status = AuthVarInitStorage();
    if (status != TEE_SUCCESS)
    {
        EMSG("AuthVars failed to initialize with error 0x%x", status);
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // Initialization complete
    AuthVarInitialized = true;

    DMSG("Done init!");

    return TEE_SUCCESS;
}

// 
// Called when TA instance destroyed.  This is the last call in the TA.
// 
void TA_DestroyEntryPoint(void)
{
    // We should only see this called after the OS has shutdown and there
    // will be no further commands sent. Close out storage.
    AuthVarCloseStorage();
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

    DMSG("Open session");

    // Unreferenced parameters
    UNREFERENCED_PARAMETER(params);
    UNREFERENCED_PARAMETER(sess_ctx);

    // Validate parameter types
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // If return value != TEE_SUCCESS the session will not be created.
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
// Get Authenticated Variable
//
static TEE_Result AuthVarGet(
    uint32_t    ParamTypes,
    TEE_Param   Params[4]
)
{
    VARIABLE_GET_PARAM  *GetParam;
    VARIABLE_GET_RESULT *GetResult;
    uint32_t    GetParamSize;
    uint32_t    GetResultSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    if (ParamTypes != ExpectedTypes) {
        DMSG("AuthVarGet: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    GetParam = (VARIABLE_GET_PARAM *)Params[0].memref.buffer;
    GetParamSize = Params[0].memref.size;

    GetResult = (VARIABLE_GET_RESULT *)Params[1].memref.buffer;
    GetResultSize = Params[1].memref.size;

    // Call VarOps
    Status = GetVariable(GetParamSize, GetParam, &GetResultSize, GetResult);
    DMSG("Get result 0x%x size: 0x%x", Status, GetResultSize);

    // Authvars driver expects TEE_SUCCESS, TEE_ERROR_SHORT_BUFFER,
    // or TEEC_ERROR_ITEM_NOT_FOUND as a return value. All other values
    // are handled as errors. Return values are also passed back through
    // parameter 2b to be handled by the command specific part of the driver.
    Params[2].value.a = GetResultSize;
    Params[2].value.b = Status;

    return Status;
}

//
// Get Next Authenticated Variable
//
static TEE_Result AuthVarGetNext(
    uint32_t    ParamTypes,
    TEE_Param   Params[4]
)
{
    VARIABLE_GET_NEXT_PARAM     *GetNextParam;
    VARIABLE_GET_NEXT_RESULT    *GetNextResult;
    uint32_t    GetNextParamSize;
    uint32_t    GetNextResultSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    if (ParamTypes != ExpectedTypes) {
        IMSG("AuthVarGetNext: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    GetNextParam = (VARIABLE_GET_NEXT_PARAM *)Params[0].memref.buffer;
    GetNextParamSize = Params[0].memref.size;

    GetNextResult = (VARIABLE_GET_RESULT *)Params[1].memref.buffer;
    GetNextResultSize = Params[1].memref.size;

    // Call VarOps
    Status = GetNextVariableName(GetNextParamSize, GetNextParam, &GetNextResultSize, GetNextResult);
    Params[2].value.a = GetNextResultSize;

    // Authvars driver expects TEE_SUCCESS, TEE_ERROR_SHORT_BUFFER,
    // or TEEC_ERROR_ITEM_NOT_FOUND as a return value. All other values
    // are handled as errors. Return values are also passed  back through
    // parameter 2b to be handled by the command specific part of the driver.
    Params[2].value.b = Status;

    return Status;
}

//
// Set Authenticated Variable
//
static TEE_Result AuthVarSet(
    uint32_t    ParamTypes,
    TEE_Param   Params[4]
)
{
    VARIABLE_SET_PARAM  *SetParam;
    uint32_t    SetParamSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    DMSG("AV cmd");

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,   // <-- Not used for Set!
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    if (ParamTypes != ExpectedTypes) {
        DMSG("AuthVarSet: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    SetParam = (VARIABLE_SET_PARAM *)Params[0].memref.buffer;
    SetParamSize = Params[0].memref.size;

    // Call VarOps
    Status = SetVariable(SetParamSize, SetParam);

    DMSG("Status: 0x%x", Status);

    Params[2].value.a = 0;
    Params[2].value.b = Status;

    return Status;
}

//
// Query Authenticated Variable Info
//
static TEE_Result AuthVarQuery(
    uint32_t  ParamTypes,
    TEE_Param Params[4]
)
{
    VARIABLE_QUERY_PARAM    *QueryParam;
    VARIABLE_QUERY_RESULT   *QueryResult;
    uint32_t    QueryParamSize;
    uint32_t   *QueryResultSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    DMSG("AV cmd");

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    if (ParamTypes != ExpectedTypes) {
        IMSG("AuthVarQuery: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    QueryParam = (VARIABLE_GET_NEXT_PARAM *)Params[0].memref.buffer;
    QueryParamSize = Params[0].memref.size;

    QueryResult = (VARIABLE_GET_RESULT *)Params[1].memref.buffer;
    QueryResultSize = &Params[1].memref.size;

    // Call VarOps
    Status = QueryVariableInfo(QueryParamSize, QueryParam, QueryResultSize, QueryResult);

    // Authvars driver expects TEE_SUCCESS, TEE_ERROR_SHORT_BUFFER,
    // or TEEC_ERROR_ITEM_NOT_FOUND as a return value. All other values
    // are handled as errors. Return values are also passed  back through
    // parameter 2b to be handled by the command specific part of the driver.
    Params[2].value.b = Status;

    return Status;
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

    // Can't proceed without init
    if (!AuthVarInitialized && (cmd_id != TA_AUTHVAR_EXIT_BOOT_SERVICES))
    {
        return TEE_ERROR_BAD_STATE;
    }

    // Handle command invocation
    switch (cmd_id) {
        case TA_AUTHVAR_GET_VARIABLE: {
            Status = AuthVarGet(param_types, params);
            return Status;
        }

        case TA_AUTHVAR_GET_NEXT_VARIABLE: {
            Status = AuthVarGetNext(param_types, params);
            return Status;
        }

        case TA_AUTHVAR_SET_VARIABLE: {
            Status = AuthVarSet(param_types, params);
            return Status;
        }

        case TA_AUTHVAR_QUERY_VARINFO: {
            Status = AuthVarQuery(param_types, params);
            return Status;
        }

        case TA_AUTHVAR_EXIT_BOOT_SERVICES: {
            AuthVarIsRuntime = true;
            return TEE_SUCCESS;
        }

        default: {
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
}