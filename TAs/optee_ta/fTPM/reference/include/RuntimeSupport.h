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

#ifndef _RUNTIMESUPPORT_H_
#define _RUNTIMESUPPORT_H_

// OPTEE provides simple versions of these headers
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stddef.h>

typedef uint64_t clock_t;

/*#if defined(TRUE)
#undef TRUE
#endif

#if defined FALSE
#undef FALSE
#endif

typedef int BOOL;
#define FALSE   ((BOOL)0)
#define TRUE    ((BOOL)1)*/

typedef uint8_t             UINT8;
typedef uint8_t             BYTE;
typedef int8_t              INT8;
typedef int                 BOOL;
typedef uint16_t            UINT16;
typedef int16_t             INT16;
typedef uint32_t            UINT32;
typedef int32_t             INT32;
typedef uint64_t            UINT64;
typedef int64_t             INT64;

//
// Wolf SSL controls function overrides via X* defines
// These defines are not used anywhere else so it is safe
// to leave them no matter what crypto package is used.
//

#ifndef XMEMCPY
#define XMEMCPY(pdest, psrc, size) memcpy((pdest), (psrc), (size))
#endif

#ifndef XMEMMOVE
#define XMEMMOVE(pdest, psrc, size) memmove((pdest), (psrc), (size))
#endif

#ifndef XMEMSET
#define XMEMSET(pdest, value, size) memset((pdest), (value), (size))
#endif

#ifndef XSTRLEN
#define XSTRLEN(str) strlen((str))
#endif

#ifndef XSTRNCPY
#define XSTRNCPY(str1,str2,n) strncpy((str1),(str2),(n))
#endif

#ifndef XSTRNCAT
char *strncat(char *dst, const char *src, size_t siz);
#define XSTRNCAT(dest, src, n) strncat(dest, src, n)
#endif

#ifndef XSNPRINTF
#define XSNPRINTF snprintf
#endif

#ifndef XSTRNCASECMP
int strncasecmp(const char *str1, const char *str2, size_t n);
#define XSTRNCASECMP(str1,str2,n) strncasecmp((str1),(str2),(n))
#endif

#ifndef XSTRNCMP
#define XSTRNCMP(str1,str2,n) strncmp((str1),(str2),(n))
#endif

#ifndef XMEMCMP
#define XMEMCMP(str1,str2,n) memcmp((str1),(str2),(n))
#endif

#ifndef XTOUPPER
int toupper (int c);
#define XTOUPPER(str1) toupper((str1))
#endif

#ifndef XTOLOWER
int tolower (int c);
#define XTOLOWER(str1) tolower((str1))
#endif

#undef  WC_NO_HASHDRBG
#define WC_NO_HASHDRBG

#if defined HAVE_TIME_T_TYPE
    typedef long time_t;
#endif

/* Bypass P-RNG and use only HW RNG */
extern int wolfRand(unsigned char* output, unsigned int sz);
#undef  CUSTOM_RAND_GENERATE_BLOCK
#define CUSTOM_RAND_GENERATE_BLOCK  wolfRand

//#ifdef XMALLOC_OVERRIDE
extern void *wolfMalloc(size_t n);
extern void *wolfRealloc(void *p, size_t n);
#define XMALLOC(sz, heap, type)     wolfMalloc(sz)
#define XREALLOC(p, sz, heap, type) wolfRealloc(p, sz)
#define XFREE(p, heap, type)        TEE_Free(p)

#endif
