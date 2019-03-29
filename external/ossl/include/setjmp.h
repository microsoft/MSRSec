#ifndef _SETJMP_H
#define _SETJMP_H

#include "sassl_common.h"

static inline void siglongjmp(sigjmp_buf env, int val)
{
    extern void sassl_siglongjmp(sigjmp_buf env, int val);
    return sassl_siglongjmp(env, val);
}

#endif /* _SETJMP_H */
