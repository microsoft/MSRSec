#ifndef _ASSERT_H
#define _ASSERT_H

#include "__common.h"

void sassl_assert_fail(
    const char* expr,
    const char* file,
    unsigned int line,
    const char* func);

#ifndef NDEBUG
# define assert(EXPR)                                                   \
    do                                                                  \
    {                                                                   \
        if (!(EXPR))                                                    \
            sassl_assert_fail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)
#else
# define assert(EXPR)
#endif

#endif /* _ASSERT_H */
