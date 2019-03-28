#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include "../sassl_common.h"

struct timezone 
{
    int tz_minuteswest;
    int tz_dsttime;
};

static inline int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    extern int sassl_gettimeofday(struct timeval *tv, struct timezone *tz);
    return sassl_gettimeofday(tv, tz);
}

#endif /* _SYS_TIME_H */
