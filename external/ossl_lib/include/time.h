#ifndef _TIME_H
#define _TIME_H

#include "__common.h"

struct tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

struct timespec
{
    time_t tv_sec;
    long tv_nsec;
};

static inline time_t time(time_t *tloc)
{
    extern time_t sassl_time(time_t *tloc);
    return sassl_time(tloc);
}

static inline struct tm *gmtime(const time_t *timep)
{
    extern struct tm *sassl_gmtime(const time_t *timep);
    return sassl_gmtime(timep);
}

static inline struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    extern struct tm *sassl_gmtime_r(const time_t *timep, struct tm *result);
    return sassl_gmtime_r(timep, result);
}

#endif /* _TIME_H */
