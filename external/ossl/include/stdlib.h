#ifndef _STDLIB_H
#define _STDLIB_H

#include "sassl_common.h"
#include "stdarg.h"
#include "sassl/sassl_debug.h"

static inline char *getenv(const char *name)
{
    extern char *sassl_getenv(const char *name);
    return sassl_getenv(name);
}

static inline int atoi(const char *nptr)
{
    extern int sassl_atoi(const char *nptr);
    return sassl_atoi(nptr);
}

__attribute__((__noreturn__))
static inline void exit(int status)
{
    extern __attribute((__noreturn__)) void sassl_exit(int status);

    for (;;)
        sassl_exit(status);
}

static inline unsigned long int strtoul(const char *nptr, char **endptr, int base)
{
    extern unsigned long int sassl_strtoul(const char *nptr, char **endptr, int base);
    return sassl_strtoul(nptr, endptr, base);
}

static inline void qsort( void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *))
{
    extern void sassl_qsort( void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
    return sassl_qsort(base, nmemb, size, compar);
} 

static inline void *malloc(size_t size)
{
    extern void *sassl_malloc(size_t size);
    return sassl_malloc(size);
}

static inline void free(void *ptr)
{
    extern void sassl_free(void *ptr);
    return sassl_free(ptr);
}

static inline void *calloc(size_t nmemb, size_t size)
{
    extern void *sassl_calloc(size_t nmemb, size_t size);
    return sassl_calloc(nmemb, size);
}

static inline void *realloc(void *ptr, size_t size)
{
    extern void *sassl_realloc(void *ptr, size_t size);
    return sassl_realloc(ptr, size);
}

static inline int sprintf(char *str, const char *format, ...)
{
    extern int sassl_vsprintf(char *str, const char *format, va_list ap);
    va_list ap;
    va_start(ap, format);
    int r = sassl_vsprintf(str, format, ap);
    va_end(ap);
    return r;
}

static inline int snprintf(char *str, size_t size, const char *format, ...)
{
    extern int sassl_vsnprintf(char *str, size_t size, const char *format, va_list ap);
    va_list ap;
    va_start(ap, format);
    int r = sassl_vsnprintf(str, size, format, ap);
    va_end(ap);
    return r;
}

static inline int atexit(void (*function)(void))
{
    extern int sassl_atexit(void (*function)(void));
    return sassl_atexit(function);
}

static inline long int strtol(const char *nptr, char **endptr, int base)
{
    extern long int sassl_strtol(const char *nptr, char **endptr, int base);
    return sassl_strtol(nptr, endptr, base);
}

__attribute__((__noreturn__))
static inline void abort(void)
{
    __attribute__((__noreturn__)) extern void sassl_abort(void);
    sassl_abort();
}

#endif /* _STDLIB_H */
