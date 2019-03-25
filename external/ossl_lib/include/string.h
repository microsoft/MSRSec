#ifndef _STRING_H
#define _STRING_H

#include "__common.h"

static inline size_t strlen(const char *s)
{
    extern size_t sassl_strlen(const char *s);
    return sassl_strlen(s);
}

static inline int strcmp(const char *s1, const char *s2)
{
    extern int sassl_strcmp(const char *s1, const char *s2);
    return sassl_strcmp(s1, s2);
}

static inline int strncmp(const char *s1, const char *s2, size_t n)
{
    extern int sassl_strncmp(const char *s1, const char *s2, size_t n);
    return sassl_strncmp(s1, s2, n);
}

static inline char *strchr(const char *s, int c)
{
    extern char *sassl_strchr(const char *s, int c);
    return sassl_strchr(s, c);
}

static inline char *strrchr(const char *s, int c)
{
    extern char *sassl_strrchr(const char *s, int c);
    return sassl_strrchr(s, c);
}

static inline int strcasecmp(const char *s1, const char *s2)
{
    extern int sassl_strcasecmp(const char *s1, const char *s2);
    return sassl_strcasecmp(s1, s2);
}

static inline int strncasecmp(const char *s1, const char *s2, size_t n)
{
    extern int sassl_strncasecmp(const char *s1, const char *s2, size_t n);
    return sassl_strncasecmp(s1, s2, n);
}

static inline void *memset(void *s, int c, size_t n)
{
    extern void *sassl_memset(void *s, int c, size_t n);
    return sassl_memset(s, c, n);
}

void *sassl_memcpy(void *dest, const void *src, size_t n);

static inline void *memcpy(void *dest, const void *src, size_t n)
{
    return sassl_memcpy(dest, src, n);
}

int sassl_memcmp(const void *s1, const void *s2, size_t n);

static inline int memcmp(const void *s1, const void *s2, size_t n)
{
    return sassl_memcmp(s1, s2, n);
}

static inline char *strcpy(char *dest, const char *src)
{
    extern char *sassl_strcpy(char *dest, const char *src);
    return sassl_strcpy(dest, src);
}

static inline char *strncpy(char *dest, const char *src, size_t n)
{
    extern char *sassl_strncpy(char *dest, const char *src, size_t n);
    return sassl_strncpy(dest, src, n);
}

static inline char *strstr(const char *haystack, const char *needle)
{
    extern char *sassl_strstr(const char *haystack, const char *needle);
    return sassl_strstr(haystack, needle);
}

static inline void *memmove(void *dest, const void *src, size_t n)
{
    extern void *sassl_memmove(void *dest, const void *src, size_t n);
    return sassl_memmove(dest, src, n);
}

static inline char *strerror(int errnum)
{
    extern char *sassl_strerror(int errnum);
    return sassl_strerror(errnum);
}

static inline void *memchr(const void *s, int c, size_t n)
{
    extern void *sassl_memchr(const void *s, int c, size_t n);
    return sassl_memchr(s, c, n);
}

static inline size_t strspn(const char *s, const char *accept)
{
    extern size_t sassl_strspn(const char *s, const char *accept);
    return sassl_strspn(s, accept);
}

static inline size_t strcspn(const char *s, const char *reject)
{
    extern size_t sassl_strcspn(const char *s, const char *reject);
    return sassl_strcspn(s, reject);
}

static inline char *strcat(char *dest, const char *src)
{
    extern char *sassl_strcat(char *dest, const char *src);
    return sassl_strcat(dest, src);
}

static inline char *strncat(char *dest, const char *src, size_t n)
{
    extern char *sassl_strncat(char *dest, const char *src, size_t n);
    return sassl_strncat(dest, src, n);
}

static inline char *strdup(const char *s)
{
    extern char *sassl_strdup(const char *s);
    return sassl_strdup(s);
}

#endif /* _STRING_H */
