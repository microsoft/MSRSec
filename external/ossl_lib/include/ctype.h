#ifndef _CTYPE_H
#define _CTYPE_H

#include "__common.h"

static inline int toupper(int c)
{
    if (c >= 'a' && c <= 'z')
        c -= ' ';

    return c;
}

static inline int tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        c += ' ';

    return c;
}

static inline int isupper(int c)
{
    if (c >= 'A' && c <= 'Z')
        return 1;

    return 0;
}

static inline int isalpha(int c)
{
    if (c >= 'a' && c <= 'z')
        return 1;
    if (c >= 'A' && c <= 'Z')
        return 1;

    return 0;
}

static inline int isdigit(int c)
{
    if (c >= '0' && c <= '9')
        return 1;

    return 0;
}

static inline int isalnum(int c)
{
    if (isalpha(c) || isdigit(c))
        return 1;

    return 0;
}

static inline int isxdigit(int c)
{
    if (isdigit(c))
        return 1;
    if (c >= 'a' && c <= 'f')
        return 1;
    if (c >= 'A' && c <= 'F')
        return 1;

    return 0;
}

static inline int isspace(int c)
{
    switch (c)
    {
        case ' ':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
        case '\v':
            return 1;
        default:
            return 0;
    }

    return 0;
}

#endif /* _CTYPE_H */
