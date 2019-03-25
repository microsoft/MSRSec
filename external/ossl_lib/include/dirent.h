#ifndef _DIRENT_H
#define _DIRENT_H

#include "__common.h"

typedef struct __DIR DIR;

struct dirent 
{
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

static inline DIR *opendir(const char *name)
{
    extern DIR *sassl_opendir(const char *name);
    return sassl_opendir(name);
}

static inline struct dirent *readdir(DIR *dirp)
{
    extern struct dirent *sassl_readdir(DIR *dirp);
    return sassl_readdir(dirp);
}

static inline int closedir(DIR *dirp)
{
    extern int sassl_closedir(DIR *dirp);
    return sassl_closedir(dirp);
}

#endif /* _DIRENT_H */
