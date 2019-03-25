#ifndef _DLFCN_H
#define _DLFCN_H

#include "__common.h"

#define RTLD_LAZY   1
#define RTLD_NOW    2
#define RTLD_NOLOAD 4
#define RTLD_GLOBAL 256
#define RTLD_LOCAL  0

typedef struct 
{
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} 
Dl_info;

static inline void *dlopen(const char *filename, int flags)
{
    extern void *sassl_dlopen(const char *filename, int flags);
    return sassl_dlopen(filename, flags);
}

static inline int dlclose(void *handle)
{
    extern int sassl_dlclose(void *handle);
    return sassl_dlclose(handle);
}

static inline char *dlerror(void)
{
    extern char *sassl_dlerror(void);
    return sassl_dlerror();
}

static inline void *dlsym(void *handle, const char *symbol)
{
    extern void *sassl_dlsym(void *handle, const char *symbol);
    return sassl_dlsym(handle, symbol);
}

static inline int dladdr(void *addr, Dl_info *info)
{
    extern int sassl_dladdr(void *addr, Dl_info *info);
    return sassl_dladdr(addr, info);
}

static inline int dlinfo(void *handle, int request, void *info)
{
    extern int sassl_dlinfo(void *handle, int request, void *info);
    return sassl_dlinfo(handle, request, info);
}

#endif /* _DLFCN_H */
