#include <trace.h>
#include <tee_internal_api.h>

#include "optee_stdlib.h"
#include "RuntimeSupport.h"

//
// Functions directly available in OP-TEE or RuntimeSupport.c
//
void sassl_free(void *ptr) {
    TEE_Free(ptr);
}

int getentropy(void *buffer, size_t length) {
    TEE_GenerateRandom(buffer, (uint32_t)length);
    return 0;
}

void *sassl_malloc(size_t size) {
    void *ret = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
    if (ret == NULL) {
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
    }
    return ret;
}

void *sassl_memchr(const void *s, int c, size_t n) {
    return memchr(s, c, n);
}

int sassl_memcmp(const void *s1, const void *s2, size_t n) {
    return memcmp(s1, s2, n);
}

void *sassl_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, n);
}

void *sassl_memmove(void *dest, const void *src, size_t n){
    return memmove(dest, src, n);
}

void *sassl_memset(void *s, int c, size_t n) {
    return memset(s, c, n);
}

void sassl_print(const char * c) {
    DMSG("%s", c);
}

void *sassl_realloc(void *ptr, size_t size) {
    void *ret = TEE_Realloc(ptr, size);
    if (ret == NULL) {
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
    }
    return ret;
}

char *sassl_strcat(char *dest, const char *src) {
    strcat(dest, src);
}

char *sassl_strchr(const char *s, int c) {
    return strchr(s, c);
}

int sassl_strcmp(const char *s1, const char *s2) {
    return strcmp(s1, s2);
}

char *sassl_strcpy(char *dest, const char *src) {
    return strcpy(dest, src);
}

size_t sassl_strcspn(const char *s, const char *reject) {
    strcspn(s, reject);
}

size_t sassl_strlen(const char *s) {
    return strlen(s);
}

int sassl_strncmp(const char *s1, const char *s2, size_t n) {
    strncmp(s1, s2, n);
}

int sassl_strncasecmp(const char *s1, const char *s2, size_t n) {
    return strncasecmp(s1,s2,n);
}

char *sassl_strncpy(char *dest, const char *src, size_t n) {
    return strncpy(dest, src, n);
}

char *sassl_strstr(const char *haystack, const char *needle) {
    strstr(haystack, needle);
}

static int sassl_errno;
int *sassl_errno_location(void) {
    return &sassl_errno;
}

//
// Stubbed
//

int sassl_atexit(void (*function)(void)) {
    return 0;
}

char *sassl_strerror(int errnum) {
    static char *strerror = "STRERROR UNIMPLEMENTED";
    return strerror;
}


//
// Functions re-mapped to OP-TEE
//
int sassl_gettimeofday(struct timeval *tv, struct timezone *tz) {
    TEE_Time time;
    uint32_t extraMicroseconds = 0;

    if(tv != NULL) {
        TEE_GetSystemTime(&time);
        tv->tv_sec = time.seconds;
        tv->tv_usec = time.millis * 1000;

        //
        // OSSL apears to use this mostly to add entropy, so pad 
        // out as much as possible with true entropy
        //
        TEE_GenerateRandom(&extraMicroseconds, sizeof(extraMicroseconds));

        //
        // This will never cause usec to overflow and require incrementing tv_sec
        //
        tv->tv_usec += (extraMicroseconds % 1000);
        DMSG("OSSL time S:%d, uS:%d", tv->tv_sec, tv->tv_usec );
    }
    return 0;
 }


time_t sassl_time(time_t *tloc) {
    TEE_Time time;
    TEE_GetSystemTime(&time);
    if (tloc) {
        tloc = time.seconds;
    }
    return time.seconds;
}

int sassl_strcasecmp(const char *s1, const char *s2) {
    size_t i = 0;
    for(i = 0; s1[i] && s2[i]; i++)
    {
        char delta = tolower(s1[i]) - tolower(s2[i]);
        if (delta != 0)
        {
            return delta;
        }
    }
    return 0;
}

size_t sassl_strspn(const char *s, const char *accept) {
    size_t i = 0;
    for(i = 0; s[i] != '\0'; i++) {
        const char c = s[i];
        if (strchr(accept, c)== NULL) {            
            return i;
        }
    }
    return i;
}

//
// Unimplemented
//

void sassl_abort(void) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_CANCEL);
}

int sassl_atoi(const char *nptr) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
    return 0;
}

int sassl_closedir(void *dirp) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

int sassl_fclose(FILE *stream) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

int sassl_ferror(FILE *stream) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

int sassl_fread(FILE *stream) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

size_t sassl_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

gid_t sassl_getegid(void) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
    return 0;
}

char *sassl_getenv(const char *name) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

uid_t sassl_geteuid(void) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
    return 0;
}

gid_t sassl_getgid(void) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
    return 0;
}

gid_t sassl_getpid(void) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
    return 0;
}

uid_t sassl_getuid(void) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
    return 0;
}

struct tm *sassl_gmtime(const time_t *timep) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

void *sassl_opendir(const char *name) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

struct dirent *sassl_readdir(void *dirp) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

int sassl_stat(const char *pathname, void *buf) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

char *sassl_strrchr(const char *s, int c) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

long int sassl_strtol(const char *nptr, char **endptr, int base) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

unsigned long int sassl_strtoul(const char *nptr, char **endptr, int base) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

void sassl_qsort( void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

int sassl_vsscanf(const char *str, const char *format, va_list ap) {
    EMSG("SASSL Unimplemented: %s",__PRETTY_FUNCTION__);
    TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}
