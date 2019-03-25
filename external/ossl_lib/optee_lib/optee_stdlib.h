#include <stddef.h>
#include <stdio.h>

typedef long time_t;
struct timezone 
{
    int tz_minuteswest;
    int tz_dsttime;
};
struct timeval { time_t tv_sec; long tv_usec; };
typedef unsigned int git_t;
typedef unsigned int gid_t;
typedef unsigned int uid_t;
typedef int64_t ino_t;
typedef int64_t off_t;
struct dirent 
{
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

void sassl_print(const char * c);
int getentropy(void *buffer, size_t length);

void sassl_abort(void);
int sassl_atexit(void (*function)(void));
int sassl_atoi(const char *nptr);
void sassl_free(void *ptr);
void *sassl_malloc(size_t size);
void *sassl_memchr(const void *s, int c, size_t n);
int sassl_memcmp(const void *s1, const void *s2, size_t n);
void *sassl_memcpy(void *dest, const void *src, size_t n);
void *sassl_memmove(void *dest, const void *src, size_t n);
void *sassl_memset(void *s, int c, size_t n);
int *sassl_errno_location(void);
int sassl_ferror(FILE *stream);
int sassl_fclose(FILE *stream);
int sassl_fread(FILE *stream);
size_t sassl_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
char *sassl_getenv(const char *name);
struct tm *sassl_gmtime(const time_t *timep);
size_t sassl_strlen(const char *s);
int sassl_strcmp(const char *s1, const char *s2);
void *sassl_realloc(void *ptr, size_t size);
char *sassl_strcpy(char *dest, const char *src);
char *sassl_strncpy(char *dest, const char *src, size_t n);
time_t sassl_time(time_t *tloc);
char *sassl_strerror(int errnum);
int sassl_gettimeofday(struct timeval *tv, struct timezone *tz);
void sassl_qsort( void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
char *sassl_strchr(const char *s, int c);
char *sassl_strrchr(const char *s, int c);
int sassl_strncmp(const char *s1, const char *s2, size_t n);
int sassl_stat(const char *pathname, void *buf);
int sassl_strcasecmp(const char *s1, const char *s2);
int sassl_strncasecmp(const char *s1, const char *s2, size_t n);
char *sassl_strstr(const char *haystack, const char *needle);
gid_t sassl_getegid(void);
gid_t sassl_getgid(void);
gid_t sassl_getpid(void);
uid_t sassl_getuid(void);
uid_t sassl_geteuid(void);
size_t sassl_strspn(const char *s, const char *accept);
unsigned long int sassl_strtoul(const char *nptr, char **endptr, int base);
long int sassl_strtol(const char *nptr, char **endptr, int base);
int sassl_vsscanf(const char *str, const char *format, va_list ap);
int sassl_closedir(void *dirp);
struct dirent *sassl_readdir(void *dirp);
void *sassl_opendir(const char *name);
char *sassl_strcat(char *dest, const char *src);
size_t sassl_strcspn(const char *s, const char *reject);
int getentropy(void *buffer, size_t length);
