#ifndef _STDIO_H
#define _STDIO_H

#include "__common.h"
#include <stdarg.h>

#define BUFSIZ 1024
#define EOF (-1)
#define stdin sassl_stdin
#define stdout sassl_stdout
#define stderr sassl_stderr

typedef struct __FILE FILE;
extern FILE* sassl_stdin;
extern FILE* sassl_stdout;
extern FILE* sassl_stderr;

static inline void perror(const char *s)
{
    extern void sassl_perror(const char *s);
    return sassl_perror(s);
}

static inline int rename(const char *oldpath, const char *newpath)
{
    extern int sassl_rename(const char *oldpath, const char *newpath);
    return sassl_rename(oldpath, newpath);
}

static inline int fileno(FILE *stream)
{
    extern int sassl_fileno(FILE *stream);
    return sassl_fileno(stream);
}

static inline FILE *fopen(const char *path, const char *mode)
{
    extern FILE *sassl_fopen(const char *path, const char *mode);
    return sassl_fopen(path, mode);
}

static inline size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    extern size_t sassl_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
    return sassl_fread(ptr, size, nmemb, stream);
}

static inline size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    extern size_t sassl_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
    return sassl_fwrite(ptr, size, nmemb, stream);
}

static inline int fclose(FILE *stream)
{
    extern int sassl_fclose(FILE *stream);
    return sassl_fclose(stream);
}

static inline int ferror(FILE *stream)
{
    extern int sassl_ferror(FILE *stream);
    return sassl_ferror(stream);
}

static inline int fseek(FILE *stream, long offset, int whence)
{
    extern int sassl_fseek(FILE *stream, long offset, int whence);
    return sassl_fseek(stream, offset, whence);
}

static inline int feof(FILE *stream)
{
    extern int sassl_feof(FILE *stream);
    return sassl_feof(stream);
}

static inline long ftell(FILE *stream)
{
    extern long sassl_ftell(FILE *stream);
    return sassl_ftell(stream);
}

static inline int fflush(FILE *stream)
{
    extern int sassl_fflush(FILE *stream);
    return sassl_fflush(stream);
}

static inline char *fgets(char *s, int size, FILE *stream)
{
    extern char *sassl_fgets(char *s, int size, FILE *stream);
    return sassl_fgets(s, size, stream);
}

static inline int fprintf(FILE *stream, const char *format, ...)
{
    extern int sassl_vfprintf(FILE *stream, const char *format, va_list ap);
    va_list ap;
    va_start(ap, format);
    int r = sassl_vfprintf(stream, format, ap);
    va_end(ap);
    return r;
}

static inline void setbuf(FILE *stream, char *buf)
{
    extern void sassl_setbuf(FILE *stream, char *buf);
    return sassl_setbuf(stream, buf);
}

static inline void clearerr(FILE *stream)
{
    extern void sassl_clearerr(FILE *stream);
}

static inline FILE *fdopen(int fd, const char *mode)
{
    extern FILE *sassl_fdopen(int fd, const char *mode);
    return sassl_fdopen(fd, mode);
}

static inline int sscanf(const char *str, const char *format, ...)
{
    extern int sassl_vsscanf(const char *str, const char *format, va_list ap);
    va_list ap;
    va_start(ap, format);
    int r = sassl_vsscanf(str, format, ap);
    va_end(ap);
    return r;
}

static inline int fputs(const char *s, FILE *stream)
{
    extern int sassl_fputs(const char *s, FILE *stream);
    return sassl_fputs(s, stream);
}

static inline int vfprintf(FILE *stream, const char *format, va_list ap)
{
    extern int sassl_vfprintf(FILE *stream, const char *format, va_list ap);
    return sassl_vfprintf(stream, format, ap);
}

#endif /* _STDIO_H */
