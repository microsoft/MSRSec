#ifndef _UNISTD_H
#define _UNISTD_H

#include "__common.h"

static inline int close(int fd)
{
    extern int sassl_close(int fd);
    return sassl_close(fd);
}

static inline ssize_t read(int fd, void *buf, size_t count)
{
    extern ssize_t sassl_read(int fd, void *buf, size_t count);
    return sassl_read(fd, buf, count);
}

static inline pid_t getpid(void)
{
    extern pid_t sassl_getpid(void);
    return sassl_getpid();
}

static inline uid_t getuid(void)
{
    extern uid_t sassl_getuid(void);
    return sassl_getuid();
}

static inline uid_t geteuid(void)
{
    extern uid_t sassl_geteuid(void);
    return sassl_geteuid();
}

static inline gid_t getgid(void)
{
    extern gid_t sassl_getgid(void);
    return sassl_getgid();
}

static inline gid_t getegid(void)
{
    extern gid_t sassl_getegid(void);
    return sassl_getegid();
}

static inline ssize_t write(int fd, const void *buf, size_t count)
{
    extern ssize_t sassl_write(int fd, const void *buf, size_t count);
    return sassl_write(fd, buf, count);
}

static inline off_t lseek(int fd, off_t offset, int whence)
{
    extern off_t sassl_lseek(int fd, off_t offset, int whence);
    return sassl_lseek(fd, offset, whence);
}

#endif /* _UNISTD_H */
