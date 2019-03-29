#define NULL 0

#define __CONCAT(X, Y) X##Y
#define CONCAT(X, Y) __CONCAT(X, Y)

#define STATIC_ASSERT(COND) \
    typedef unsigned char CONCAT( \
    __STATIC_ASSERT, __LINE__)[(COND) ? 1 : -1] __attribute__((unused))

#ifdef __x86_64
typedef signed long long ptrdiff_t;
typedef unsigned long long size_t;
typedef long long ssize_t;
#elif defined(__arm__)
STATIC_ASSERT(sizeof(long) == 4);
typedef signed int ptrdiff_t;
typedef unsigned int size_t;
typedef int ssize_t;
#endif

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef long time_t;
typedef long suseconds_t;
typedef struct timespec __timespec_dummy;
typedef unsigned mode_t;
typedef int64_t dev_t;
typedef unsigned nlink_t;
typedef unsigned uid_t;
typedef unsigned gid_t;
typedef int pid_t;
typedef long blksize_t;
typedef int64_t blkcnt_t;
typedef int64_t ino_t;
typedef int64_t off_t;

STATIC_ASSERT(sizeof(uint8_t) == 1);
STATIC_ASSERT(sizeof(uint16_t) == 2);
STATIC_ASSERT(sizeof(uint32_t) == 4);
STATIC_ASSERT(sizeof(uint64_t) == 8);

#if defined(NEED_sigset_t) && !defined(DEFINED_sigset_t)
typedef struct __sigset_t 
{ 
    unsigned long __bits[128/sizeof(long)]; 
} 
sigset_t;
# define DEFINED_sigset_t
#endif

typedef unsigned long long jmp_buf[32];

typedef jmp_buf sigjmp_buf;

#define NEED_struct_timeval

#if defined(NEED_struct_timeval) && !defined(DEFINED_struct_timeval)
struct timeval { time_t tv_sec; suseconds_t tv_usec; };
# define DEFINED_struct_timeval
#endif
