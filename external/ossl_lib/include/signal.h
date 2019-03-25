#ifndef _SIGNAL_H
#define _SIGNAL_H

#define NEED_sigset_t
#include "__common.h"

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED SIGSYS

#define SIG_BLOCK     0
#define SIG_UNBLOCK   1
#define SIG_SETMASK   2

typedef struct __siginfo_struct siginfo_t;

struct sigaction 
{
    union 
    {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, siginfo_t *, void *);
    } __sa_handler;
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};

#define sa_handler   __sa_handler.sa_handler
#define sa_sigaction __sa_handler.sa_sigaction

static inline int sigfillset(sigset_t *set)
{
    extern int sassl_sigfillset(sigset_t *set);
    return sassl_sigfillset(set);
}

static inline int sigdelset(sigset_t *set, int signum)
{
    extern int sassl_sigdelset(sigset_t *set, int signum);
    return sassl_sigdelset(set, signum);
}

static inline int sigprocmask(
    int how, 
    const sigset_t *set, 
    sigset_t *oldset)
{
    extern int sassl_sigprocmask(
        int how, 
        const sigset_t *set, 
        sigset_t *oldset);
    return sassl_sigprocmask(how, set, oldset);
}

static inline int sigaction(
    int signum, 
    const struct sigaction *act,
    struct sigaction *oldact)
{
    extern int sassl_sigaction(
        int signum, 
        const struct sigaction *act,
        struct sigaction *oldact);
    return sassl_sigaction(signum, act, oldact);
}

static inline int sigsetjmp(sigjmp_buf env, int savesigs)
{
    extern int sassl_sigsetjmp(sigjmp_buf env, int savesigs);
    return sassl_sigsetjmp(env, savesigs);
}

#endif /* _SIGNAL_H */
