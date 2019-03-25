// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _PTHREAD_H
#define _PTHREAD_H

#include "__common.h"
#include "time.h"

#define PTHREAD_MUTEX_INITIALIZER {{0}}
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_ONCE_INIT 0

typedef uint64_t pthread_t;

typedef uint32_t pthread_once_t;

typedef uint32_t pthread_key_t;

typedef struct _pthread_attr
{
    uint64_t __private[7];
} pthread_attr_t;

typedef struct _pthread_mutexattr
{
    uint32_t __private;
} pthread_mutexattr_t;

typedef struct _pthread_mutex
{
    uint64_t __private[4];
} pthread_mutex_t;

static inline pthread_t pthread_self(void)
{
    extern pthread_t sassl_pthread_self(void);
    return sassl_pthread_self();
}

static inline int pthread_equal(pthread_t thread1, pthread_t thread2)
{
    extern int sassl_pthread_equal(pthread_t thread1, pthread_t thread2);
    return sassl_pthread_equal(thread1, thread2);
}

static inline int pthread_once(pthread_once_t* once, void (*func)(void))
{
    extern int sassl_pthread_once(pthread_once_t* once, void (*func)(void));
    return sassl_pthread_once(once, func);
}

static inline int pthread_mutexattr_init(pthread_mutexattr_t* attr)
{
    extern int sassl_pthread_mutexattr_init(pthread_mutexattr_t* attr);
    return sassl_pthread_mutexattr_init(attr);
}

static inline int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type)
{
    extern int sassl_pthread_mutexattr_settype(pthread_mutexattr_t* attr, 
        int type);

    return sassl_pthread_mutexattr_settype(attr, type);
}

static inline int pthread_mutexattr_destroy(pthread_mutexattr_t* attr)
{
    extern int sassl_pthread_mutexattr_destroy(pthread_mutexattr_t* attr);
    return sassl_pthread_mutexattr_destroy(attr);
}

static inline int pthread_mutex_init(
    pthread_mutex_t* m,
    const pthread_mutexattr_t* attr)
{
    extern int sassl_pthread_mutex_init(
        pthread_mutex_t* m,
        const pthread_mutexattr_t* attr);

    return sassl_pthread_mutex_init(m, attr);
}

static inline int pthread_mutex_lock(pthread_mutex_t* m)
{
    extern int sassl_pthread_mutex_lock(pthread_mutex_t* m);
    return sassl_pthread_mutex_lock(m);
}

static inline int pthread_mutex_trylock(pthread_mutex_t* m)
{
    extern int sassl_pthread_mutex_trylock(pthread_mutex_t* m);
    return sassl_pthread_mutex_trylock(m);
}

static inline int pthread_mutex_unlock(pthread_mutex_t* m)
{
    extern int sassl_pthread_mutex_unlock(pthread_mutex_t* m);
    return sassl_pthread_mutex_unlock(m);
}

static inline int pthread_mutex_destroy(pthread_mutex_t* m)
{
    extern int sassl_pthread_mutex_destroy(pthread_mutex_t* m);
    return sassl_pthread_mutex_destroy(m);
}

static inline int pthread_key_create(
    pthread_key_t* key,
    void (*destructor)(void* value))
{
    extern int sassl_pthread_key_create(
        pthread_key_t* key,
        void (*destructor)(void* value));

    return sassl_pthread_key_create(key, destructor);
}

static inline int pthread_key_delete(pthread_key_t key)
{
    extern int sassl_pthread_key_delete(pthread_key_t key);
    return sassl_pthread_key_delete(key);
}

static inline int pthread_setspecific(pthread_key_t key, const void* value)
{
    extern int sassl_pthread_setspecific(pthread_key_t key, const void* value);
    return sassl_pthread_setspecific(key, value);
}

static inline void* pthread_getspecific(pthread_key_t key)
{
    extern void* sassl_pthread_getspecific(pthread_key_t key);
    return sassl_pthread_getspecific(key);
}

static inline int pthread_atfork(
    void (*prepare)(void), 
    void (*parent)(void), 
    void (*child)(void))
{
    extern int sassl_pthread_atfork(
        void (*prepare)(void), 
        void (*parent)(void), 
        void (*child)(void));
    return sassl_pthread_atfork(prepare, parent, child);
}

#endif /* _PTHREAD_H */
