#ifndef _ENTROPYOVERRIDE_H
#define _ENTROPYOVERRIDE_H

int getentropy(void *buffer, size_t length) {
    extern int sassl_getentropy(void *buffer, size_t length);
    return sassl_getentropy(buffer, length);
}

#endif