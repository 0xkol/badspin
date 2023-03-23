#ifndef _LIGHT_COND_H
#define _LIGHT_COND_H
#include "util.h"
#include <stdint.h>

typedef struct light_cond_s {
    _Atomic uint32_t futex;
    int flags;
} light_cond_t;

enum {
    LIGHT_COND_FLAG_PROCESS_SHARED = 1,
};

int light_cond_init(light_cond_t *c, int flags);
int light_cond_init_shared(light_cond_t *c);
int light_cond_wait(light_cond_t *c);
int light_cond_broadcast(light_cond_t *c);

#endif // _LIGHT_COND_H