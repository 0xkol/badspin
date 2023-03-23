#include "light_cond.h"
#include <stdatomic.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <unistd.h>

static int futex(uint32_t *uaddr, int futex_op, uint32_t val,
                 const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

#define LIGHT_COND_SHOULD_WAIT  0
#define LIGHT_COND_SHOULD_GO    1

int light_cond_init(light_cond_t *c, int flags) {
    c->futex = LIGHT_COND_SHOULD_WAIT;
    c->flags = 0;
    if (!(flags & LIGHT_COND_FLAG_PROCESS_SHARED)) {
        c->flags |= FUTEX_PRIVATE_FLAG;
    }
    return 0;
}

int light_cond_init_shared(light_cond_t *c) {
    return light_cond_init(c, LIGHT_COND_FLAG_PROCESS_SHARED);
}

int light_cond_wait(light_cond_t *c) {
    int rc;
    while (1) {

        if (atomic_load(&c->futex) != LIGHT_COND_SHOULD_WAIT) {
            break;
        }

        rc = futex((uint32_t *)&c->futex, FUTEX_WAIT | c->flags, LIGHT_COND_SHOULD_WAIT, NULL, NULL, 0);
        if (rc < 0) {
            if (errno != EAGAIN) {
                return -1;
            }
        }
    }
    return 0;
}


int light_cond_broadcast(light_cond_t *c) {
    int rc;
    atomic_store(&c->futex, LIGHT_COND_SHOULD_GO);

    rc = futex((uint32_t *)&c->futex, FUTEX_WAKE | c->flags, INT_MAX, NULL, NULL, 0);
    
    return rc;
}