#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <limits.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include "util.h"
#include "uao.h"
#include "kernel_constants.h"
#include "rw.h"

/*

State machine




                 main:wait_for_uao_ready()           main:set_uao_new_job()
  ┌────────────────┐ ─────────────► ┌───────────────┐ ───────────────────►┌──────────────────┐
  │ uao_state_ready│                │ uao_state_busy│                     │ uao_state_new_job│
  └────────────────┘ ◄───────────── └───────────────┘◄─────────────────── └──────────────────┘
                 thread:set_uao_ready()          thread:wait_for_uao_new_job()




*/

enum uao_state {
    uao_state_ready = 0,
    uao_state_new_job = 1,
    uao_state_busy = 2,
};

/* Spins as long as uao->state is not "ready". 
When it becomes "ready", its value is updated to "busy". */
static inline void wait_for_uao_ready(struct uao_info *uao) {
    unsigned int val;
    do{
        val = uao_state_ready;
    }while(!atomic_compare_exchange_strong(&uao->state, &val, uao_state_busy));
}

/* Spins as long as uao->state is not "new job".
When it becomes "new job", its value is updated to "busy". */
static inline void wait_for_uao_new_job(struct uao_info *uao){
    unsigned int val;
    do{
        val = uao_state_new_job;
    }while(!atomic_compare_exchange_strong(&uao->state, &val, uao_state_busy));
}

static inline void set_uao_ready(struct uao_info *uao) {
    atomic_thread_fence(memory_order_seq_cst);
    atomic_store(&uao->state, uao_state_ready);
}

static inline void set_uao_new_job(struct uao_info *uao) {
    atomic_thread_fence(memory_order_seq_cst);
    atomic_store(&uao->state, uao_state_new_job);
}

void *uao_thread(void *arg) {
    struct rw_info *rw = arg;
    struct uao_info *uao = &rw->uao;
    uao->tid = gettid();
    for(;;) {
        wait_for_uao_new_job(uao);

        // now kaddr and size are valid
        switch (uao->op){
        case uao_op_read:
            SYSCHK(write(uao->pipe[1], (void *)uao->kaddr, uao->size));
            break;
        case uao_op_write:
            SYSCHK(read(uao->pipe[0], (void *)uao->kaddr, uao->size));
            break;
        case uao_op_done:
            return NULL;
        }
        
        set_uao_ready(uao);
    }
    return NULL;
}


int uao_kread(struct rw_info *rw, u64 kaddr, void *buf, u64 size) {
    struct uao_info *uao = &rw->uao;

    pthread_mutex_lock(&uao->mutex);
    if (uao->dead){
        pthread_mutex_unlock(&uao->mutex);
        return -1;
    }
    wait_for_uao_ready(uao);

    uao->op = uao_op_read;
    uao->kaddr = kaddr;
    uao->size = size;

    set_uao_new_job(uao);

    // Now you can proceed with reading from the pipe.
    SYSCHK(read(uao->pipe[0], buf, size));
    pthread_mutex_unlock(&uao->mutex);

    return 0;
}

int uao_kwrite(struct rw_info *rw, u64 kaddr, void *buf, u64 size) {
    struct uao_info *uao = &rw->uao;

    pthread_mutex_lock(&uao->mutex);
    if (uao->dead){
        pthread_mutex_unlock(&uao->mutex);
        return -1;
    }
    wait_for_uao_ready(uao);

    uao->op = uao_op_write;
    uao->kaddr = kaddr;
    uao->size = size;

    set_uao_new_job(uao);

    SYSCHK(write(uao->pipe[1], buf, size));
    pthread_mutex_unlock(&uao->mutex);

    return 0;
}

int uao_close(struct rw_info *rw) {
    struct uao_info *uao = &rw->uao;
    pthread_mutex_lock(&uao->mutex);
    wait_for_uao_ready(uao);
    uao->op = uao_op_done;
    set_uao_new_job(uao);
    pthread_join(uao->uao_th, NULL);
    close(uao->pipe[0]);
    close(uao->pipe[1]);
    uao->dead = true;
    pthread_mutex_unlock(&uao->mutex);
    return 0;
}

int uao_init(struct rw_info *rw) {
    SYSCHK(pipe(rw->uao.pipe));
    pthread_create(&rw->uao.uao_th, NULL, uao_thread, rw);
    /* Wait for the tid field to be populated by the newly created thread */
    while(!rw->uao.tid);
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&rw->uao.mutex, &attr);
    return 0;
}
