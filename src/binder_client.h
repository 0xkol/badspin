#ifndef _BINDER_CLIENT_H
#define _BINDER_CLIENT_H
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "binder.h"
#include "util.h"

#define BINDER_DEVICE "/dev/hwbinder"

typedef struct binder_client_s {
    int fd;
    void *vmstart;
    size_t vmsize;
} binder_client_t;

int binder_client_init(binder_client_t *client, char *driver);
int binder_client_destroy(binder_client_t *client);

int binder_write_read(int fd, void *write_buf,
                      size_t write_size,
                      void *read_buf,
                      size_t read_size, size_t *read_consumed);
int binder_write(int fd, void *write_buf, size_t write_size);
int binder_read(int fd, void *read_buf, size_t read_size, size_t *read_consumed);

int binder_read_buffer_lookup(void *buffer, size_t buffer_size, uint32_t command, void **payload);
int binder_read_buffer_parse(void *buffer, size_t buffer_size, void *context, int (*handler)(void *context, uint32_t cmd, void *payload));
int binder_read_buffer_dump(void *buffer, size_t buffer_size);
int binder_read_buffer_count(void *buffer, size_t buffer_size, uint32_t command);

int binder_enter_looper(int fd);
int binder_free_transaction_buffer(int fd, binder_uintptr_t buffer_ptr);
int binder_acquire(int fd, uint32_t handle);
int binder_release(int fd, uint32_t handle);
int binder_increfs(int fd, uint32_t handle);
int binder_decrefs(int fd, uint32_t handle);
int binder_register_death(int fd, uint32_t handle, binder_uintptr_t cookie);
int binder_dead_done(int fd, binder_uintptr_t cookie);
bool binder_node_is_exists(int fd, binder_uintptr_t ptr);

struct binder_txn {
    u32 txn_target, txn_code, txn_flags;
    void *data;
    binder_size_t data_size;
    size_t data_capacity;
    void *offsets;
    binder_size_t offsets_size;
    size_t offsets_capacity;
    binder_size_t buffers_size;
};

struct binder_txn *binder_txn_create(u32 txn_target, u32 txn_code, u32 txn_flags);
int binder_txn_add_raw(struct binder_txn *txn, void *data, binder_size_t data_size);
int binder_txn_add_buffer_object(struct binder_txn *txn, struct binder_buffer_object *bbo);
int binder_txn_add_fd_object(struct binder_txn *txn, int fd);
int binder_txn_add_fd_array(struct binder_txn *txn, int *fd_array, int nr_fds);
int binder_txn_add_binder_object(struct binder_txn *txn, binder_uintptr_t ptr, binder_uintptr_t cookie);
int binder_txn_add_weak_binder_object(struct binder_txn *txn, binder_uintptr_t ptr, binder_uintptr_t cookie);
int binder_txn_add_handle_object(struct binder_txn *txn, u32 handle);
int binder_txn_add_weak_handle_object(struct binder_txn *txn, u32 handle);
int binder_txn_dispatch(struct binder_txn *txn, int fd, int reply, void *read_buf, size_t read_size, size_t *read_consumed);
void binder_txn_destroy(struct binder_txn *txn);
binder_size_t binder_txn_size(struct binder_txn *txn);


#endif