#include <unistd.h>
#include <stdio.h>
#include "binder.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "binder_client.h"
#include <ctype.h>
#include <sys/mman.h>
#include <string.h>



int binder_write_read(int fd, void *write_buf, size_t write_size,
                      void *read_buf, size_t read_size, size_t *read_consumed) {
    struct binder_write_read bwr;
    bwr.write_size = write_size;
    bwr.write_consumed = 0;
    bwr.write_buffer = (binder_uintptr_t)write_buf;
    bwr.read_size = read_size;
    bwr.read_consumed = 0;
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    SYSCHK(ioctl(fd, BINDER_WRITE_READ, &bwr));

    if (read_consumed) {
        *read_consumed = bwr.read_consumed;
    }

    return 0;
}

int binder_write(int fd, void *write_buf, size_t write_size) {
    return binder_write_read(fd, write_buf, write_size, NULL, 0, NULL);
}
int binder_read(int fd, void *read_buf, size_t read_size, size_t *read_consumed) {
    return binder_write_read(fd, NULL, 0, read_buf, read_size, read_consumed);
}

char *__return_command_string(uint32_t command) {
#define _SWITCH_CASE(x) case x: return #x;

    switch (command){
    _SWITCH_CASE(BR_ERROR)
    _SWITCH_CASE(BR_OK)
    _SWITCH_CASE(BR_TRANSACTION_SEC_CTX)
    _SWITCH_CASE(BR_TRANSACTION)
    _SWITCH_CASE(BR_REPLY)
    _SWITCH_CASE(BR_ACQUIRE_RESULT)
    _SWITCH_CASE(BR_DEAD_REPLY)
    _SWITCH_CASE(BR_TRANSACTION_COMPLETE)
    _SWITCH_CASE(BR_INCREFS)
    _SWITCH_CASE(BR_ACQUIRE)
    _SWITCH_CASE(BR_RELEASE)
    _SWITCH_CASE(BR_DECREFS)
    _SWITCH_CASE(BR_ATTEMPT_ACQUIRE)
    _SWITCH_CASE(BR_NOOP)
    _SWITCH_CASE(BR_SPAWN_LOOPER)
    _SWITCH_CASE(BR_FINISHED)
    _SWITCH_CASE(BR_DEAD_BINDER)
    _SWITCH_CASE(BR_CLEAR_DEATH_NOTIFICATION_DONE)
    _SWITCH_CASE(BR_FAILED_REPLY)
    default:
        return "";
    }
#undef _SWITCH_CASE
}

#define EAT(p, end, sz) do{ if((end) - *(p) < sz) { return -1; } *(p) += sz; }while(0)

int extract_command(uint8_t **p, uint8_t *end, uint32_t command, void **payload) {
    void *q = *p;
	switch (command) {
	case BR_ERROR:
		EAT(p, end, sizeof(__s32));
	    break;
	case BR_OK:
		break;
	case BR_TRANSACTION_SEC_CTX:
		EAT(p, end, sizeof(struct binder_transaction_data_secctx));
	    break;
	case BR_TRANSACTION:{
		EAT(p, end, sizeof(struct binder_transaction_data));
	}break;
	case BR_REPLY: {
		EAT(p, end, sizeof(struct binder_transaction_data));
	} break;
	case BR_ACQUIRE_RESULT:
		EAT(p, end, sizeof(__s32));
		break;
	case BR_DEAD_REPLY:
		break;
	case BR_TRANSACTION_COMPLETE:
		break;
	case BR_INCREFS:
	case BR_ACQUIRE:
	case BR_RELEASE:
	case BR_DECREFS:
		EAT(p, end, sizeof(struct binder_ptr_cookie));
		break;
	case BR_ATTEMPT_ACQUIRE:
		EAT(p, end, sizeof(struct binder_pri_ptr_cookie));
		break;
	case BR_NOOP:
		break;
	case BR_SPAWN_LOOPER:
		break;
	case BR_FINISHED:
		break;
	case BR_DEAD_BINDER:
	case BR_CLEAR_DEATH_NOTIFICATION_DONE:
		EAT(p, end, sizeof(binder_uintptr_t));
		break;
	case BR_FAILED_REPLY:
		break;
	default:
		return -1;
	}
    if (payload) {
        *payload = q;
    }
	return 0;
}

int binder_read_buffer_parse(void *buffer, size_t buffer_size, 
        void *context, int (*handler)(void *context, uint32_t cmd, void *payload)) {
    int rc;
    uint8_t *p = buffer;
    uint8_t *end = p + buffer_size;
    uint32_t cmd;
    void *payload;
    while (1) {
        if (end - p < 4) {
            break;
        }
        cmd = *(uint32_t *)p;
        p += sizeof(uint32_t);
        rc = extract_command(&p, end, cmd, &payload);
        if (rc < 0) {
            return -1;
        }
        rc = handler(context, cmd, payload);
        if (rc) {
            return rc;
        }
    }
    return 0;
}

struct lookup_command_context {
    uint32_t target_command;
    void **out_payload;
};

int __binder_read_buffer_lookup_handler(void *context, uint32_t cmd, void *payload) {
    struct lookup_command_context *lc_context = context;
    if (lc_context->target_command == cmd) {
        if (lc_context->out_payload) {
            *lc_context->out_payload = payload;
        }
        return 8;
    }
    return 0;
}

int binder_read_buffer_lookup(void *buffer, size_t buffer_size, uint32_t command, void **payload) {
    struct lookup_command_context lc_context;
    lc_context.target_command = command;
    lc_context.out_payload = payload;
    if (binder_read_buffer_parse(buffer, buffer_size, &lc_context, __binder_read_buffer_lookup_handler) == 8) {
        return 0;
    }
    return -1;
}

int __binder_read_buffer_dump(void *context, uint32_t cmd, void *payload) {
    LOG("\t[%4x] %s\n", (int)(payload-context) - 4, __return_command_string(cmd));
    return 0;
}

int binder_read_buffer_dump(void *buffer, size_t buffer_size) {
    LOG("Dumping binder read buffer @%016lx\n", (uint64_t)buffer);
    return binder_read_buffer_parse(buffer, buffer_size, buffer, __binder_read_buffer_dump);
}


int __binder_read_buffer_count_handler(void *context, uint32_t cmd, void *payload) {
    uint32_t *counter_context = context;
    if (counter_context[0] == cmd) {
        counter_context[1]++;
    }
    return 0;
}

int binder_read_buffer_count(void *buffer, size_t buffer_size, uint32_t command){
    uint32_t counter_context[2] = {command, 0};
    binder_read_buffer_parse(buffer, buffer_size, counter_context, __binder_read_buffer_count_handler);
    return (int)counter_context[1];
}

int binder_enter_looper(int fd) {
    uint32_t command = BC_ENTER_LOOPER;
    return binder_write(fd, &command, sizeof(command));
}

int binder_client_init(binder_client_t *client, char *driver) {
	int version = 0;
    int mmap_flags = 0;

    client->fd = -1;
    client->vmstart = NULL;
    client->vmsize = 0;
    client->fd = SYSCHK(open(driver ? driver : BINDER_DEVICE, O_RDONLY));

	SYSCHK(ioctl(client->fd, BINDER_VERSION, &version));

    client->vmsize = 4*1024*1024; // 4M
    mmap_flags |= MAP_PRIVATE | MAP_NORESERVE;
	client->vmstart = SYSCHK(mmap(NULL, client->vmsize, PROT_READ, mmap_flags, client->fd, 0));

    return 0;
}

int binder_client_destroy(binder_client_t *client) {
    int ret = 0;
    if (client->vmstart) {
        if (munmap(client->vmstart, client->vmsize) < 0){
            perror("munmap");
            ret = -1;
        } else {
            client->vmstart = NULL;
        }
    }

    if (client->fd >= 0) {
        close(client->fd);
        client->fd = -1;
    }

    return ret;
}

int binder_free_transaction_buffer(int fd, binder_uintptr_t buffer_ptr) {
	uint8_t write_buf[sizeof(binder_uintptr_t) + sizeof(uint32_t)];
	*(uint32_t *)&write_buf = BC_FREE_BUFFER;
	*(binder_uintptr_t *)&write_buf[sizeof(uint32_t)] = buffer_ptr;
	if (binder_write(fd, write_buf, sizeof(write_buf)) < 0) {
		return -1;
	}
	return 0;
}

int binder_acquire(int fd, uint32_t handle) {
	uint32_t write_buf[2];
	write_buf[0] = BC_ACQUIRE;
	write_buf[1] = handle;
	if (binder_write(fd, write_buf, sizeof(write_buf)) < 0) {
		return -1;
	}
	return 0;
}

int binder_increfs(int fd, uint32_t handle) {
	uint32_t write_buf[2];
	write_buf[0] = BC_INCREFS;
	write_buf[1] = handle;
	if (binder_write(fd, write_buf, sizeof(write_buf)) < 0) {
		return -1;
	}
	return 0;
}

int binder_release(int fd, uint32_t handle) {
	uint32_t write_buf[2];
	write_buf[0] = BC_RELEASE;
	write_buf[1] = handle;
	if (binder_write(fd, write_buf, sizeof(write_buf)) < 0) {
		return -1;
	}
	return 0;
}

int binder_decrefs(int fd, uint32_t handle) {
	uint32_t write_buf[2];
	write_buf[0] = BC_DECREFS;
	write_buf[1] = handle;
	if (binder_write(fd, write_buf, sizeof(write_buf)) < 0) {
		return -1;
	}
	return 0;
}

int binder_register_death(int fd, uint32_t handle, binder_uintptr_t cookie) {
    uint32_t write_buf[4];
	write_buf[0] = BC_REQUEST_DEATH_NOTIFICATION;
	write_buf[1] = handle;
    *(binder_uintptr_t *)&write_buf[2] = cookie;
	return binder_write(fd, write_buf, sizeof(write_buf));
}

int binder_dead_done(int fd, binder_uintptr_t cookie) {
    uint32_t write_buf[3];
	write_buf[0] = BC_DEAD_BINDER_DONE;
    *(binder_uintptr_t *)&write_buf[1] = cookie;
	return binder_write(fd, write_buf, sizeof(write_buf));
}

bool binder_node_is_exists(int fd, binder_uintptr_t ptr) {
    struct binder_node_debug_info info = {0};
    int ret = 0;
    if (ptr == 0) {
        return false;
    }
    info.ptr = ptr - 1;
    ret = ioctl(fd, BINDER_GET_NODE_DEBUG_INFO, &info);
    if (ret < 0) {
        perror("ioctl-BINDER_GET_NODE_DEBUG_INFO");
        return false;
    }
    return (info.ptr == ptr);
}

struct binder_txn *binder_txn_create(u32 txn_target, u32 txn_code, u32 txn_flags) {
    struct binder_txn *txn = malloc(sizeof(struct binder_txn));
    if (txn == NULL) {
        return NULL;
    }
    memset(txn, 0, sizeof(*txn));
    txn->txn_target = txn_target;
    txn->txn_code = txn_code;
    txn->txn_flags = txn_flags;
    txn->data = calloc(1, 0x1000);
    if (txn->data == NULL) {
        free(txn);
        return NULL;
    }
    txn->data_capacity = 0x1000;
    return txn;
}

int binder_txn_add_raw(struct binder_txn *txn, void *data, binder_size_t data_size) {
    size_t new_capacity = txn->data_capacity;
    while(txn->data_size + ALIGN(data_size, sizeof(u32)) >= new_capacity) {
        new_capacity *= 2;
    }
    if (new_capacity > txn->data_capacity) {
        void *new_data = NULL;
        new_data = realloc(txn->data, new_capacity);
        if (new_data == NULL) {
            printf("realloc failed (%s:%d), new capacity %d\n", __func__, __LINE__, (int)new_capacity);
            return -1;
        }
        txn->data = new_data;
        txn->data_capacity = new_capacity;
    }
    memcpy((u8 *)txn->data + txn->data_size, data, data_size);
    memset((u8 *)txn->data + txn->data_size + data_size, 0, ALIGN(data_size, sizeof(u32)) - data_size);
    txn->data_size += ALIGN(data_size, sizeof(u32));
    return 0;
}

int __binder_txn_add_offset(struct binder_txn *txn, binder_uintptr_t offset) {
    if (txn->offsets == NULL) {
        txn->offsets = calloc(1, 0x1000);
        if (txn->offsets == NULL) {
            printf("calloc failed\n");
            return -1;
        }
        txn->offsets_capacity = 0x1000;
    } else if (txn->offsets_size == txn->offsets_capacity) {
        void *new_offsets = NULL;
        size_t new_capacity = txn->offsets_capacity * 2;
        new_offsets = realloc(txn->offsets, new_capacity);
        if (new_offsets == NULL) {
            printf("realloc failed (%s:%d), new capacity %d\n", __func__, __LINE__, (int)new_capacity);
            return -1;
        }
        txn->offsets = new_offsets;
        txn->offsets_capacity = new_capacity;
    }
    if (offset != ALIGN(offset, sizeof(u32))) {
        printf("unaligned offset\n");
        return -1;
    }
    memcpy((u8 *)txn->offsets + txn->offsets_size, &offset, sizeof(offset));
    txn->offsets_size += sizeof(offset);
    return 0;
}

int __binder_txn_add_object(struct binder_txn *txn, void *object_data, binder_size_t object_size) {
    binder_size_t prev_data_size = txn->data_size;
    if (binder_txn_add_raw(txn, object_data, object_size) < 0) { return -1; }
    if (__binder_txn_add_offset(txn, prev_data_size) < 0) { return -1; }
    return 0;
}

int binder_txn_add_buffer_object(struct binder_txn *txn, struct binder_buffer_object *bbo) {
    bbo->hdr.type = BINDER_TYPE_PTR;
    if (__binder_txn_add_object(txn, bbo, sizeof(struct binder_buffer_object)) < 0) {return -1;}
    txn->buffers_size += bbo->length;
    return 0;
}

int binder_txn_add_fd_object(struct binder_txn *txn, int fd) {
    struct binder_fd_object fdo;
    memset(&fdo, 0, sizeof(fdo));
    fdo.hdr.type = BINDER_TYPE_FD;
    fdo.fd = fd;
    if (__binder_txn_add_object(txn, &fdo, sizeof(struct binder_fd_object)) < 0) {return -1;}
    return 0;
}
int __binder_txn_add_binder_object(struct binder_txn *txn, int strong, u32 flags, binder_uintptr_t ptr, binder_uintptr_t cookie) {
    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr.type = strong ? BINDER_TYPE_BINDER : BINDER_TYPE_WEAK_BINDER;
    fbo.flags = flags;
    fbo.binder = ptr;
    fbo.cookie = cookie;
    if (__binder_txn_add_object(txn, &fbo, sizeof(fbo)) < 0) {return -1;}
    return 0;
}

int binder_txn_add_binder_object(struct binder_txn *txn, binder_uintptr_t ptr, binder_uintptr_t cookie) {
    return __binder_txn_add_binder_object(txn, 1, FLAT_BINDER_FLAG_ACCEPTS_FDS, ptr, cookie);
}

int binder_txn_add_weak_binder_object(struct binder_txn *txn, binder_uintptr_t ptr, binder_uintptr_t cookie) {
    return __binder_txn_add_binder_object(txn, 0, FLAT_BINDER_FLAG_ACCEPTS_FDS, ptr, cookie);
}

int __binder_txn_add_handle_object(struct binder_txn *txn, int strong, u32 handle) {
    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr.type = strong ? BINDER_TYPE_HANDLE : BINDER_TYPE_WEAK_HANDLE;
    fbo.handle = handle;
    if (__binder_txn_add_object(txn, &fbo, sizeof(fbo)) < 0) {return -1;}
    return 0;
}

int binder_txn_add_handle_object(struct binder_txn *txn, u32 handle) {
    return __binder_txn_add_handle_object(txn, 1, handle);
}

int binder_txn_add_weak_handle_object(struct binder_txn *txn, u32 handle) {
    return __binder_txn_add_handle_object(txn, 0, handle);
}

int binder_txn_add_fd_array(struct binder_txn *txn, int *fd_array, int nr_fds) {
    struct binder_buffer_object bbo = {0};
    bbo.hdr.type = BINDER_TYPE_PTR;
    bbo.buffer = (binder_uintptr_t)(fd_array);
    bbo.length = nr_fds*sizeof(int);
    bbo.flags = 0;
    bbo.parent = 0;
    bbo.parent_offset = 0;
    if (binder_txn_add_buffer_object(txn, &bbo) < 0) {return -1;}

    struct binder_fd_array_object fao = {0};
    fao.hdr.type = BINDER_TYPE_FDA;
    fao.num_fds = nr_fds;
    fao.parent = (txn->offsets_size - sizeof(binder_uintptr_t))/sizeof(binder_uintptr_t); // index in offset array
    fao.parent_offset = 0;
    if (__binder_txn_add_object(txn, &fao, sizeof(fao)) < 0) {return -1;}
    return 0;
}

binder_size_t binder_txn_size(struct binder_txn *txn) {
    return txn->data_size + txn->offsets_size + ALIGN(txn->buffers_size, sizeof(binder_uintptr_t));
}

int binder_txn_dispatch(struct binder_txn *txn, int fd, int reply, void *read_buf, size_t read_size, size_t *read_consumed) {
    struct {
        uint32_t cmd;
        struct binder_transaction_data txn_data;
        binder_size_t buffers_size;
    } __attribute__((packed)) writebuf;


    writebuf.cmd = reply ? BC_REPLY_SG : BC_TRANSACTION_SG;
    writebuf.txn_data.target.handle = txn->txn_target;
    writebuf.txn_data.code = txn->txn_code;
    writebuf.txn_data.flags = txn->txn_flags;
    writebuf.txn_data.data_size = txn->data_size;
    writebuf.txn_data.offsets_size = txn->offsets_size;
    writebuf.txn_data.data.ptr.buffer = (binder_uintptr_t)txn->data;
    writebuf.txn_data.data.ptr.offsets = (binder_uintptr_t)txn->offsets;
    writebuf.buffers_size = ALIGN(txn->buffers_size, sizeof(binder_uintptr_t));

    // for (size_t o = 0; o < txn->offsets_size; o += sizeof(binder_uintptr_t)) {
    //     binder_uintptr_t oo = *(binder_uintptr_t *)&((u8 *)txn->offsets)[o];
    //     printf("offset %d   %d\n", (int)o, (int)oo);
    // }

    if(binder_txn_size(txn) >= 1024*1024 - 128) { // 1M - 128 for binder_buffer object
        LOG("WARNING: transaction too large\n");
    }

    return binder_write_read(fd, &writebuf, sizeof(writebuf), read_buf, read_size, read_consumed);
}

void binder_txn_destroy(struct binder_txn *txn) {
    free(txn->data);
    free(txn->offsets);
    free(txn);
}