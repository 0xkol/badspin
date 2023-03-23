#include <unistd.h>
#include <stdio.h>
#include "binder.h"
#include "binder_client.h"
#include "token_manager.h"
#include <string.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <assert.h>

#define HWSVCMAN_CODE        1
#define TM_CODE_CREATE_TOKEN 1
#define TM_CODE_GET_BY_TOKEN 3

/* Create wrapper for hidl_strings. */
hidl_string *hidl_string_new(const char *str){
    size_t slen;
    slen = strlen(str);
    hidl_string *hstr = calloc(1, sizeof(*hstr) + slen + 1);
    if (hstr == NULL) {
        return NULL;
    }

    hstr->buffer = (hidl_pointer)((size_t)hstr + sizeof(*hstr));
    memcpy(hstr->buffer, str, slen);
    hstr->size = slen;

    return hstr;
}

int find_hwservice(int fd, const char *service, uint32_t *tm_handle){
    int rc;
    struct hidl_string *hstr_service_name = NULL;
    struct hidl_string *hstr_instance = NULL;

    struct binder_buffer_object bbo;

    struct binder_txn *txn = binder_txn_create(0 /* Hardware Service Manager */, HWSVCMAN_CODE, 0);
    if (txn == NULL) { FAIL(); }

    binder_txn_add_raw(txn, HWSERVICE_MANAGER, sizeof(HWSERVICE_MANAGER));

    hstr_service_name = hidl_string_new(service);
    if (hstr_service_name == NULL) { FAIL(); }

    bbo.hdr.type = BINDER_TYPE_PTR;
    bbo.buffer = (binder_uintptr_t)hstr_service_name;
    bbo.length = sizeof(struct hidl_string);
    bbo.flags = 0;
    bbo.parent = 0;
    bbo.parent_offset = 0;
    binder_txn_add_buffer_object(txn, &bbo);

    bbo.hdr.type = BINDER_TYPE_PTR;
    bbo.buffer = (binder_uintptr_t)hstr_service_name->buffer;
    bbo.length = hstr_service_name->size + 1;
    bbo.flags = 1; // HAS_PARENT
    bbo.parent = 0;
    bbo.parent_offset = 0;
    binder_txn_add_buffer_object(txn, &bbo);

    hstr_instance = hidl_string_new("default");
    if (hstr_instance == NULL) { FAIL(); }

    bbo.hdr.type = BINDER_TYPE_PTR;
    bbo.buffer = (binder_uintptr_t)hstr_instance;
    bbo.length = sizeof(struct hidl_string);
    bbo.flags = 0;
    bbo.parent = 0;
    bbo.parent_offset = 0;
    binder_txn_add_buffer_object(txn, &bbo);

    bbo.hdr.type = BINDER_TYPE_PTR;
    bbo.buffer = (binder_uintptr_t)hstr_instance->buffer;
    bbo.length = hstr_instance->size + 1;
    bbo.flags = 1; // HAS_PARENT
    bbo.parent = 2;
    bbo.parent_offset = 0;
    binder_txn_add_buffer_object(txn, &bbo);

    size_t consumed;
    uint32_t rdata[32];

    binder_txn_dispatch(txn, fd, false, rdata, sizeof(rdata), &consumed);

    free(hstr_instance);
    hstr_instance = NULL;
    free(hstr_service_name);
    hstr_service_name = NULL;

    struct binder_transaction_data *tr = NULL;
    rc = binder_read_buffer_lookup(rdata, consumed, BR_REPLY, (void **)&tr);
    if (rc == -1) {
        LOG("find_hwservice: binder_read_buffer_lookup: no BR_REPLY\n");
        return -1;
    }

    struct flat_binder_object *fbo = (struct flat_binder_object *)(tr->data.ptr.buffer + 4);

    if (tm_handle) {
        *tm_handle = (uint32_t)fbo->handle;
    }

    /* Acquire the ref. */
    binder_acquire(fd, fbo->handle);

    binder_free_transaction_buffer(fd, tr->data.ptr.buffer);
    return 0;
}

int find_token_manager(int fd, uint32_t *tm_handle) {
    return find_hwservice(fd, TOKEN_MANAGER, tm_handle);
}


int token_manager_register(int fd, uint32_t tm_handle, binder_uintptr_t binder, binder_uintptr_t cookie, struct token *token) {
    int rc;
    struct binder_buffer_object *bbo;

    struct binder_txn *txn = binder_txn_create(tm_handle, TM_CODE_CREATE_TOKEN, 0);
    if (txn == NULL) { FAIL(); }

    binder_txn_add_raw(txn, TOKEN_MANAGER, sizeof(TOKEN_MANAGER));

    /* Add our strong binder. */
    binder_txn_add_binder_object(txn, binder, cookie);

    size_t consumed;
    uint32_t rdata[32];

    binder_txn_dispatch(txn, fd, false, rdata, sizeof(rdata), &consumed);

    struct binder_transaction_data *tr = NULL;
    rc = binder_read_buffer_lookup(rdata, consumed, BR_REPLY, (void **)&tr);
    if (rc == -1){
        LOG("binder_read_buffer_lookup: no BR_REPLY\n");
        return -1;
    }

    bbo = (struct binder_buffer_object *)(tr->data.ptr.buffer + 4);
    assert(bbo->hdr.type == BINDER_TYPE_PTR);

    hidl_vec *vec = &token->vec;

    memcpy(vec, (void *)bbo->buffer, sizeof(*vec));

    assert(sizeof(struct token) - sizeof(*vec) >= vec->size);

    /* copy and replace the pointers. */
    memcpy(token->data, vec->buffer, vec->size);
    vec->buffer = token->data;

    binder_free_transaction_buffer(fd, tr->data.ptr.buffer);

    return 0;
}

int token_manager_lookup(int fd, uint32_t tm_handle, struct token *token, uint32_t *handle) {
    int rc;
    hidl_vec *vec = &token->vec;

    struct binder_buffer_object bbo;

    struct binder_txn *txn = binder_txn_create(tm_handle, TM_CODE_GET_BY_TOKEN, 0);
    if (txn == NULL) { FAIL(); }

    binder_txn_add_raw(txn, TOKEN_MANAGER, sizeof(TOKEN_MANAGER));

    /* write the hidl_vec. */
    bbo.hdr.type = BINDER_TYPE_PTR;
    bbo.buffer = (binder_uintptr_t)vec;
    bbo.length = sizeof(*vec);
    bbo.flags = 0;
    bbo.parent = 0;
    bbo.parent_offset = 0;
    binder_txn_add_buffer_object(txn, &bbo);

    /* Embed the pointer. */
    bbo.hdr.type = BINDER_TYPE_PTR;
    bbo.buffer = (binder_uintptr_t)vec->buffer;
    bbo.length = vec->size;
    bbo.flags = 1; // HAS_PARENT
    bbo.parent = 0;
    bbo.parent_offset = 0;
    binder_txn_add_buffer_object(txn, &bbo);

    size_t consumed;
    uint32_t rdata[32];

    binder_txn_dispatch(txn, fd, false, rdata, sizeof(rdata), &consumed);

    struct binder_transaction_data *tr = NULL;
    rc = binder_read_buffer_lookup(rdata, consumed, BR_REPLY, (void **)&tr);
    if (rc == -1){
        LOG("binder_read_buffer_lookup: no BR_REPLY\n");
        return -1;
    }

    struct flat_binder_object *fbo = (struct flat_binder_object *)(tr->data.ptr.buffer + 4);

    if (handle){
        *handle = fbo->handle;
    }
    
    binder_acquire(fd, fbo->handle);

    binder_free_transaction_buffer(fd, tr->data.ptr.buffer);
    
    return 0;
}