#ifndef _TOKEN_MANAGER_H
#define _TOKEN_MANAGER_H

#include <stdbool.h>

#define HWSERVICE_MANAGER   "android.hidl.manager@1.0::IServiceManager"
#define TOKEN_MANAGER       "android.hidl.token@1.0::ITokenManager"

typedef void *hidl_pointer;

struct hidl_handle {
   hidl_pointer phandle;
   bool owns_handle;
};

typedef struct hidl_string {
   hidl_pointer buffer;
   uint32_t size;
   bool owns_buffer;
} hidl_string;

typedef struct hidl_vec {
   hidl_pointer buffer;
   uint32_t size;
   bool owns_buffer;
} hidl_vec;

#define HMAC_LENGTH 32
#define TOKEN_LENGTH (8 + HMAC_LENGTH)

struct token {
   hidl_vec vec;
   uint8_t data[TOKEN_LENGTH];
};

int find_token_manager(int fd, uint32_t *tm_handle);
int token_manager_register(int fd, uint32_t tm_handle, binder_uintptr_t binder, binder_uintptr_t cookie, struct token *token);
int token_manager_lookup(int fd, uint32_t tm_handle, struct token *token, uint32_t *handle);

#endif