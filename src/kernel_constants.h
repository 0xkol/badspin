#ifndef _KERNEL_CONSTANTS_H_
#define _KERNEL_CONSTANTS_H_

#include <stdint.h>
#include <stdbool.h>
#include "dev_config.h"

#define FMODE_PATH   0x4000

#define PIPE_BUF_FLAG_CAN_MERGE	0x10
struct pipe_buffer {
	u64 page;
	unsigned int offset, len;
	u64 ops;
	unsigned int flags;
    unsigned int __filler;
	u64 private;
} __attribute__((packed));

/* Is address in linear mapping? (for kernels >= 5.4) */
static inline int is_lm_addr(u64 kaddr) {
    return (kaddr & 0xffffffc000000000UL) == 0xffffff8000000000UL;
}

/* For SPARSEMEM_VMEMMAP kernels */
static inline u64 virt_to_page(u64 kaddr) {
    assert(is_lm_addr(kaddr));
    return (((kaddr - (0xffffff8000000000UL)) >> 12) << 6) + dev_config->vmemmap_start;
}

static inline u64 page_to_virt(u64 page_kaddr) {
    return (((page_kaddr - dev_config->vmemmap_start)>>6)<<12) + 0xffffff8000000000UL;
}

#define KERNEL_DS (~0UL)

#define TASK_STRUCT__ADDR_LIMIT 8
#define TTY_FILE_PRIVATE__TTY   0
#define FDTABLE__MAX_FDS        0
#define FDTABLE__FD             8

#define VMEMMAP_START 0xfffffffeffe00000UL
#define FILE__F_OP 40
#define FILE__F_COUNT 56
#define FILE__F_MODE 68
#define FILE_OPERATIONS__F_OP_FLUSH 120

#endif