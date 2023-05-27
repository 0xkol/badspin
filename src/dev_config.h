#ifndef _DEV_CONFIG_H_
#define _DEV_CONFIG_H_
#define _GNU_SOURCE
#include <linux/version.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct ____offset {
    int valid : 1;
    int offset : 31;
} __attribute__((packed))  __offset;

#define OFFCHK(o) ({ \
    if (!(o).valid) { \
        LOG("OFFCHK(" #o ")"); \
        exit(0); \
    } \
    ((o).offset);\
})

#define STATIC_OFFSET(name, o) \
    name.valid = 1, \
    name.offset = (o), \

#define OFFSET(o) ({__offset __o = { .valid = 1, .offset = (o) }; __o;})

struct kernel_constants {
    struct {
        __offset k_init_uts_ns;
        __offset k_init_task;
        __offset k_anon_pipe_buf_ops;
        __offset k_selinux_state;
    } kernel_offsets;
    struct {
        __offset binder_inner_lock;
    } binder_proc_offsets;
    struct {
        __offset ts_tasks_next;
        __offset ts_thread_group_next;
        __offset ts_pid;
        __offset ts_tgid;
        __offset ts_files;
        __offset ts_cred;
    } task_struct_offsets;
    struct {
        __offset file_f_op;
        __offset file_f_count;
        __offset file_f_mode;
        __offset file_f_private_data;
    } file_offsets;
    struct {
        __offset f_op_flush;
    } file_operations_offsets;
    struct {
        __offset fs_fdt;
    } files_struct_offsets;
    struct {
        __offset tty_write_buf;
    } tty_struct_offsets;
};

struct rw_info;

u64 samsung_kimg_to_lm(struct rw_info *rw, u64 kaddr);
u64 pixel_kimg_to_lm(struct rw_info *rw, u64 kaddr);

u64 scan_kbase(struct rw_info *rw);
u64 noop_kbase(struct rw_info *rw);
u64 offset_kbase(struct rw_info *rw);

static struct device_config {
    char *name;
    char *model;
    int android_version;
    struct { int year; int month; } android_security_patch;
    int kernel_version;
    u64 ram_offset;
    u64 vmemmap_start;
    u64 kzero_address;
    /*
     * Convert a kernel image virtual address
     * to the linear mapping.
     */
    u64 (*kimg_to_lm)(struct rw_info *rw, u64 kaddr);
    /*
     * Return the kernel base address. Might be 0 if
     * kimg_to_lm(rw, 0) will return the address of 
     * the first page of the kernel. (If not sure,
     * specify the anon_pipe_buf_ops offset and use
     * offset_kbase() function.)
     */
    u64 (*find_kbase)(struct rw_info *rw);
    struct kernel_constants kconsts;
} device_configs[] = {
    {
        /* SP1A.210812.016.S901EXXU2AVF1 */
        .name = "Samsung Galaxy S22",
        .model = "SM-S901E",
        .android_version = 12,
        .android_security_patch.year = 2022,
        .android_security_patch.month = 6,
        .kernel_version = KERNEL_VERSION(5, 10, 81),
        .ram_offset = 0x28000000UL,
        .kimg_to_lm = samsung_kimg_to_lm,
        .find_kbase = scan_kbase,
    },
    {
        /* G998BXXU4CVC4 */
        .name = "Samsung Galaxy S21 Ultra",
        .model = "SM-G998B",
        .android_version = 12,
        .android_security_patch.year = 2022,
        .android_security_patch.month = 3,
        .kernel_version = KERNEL_VERSION(5, 4, 129),
        .ram_offset = 0x0,
        .kimg_to_lm = samsung_kimg_to_lm,
        .find_kbase = scan_kbase,
    },
    {
        /* Oriole 12.1.0 (SP2A.220505.002, May 2022) */
        .name = "Google Pixel 6",
        .model = "Pixel 6",
        .android_version = 12,
        .android_security_patch.year = 2022,
        .android_security_patch.month = 5,
        .kernel_version = KERNEL_VERSION(5, 10, 66),
        .kimg_to_lm = pixel_kimg_to_lm,
        .find_kbase = noop_kbase,
    },
    {
        /* Oriole 13.0.0 (TP1A.220905.004, Sep 2022) */
        .name = "Google Pixel 6",
        .model = "Pixel 6",
        .android_version = 13,
        .android_security_patch.year = 2022,
        .android_security_patch.month = 9,
        .kernel_version = KERNEL_VERSION(5, 10, 107),
        .kimg_to_lm = pixel_kimg_to_lm,
        .find_kbase = noop_kbase,
    }
};


extern struct device_config *dev_config;

void dev_config_init();

static inline bool is_device(char *name) {
    size_t l = strlen(name);
    if (strlen(dev_config->name) < l) {
        return false;
    }
    return strncmp(dev_config->name, name, l) == 0;
}

#ifdef LIST_DEVICES
#include <stdio.h>
int main(){
    struct device_config *dev;
    for (int i = 0; i < sizeof(device_configs)/sizeof(device_configs[0]); i++) {
        dev = &device_configs[i];
        printf("%d: %s, Android %d (%d/%d), kernel %d.%d.%d\n", 
                i, dev->name,
                dev->android_version,
                dev->android_security_patch.month,
                dev->android_security_patch.year,
                (dev->kernel_version >> 16) & 0xff,
                (dev->kernel_version >> 8) & 0xff,
                (dev->kernel_version >> 0) & 0xff);
    }
    return 0;
}
#endif

#endif
