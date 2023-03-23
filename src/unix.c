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
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/fs.h>
#include "util.h"
#include "unix.h"

int unix_recv_files(int sock, int *fds, unsigned int max_fds, unsigned int *nr_fds_recv) {
    struct msghdr msgh = {0};
    unsigned int data = 0;
    unsigned int fd_count = 0;
    struct iovec iov;
    iov.iov_base = &data;
    iov.iov_len = sizeof(data);

    size_t cbuf_len = sizeof(struct cmsghdr) + max_fds*sizeof(int);
    char *cbuf = malloc(cbuf_len);
    if (cbuf == NULL) {FAIL();}
    memset(cbuf, 0, cbuf_len);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    msgh.msg_control = cbuf;
    msgh.msg_controllen = cbuf_len;

    SYSCHK(recvmsg(sock, &msgh, 0));
    if (msgh.msg_flags & MSG_CTRUNC) {
        LOG("WARNING: Ancillary data was truncated\n");
    }

    for (struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
        cmsgp != NULL;
        cmsgp = CMSG_NXTHDR(&msgh, cmsgp)) {

        assert(cmsgp->cmsg_level == SOL_SOCKET);

        if (cmsgp->cmsg_type == SCM_RIGHTS) {
            int fd_count = (cmsgp->cmsg_len - CMSG_LEN(0)) / sizeof(int);

            memcpy(fds, CMSG_DATA(cmsgp), (fd_count > max_fds ? max_fds : fd_count) * sizeof(int));

            if (nr_fds_recv) {
                *nr_fds_recv = fd_count;
            }
            break;
        }
    }
    free(cbuf);
    return 0;
}

int unix_send_files(int sock, int *fds, unsigned int nr_fds) {
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    int dummy = nr_fds;
    struct iovec io = {
        .iov_base = &dummy,
        .iov_len = sizeof(dummy)
    };
    size_t cbuf_len = sizeof(struct cmsghdr) + nr_fds*sizeof(int);
    char *cbuf = malloc(cbuf_len);
    if (cbuf == NULL) {FAIL();}
    memset(cbuf, 0, cbuf_len);

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = cbuf_len;
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(nr_fds*sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, nr_fds*sizeof(int));

    SYSCHK(sendmsg(sock, &msg, 0));

    free(cbuf);
    return 0;
}
