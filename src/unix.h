#ifndef _UNIX_H_
#define _UNIX_H_

#include <sys/socket.h>
#include <sys/un.h>

int unix_recv_files(int sock, int *fds, unsigned int max_fds, unsigned int *nr_fds_recv);

int unix_send_files(int sock, int *fds, unsigned int nr_fds);

#endif