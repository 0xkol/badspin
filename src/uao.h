#ifndef _UAO_H_
#define _UAO_H_

#include "rw.h"

int uao_init(struct rw_info *rw);
int uao_kread(struct rw_info *rw, u64 kaddr, void *buf, u64 size);
int uao_kwrite(struct rw_info *rw, u64 kaddr, void *buf, u64 size);
int uao_close(struct rw_info *rw);

#endif