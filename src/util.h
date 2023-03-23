#ifndef _UTIL_H_
#define _UTIL_H_

#include <unistd.h>
#include <stdint.h>

// allocate memory initialized with zeroes
void *zalloc(size_t sz);

// if cpu is -1 then the process can be scheduled on every online cpu
int pin_to_cpu(int cpu);

// wait for 'x' or 'X' character on stdin
void wait_for_x();


void hexdump(void *buf, size_t sz);



#define SZ_1				0x00000001
#define SZ_2				0x00000002
#define SZ_4				0x00000004
#define SZ_8				0x00000008
#define SZ_16				0x00000010
#define SZ_32				0x00000020
#define SZ_64				0x00000040
#define SZ_128				0x00000080
#define SZ_256				0x00000100
#define SZ_512				0x00000200

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_8K				0x00002000
#define SZ_16K				0x00004000
#define SZ_32K				0x00008000
#define SZ_64K				0x00010000
#define SZ_128K				0x00020000
#define SZ_256K				0x00040000
#define SZ_512K				0x00080000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_4M				0x00400000
#define SZ_8M				0x00800000
#define SZ_16M				0x01000000
#define SZ_32M				0x02000000
#define SZ_64M				0x04000000
#define SZ_128M				0x08000000
#define SZ_256M				0x10000000
#define SZ_512M				0x20000000

#define SZ_1G				0x40000000
#define SZ_2G				0x80000000


#define ALIGN(x, sz) (((x) + (sz) - 1) & ~((sz)-1))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#include <android/log.h>

#define LOG(fmt, ...) do { \
  __android_log_print(ANDROID_LOG_INFO, "BADSPIN", fmt, ##__VA_ARGS__); \
  printf(fmt, ##__VA_ARGS__); \
  } while(0)

#define LOGD(fmt, ...) ({           \
    if (VERBOSE) {                  \
        LOG(fmt, ##__VA_ARGS__);    \
    }                               \
})

#define FAIL() do { LOG("Failed on %s:%d\n", __func__, __LINE__); exit(1); } while(0)

#define SYSCHK(x) ({                  \
  __typeof__(x) __res = (x);          \
  if (__res == (__typeof__(x))-1) {   \
    LOG("SYSCHK(" #x ")");            \
    exit(1);                          \
  }                                   \
  __res;                              \
})

#endif