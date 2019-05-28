#include "tomcrypt_macros.h"


#ifndef SHA256_H
#define SHA256_H

#define SHA256_BLOCK_SIZE 32

struct sha256_state {
    ulong64 length;
    ulong32 state[8], curlen;
    unsigned char buf[64];
};

typedef struct {
    struct sha256_state sha256;
} hash_state;

void __host__ __device__ sha256_init(hash_state*);

void __host__ __device__ sha256_process(hash_state*, unsigned char const*, unsigned long);

void __host__ __device__ sha256_done(hash_state*, unsigned char*);

#endif
