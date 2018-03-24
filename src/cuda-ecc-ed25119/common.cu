#include <assert.h>

#ifndef COMMON_CU
#define COMMON_CU

#define CUDA_CHK(ans) { cuda_assert((ans), __FILE__, __LINE__); }

inline void cuda_assert(cudaError_t err, const char *file, int line)
{
    if (err != cudaSuccess) 
    {
        fprintf(stderr,"ERR: %s %s %d\n", cudaGetErrorString(err), file, line);
        assert(0);
    }
}

static uint64_t __host__ __device__ load_3(const unsigned char *in) {
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;

    return result;
}

static uint64_t __host__ __device__ load_4(const unsigned char *in) {
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;
    
    return result;
}

#endif
