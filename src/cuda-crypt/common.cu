#include <assert.h>
#include <stdio.h>

#ifndef COMMON_CU
#define COMMON_CU

#define BLOCK_SIZE (4 * 1024)

#define CUDA_CHK(ans) { cuda_assert((ans), __FILE__, __LINE__); }

inline void cuda_assert(cudaError_t err, const char *file, int line)
{
    if (err != cudaSuccess)
    {
        fprintf(stderr,"ERR: %s %s %d\n", cudaGetErrorString(err), file, line);
        assert(0);
    }
}

#endif
