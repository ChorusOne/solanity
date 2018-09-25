#include "common.cu"
#include "chacha.h"
#include "modes_lcl.h"
#include "perftime.h"
#include <algorithm>
#include "chacha20_core.cu"

#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
# define STRICT_ALIGNMENT 0
#endif

__host__ __device__ void chacha20_cbc128_encrypt(const unsigned char* in, unsigned char* out,
                                                 uint32_t len, const uint8_t* key,
                                                 unsigned char* ivec)
{
    size_t n;
    unsigned char *iv = ivec;

    if (len == 0) {
        return;
    }

#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (STRICT_ALIGNMENT &&
        ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
        while (len >= CHACHA_BLOCK_SIZE) {
            for (n = 0; n < CHACHA_BLOCK_SIZE; ++n) {
                out[n] = in[n] ^ iv[n];
                //printf("%x ", out[n]);
            }
            chacha20_encrypt((const u32*)out, out, CHACHA_ROUNDS);
            iv = out;
            len -= CHACHA_BLOCK_SIZE;
            in += CHACHA_BLOCK_SIZE;
            out += CHACHA_BLOCK_SIZE;
        }
    } else {
        while (len >= CHACHA_BLOCK_SIZE) {
            for (n = 0; n < CHACHA_BLOCK_SIZE; n += sizeof(size_t)) {
                *(size_t *)(out + n) =
                    *(size_t *)(in + n) ^ *(size_t *)(iv + n);
                //printf("%zu ", *(size_t *)(iv + n));
            }
            chacha20_encrypt((const u32*)out, out, CHACHA_ROUNDS);
            iv = out;
            len -= CHACHA_BLOCK_SIZE;
            in += CHACHA_BLOCK_SIZE;
            out += CHACHA_BLOCK_SIZE;
        }
    }
#endif
    while (len) {
        for (n = 0; n < CHACHA_BLOCK_SIZE && n < len; ++n) {
            out[n] = in[n] ^ iv[n];
        }
        for (; n < CHACHA_BLOCK_SIZE; ++n) {
            out[n] = iv[n];
        }
        chacha20_encrypt((const u32*)out, out, CHACHA_ROUNDS);
        iv = out;
        if (len <= CHACHA_BLOCK_SIZE) {
            break;
        }
        len -= CHACHA_BLOCK_SIZE;
        in += CHACHA_BLOCK_SIZE;
        out += CHACHA_BLOCK_SIZE;
    }
    memcpy(ivec, iv, CHACHA_BLOCK_SIZE);

}

void chacha20_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t in_len,
                          const uint8_t key[CHACHA_KEY_SIZE], uint8_t* ivec)
{
    chacha20_cbc128_encrypt(in, out, in_len, key, ivec);
}

__global__ void chacha20_cbc128_encrypt_kernel(const unsigned char* input, unsigned char* output,
                                               size_t length, const uint8_t* keys,
                                               unsigned char* ivec, uint32_t num_keys,
                                               unsigned char* sha_state,
                                               uint32_t* sample_idx,
                                               uint32_t sample_len,
                                               uint32_t block_offset)
{
    size_t i = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);

    if (i < num_keys) {
        chacha20_cbc128_encrypt(input, &output[i * length], length, &keys[i], &ivec[i * CHACHA_BLOCK_SIZE]);

        /*for (uint32_t j = 0; j < sample_len; j++) {
            if (sample_idx[j] > block_offset && sample_idx[j] < (block_offset + length)) {
            }
        }*/
    }
}


__global__ void chacha_ctr_encrypt_kernel(const unsigned char* input, unsigned char* output,
                                          size_t length, const uint8_t* keys,
                                          unsigned char* nonces, uint32_t num_keys,
                                          unsigned char* sha_state,
                                          uint32_t* sample_idx,
                                          uint32_t sample_len,
                                          uint32_t block_offset)
{
    size_t i = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);

    if (i < num_keys) {
        chacha20_ctr_encrypt(input, &output[i * length], length, &keys[i * CHACHA_KEY_SIZE], &nonces[i * CHACHA_NONCE_SIZE], 0);
    }
}


void chacha_cbc_encrypt_many(const unsigned char *in, unsigned char *out,
                             size_t length, const uint8_t *keys,
                             uint8_t* ivec,
                             uint32_t num_keys,
                             float* time_us)
{
    if (length < BLOCK_SIZE) {
        printf("ERROR! block size(%d) > length(%zu)\n", BLOCK_SIZE, length);
        return;
    }
    uint8_t* in_device = NULL;
    uint8_t* in_device0 = NULL;
    uint8_t* in_device1 = NULL;
    uint8_t* keys_device = NULL;
    uint8_t* output_device = NULL;
    uint8_t* output_device0 = NULL;
    uint8_t* output_device1 = NULL;
    uint8_t* ivec_device = NULL;

    uint8_t* sha_state_device = NULL;

    uint32_t sample_len = 0;
    uint32_t* samples_device = NULL;

    CUDA_CHK(cudaMalloc(&in_device0, BLOCK_SIZE));
    CUDA_CHK(cudaMalloc(&in_device1, BLOCK_SIZE));

    size_t ctx_size = CHACHA_KEY_SIZE * num_keys;
    CUDA_CHK(cudaMalloc(&keys_device, ctx_size));
    CUDA_CHK(cudaMemcpy(keys_device, keys, ctx_size, cudaMemcpyHostToDevice));

    size_t ivec_size = CHACHA_BLOCK_SIZE * num_keys;
    CUDA_CHK(cudaMalloc(&ivec_device, ivec_size));
    CUDA_CHK(cudaMemcpy(ivec_device, ivec, ivec_size, cudaMemcpyHostToDevice));

    size_t output_size = (size_t)num_keys * (size_t)BLOCK_SIZE;
    CUDA_CHK(cudaMalloc(&output_device0, output_size));
    CUDA_CHK(cudaMalloc(&output_device1, output_size));

    int num_threads_per_block = 64;
    int num_blocks = (num_keys + num_threads_per_block - 1) / num_threads_per_block;

    perftime_t start, end;

    get_time(&start);

    cudaStream_t stream, stream0, stream1;
    cudaStreamCreate(&stream0);
    cudaStreamCreate(&stream1);

    ssize_t slength = length;
    size_t num_data_blocks = (length + BLOCK_SIZE - 1) / (BLOCK_SIZE);

    printf("num_blocks: %d threads_per_block: %d keys size: %zu in: %p ind0: %p ind1: %p output_size: %zu num_data_blocks: %zu\n",
                    num_blocks, num_threads_per_block, ctx_size, in, in_device0, in_device1, output_size, num_data_blocks);

    for (uint32_t i = 0;; i++) {
        //if (i & 0x1) {
        if (0) {
            in_device = in_device1;
            output_device = output_device1;
            stream = stream1;
        } else {
            in_device = in_device0;
            output_device = output_device0;
            stream = stream0;
        }
        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);
        //printf("copying to in_device: %p in: %p size: %zu num_data_blocks: %zu\n", in_device, in, size, num_data_blocks);
        CUDA_CHK(cudaMemcpyAsync(in_device, in, size, cudaMemcpyHostToDevice, stream));

        chacha20_cbc128_encrypt_kernel<<<num_blocks, num_threads_per_block, 0, stream>>>(
                            in_device, output_device, size,
                            keys_device, ivec_device, num_keys,
                            sha_state_device,
                            samples_device,
                            sample_len,
                            i * BLOCK_SIZE);
//#define DO_COPY
#ifdef DO_COPY
        for (uint32_t j = 0; j < num_keys; j++) {
            size_t block_offset = j * length + i * BLOCK_SIZE;
            size_t out_offset = j * size;
            //printf("i: %d j: %d copy %zi b block offset: %zu output offset: %zu num_data_blocks: %zu\n",
            //                i, j, size, block_offset, out_offset, num_data_blocks);
            CUDA_CHK(cudaMemcpy(&out[block_offset], &output_device[out_offset], size, cudaMemcpyDeviceToHost));
        }
#endif

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        if (slength <= 0) {
            break;
        }
    }

    CUDA_CHK(cudaMemcpy(ivec, ivec_device, ivec_size, cudaMemcpyDeviceToHost));

    get_time(&end);
    *time_us = get_diff(&start, &end);

    //printf("gpu time: %f us\n", get_diff(&start, &end));
}

void chacha_ctr_encrypt_many(const unsigned char *in, unsigned char *out,
                             size_t length,
                             const uint8_t *keys,
                             const uint8_t* nonces,
                             uint32_t num_keys,
                             float* time_us)
{
    if (length < BLOCK_SIZE) {
        printf("ERROR! block size(%d) > length(%zu)\n", BLOCK_SIZE, length);
        return;
    }
    uint8_t* in_device = NULL;
    uint8_t* in_device0 = NULL;
    uint8_t* in_device1 = NULL;
    uint8_t* keys_device = NULL;
    uint8_t* output_device = NULL;
    uint8_t* output_device0 = NULL;
    uint8_t* output_device1 = NULL;
    uint8_t* nonces_device = NULL;

    uint8_t* sha_state_device = NULL;

    uint32_t sample_len = 0;
    uint32_t* samples_device = NULL;

    CUDA_CHK(cudaMalloc(&in_device0, BLOCK_SIZE));
    CUDA_CHK(cudaMalloc(&in_device1, BLOCK_SIZE));

    size_t ctx_size = CHACHA_KEY_SIZE * num_keys;
    CUDA_CHK(cudaMalloc(&keys_device, ctx_size));
    CUDA_CHK(cudaMemcpy(keys_device, keys, ctx_size, cudaMemcpyHostToDevice));

    size_t nonces_size = CHACHA_NONCE_SIZE * num_keys;
    CUDA_CHK(cudaMalloc(&nonces_device, nonces_size));
    CUDA_CHK(cudaMemcpy(nonces_device, nonces, nonces_size, cudaMemcpyHostToDevice));

    size_t output_size = (size_t)num_keys * (size_t)BLOCK_SIZE;
    CUDA_CHK(cudaMalloc(&output_device0, output_size));
    CUDA_CHK(cudaMalloc(&output_device1, output_size));

    int num_threads_per_block = 64;
    int num_blocks = (num_keys + num_threads_per_block - 1) / num_threads_per_block;

    perftime_t start, end;

    get_time(&start);

    cudaStream_t stream, stream0, stream1;
    cudaStreamCreate(&stream0);
    cudaStreamCreate(&stream1);

    ssize_t slength = length;
    size_t num_data_blocks = (length + BLOCK_SIZE - 1) / (BLOCK_SIZE);

    printf("num_blocks: %d threads_per_block: %d keys size: %zu in: %p ind0: %p ind1: %p output_size: %zu num_data_blocks: %zu\n",
                    num_blocks, num_threads_per_block, ctx_size, in, in_device0, in_device1, output_size, num_data_blocks);

    for (uint32_t i = 0;; i++) {
        //if (i & 0x1) {
        if (0) {
            in_device = in_device1;
            output_device = output_device1;
            stream = stream1;
        } else {
            in_device = in_device0;
            output_device = output_device0;
            stream = stream0;
        }
        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);
        //printf("copying to in_device: %p in: %p size: %zu num_data_blocks: %zu\n", in_device, in, size, num_data_blocks);
        CUDA_CHK(cudaMemcpyAsync(in_device, in, size, cudaMemcpyHostToDevice, stream));

        chacha_ctr_encrypt_kernel<<<num_blocks, num_threads_per_block, 0, stream>>>(
                            in_device, output_device, size,
                            keys_device, nonces_device, num_keys,
                            sha_state_device,
                            samples_device,
                            sample_len,
                            i * BLOCK_SIZE);
#ifdef DO_COPY
        for (uint32_t j = 0; j < num_keys; j++) {
            size_t block_offset = j * length + i * BLOCK_SIZE;
            size_t out_offset = j * size;
            //printf("i: %d j: %d copy %zi b block offset: %zu output offset: %zu num_data_blocks: %zu\n",
            //                i, j, size, block_offset, out_offset, num_data_blocks);
            CUDA_CHK(cudaMemcpy(&out[block_offset], &output_device[out_offset], size, cudaMemcpyDeviceToHost));
        }
#endif

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        if (slength <= 0) {
            break;
        }
    }

#ifndef DO_COPY
    CUDA_CHK(cudaDeviceSynchronize());
#endif

    get_time(&end);
    *time_us = get_diff(&start, &end);

    //printf("gpu time: %f us\n", get_diff(&start, &end));
}
