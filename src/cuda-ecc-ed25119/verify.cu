#include "sha512.h"
#include <algorithm>
#include <stdio.h>
#include "ge.cu"
#include "sc.cu"
#include "fe.cu"
#include "seed.cu"
#include "keypair.cu"
#include "sign.cu"
#include "sha512.cu"

#include "ed25519.h"

#define USE_CLOCK_GETTIME
#include "perftime.h"

static int __host__ __device__ consttime_equal(const unsigned char *x, const unsigned char *y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
    #define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
    #undef F

    return !r;
}

static int __device__ __host__
ed25519_verify_device(const unsigned char *signature,
                      const unsigned char *message,
                      uint32_t message_len,
                      const unsigned char *public_key) {
    unsigned char h[64];
    unsigned char checker[32];
    sha512_context hash;
    ge_p3 A;
    ge_p2 R;

    if (signature[63] & 224) {
        return 5;
    }

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return 3;
    }

    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, public_key, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, h);
    
    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);

    if (!consttime_equal(checker, signature)) {
        return 0;
    }

    return 1;
}

int 
ed25519_verify(const unsigned char *signature,
               const unsigned char *message,
               uint32_t message_len,
               const unsigned char *public_key) {
    return ed25519_verify_device(signature, message, message_len, public_key);
}

__global__ void ed25519_verify_kernel(const unsigned char* packets,
                                      const uint32_t* packet_offsets,
                                      const uint32_t* packet_lens,
                                      const uint32_t* message_lens,
                                      const uint32_t* message_offsets,
                                      uint32_t public_key_offset,
                                      uint32_t signature_offset,
                                      size_t num_keys,
                                      uint8_t* out)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < num_keys) {
        const uint8_t* packet = &packets[packet_offsets[i]];
        out[i] = ed25519_verify_device(&packet[signature_offset],
                                       &packet[message_offsets[i]],
                                       message_lens[i],
                                       &packet[public_key_offset]);
    }
}

typedef struct {
    unsigned char* packets;
    uint32_t* packet_lens;
    uint32_t* packet_offsets;
    uint32_t* message_lens;
    uint32_t* message_offsets;
    uint8_t* out;

    size_t num_keys;
    uint32_t total_packets_len;
} gpu_ctx;

static gpu_ctx g_gpu_ctx = {0};
static bool g_verbose = false;
#define LOG(...) if (g_verbose) { printf(__VA_ARGS__); }

void ed25519_verify_many(const uint8_t* packets,
                         const uint32_t* packet_lens,
                         const uint32_t* packet_offsets,
                         const uint32_t* message_lens,
                         const uint32_t* message_offsets,
                         uint32_t public_key_offset,
                         uint32_t signature_offset,
                         size_t num_keys,
                         uint8_t* out)
{
    size_t out_size = num_keys * sizeof(uint8_t);

    uint32_t total_packets_len = packet_offsets[num_keys-1] + packet_lens[num_keys-1];

    LOG("device allocate.. %d\n", total_packets_len);
    // Device allocate

    if (g_gpu_ctx.packets == NULL ||
        total_packets_len > g_gpu_ctx.total_packets_len) {
        CUDA_CHK(cudaFree(g_gpu_ctx.packets));
        CUDA_CHK(cudaMalloc(&g_gpu_ctx.packets, total_packets_len));

        g_gpu_ctx.total_packets_len = total_packets_len;
    }

    if (g_gpu_ctx.message_lens == NULL ||
        num_keys > g_gpu_ctx.num_keys) {

        LOG("allocating keys.. %d\n", (int)num_keys);

        CUDA_CHK(cudaFree(g_gpu_ctx.packet_lens));
        CUDA_CHK(cudaMalloc(&g_gpu_ctx.packet_lens, num_keys * sizeof(uint32_t)));

        CUDA_CHK(cudaFree(g_gpu_ctx.packet_offsets));
        CUDA_CHK(cudaMalloc(&g_gpu_ctx.packet_offsets, num_keys * sizeof(uint32_t)));

        CUDA_CHK(cudaFree(g_gpu_ctx.message_lens));
        CUDA_CHK(cudaMalloc(&g_gpu_ctx.message_lens, num_keys * sizeof(uint32_t)));

        CUDA_CHK(cudaFree(g_gpu_ctx.message_offsets));
        CUDA_CHK(cudaMalloc(&g_gpu_ctx.message_offsets, num_keys * sizeof(uint32_t)));

        CUDA_CHK(cudaFree(g_gpu_ctx.out));
        CUDA_CHK(cudaMalloc(&g_gpu_ctx.out, out_size));

        g_gpu_ctx.num_keys = num_keys;
    }

    CUDA_CHK(cudaMemcpy(g_gpu_ctx.packets, packets, total_packets_len, cudaMemcpyHostToDevice));
    CUDA_CHK(cudaMemcpy(g_gpu_ctx.message_lens, message_lens, num_keys * sizeof(uint32_t), cudaMemcpyHostToDevice));
    CUDA_CHK(cudaMemcpy(g_gpu_ctx.message_offsets, message_offsets, num_keys * sizeof(uint32_t), cudaMemcpyHostToDevice));
    CUDA_CHK(cudaMemcpy(g_gpu_ctx.packet_lens, packet_lens, num_keys * sizeof(uint32_t), cudaMemcpyHostToDevice));
    CUDA_CHK(cudaMemcpy(g_gpu_ctx.packet_offsets, packet_offsets, num_keys * sizeof(uint32_t), cudaMemcpyHostToDevice));

    int num_threads_per_block = 64;
    int num_blocks = (num_keys + num_threads_per_block - 1) / num_threads_per_block;
    LOG("num_blocks: %d threads_per_block: %d keys: %d\n",
           num_blocks, num_threads_per_block, (int)num_keys);
    perftime_t start, end;
    get_time(&start);
    ed25519_verify_kernel<<<num_blocks, num_threads_per_block>>>
                            (g_gpu_ctx.packets, g_gpu_ctx.packet_lens, g_gpu_ctx.packet_offsets,
                             g_gpu_ctx.message_lens, g_gpu_ctx.message_offsets,
                             public_key_offset, signature_offset,
                             g_gpu_ctx.num_keys, g_gpu_ctx.out);

    CUDA_CHK(cudaMemcpy(out, g_gpu_ctx.out, out_size, cudaMemcpyDeviceToHost));
    get_time(&end);
    LOG("time diff: %f\n", get_diff(&start, &end));
}

void ED25519_DECLSPEC ed25519_free_gpu_mem() {
    CUDA_CHK(cudaFree(g_gpu_ctx.packets));
    CUDA_CHK(cudaFree(g_gpu_ctx.message_lens));
    CUDA_CHK(cudaFree(g_gpu_ctx.message_offsets));
    CUDA_CHK(cudaFree(g_gpu_ctx.packet_offsets));
    CUDA_CHK(cudaFree(g_gpu_ctx.packet_lens));
    CUDA_CHK(cudaFree(g_gpu_ctx.out));
}
