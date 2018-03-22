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

__global__ void ed25519_verify_kernel(const unsigned char* signatures,
                                      const unsigned char* messages,
                                      const uint32_t* message_lens,
                                      const uint32_t* message_offsets,
                                      const unsigned char* public_keys,
                                      size_t num_keys,
                                      int* out)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < num_keys) {
        out[i] = ed25519_verify_device(&signatures[SIG_SIZE * i],
                                       &messages[message_offsets[i]],
                                       message_lens[i],
                                       &public_keys[i * PUB_KEY_SIZE]);
    }
}

void ed25519_verify_many(const unsigned char* signatures,
                         const unsigned char* messages,
                         const uint32_t* message_lens,
                         const uint32_t* message_offsets,
                         const unsigned char* public_keys,
                         size_t num_keys,
                         int* out)
{
    int num_threads_per_block = 64;
    int num_blocks = std::max(1ul, num_keys / num_threads_per_block);
    printf("num_blocks: %d threads_per_block: %d\n", num_blocks, num_threads_per_block);
    ed25519_verify_kernel<<<num_blocks, num_threads_per_block>>>
                            (signatures, messages, message_lens, message_offsets, public_keys, num_keys, out);
}


