#include <stdio.h>
#include "ed25519.h"
#include <inttypes.h>
#include <assert.h>

#define LOG(...) if (verbose) { printf(__VA_ARGS__); }

bool verbose = false;

void print_dwords(unsigned char* ptr, int size) {
    for (int j = 0; j < (size)/(int)sizeof(uint32_t); j++) {
        LOG("%x ", ((uint32_t*)ptr)[j]);
    }
}

int main(int argc, const char* argv[]) {
    if (argc != 2 && argc != 3) {
        printf("usage: %s [-v] <num_signatures>\n", argv[0]);
        return 1;
    }
    const char* sig_ptr = argv[1];
    if (argc == 3) {
        if (0 == strcmp(argv[1], "-v")) {
            verbose = true;
            sig_ptr = argv[2];
        } else {
            printf("what is this? %s\n", argv[1]);
            return 1;
        }
    }
    int num_signatures = strtol(sig_ptr, NULL, 10);
    // Host allocate
    unsigned char* seed_h = (unsigned char*)calloc(num_signatures * SEED_SIZE, sizeof(uint32_t));
    unsigned char* public_key_h = (unsigned char*)calloc(num_signatures, PUB_KEY_SIZE);
    unsigned char* private_key_h = (unsigned char*)calloc(num_signatures, PRIV_KEY_SIZE);
    unsigned char* signature_h = (unsigned char*)calloc(num_signatures, SIG_SIZE);
    unsigned char message_h[] = "abcd1234";
    int message_h_len = strlen((char*)message_h);
    unsigned char* messages_h = (unsigned char*)calloc(num_signatures, message_h_len);
    uint32_t* message_lens_h = (uint32_t*)calloc(num_signatures, sizeof(uint32_t));
    uint32_t* message_offsets_h = (uint32_t*)calloc(num_signatures, sizeof(uint32_t));

    LOG("initing signatures..\n");
    for (int i = 0; i < num_signatures; i++) {
        message_lens_h[i] = message_h_len;
        memcpy(&messages_h[i * message_h_len], message_h, message_h_len);
        message_offsets_h[i] = i * message_h_len;
        LOG("message_len: %d offsets: %d message: %d\n",
               message_lens_h[i], message_offsets_h[i], messages_h[i * message_h_len]);
    }

    LOG("device allocate..\n");
    // Device allocate
    unsigned char* signature = NULL;
    cudaMalloc(&signature, num_signatures * SIG_SIZE);

    unsigned char* messages = NULL;
    cudaMalloc(&messages, num_signatures * message_h_len);

    LOG("device allocate2..\n");
    uint32_t* message_lens = NULL;
    cudaMalloc(&message_lens, num_signatures * sizeof(uint32_t));

    uint32_t* message_offsets = NULL;
    cudaMalloc(&message_offsets, num_signatures * sizeof(uint32_t));

    unsigned char* public_key = NULL;
    cudaMalloc(&public_key, num_signatures * PUB_KEY_SIZE);

    unsigned char* private_key = NULL;
    cudaMalloc(&private_key, num_signatures * PRIV_KEY_SIZE);

    int* out = NULL;
    int out_size = num_signatures * sizeof(int);
    cudaMalloc(&out, out_size);

    int* out_h = (int*)calloc(1, out_size);

    LOG("creating seed..\n");
    int ret = ed25519_create_seed(seed_h);
    LOG("create_seed: %d\n", ret);
    ed25519_create_keypair(public_key_h, private_key_h, seed_h);
    ed25519_sign(signature_h, message_h, message_h_len, public_key_h, private_key_h);
    ret = ed25519_verify(signature_h, message_h, message_h_len, public_key_h);
    LOG("verify: %d\n", ret);

    for (int i = 1; i < num_signatures; i++) {
        memcpy(&signature_h[i * SIG_SIZE], signature_h, SIG_SIZE);
        memcpy(&public_key_h[i * PUB_KEY_SIZE], public_key_h, PUB_KEY_SIZE);
    }

    for (int i = 0; i < num_signatures; i++ ) {
        unsigned char* sig_ptr = &signature_h[i * SIG_SIZE];
        unsigned char* messages_ptr = &messages_h[i * message_h_len];
        print_dwords(sig_ptr, SIG_SIZE);
        LOG("\n");
        print_dwords(messages_ptr, message_h_len);
        LOG("\n");
    }
    LOG("\n");

    cudaMemcpy(signature, signature_h, num_signatures * SIG_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(messages, messages_h, num_signatures * message_h_len, cudaMemcpyHostToDevice);
    cudaMemcpy(message_lens, message_lens_h, num_signatures * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(message_offsets, message_offsets_h, num_signatures * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(public_key, public_key_h, num_signatures * PUB_KEY_SIZE, cudaMemcpyHostToDevice);

    ed25519_verify_many(signature, messages, message_lens, message_offsets, public_key, num_signatures, out);

    cudaMemcpy(out_h, out, out_size, cudaMemcpyDeviceToHost);
    LOG("ret:\n");
    bool verify_failed = false;
    for (int i = 0; i < out_size / (int)sizeof(int); i++) {
        LOG("%x ", out_h[i]);
        if (out_h[i] != 1) {
            verify_failed = true;
        }
    }
    LOG("\n");
    fflush(stdout);
    assert(verify_failed == false);
    return 0;
}
