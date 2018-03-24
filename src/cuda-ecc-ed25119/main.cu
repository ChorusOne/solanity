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
    unsigned char* public_keys_h = (unsigned char*)calloc(num_signatures, PUB_KEY_SIZE);
    unsigned char* private_key_h = (unsigned char*)calloc(num_signatures, PRIV_KEY_SIZE);
    unsigned char* signatures_h = (unsigned char*)calloc(num_signatures, SIG_SIZE);
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

    int out_size = num_signatures * sizeof(int);
    int* out_h = (int*)calloc(1, out_size);

    LOG("creating seed..\n");
    int ret = ed25519_create_seed(seed_h);
    LOG("create_seed: %d\n", ret);
    ed25519_create_keypair(&public_keys_h[0], private_key_h, seed_h);
    ed25519_sign(signatures_h, message_h, message_h_len, &public_keys_h[0], private_key_h);
    ret = ed25519_verify(signatures_h, message_h, message_h_len, &public_keys_h[0]);
    LOG("verify: %d\n", ret);

    for (int i = 1; i < num_signatures; i++) {
        memcpy(&signatures_h[i * SIG_SIZE], signatures_h, SIG_SIZE);
        memcpy(&public_keys_h[i * PUB_KEY_SIZE], &public_keys_h[0], PUB_KEY_SIZE);
    }

    for (int i = 0; i < num_signatures; i++ ) {
        unsigned char* sig_ptr = &signatures_h[i * SIG_SIZE];
        unsigned char* messages_ptr = &messages_h[i * message_h_len];
        print_dwords(sig_ptr, SIG_SIZE);
        LOG("\n");
        print_dwords(messages_ptr, message_h_len);
        LOG("\n");
    }
    LOG("\n");

    ed25519_verify_many(signatures_h, messages_h,
                        message_lens_h, message_offsets_h,
                        &public_keys_h[0], num_signatures, out_h);

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
    ed25519_free_gpu_mem();
    return 0;
}
