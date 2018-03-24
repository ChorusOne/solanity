#include <stdio.h>
#include "ed25519.h"
#include <inttypes.h>
#include <assert.h>
#include <vector>

#define LOG(...) if (verbose) { printf(__VA_ARGS__); }

bool verbose = false;

void print_dwords(unsigned char* ptr, int size) {
    for (int j = 0; j < (size)/(int)sizeof(uint32_t); j++) {
        LOG("%x ", ((uint32_t*)ptr)[j]);
    }
}

typedef struct {
    uint8_t signature[SIG_SIZE];
    uint8_t public_key[PUB_KEY_SIZE];
    uint8_t message[8];
} packet_t;

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
    if (num_signatures <= 0) {
        printf("num_signatures should be > 0! %d\n", num_signatures);
        return 1;
    }

    // Host allocate
    unsigned char* seed_h = (unsigned char*)calloc(num_signatures * SEED_SIZE, sizeof(uint32_t));
    unsigned char* private_key_h = (unsigned char*)calloc(num_signatures, PRIV_KEY_SIZE);
    unsigned char message_h[] = "abcd1234";
    int message_h_len = strlen((char*)message_h);

    std::vector<packet_t> packets_h = std::vector<packet_t>(num_signatures);
    std::vector<uint32_t> packet_offsets_h = std::vector<uint32_t>(num_signatures);
    std::vector<uint32_t> packet_lens_h = std::vector<uint32_t>(num_signatures);

    std::vector<uint32_t> message_offsets_h = std::vector<uint32_t>(num_signatures);
    std::vector<uint32_t> message_lens_h = std::vector<uint32_t>(num_signatures);

    assert(message_h_len == sizeof(packets_h[0].message));

    LOG("initing signatures..\n");
    for (int i = 0; i < num_signatures; i++) {
        memcpy(packets_h[i].message, message_h, message_h_len);
        message_lens_h[i] = message_h_len;
        message_offsets_h[i] = offsetof(packet_t, message);
        packet_offsets_h[i] = i * sizeof(packet_t);
        packet_lens_h[i] = sizeof(packet_t);

        LOG("message_len: %d offsets: %d message: %d packet_offset: %d packet_len: %d\n",
            message_lens_h[i], message_offsets_h[i], packets_h[i].message[0], packet_offsets_h[i], packet_lens_h[i]);
    }

    int out_size = num_signatures * sizeof(uint8_t);
    uint8_t* out_h = (uint8_t*)calloc(1, out_size);

    LOG("creating seed..\n");
    int ret = ed25519_create_seed(seed_h);
    LOG("create_seed: %d\n", ret);
    ed25519_create_keypair(packets_h[0].public_key, private_key_h, seed_h);
    ed25519_sign(packets_h[0].signature, packets_h[0].message, message_h_len, packets_h[0].public_key, private_key_h);
    ret = ed25519_verify(packets_h[0].signature, message_h, message_h_len, packets_h[0].public_key);
    LOG("verify: %d\n", ret);

    for (int i = 1; i < num_signatures; i++) {
        memcpy(packets_h[i].signature, packets_h[0].signature, SIG_SIZE);
        memcpy(packets_h[i].public_key, packets_h[0].public_key, PUB_KEY_SIZE);
    }

    for (int i = 0; i < num_signatures; i++ ) {
        unsigned char* sig_ptr = packets_h[i].signature;
        unsigned char* messages_ptr = packets_h[i].message;
        print_dwords(sig_ptr, SIG_SIZE);
        LOG("\n");
        print_dwords(messages_ptr, message_h_len);
        LOG("\n");
    }
    LOG("\n");

    ed25519_verify_many((uint8_t*)&packets_h[0],
                        &packet_lens_h[0], &packet_offsets_h[0],
                        &message_lens_h[0], &message_offsets_h[0],
                        offsetof(packet_t, public_key),
                        offsetof(packet_t, signature),
                        num_signatures, out_h);

    LOG("ret:\n");
    bool verify_failed = false;
    for (int i = 0; i < out_size / (int)sizeof(uint8_t); i++) {
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
