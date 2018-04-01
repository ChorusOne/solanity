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
    uint32_t message_len;
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

    ed25519_set_verbose(verbose);

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
    uint32_t message_len_offset = offsetof(packet_t, message_len);
    uint32_t signature_offset = offsetof(packet_t, signature);
    uint32_t public_key_offset = offsetof(packet_t, public_key);
    uint32_t message_start_offset = offsetof(packet_t, message);

    std::vector<streamer_Packet> packets_h = std::vector<streamer_Packet>(num_signatures);
    int num_elems = 2;
    std::vector<gpu_Elems> elems_h = std::vector<gpu_Elems>(num_elems);
    for (int i = 0; i < num_elems; i++) {
        elems_h[i].num = num_signatures;
        elems_h[i].elems = &packets_h[0];
    }

    LOG("initing signatures..\n");
    for (int i = 0; i < num_signatures; i++) {
        packet_t* packet = (packet_t*)packets_h[i].data;
        memcpy(packet->message, message_h, message_h_len);
        packet->message_len = message_h_len;

        LOG("message_len: %d sig_offset: %d pub_key_offset: %d message_start_offset: %d message_len_offset: %d\n",
            message_h_len, signature_offset, public_key_offset, message_start_offset, message_len_offset);
    }

    int out_size = num_elems * num_signatures * sizeof(uint8_t);
    uint8_t* out_h = (uint8_t*)calloc(1, out_size);

    LOG("creating seed..\n");
    int ret = ed25519_create_seed(seed_h);
    LOG("create_seed: %d\n", ret);
    packet_t* first_packet_h = (packet_t*)packets_h[0].data;
    ed25519_create_keypair(first_packet_h->public_key, private_key_h, seed_h);
    ed25519_sign(first_packet_h->signature, first_packet_h->message, message_h_len, first_packet_h->public_key, private_key_h);
    ret = ed25519_verify(first_packet_h->signature, message_h, message_h_len, first_packet_h->public_key);
    LOG("verify: %d\n", ret);

    for (int i = 1; i < num_signatures; i++) {
        packet_t* packet_h = (packet_t*)packets_h[i].data;
        memcpy(packet_h->signature, first_packet_h->signature, SIG_SIZE);
        memcpy(packet_h->public_key, first_packet_h->public_key, PUB_KEY_SIZE);
    }

    for (int i = 0; i < num_signatures; i++ ) {
        packet_t* packet_h = (packet_t*)packets_h[i].data;
        unsigned char* sig_ptr = packet_h->signature;
        unsigned char* messages_ptr = packet_h->message;
        LOG("sig:");
        print_dwords(sig_ptr, SIG_SIZE);
        LOG("\nmessage: ");
        print_dwords(messages_ptr, message_h_len);
        LOG("\n\n");
    }
    LOG("\n");

    for (int i = 0; i < 2; i++) {
        ed25519_verify_many(&elems_h[0],
                            num_elems,
                            public_key_offset,
                            signature_offset,
                            message_start_offset,
                            message_len_offset,
                            out_h);

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
    }
    ed25519_free_gpu_mem();
    return 0;
}
