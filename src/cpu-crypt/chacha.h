#ifndef HEADER_CHACHA_H
# define HEADER_CHACHA_H

#include <string.h>
#include <inttypes.h>
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

typedef unsigned int u32;

#define CHACHA_KEY_SIZE 32
#define CHACHA_NONCE_SIZE 12

void chacha20_encrypt_ctr(uint8_t *out, const uint8_t *in, size_t in_len,
                          const uint8_t key[CHACHA_KEY_SIZE], const uint8_t nonce[CHACHA_NONCE_SIZE],
                          uint32_t counter);

# ifdef  __cplusplus
}
# endif

#endif
