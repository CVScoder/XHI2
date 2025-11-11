#include "salsa20_impl.h"
#include <cstring>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

Salsa20::Salsa20() : counter(0), keystreamPos(BLOCK_SIZE) {
    memset(state, 0, sizeof(state));
    memset(keystream, 0, sizeof(keystream));
}

void Salsa20::init(const uint8_t* key, size_t keyLen,
                   const uint8_t* nonce, size_t nonceLen) {
    if (keyLen != KEY_SIZE || nonceLen != NONCE_SIZE) {
        return;
    }
    
    // Salsa20 constants
    state[0] = 0x61707865;   // "expa"
    state[5] = 0x3320646e;   // "nd 3"
    state[10] = 0x79622d32;  // "2-by"
    state[15] = 0x6b206574;  // "te k"
    
    // 256-bit key
    for (int i = 0; i < 8; i++) {
        state[(i < 4) ? (1 + i) : (11 + (i - 4))] = 
            (key[4*i] | (key[4*i+1] << 8) |
             (key[4*i+2] << 16) | (key[4*i+3] << 24));
    }
    
    // 64-bit nonce
    state[6] = (nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24));
    state[7] = (nonce[4] | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24));
    
    // Counter
    state[8] = state[9] = 0;
    
    counter = 0;
    keystreamPos = BLOCK_SIZE;
}

void Salsa20::salsa20Block() {
    uint32_t working[16];
    memcpy(working, state, sizeof(state));
    
    // Salsa20 quarterround: simplified version
    for (int i = 0; i < 10; i++) {
        working[4] ^= ROTL32(working[0] + working[12], 7);
        working[8] ^= ROTL32(working[4] + working[0], 9);
        working[12] ^= ROTL32(working[8] + working[4], 13);
        working[0] ^= ROTL32(working[12] + working[8], 18);
        
        working[9] ^= ROTL32(working[5] + working[1], 7);
        working[13] ^= ROTL32(working[9] + working[5], 9);
        working[1] ^= ROTL32(working[13] + working[9], 13);
        working[5] ^= ROTL32(working[1] + working[13], 18);
        
        working[14] ^= ROTL32(working[10] + working[6], 7);
        working[2] ^= ROTL32(working[14] + working[10], 9);
        working[6] ^= ROTL32(working[2] + working[14], 13);
        working[10] ^= ROTL32(working[6] + working[2], 18);
        
        working[3] ^= ROTL32(working[15] + working[11], 7);
        working[7] ^= ROTL32(working[3] + working[15], 9);
        working[11] ^= ROTL32(working[7] + working[3], 13);
        working[15] ^= ROTL32(working[11] + working[7], 18);
    }
    
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
        uint32_t val = working[i];
        keystream[4*i] = val & 0xFF;
        keystream[4*i+1] = (val >> 8) & 0xFF;
        keystream[4*i+2] = (val >> 16) & 0xFF;
        keystream[4*i+3] = (val >> 24) & 0xFF;
    }
    
    state[8]++;
    if (state[8] == 0) state[9]++;
    keystreamPos = 0;
}

void Salsa20::encrypt(const uint8_t* plaintext, uint8_t* ciphertext, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (keystreamPos >= BLOCK_SIZE) {
            salsa20Block();
        }
        ciphertext[i] = plaintext[i] ^ keystream[keystreamPos++];
    }
}

void Salsa20::decrypt(const uint8_t* ciphertext, uint8_t* plaintext, size_t len) {
    encrypt(ciphertext, plaintext, len);
}

uint32_t Salsa20::rotl32(uint32_t x, uint32_t n) {
    return ROTL32(x, n);
}
